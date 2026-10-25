package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// EdgeSessionVersion is the schema of edge-session.json. A document carrying any other
// version is treated as absent, never guessed at.
const EdgeSessionVersion = "gasworks.dev/edge-session/v1"

// EdgeSession is the cli-edge device root `gasworks login --edge-device` signed in with: an
// opaque CLI root session the cli-edge bound to a DPoP key when this device redeemed the
// approval, plus a reference to that key in an approved credential store. It is the
// edge-device counterpart of the Keycloak id_token/refresh token pair in credentials.json, and
// the STS takes it in place of a /sts/v0/login session.
//
// It lives in its own file, not in credentials.json, because that document is shared with
// bd-enterprise: bd's store decodes credentials.json into its own struct and writes it back,
// dropping every field it does not know. A root stored there would be erased by the next bd
// write. What the two documents DO share is the credential generation: an edge session is in
// force only while its CredentialGeneration equals the one in credentials.json, so any login
// or logout — by this CLI or by bd — that rewrites the generation fences it out.
//
// Like a Session it carries only a KeyRef, never the key: the root and the key it is bound to
// are never stored together.
type EdgeSession struct {
	Version              string `json:"version"`
	CredentialGeneration string `json:"credential_generation"`
	RootToken            string `json:"root_token"`
	TokenType            string `json:"token_type"`
	Key                  KeyRef `json:"key"`
	// EdgeOrigin is where the root was issued, and so where it is revoked.
	EdgeOrigin string `json:"edge_origin"`
	// OrgID, OrgSlug and UserID are what the STS reported for the root when it was issued.
	// They are display metadata for `gasworks inspect`; every mint re-reads the org from the
	// STS rather than trusting this copy.
	OrgID   string `json:"org_id,omitempty"`
	OrgSlug string `json:"org_slug,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	// IssuedAt is when this device redeemed the approval. ExpiresAt is the root's expiry when
	// the cli-edge reported one, else 0: the lifetime is server-defined.
	IssuedAt  int64 `json:"issued_at,omitempty"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// EdgeSessionPath is the path to edge-session.json: in the config dir beside credentials.json,
// for the same custody reason the STS sessions live there — the DPoP key it is bound to sits
// in the credential store, outside the config dir.
func EdgeSessionPath() string {
	return filepath.Join(ConfigDir(), "edge-session.json")
}

// Snapshot is both credential documents as one hold of the store lock saw them.
type Snapshot struct {
	Data *Data
	// Edge is nil when edge-session.json is absent, corrupt, or of an unknown schema.
	Edge *EdgeSession
}

// LoadSnapshot reads credentials.json and edge-session.json under one hold of the
// cross-process lock, so a caller deciding which credential is in force never pairs one
// login's generation with another login's edge session. Each document degrades the way Load
// does: missing or corrupt reads as empty, unreadable is an error.
func LoadSnapshot() (Snapshot, error) {
	unlock, err := lock()
	if err != nil {
		return Snapshot{}, err
	}
	defer unlock()
	d, err := load()
	if err != nil {
		return Snapshot{}, err
	}
	edge, _, err := loadEdge()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Data: d, Edge: edge}, nil
}

type edgeChange int

const (
	edgeKeep edgeChange = iota
	edgeReplace
	edgeRemove
)

// Tx is one locked read-modify-write of both credential documents. Edit Data in place; leave
// the edge session alone, or call ReplaceEdge or RemoveEdge.
type Tx struct {
	Data *Data
	// Edge is the edge session as loaded (nil when absent, corrupt, or of an unknown schema).
	// Read it; change it only through ReplaceEdge or RemoveEdge.
	Edge *EdgeSession

	change  edgeChange
	newEdge EdgeSession
}

// ReplaceEdge makes e the edge session this transaction commits.
func (tx *Tx) ReplaceEdge(e EdgeSession) {
	e.Version = EdgeSessionVersion
	tx.change, tx.newEdge = edgeReplace, e
}

// RemoveEdge deletes edge-session.json when this transaction commits. It removes the file
// even when Edge is nil because the file was corrupt or of an unknown schema.
func (tx *Tx) RemoveEdge() { tx.change = edgeRemove }

// Transact is Update for both documents. The commit point is the credentials.json write —
// the credential generation it carries decides which edge session, if any, is in force — so
// the edge file is ordered around it:
//
//   - ReplaceEdge writes the new edge session FIRST. It carries the generation the
//     credentials.json write is about to commit, so until that write lands it is fenced out.
//     A crash in between therefore fails closed: a previous Keycloak login stays in force, and
//     a previous edge session — whose file was just overwritten — is signed out, never mixed
//     with the new one. If the credentials.json write fails instead, the previous edge file is
//     put back.
//   - RemoveEdge deletes the file AFTER the commit. The new generation has already fenced the
//     old session out by then, so a crash — or a failed unlink, which is not reported — leaves
//     only an inert file for the next login or logout to remove. Every caller that removes an
//     edge session therefore commits a new generation in the same transaction.
//
// If mutate returns an error, nothing is written.
func Transact(mutate func(*Tx) error) error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()

	d, err := load()
	if err != nil {
		return err
	}
	edge, previous, err := loadEdge()
	if err != nil {
		return err
	}
	tx := &Tx{Data: d, Edge: edge}
	if err := mutate(tx); err != nil {
		return err
	}
	switch tx.change {
	case edgeReplace:
		if err := saveEdge(tx.newEdge); err != nil {
			return err
		}
		if err := Save(d); err != nil {
			restoreEdge(previous)
			return err
		}
		return nil
	case edgeRemove:
		if err := Save(d); err != nil {
			return err
		}
		_ = removeEdge()
		return nil
	default:
		return Save(d)
	}
}

// loadEdge reads edge-session.json while the caller holds the store lock. It also returns the
// file's raw bytes (nil when there is no file) so a failed Transact can put them back exactly.
func loadEdge() (*EdgeSession, []byte, error) {
	raw, err := os.ReadFile(EdgeSessionPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var e EdgeSession
	if err := json.Unmarshal(raw, &e); err != nil || e.Version != EdgeSessionVersion {
		return nil, raw, nil
	}
	return &e, raw, nil
}

func saveEdge(e EdgeSession) error {
	buf, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return writeOwnerOnly(EdgeSessionPath(), ".edge-*.tmp", buf)
}

// restoreEdge puts the edge file back the way a failed Transact found it: its previous bytes,
// or no file at all. Best-effort — the edge session it would leave behind on failure carries a
// generation credentials.json never committed, so it is fenced out either way.
func restoreEdge(previous []byte) {
	if previous == nil {
		_ = removeEdge()
		return
	}
	_ = writeOwnerOnly(EdgeSessionPath(), ".edge-*.tmp", previous)
}

func removeEdge() error {
	if err := os.Remove(EdgeSessionPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
