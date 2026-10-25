package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	edgeTestGenerationA = "g1:00000000000000000000000000000001"
	edgeTestGenerationB = "g1:00000000000000000000000000000002"
	edgeTestRoot        = "gcs_cli_aaaabbbbccccddddeeeeffffgggghhhh"
)

func testEdgeSession(generation string) EdgeSession {
	return EdgeSession{
		CredentialGeneration: generation,
		RootToken:            edgeTestRoot,
		TokenType:            "DPoP",
		Key:                  KeyRef{Backend: "file", Handle: "dpop-edge"},
		EdgeOrigin:           "https://works.gascity.com",
		OrgID:                "org_a",
		OrgSlug:              "acme",
		IssuedAt:             1_000,
	}
}

// The root never lands in credentials.json: bd-enterprise rewrites that document without the
// fields it does not know. Both documents are owner-only.
func TestTransactKeepsTheEdgeSessionOutOfCredentialsJSON(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return nil
	}); err != nil {
		t.Fatalf("Transact: %v", err)
	}
	creds, err := os.ReadFile(CredsPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(creds), edgeTestRoot) || strings.Contains(string(creds), "dpop-edge") {
		t.Fatalf("credentials.json carries the edge session: %s", creds)
	}
	snapshot, err := LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Data.CredentialGeneration != edgeTestGenerationA || snapshot.Edge == nil ||
		snapshot.Edge.RootToken != edgeTestRoot || snapshot.Edge.Version != EdgeSessionVersion ||
		snapshot.Edge.CredentialGeneration != edgeTestGenerationA {
		t.Fatalf("snapshot = %+v / %+v", snapshot.Data, snapshot.Edge)
	}
	if filepath.Dir(EdgeSessionPath()) != filepath.Dir(CredsPath()) {
		t.Fatalf("edge session at %s, want it beside credentials.json", EdgeSessionPath())
	}
	if os.PathSeparator != '\\' {
		for _, path := range []string{CredsPath(), EdgeSessionPath()} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("%s mode = %o, want 600", path, mode)
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(CredsPath()), ".edge-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

// Update is a credentials.json-only read-modify-write: it never touches the edge session.
func TestUpdateLeavesTheEdgeSessionAlone(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(EdgeSessionPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := Update(func(d *Data) error {
		d.EIACache = map[string]EIACacheEntry{"k": {EIA: "eia", ExpiresAt: 9}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(EdgeSessionPath())
	if err != nil || string(after) != string(before) {
		t.Fatalf("Update rewrote the edge session: %v\n%s\n%s", err, before, after)
	}
}

// A failed commit leaves the previous login in force: the edge file is put back exactly as it
// was, and credentials.json is unchanged.
func TestTransactPutsThePreviousEdgeSessionBackWhenTheCommitFails(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("relies on POSIX rename-onto-directory semantics")
	}
	setConfigDir(t, "cfg")
	if err := Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(EdgeSessionPath())
	if err != nil {
		t.Fatal(err)
	}

	err = Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationB
		replacement := testEdgeSession(edgeTestGenerationB)
		replacement.RootToken = "gcs_cli_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		tx.ReplaceEdge(replacement)
		// Make the commit point fail AFTER the edge file has been written: rename cannot
		// replace a non-empty directory.
		if err := os.Remove(CredsPath()); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(CredsPath(), "blocker"), 0o700)
	})
	if err == nil {
		t.Fatal("Transact reported success with an unwritable credentials.json")
	}
	after, err := os.ReadFile(EdgeSessionPath())
	if err != nil || string(after) != string(before) {
		t.Fatalf("edge session after a failed commit = %v\n%s\nwant\n%s", err, after, before)
	}

	// With no previous edge file, a failed commit leaves none.
	setConfigDir(t, "fresh")
	err = Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return os.MkdirAll(filepath.Join(CredsPath(), "blocker"), 0o700)
	})
	if err == nil {
		t.Fatal("Transact reported success with an unwritable credentials.json")
	}
	if _, err := os.Stat(EdgeSessionPath()); !os.IsNotExist(err) {
		t.Fatalf("a failed first commit left an edge session behind: %v", err)
	}
}

// RemoveEdge deletes the file after the commit, including one that was unreadable as an edge
// session (corrupt, or a schema this build does not know), which loads as absent.
func TestRemoveEdgeDeletesEvenAnUnusableFile(t *testing.T) {
	for name, body := range map[string]string{
		"corrupt":        "{not json",
		"unknown schema": `{"version":"gasworks.dev/edge-session/v9","root_token":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			setConfigDir(t, "cfg")
			if err := os.MkdirAll(ConfigDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(EdgeSessionPath(), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := LoadSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Edge != nil {
				t.Fatalf("an unusable edge file loaded as %+v", snapshot.Edge)
			}
			if err := Transact(func(tx *Tx) error {
				if tx.Edge != nil {
					t.Fatalf("tx.Edge = %+v", tx.Edge)
				}
				tx.Data.CredentialGeneration = edgeTestGenerationB
				tx.RemoveEdge()
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(EdgeSessionPath()); !os.IsNotExist(err) {
				t.Fatalf("edge file survived RemoveEdge: %v", err)
			}
			if d, _ := Load(); d.CredentialGeneration != edgeTestGenerationB {
				t.Fatalf("generation = %q", d.CredentialGeneration)
			}
		})
	}
}

func TestTransactErrorWritesNothing(t *testing.T) {
	setConfigDir(t, "cfg")
	err := Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return sentinelError("stop")
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Transact = %v", err)
	}
	for _, path := range []string{CredsPath(), EdgeSessionPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s written by an aborted transaction: %v", path, err)
		}
	}
}

func TestClearRemovesTheEdgeSession(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Transact(func(tx *Tx) error {
		tx.Data.CredentialGeneration = edgeTestGenerationA
		tx.ReplaceEdge(testEdgeSession(edgeTestGenerationA))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{CredsPath(), EdgeSessionPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived Clear: %v", path, err)
		}
	}
	if err := Clear(); err != nil {
		t.Fatalf("Clear on an empty profile: %v", err)
	}
}

// Transact holds the same cross-process lock as Update, so concurrent read-modify-writes of
// both documents never lose one another's changes.
func TestConcurrentTransactsSerialize(t *testing.T) {
	setConfigDir(t, "cfg")
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Transact(func(tx *Tx) error {
				next := testEdgeSession(edgeTestGenerationA)
				if tx.Edge != nil {
					next.UserID = tx.Edge.UserID
				}
				next.UserID += "x"
				if tx.Data.Sessions == nil {
					tx.Data.Sessions = map[string]Session{}
				}
				tx.Data.Sessions[next.UserID] = Session{SessionToken: next.UserID}
				tx.ReplaceEdge(next)
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Edge == nil || len(snapshot.Edge.UserID) != n || len(snapshot.Data.Sessions) != n {
		t.Fatalf("lost a concurrent transaction: edge %+v sessions %d", snapshot.Edge, len(snapshot.Data.Sessions))
	}
}
