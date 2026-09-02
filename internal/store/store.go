// Package store is the credential store: $CONFIG/gasworks/credentials.json (0600),
// atomic + cross-process locked.
//
// It holds the Keycloak refresh token, the per-org STS session, and an EIA cache. It does
// NOT hold the session's DPoP private key: Auth Access v1 credential custody requires the
// opaque session and the key it is bound to never to be stored together, so a Session
// carries only a KeyRef naming the credential store (internal/keystore) that holds the key.
// A stolen credentials file therefore yields no signing key.
//
// A missing or corrupt-JSON file degrades to "logged out" (empty Data), never a crash. An
// unreadable-but-present file (a transient IO/perms error) returns a real error instead, so
// a read-modify-write aborts rather than overwriting good credentials with empty.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// KeyRef locates the DPoP private key a session is jkt-pinned to: the registry id of the
// credential store holding it, plus that store's handle. It is a pointer to a secret, never
// the secret.
type KeyRef struct {
	Backend string `json:"backend"`
	Handle  string `json:"handle"`
}

// Enrolled reports whether the reference names a key at all.
func (r KeyRef) Enrolled() bool { return r.Backend != "" && r.Handle != "" }

// Session is a per-org STS session and a reference to the DPoP key it is jkt-pinned to.
//
// Sessions written before split credential storage carried the key inline as a "dpop_pem"
// field. That field is deliberately absent from this struct: an old document decodes into a
// Session with no KeyRef (unusable, so the CLI re-establishes the session) and the next Save
// writes the document back WITHOUT the PEM, which erases the co-located key from disk.
type Session struct {
	SessionToken string `json:"session_token"`
	Key          KeyRef `json:"key"`
	ExpiresAt    int64  `json:"expires_at"`
}

// EIACacheEntry is a cached Exchanged Identity Assertion with its expiry.
type EIACacheEntry struct {
	EIA       string `json:"eia"`
	ExpiresAt int64  `json:"expires_at"`
}

// Data is the on-disk credential document. CredentialGeneration fences session and EIA
// writes across login/logout changes. Maps are omitempty so a fresh, never-written store
// roundtrips to {} rather than {"sessions":null,...}.
type Data struct {
	IDToken              string                   `json:"id_token,omitempty"`
	RefreshToken         string                   `json:"refresh_token,omitempty"`
	CredentialGeneration string                   `json:"credential_generation,omitempty"`
	DefaultOrg           string                   `json:"default_org,omitempty"`
	Sessions             map[string]Session       `json:"sessions,omitempty"`
	EIACache             map[string]EIACacheEntry `json:"eia_cache,omitempty"`
}

// ConfigDir resolves the gasworks config directory:
//
//	$GASWORKS_CONFIG_DIR                              (override, any platform)
//	%APPDATA%/gasworks      (or ~/AppData/Roaming)   on Windows
//	$XDG_CONFIG_HOME/gasworks  else  ~/.config/gasworks  elsewhere
func ConfigDir() string {
	if override := os.Getenv("GASWORKS_CONFIG_DIR"); override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("APPDATA")
		if base == "" {
			home, _ := os.UserHomeDir()
			base = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(base, "gasworks")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "gasworks")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "gasworks")
}

// CredsPath is the path to credentials.json.
func CredsPath() string {
	return filepath.Join(ConfigDir(), "credentials.json")
}

func lockPath() string {
	return filepath.Join(ConfigDir(), ".lock")
}

// ensureDir creates the config dir (0700 on POSIX) if missing.
func ensureDir() (string, error) {
	d := ConfigDir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		// MkdirAll honors umask; re-assert 0700 like the Python store does.
		_ = os.Chmod(d, 0o700)
	}
	return d, nil
}

// Load reads credentials.json under the cross-process lock. This prevents a reader from
// colliding with an Update's atomic replacement (or its Windows ACL update). A MISSING file
// (the logged-out state) or a CORRUPT-JSON file degrades to an empty Data with no error
// (re-login), matching the Python store's fail-soft contract. Any OTHER read error — the
// file exists but is unreadable (EACCES, EIO, EINTR, fd exhaustion) — returns a real error
// instead of empty Data.
func Load() (*Data, error) {
	unlock, err := lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return load()
}

// load reads credentials.json while the caller holds the store lock when synchronization is
// required. Keeping it separate lets Update perform its locked read-modify-write without
// recursively acquiring the non-reentrant cross-process lock.
func load() (*Data, error) {
	raw, err := os.ReadFile(CredsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Data{}, nil
		}
		// File exists but couldn't be read (perms/IO/transient): surface the error so a
		// read-modify-write aborts rather than overwriting good credentials with empty.
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		// Corrupt JSON degrades to empty (re-login); a truncated/garbled file is not
		// recoverable and is treated like a logged-out state, as the Python store does.
		return &Data{}, nil
	}
	return &d, nil
}

// Save atomically writes credentials.json: a 0600 temp file in the same dir, then rename
// over the target. NOTE: like the Python store, Save does NOT take the lock itself — the
// lock is held by Update/Clear around the full read-modify-write.
func Save(d *Data) error {
	dir, err := ensureDir()
	if err != nil {
		return err
	}
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".cred-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			cleanup()
			return err
		}
	}
	if _, err := tmp.Write(buf); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, CredsPath()); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// On Windows the 0600 chmod above is a no-op (NTFS ignores POSIX bits), so the file
	// would inherit the parent dir's ACL — potentially readable by other users. Re-apply a
	// user-only ACL like the Python store's icacls call. Best-effort: a failure is logged,
	// not fatal (the credentials are already written; failing here would lose the login).
	lockdownFile(CredsPath())
	return nil
}

// Update is a locked read-modify-write: it acquires the cross-process lock, loads, applies
// mutate, and saves — so two concurrent getToken invocations cannot lose each other's
// session/key. If mutate returns an error, nothing is saved.
func Update(mutate func(*Data) error) error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()

	d, err := load()
	if err != nil {
		return err
	}
	if err := mutate(d); err != nil {
		return err
	}
	return Save(d)
}

// Clear removes credentials.json under the lock. A missing file is not an error.
func Clear() error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()

	if err := os.Remove(CredsPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
