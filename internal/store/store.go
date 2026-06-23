// Package store is the credential store: $CONFIG/gasworks/credentials.json (0600),
// atomic + cross-process locked.
//
// It holds the Keycloak refresh token, the per-org STS session + its DPoP key (PEM), and
// an EIA cache. A stolen credentials file is co-located-key vulnerable (the token scheme's
// acknowledged limit — DPoP binds the key, not the file); OS-keyring storage is a
// documented follow-up.
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

// Session is a per-org STS session plus the DPoP key (PEM) it is jkt-pinned to.
type Session struct {
	SessionToken string `json:"session_token"`
	DPoPPEM      string `json:"dpop_pem"`
	ExpiresAt    int64  `json:"expires_at"`
}

// EIACacheEntry is a cached Exchanged Identity Assertion with its expiry.
type EIACacheEntry struct {
	EIA       string `json:"eia"`
	ExpiresAt int64  `json:"expires_at"`
}

// Data is the on-disk credential document. Maps are omitempty so a fresh, never-written
// store roundtrips to {} rather than {"sessions":null,...}.
type Data struct {
	IDToken      string                   `json:"id_token,omitempty"`
	RefreshToken string                   `json:"refresh_token,omitempty"`
	DefaultOrg   string                   `json:"default_org,omitempty"`
	Sessions     map[string]Session       `json:"sessions,omitempty"`
	EIACache     map[string]EIACacheEntry `json:"eia_cache,omitempty"`
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

// Load reads credentials.json. A MISSING file (the logged-out state) or a CORRUPT-JSON file
// degrades to an empty Data with no error (re-login), matching the Python store's fail-soft
// contract. Any OTHER read error — the file exists but is unreadable (EACCES, EIO, EINTR,
// fd exhaustion) — returns a real error instead of empty Data. This is load-bearing for the
// Update read-modify-write: a transient read failure that silently became &Data{} would
// then be Save'd back over good credentials, WIPING the user's session. Returning an error
// makes Update abort without saving, so the on-disk credentials are left intact.
func Load() (*Data, error) {
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

	d, err := Load()
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
