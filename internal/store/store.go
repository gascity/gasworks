// Package store is the credential store: $CONFIG/gasworks/credentials.json (0600),
// atomic + cross-process locked.
//
// It holds the Keycloak refresh token, the per-org STS session, and an EIA cache. It does
// NOT hold the DPoP private key of any session this CLI writes: Auth Access v1 credential
// custody requires the opaque session and the key it is bound to never to be stored
// together, so a Session carries only a KeyRef naming the credential store
// (internal/keystore) that holds the key. A stolen credentials file therefore yields no
// signing key of ours — entries written by an older CLI, or by another tool that shares this
// document, are carried through untouched (see Session.InlineKeyPEM).
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

	"github.com/gascity/gasworks/internal/lockdown"
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
// Sessions written before split credential storage carry the key inline as "dpop_pem", and
// so do the sessions of other tools that share this document — bd-enterprise vendors this
// store and writes its key inline under its own cache key. The CLI never writes InlineKeyPEM
// and never signs with it; it carries the field through a load/save cycle so that OUR write
// does not silently strip SOMEONE ELSE'S credential. Replacing an entry (which is what
// establishing a session does) drops the field, so the co-located key of the session being
// replaced does leave the disk.
type Session struct {
	SessionToken string `json:"session_token"`
	Key          KeyRef `json:"key"`
	ExpiresAt    int64  `json:"expires_at"`
	InlineKeyPEM string `json:"dpop_pem,omitempty"`
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

// ConfigDirEnv pins the config directory to one self-contained profile (the canary runbook,
// a test). It also pins the state directory — see StateDir.
const ConfigDirEnv = "GASWORKS_CONFIG_DIR"

// ConfigDir resolves the gasworks config directory:
//
//	$GASWORKS_CONFIG_DIR                              (override, any platform)
//	%APPDATA%/gasworks      (or ~/AppData/Roaming)   on Windows
//	$XDG_CONFIG_HOME/gasworks  else  ~/.config/gasworks  elsewhere
func ConfigDir() string {
	if override := os.Getenv(ConfigDirEnv); override != "" {
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

// StateDir resolves the gasworks state directory — where secrets the user never edits and
// never syncs live:
//
//	<config dir>              when $GASWORKS_CONFIG_DIR pins a profile
//	%LOCALAPPDATA%/gasworks   on Windows
//	$XDG_STATE_HOME/gasworks  else  ~/.local/state/gasworks  elsewhere
//
// It is deliberately NOT the config dir: Auth Access v1 requires the opaque session and the
// key it is bound to never to be stored or backed up together, and the config dir is what
// "sync my dotfiles" and "back up ~/.config" carry. On Windows that means LocalAppData, not
// the roaming APPDATA the config dir uses — a roaming profile copies the key to every
// machine the user signs in to. A profile pinned with GASWORKS_CONFIG_DIR is meant to be
// self-contained and disposable, so its state stays inside it; the per-directory overrides
// below split those back out.
func StateDir() string {
	if profile := os.Getenv(ConfigDirEnv); profile != "" {
		return profile
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			home, _ := os.UserHomeDir()
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "gasworks")
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "gasworks")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "gasworks")
}

// KeyDirEnv overrides where the file credential store keeps DPoP private keys.
const KeyDirEnv = "GASWORKS_KEY_DIR"

// KeyDir resolves the directory the file credential store keeps DPoP private keys in:
// $GASWORKS_KEY_DIR, else <state dir>/dpop-keys.
func KeyDir() string {
	if override := os.Getenv(KeyDirEnv); override != "" {
		return override
	}
	return filepath.Join(StateDir(), keyDirName)
}

// MintedKeyDirEnv overrides where the CLI keeps the credentials it mints.
const MintedKeyDirEnv = "GASWORKS_MINTED_KEY_DIR"

// MintedKeyDir resolves the directory a minted credential is written to:
// $GASWORKS_MINTED_KEY_DIR, else <state dir>/minted-keys.
//
// It sits in the state namespace beside the DPoP keys, for the same reason they do: a minted
// credential is a bearer secret, and the config dir is the one that gets synced and backed
// up. The one exception is the one StateDir already makes — a profile pinned with
// $GASWORKS_CONFIG_DIR IS the state dir, so there the minted keys do land under the config
// dir, which is what "self-contained and disposable" means. Set $GASWORKS_MINTED_KEY_DIR to
// split them back out.
func MintedKeyDir() string {
	if override := os.Getenv(MintedKeyDirEnv); override != "" {
		return override
	}
	return filepath.Join(StateDir(), mintedKeyDirName)
}

// The leaf directories under the state dir.
const (
	keyDirName       = "dpop-keys"
	mintedKeyDirName = "minted-keys"
)

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
	lockdown.Apply(CredsPath())
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
