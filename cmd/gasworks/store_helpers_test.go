package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/keystore"
	"github.com/gascity/gasworks/internal/store"
)

// writeStoreRaw writes the given JSON bytes directly to credentials.json under the env-driven
// config dir, so a test can seed arbitrary on-disk shapes (matching gasworks.store.save). The
// store reads GASWORKS_CONFIG_DIR, which seed() has already set for the test.
func writeStoreRaw(b []byte) error {
	dir := store.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "credentials.json"), b, 0o600)
}

// loadStore reads back the on-disk credentials for assertions.
func loadStore(t *testing.T) *store.Data {
	t.Helper()
	d, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	// Round-trip through the raw file to ensure we're asserting persisted bytes, not a cache.
	raw, err := os.ReadFile(store.CredsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &store.Data{}
		}
		t.Fatalf("read creds: %v", err)
	}
	var fresh store.Data
	if err := json.Unmarshal(raw, &fresh); err != nil {
		t.Fatalf("unmarshal creds: %v", err)
	}
	_ = d
	return &fresh
}

// useFileKeystore points the CLI at a fresh temp config dir, a fresh temp key dir, and a
// scratch file keystore that must be opted into. Every test that establishes a session needs
// it, on every platform: the real registry reaches the developer's macOS login keychain, and
// a test may neither enrol a key there nor let `logout` purge items it did not create.
func useFileKeystore(t *testing.T) {
	t.Helper()
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	t.Setenv(store.KeyDirEnv, filepath.Join(t.TempDir(), "dpop-keys"))
	t.Setenv(config.AllowFileKeystoreEnv, "1")
	useKeystore(t, keystore.NewFile(store.KeyDir(), true))
}

// useKeystore substitutes the credential-store registry for the duration of the test.
func useKeystore(t *testing.T, backends ...keystore.Backend) {
	t.Helper()
	previous := keystoreRegistry
	keystoreRegistry = func() []keystore.Backend { return backends }
	t.Cleanup(func() { keystoreRegistry = previous })
}

// enrollTestKey generates a DPoP key, enrolls it under handle, and returns the reference a
// stored session would carry.
func enrollTestKey(t *testing.T, handle string) store.KeyRef {
	t.Helper()
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("dpop.NewKey: %v", err)
	}
	backend, err := keystore.Select(keystoreRegistry(), true)
	if err != nil {
		t.Fatalf("keystore.Select: %v", err)
	}
	ref, err := enrollSessionKey(backend, handle, key)
	if err != nil {
		t.Fatalf("enrollSessionKey: %v", err)
	}
	return ref
}
