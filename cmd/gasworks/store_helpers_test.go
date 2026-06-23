package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
