package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPEM = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n"

func TestFileRoundTrip(t *testing.T) {
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := backend.Get("dpop-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != testPEM {
		t.Fatalf("Get = %q, want the stored PEM", got)
	}
}

func TestFilePutReplacesAnExistingKey(t *testing.T) {
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := backend.Put("dpop-a", "rotated"); err != nil {
		t.Fatalf("Put (rotation): %v", err)
	}
	if got, _ := backend.Get("dpop-a"); got != "rotated" {
		t.Fatalf("Get = %q, want the rotated key", got)
	}
	// Rotating in place must not leave the superseded key behind as a stray temp file.
	entries, err := os.ReadDir(backend.Dir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("key dir holds %d files after a rotation, want 1", len(entries))
	}
}

func TestFileGetOnAMissingHandleIsErrNotFound(t *testing.T) {
	backend := NewFile(t.TempDir())
	if _, err := backend.Get("dpop-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestFileDeleteIsIdempotent(t *testing.T) {
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := backend.Delete("dpop-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := backend.Delete("dpop-a"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	if _, err := backend.Get("dpop-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestFilePurgeRemovesEveryKey(t *testing.T) {
	backend := NewFile(t.TempDir())
	for _, handle := range []string{"dpop-a", "dpop-b"} {
		if err := backend.Put(handle, testPEM); err != nil {
			t.Fatalf("Put %s: %v", handle, err)
		}
	}
	if err := backend.Purge(); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := os.Stat(backend.Dir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key dir still present after Purge (%v)", err)
	}
	// A purge of an already-empty store is not an error either.
	if err := backend.Purge(); err != nil {
		t.Fatalf("second Purge: %v", err)
	}
}

func TestFileRejectsAHostileHandle(t *testing.T) {
	dir := t.TempDir()
	backend := NewFile(dir)
	for _, handle := range []string{"../escape", "dpop/abc", ""} {
		if err := backend.Put(handle, testPEM); err == nil {
			t.Errorf("Put(%q) was accepted", handle)
		}
		if _, err := backend.Get(handle); err == nil {
			t.Errorf("Get(%q) was accepted", handle)
		}
		if err := backend.Delete(handle); err == nil {
			t.Errorf("Delete(%q) was accepted", handle)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.pem")); err == nil {
		t.Fatal("a traversal handle escaped the key directory")
	}
}

func TestFileKeysAre0600InA0700Dir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ignores POSIX mode bits; the store relies on the config-dir ACL there")
	}
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	dirInfo, err := os.Stat(backend.Dir())
	if err != nil {
		t.Fatalf("stat key dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("key dir mode = %#o, want 0700", perm)
	}
	keyInfo, err := os.Stat(filepath.Join(backend.Dir(), "dpop-a.pem"))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", perm)
	}
}

func TestFileRefusesAGroupReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ignores POSIX mode bits")
	}
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	path := filepath.Join(backend.Dir(), "dpop-a.pem")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := backend.Get("dpop-a")
	if err == nil || !strings.Contains(err.Error(), "group/world-accessible") {
		t.Fatalf("Get = %v, want a group/world-accessible refusal", err)
	}
}

func TestFileRefusesASymlinkedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation on Windows")
	}
	backend := NewFile(t.TempDir())
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	target := filepath.Join(backend.Dir(), "dpop-a.pem")
	link := filepath.Join(backend.Dir(), "dpop-b.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := backend.Get("dpop-b")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Get = %v, want a non-regular-file refusal", err)
	}
}

// The key directory is a sibling of credentials.json, never a field inside it: Auth Access v1
// forbids storing the opaque session and the key it is bound to together.
func TestFileKeepsKeysOutOfTheCredentialsFile(t *testing.T) {
	configDir := t.TempDir()
	backend := NewFile(configDir)
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if backend.Dir() == configDir {
		t.Fatal("the key backend writes into the config dir root")
	}
	if _, err := os.Stat(filepath.Join(configDir, "credentials.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enrolling a key touched credentials.json (%v)", err)
	}
}
