//go:build darwin

package keystore

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestKeychain returns the backend pointed at a scratch keychain file. The tests must
// never touch the developer's (or the runner's) login keychain: enrolling there would leave
// real items behind, and Purge would delete items these tests did not create.
func newTestKeychain(t *testing.T) *Keychain {
	t.Helper()
	if _, err := os.Stat(securityPath); err != nil {
		t.Skipf("%s is not available: %v", securityPath, err)
	}
	const password = "gasworks-keystore-test"
	path := filepath.Join(t.TempDir(), "gasworks-test.keychain")
	if out, err := exec.Command(securityPath, "create-keychain", "-p", password, path).CombinedOutput(); err != nil {
		t.Skipf("could not create a scratch keychain (%v): %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(securityPath, "delete-keychain", path).Run() })
	// Recent macOS stores the file as <name>-db; `security` accepts either spelling, but use
	// whichever actually exists so a failure is a real failure and not a path mismatch.
	if _, err := os.Stat(path); err != nil {
		if _, dbErr := os.Stat(path + "-db"); dbErr == nil {
			path += "-db"
		}
	}
	if out, err := exec.Command(securityPath, "unlock-keychain", "-p", password, path).CombinedOutput(); err != nil {
		t.Skipf("could not unlock the scratch keychain (%v): %s", err, out)
	}
	return &Keychain{service: keychainService(t.TempDir()), keychain: path}
}

func TestKeychainRoundTripsAMultiLinePEM(t *testing.T) {
	backend := newTestKeychain(t)
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := backend.Get("dpop-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != testPEM {
		t.Fatalf("Get = %q, want the stored PEM verbatim", got)
	}
}

func TestKeychainPutReplacesAnExistingItem(t *testing.T) {
	backend := newTestKeychain(t)
	if err := backend.Put("dpop-a", testPEM); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := backend.Put("dpop-a", "rotated"); err != nil {
		t.Fatalf("Put (rotation): %v", err)
	}
	if got, _ := backend.Get("dpop-a"); got != "rotated" {
		t.Fatalf("Get = %q, want the rotated key", got)
	}
}

func TestKeychainGetOnAMissingHandleIsErrNotFound(t *testing.T) {
	backend := newTestKeychain(t)
	if _, err := backend.Get("dpop-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestKeychainDeleteIsIdempotentAndPurgeClearsTheService(t *testing.T) {
	backend := newTestKeychain(t)
	for _, handle := range []string{"dpop-a", "dpop-b"} {
		if err := backend.Put(handle, testPEM); err != nil {
			t.Fatalf("Put(%s): %v", handle, err)
		}
	}
	if err := backend.Delete("dpop-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := backend.Delete("dpop-a"); err != nil {
		t.Fatalf("Delete of an absent handle: %v", err)
	}
	if err := backend.Purge(); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := backend.Get("dpop-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Purge = %v, want ErrNotFound", err)
	}
}

// Logout purges by service, so two config dirs (GASWORKS_CONFIG_DIR profiles) must not share
// one: a logout in the canary profile may not delete the operator's main-profile keys.
func TestKeychainServiceIsScopedToTheConfigDir(t *testing.T) {
	main := keychainService("/home/u/.config/gasworks")
	canary := keychainService("/home/u/.config/gasworks-canary")
	if main == canary {
		t.Fatal("two profiles share one keychain service, so a logout would cross profiles")
	}
	if !strings.HasPrefix(main, keychainServicePrefix) {
		t.Fatalf("service %q does not carry the gasworks prefix", main)
	}
	if main != keychainService("/home/u/.config/gasworks/") {
		t.Fatal("the service name is not stable under a trailing separator")
	}
}
