package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/keystore"
	"github.com/gascity/gasworks/internal/store"
)

func TestSessionKeyHandleIsStablePerSessionAndSafeToUse(t *testing.T) {
	first := sessionCacheKey("https://api.gascity.com", "org_a", "g1:aaaa")
	second := sessionCacheKey("https://api.gascity.com", "org_b", "g1:aaaa")

	handle := sessionKeyHandle(first)
	if handle != sessionKeyHandle(first) {
		t.Fatal("the handle for one session is not stable, so a rotation would orphan the old key")
	}
	if handle == sessionKeyHandle(second) {
		t.Fatal("two orgs share a key handle")
	}
	if !keystore.ValidHandle(handle) {
		t.Fatalf("derived handle %q is not a valid store handle", handle)
	}
	// The handle is a digest: it must not leak the org or the STS origin into a filesystem
	// path or a keychain item name.
	for _, leak := range []string{"org_a", "api.gascity.com", "g1:aaaa"} {
		if strings.Contains(handle, leak) {
			t.Errorf("handle %q leaks %q", handle, leak)
		}
	}
}

func TestEnrollmentKeystoreFailsClosedWithActionableAdvice(t *testing.T) {
	useFileKeystore(t)
	_, err := enrollmentKeystore(config.Config{AllowFileKeystore: false})
	if err == nil {
		t.Fatal("enrollmentKeystore selected a store without an opt-in")
	}
	for _, want := range []string{"no approved credential store", "--allow-file-keystore", config.AllowFileKeystoreEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	// The failure is an interaction-required credential error, so the noninteractive
	// credential-provider boundary reports it as something a human must fix.
	commandErr, ok := err.(*cmdError)
	if !ok || commandErr.credentialErrCode != credentialErrorInteraction {
		t.Fatalf("error = %#v, want an interaction_required credential error", err)
	}
	// The credential-provider protocol replaces the free-text error with one fixed sentence
	// per code, and "run gasworks login" is the wrong advice here, so the failure carries
	// its own machine-facing message.
	if !strings.Contains(commandErr.credentialErrHint, config.AllowFileKeystoreEnv) {
		t.Errorf("credential hint %q does not name %s", commandErr.credentialErrHint, config.AllowFileKeystoreEnv)
	}
}

// On a platform this build has no keystore backend for, the file store is selected without
// an opt-in — refusing would leave every non-interactive caller unable to mint — and the
// enrolment says on stderr that a private key just landed in a file.
func TestEnrollmentUsesTheFileStoreByDefaultWhereThereIsNoPlatformKeystore(t *testing.T) {
	useFileKeystore(t)
	keyDir := store.KeyDir()
	useKeystore(t, keystore.NewFile(keyDir, false))

	_, errOut, code := capture(t, func() int {
		backend, err := enrollmentKeystore(config.Config{AllowFileKeystore: false})
		if err != nil {
			t.Errorf("enrollmentKeystore: %v", err)
			return 1
		}
		if backend.Descriptor().ID != keystore.FileBackendID {
			t.Errorf("selected %q, want the file store", backend.Descriptor().ID)
		}
		return 0
	})
	if code != 0 {
		t.Fatalf("enrolment failed (exit %d)", code)
	}
	for _, want := range []string{"no OS keystore backend", keyDir} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr %q does not mention %q", errOut, want)
		}
	}
}

func TestSessionKeyRoundTripsThroughTheSelectedStore(t *testing.T) {
	useFileKeystore(t)
	ref := enrollTestKey(t, "dpop-roundtrip")
	if ref.Backend != keystore.FileBackendID {
		t.Fatalf("enrolled into %q, want the opted-in file store", ref.Backend)
	}
	key, err := loadSessionKey(ref)
	if err != nil {
		t.Fatalf("loadSessionKey: %v", err)
	}
	if key.Thumbprint() == "" {
		t.Fatal("the loaded key has no thumbprint")
	}

	forgetSessionKey(ref)
	if _, err := loadSessionKey(ref); err == nil {
		t.Fatal("the key is still readable after forgetSessionKey")
	}
}

func TestLoadSessionKeyRejectsAnUnenrolledReference(t *testing.T) {
	useFileKeystore(t)
	if _, err := loadSessionKey(store.KeyRef{}); err == nil {
		t.Fatal("loadSessionKey accepted an empty reference")
	}
	if _, err := loadSessionKey(store.KeyRef{Backend: "nonesuch", Handle: "dpop-a"}); err == nil {
		t.Fatal("loadSessionKey accepted a backend that is not in the registry")
	}
}

// The key is enrolled inside the locked store write, so a store that cannot hold it leaves
// no session behind pointing at a key that does not exist.
func TestAFailedEnrolmentPersistsNoSession(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	useKeystore(t, refusingKeystore{})

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code == 0 {
		t.Fatal("getToken succeeded although the credential store refused the key")
	}
	if !strings.Contains(errOut, "could not store the session key") {
		t.Errorf("stderr = %q, want the enrolment failure", errOut)
	}
	if sessions := loadStore(t).Sessions; len(sessions) != 0 {
		t.Fatalf("persisted %d sessions for a key that was never stored", len(sessions))
	}
}

// refusingKeystore is available and eligible but cannot hold a key.
type refusingKeystore struct{}

func (refusingKeystore) Descriptor() keystore.Descriptor {
	return keystore.Descriptor{ID: "refusing", Summary: "a store that refuses every key"}
}
func (refusingKeystore) Available() bool            { return true }
func (refusingKeystore) Put(string, string) error   { return errors.New("read-only store") }
func (refusingKeystore) Get(string) (string, error) { return "", keystore.ErrNotFound }
func (refusingKeystore) Delete(string) error        { return nil }
func (refusingKeystore) Purge() error               { return nil }
