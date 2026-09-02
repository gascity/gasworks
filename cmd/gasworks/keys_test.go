package main

import (
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
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
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
