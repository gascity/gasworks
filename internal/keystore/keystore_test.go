package keystore

import (
	"errors"
	"strings"
	"testing"
)

// fakeBackend is a registry entry under test. It records nothing beyond what the selection
// rules read, so the tests exercise the policy and not a store implementation.
type fakeBackend struct {
	id        string
	available bool
	optIn     bool
}

func (f fakeBackend) Descriptor() Descriptor {
	return Descriptor{ID: f.id, RequiresOptIn: f.optIn}
}
func (f fakeBackend) Available() bool            { return f.available }
func (f fakeBackend) Put(string, string) error   { return nil }
func (f fakeBackend) Get(string) (string, error) { return "", ErrNotFound }
func (f fakeBackend) Delete(string) error        { return nil }
func (f fakeBackend) Purge() error               { return nil }

func TestSelectTakesTheFirstEligibleStoreInRegistryOrder(t *testing.T) {
	registry := []Backend{
		fakeBackend{id: "keychain", available: true},
		fakeBackend{id: FileBackendID, available: true},
	}
	backend, err := Select(registry, false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := backend.Descriptor().ID; got != "keychain" {
		t.Fatalf("selected %q, want the platform keystore that is listed first", got)
	}
}

func TestSelectSkipsUnavailableStores(t *testing.T) {
	registry := []Backend{
		fakeBackend{id: "keychain"},
		fakeBackend{id: "wincred", available: true},
	}
	backend, err := Select(registry, false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := backend.Descriptor().ID; got != "wincred" {
		t.Fatalf("selected %q, want the only available store", got)
	}
}

func TestSelectFailsClosedRatherThanFallingBackToAnOptInStore(t *testing.T) {
	registry := []Backend{
		fakeBackend{id: "keychain"},
		fakeBackend{id: FileBackendID, available: true, optIn: true},
	}
	_, err := Select(registry, false)
	if !errors.Is(err, ErrNoApprovedStore) {
		t.Fatalf("Select err = %v, want ErrNoApprovedStore", err)
	}
	for _, want := range []string{Version, "keychain unavailable", "requires an explicit opt-in"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not explain %q", err, want)
		}
	}
}

func TestSelectUsesTheOptInStoreOnlyWhenAsked(t *testing.T) {
	registry := []Backend{fakeBackend{id: FileBackendID, available: true, optIn: true}}
	backend, err := Select(registry, true)
	if err != nil {
		t.Fatalf("Select with opt-in: %v", err)
	}
	if got := backend.Descriptor().ID; got != FileBackendID {
		t.Fatalf("selected %q, want %q", got, FileBackendID)
	}
}

func TestSelectOnAnEmptyRegistryFailsClosed(t *testing.T) {
	if _, err := Select(nil, true); !errors.Is(err, ErrNoApprovedStore) {
		t.Fatalf("Select(nil) = %v, want ErrNoApprovedStore", err)
	}
}

func TestByIDIgnoresTheOptInGate(t *testing.T) {
	registry := []Backend{fakeBackend{id: FileBackendID, available: true, optIn: true}}
	// Reading back a key the operator already enrolled is not a new enrolment.
	if _, err := ByID(registry, FileBackendID); err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if _, err := ByID(registry, "keychain"); err == nil {
		t.Fatal("ByID resolved a backend that is not in the registry")
	}
}

func TestValidHandleRejectsPathAndArgvHostileNames(t *testing.T) {
	for _, ok := range []string{"dpop-abc", "dpop_ABC.1", strings.Repeat("a", 128)} {
		if !ValidHandle(ok) {
			t.Errorf("ValidHandle(%q) = false, want true", ok)
		}
	}
	bad := []string{"", "..", "../escape", "dpop/abc", "dpop abc", "-w", ".hidden", strings.Repeat("a", 129)}
	for _, h := range bad {
		if ValidHandle(h) {
			t.Errorf("ValidHandle(%q) = true, want false", h)
		}
	}
}

func TestStatusExplainsWhyABackendIsOrIsNotEligible(t *testing.T) {
	unavailable := fakeBackend{id: "keychain"}
	optIn := fakeBackend{id: FileBackendID, available: true, optIn: true}
	cases := []struct {
		backend    Backend
		allowOptIn bool
		want       string
	}{
		{unavailable, true, "unavailable on this host"},
		{optIn, false, "registered but requires an explicit opt-in"},
		{optIn, true, "available"},
	}
	for _, tc := range cases {
		if got := Status(tc.backend, tc.allowOptIn); got != tc.want {
			t.Errorf("Status(%s, allowOptIn=%v) = %q, want %q",
				tc.backend.Descriptor().ID, tc.allowOptIn, got, tc.want)
		}
	}
}

// Every registered backend must document the four custody properties Auth Access v1 requires
// before a store may hold a key. This is the registry's entry ticket, enforced as a test.
func TestRegisteredBackendsDocumentTheirCustodyProperties(t *testing.T) {
	for _, backend := range Registry(t.TempDir(), t.TempDir()) {
		d := backend.Descriptor()
		for label, value := range map[string]string{
			"ID":            d.ID,
			"Summary":       d.Summary,
			"Exportability": d.Exportability,
			"Backup":        d.Backup,
			"AccessControl": d.AccessControl,
			"Deletion":      d.Deletion,
		} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("backend %q does not document %s", d.ID, label)
			}
		}
	}
}

// The file backend is registered on every platform, and it is opt-in exactly where this
// build has a platform keystore to prefer over it.
func TestTheFileBackendIsOptInWhereAPlatformKeystoreExists(t *testing.T) {
	registry := Registry(t.TempDir(), t.TempDir())
	var file Backend
	platform := 0
	for _, backend := range registry {
		if backend.Descriptor().ID == FileBackendID {
			file = backend
			continue
		}
		platform++
	}
	if file == nil {
		t.Fatal("the per-platform registry has no file backend")
	}
	if got, want := file.Descriptor().RequiresOptIn, platform > 0; got != want {
		t.Errorf("file backend RequiresOptIn = %v with %d platform keystore(s) registered, want %v",
			got, platform, want)
	}
}

// The file backend is last: a platform keystore is always preferred over a plain file.
func TestTheFileBackendIsRegisteredLast(t *testing.T) {
	registry := Registry(t.TempDir(), t.TempDir())
	if last := registry[len(registry)-1].Descriptor().ID; last != FileBackendID {
		t.Fatalf("last registry entry is %q, want the file backend", last)
	}
}
