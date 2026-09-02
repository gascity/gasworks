package keystore

import (
	"errors"
	"strings"
	"testing"
)

// fakeBackend is a registry entry under test. It records nothing beyond what the selection
// rules read, so the tests exercise the policy and not a store implementation.
type fakeBackend struct {
	id            string
	available     bool
	nonExportable bool
	optIn         bool
}

func (f fakeBackend) Descriptor() Descriptor {
	return Descriptor{ID: f.id, NonExportable: f.nonExportable, RequiresOptIn: f.optIn}
}
func (f fakeBackend) Available() bool            { return f.available }
func (f fakeBackend) Put(string, string) error   { return nil }
func (f fakeBackend) Get(string) (string, error) { return "", ErrNotFound }
func (f fakeBackend) Delete(string) error        { return nil }
func (f fakeBackend) Purge() error               { return nil }

func TestSelectPrefersANonExportableStoreOverRegistryOrder(t *testing.T) {
	registry := []Backend{
		fakeBackend{id: "exportable", available: true},
		fakeBackend{id: "hardware", available: true, nonExportable: true},
	}
	backend, err := Select(registry, false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got := backend.Descriptor().ID; got != "hardware" {
		t.Fatalf("selected %q, want the non-exportable store even though it is listed second", got)
	}
}

func TestSelectSkipsUnavailableStores(t *testing.T) {
	registry := []Backend{
		fakeBackend{id: "keychain", nonExportable: true},
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
	for _, backend := range Registry(t.TempDir()) {
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

// The file backend is registered on every platform and must never be selectable by default.
func TestTheFileBackendIsAlwaysOptIn(t *testing.T) {
	registry := Registry(t.TempDir())
	found := false
	for _, backend := range registry {
		if backend.Descriptor().ID == FileBackendID {
			found = true
			if !backend.Descriptor().RequiresOptIn {
				t.Error("the plaintext-file backend is selectable without an opt-in")
			}
		}
	}
	if !found {
		t.Fatal("the per-platform registry has no file backend")
	}
}
