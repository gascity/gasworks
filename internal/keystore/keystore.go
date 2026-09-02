// Package keystore is the closed, versioned registry of credential stores the SDK may hold
// a DPoP private key in.
//
// Auth Access v1 ("Client credential custody") requires the DPoP private key to live in an
// approved per-platform store, SEPARATE from the opaque STS session it is bound to, and
// forbids a silent fallback to a plaintext dotfile: when no approved store is available the
// SDK fails closed with an actionable enrollment error. A plain 0600 file IS a registered
// backend — but it is opt-in, so nothing lands there unless the operator asked for it.
//
// Every backend documents its exportability, backup behaviour, access control and deletion
// semantics in its Descriptor; that documentation is the entry ticket to the registry.
// Select prefers a NON-EXPORTABLE backend (one whose key material cannot be read back out
// at all). None of the backends registered today is non-exportable — a Secure Enclave / TPM
// backend that signs inside the store would be, and would sort ahead of these when added.
package keystore

import (
	"errors"
	"fmt"
	"strings"
)

// Version identifies the registry contract. It is reported by `gasworks inspect` so an
// operator can tell which backend set a client was built with.
const Version = "gasworks.dev/keystore-registry/v1"

// ErrNotFound is returned by Get and Delete when a handle is not enrolled.
var ErrNotFound = errors.New("keystore: no key for that handle")

// ErrNoApprovedStore is returned by Select when nothing in the registry may hold a key.
var ErrNoApprovedStore = errors.New("keystore: no approved credential store is available")

// Descriptor is a backend's registry entry: its identity plus the four custody properties
// Auth Access v1 requires a store to document before it may hold a key.
type Descriptor struct {
	// ID is the stable identifier persisted next to a session so the key can be found
	// again. It never changes for a given backend.
	ID string
	// Summary is a one-line human description ("macOS login keychain").
	Summary string
	// NonExportable reports that key material cannot be read back out of the store at
	// all (the store signs internally). Select prefers these.
	NonExportable bool
	// RequiresOptIn marks a backend that must be asked for explicitly. It exists so the
	// plaintext-file backend can be registered without ever being chosen silently.
	RequiresOptIn bool

	Exportability string
	Backup        string
	AccessControl string
	Deletion      string
}

// Backend is one credential store. Handles are opaque, caller-chosen identifiers; a backend
// rejects any handle that is not a valid handle (see ValidHandle).
type Backend interface {
	Descriptor() Descriptor
	// Available reports whether this backend can be used on this host right now.
	Available() bool
	// Put enrolls (or replaces) the PKCS#8 PEM private key held under handle.
	Put(handle, pem string) error
	// Get returns the PEM previously enrolled under handle, or ErrNotFound.
	Get(handle string) (string, error)
	// Delete removes handle. Deleting an absent handle is not an error.
	Delete(handle string) error
	// Purge removes every key this backend holds for gasworks. It is what `logout` calls,
	// so a sign-out leaves no key material behind.
	Purge() error
}

// ValidHandle reports whether h is a safe handle: 1-128 characters drawn from the base64url
// alphabet plus '.'. Handles reach a filesystem path and a `security` argv, so anything
// outside that set (a separator, a leading dash, whitespace) is refused at the boundary.
func ValidHandle(h string) bool {
	if h == "" || len(h) > 128 || h[0] == '-' || h[0] == '.' {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// Select returns the backend a NEW key must be enrolled in: the first available backend,
// non-exportable stores first, skipping opt-in stores unless allowOptIn is set. When nothing
// is eligible it fails closed with an error naming every registry entry and why it was
// skipped — the caller adds the product-specific "here is how to opt in" advice.
func Select(backends []Backend, allowOptIn bool) (Backend, error) {
	eligible := func(b Backend) bool {
		return b.Available() && (allowOptIn || !b.Descriptor().RequiresOptIn)
	}
	for _, b := range backends {
		if b.Descriptor().NonExportable && eligible(b) {
			return b, nil
		}
	}
	for _, b := range backends {
		if eligible(b) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w (registry %s: %s)", ErrNoApprovedStore, Version, explain(backends, allowOptIn))
}

// ByID returns the registered backend with the given id. Reading or deleting an already
// enrolled key resolves the backend this way rather than through Select: the session records
// where its key went, and the opt-in gate applies to CHOOSING a store, not to reading back a
// key the operator already opted into.
func ByID(backends []Backend, id string) (Backend, error) {
	for _, b := range backends {
		if b.Descriptor().ID == id {
			return b, nil
		}
	}
	return nil, fmt.Errorf("keystore: %q is not in registry %s", id, Version)
}

// Status explains, in one phrase, whether Select could pick this backend right now. It is
// what the fail-closed error and `gasworks inspect` both report.
func Status(b Backend, allowOptIn bool) string {
	switch {
	case !b.Available():
		return "unavailable on this host"
	case b.Descriptor().RequiresOptIn && !allowOptIn:
		return "registered but requires an explicit opt-in"
	default:
		return "available"
	}
}

func explain(backends []Backend, allowOptIn bool) string {
	if len(backends) == 0 {
		return "empty"
	}
	parts := make([]string, 0, len(backends))
	for _, b := range backends {
		parts = append(parts, b.Descriptor().ID+" "+Status(b, allowOptIn))
	}
	return strings.Join(parts, "; ")
}
