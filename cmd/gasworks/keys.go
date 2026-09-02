package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"runtime"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/keystore"
	"github.com/gascity/gasworks/internal/store"
)

// keyHandlePrefix labels the credential-store handles this CLI owns.
const keyHandlePrefix = "dpop-"

// keystoreRegistry is the closed per-platform credential-store list for this host. It is a
// var so a test can substitute a scratch store: the real registry reaches the developer's
// login keychain, and a test must never enrol into (or purge) that.
var keystoreRegistry = func() []keystore.Backend {
	return keystore.Registry(store.ConfigDir(), store.KeyDir())
}

// enrollmentKeystore picks the store a NEW DPoP key goes into, or fails closed with the
// enrolment error the custody clause requires. It is called BEFORE the STS round-trip so an
// unenrollable host does not burn a session it cannot keep the key for.
func enrollmentKeystore(cfg config.Config) (keystore.Backend, error) {
	backend, err := keystore.Select(keystoreRegistry(), cfg.AllowFileKeystore)
	if err != nil {
		if errors.Is(err, keystore.ErrNoApprovedStore) {
			return nil, dieCredential(credentialErrorInteraction,
				"%s.\nThe DPoP private key is never written to a plain file unless you ask for it: "+
					"re-run with --allow-file-keystore, or set %s=1, to keep it in a 0600 file under %s.",
				err, config.AllowFileKeystoreEnv, store.KeyDir()).
				withCredentialHint("No approved credential store for the DPoP private key. Set " +
					config.AllowFileKeystoreEnv + "=1 to permit a 0600 key file; signing in again will not fix this.")
		}
		return nil, die("could not select a credential store: %s", err)
	}
	// This build has no keystore backend for Linux or Windows, so the file store is picked
	// there by default rather than leaving the host unable to establish a session at all.
	// Say so once per enrolment when nobody asked for it: the operator should know a private
	// key just landed in a file, and where. An explicit opt-in already means they know.
	if d := backend.Descriptor(); d.ID == keystore.FileBackendID && !d.RequiresOptIn && !cfg.AllowFileKeystore {
		eprintf("gasworks: no OS keystore backend for %s in this build — the session's DPoP private key "+
			"is kept as %s", runtime.GOOS, d.Summary)
	}
	return backend, nil
}

// sessionKeyHandle derives the credential-store handle for a session's DPoP key. It is a
// hash of the session cache key, so it is stable across rotations of the same session (a
// rotation replaces the key in place and leaves no orphan) and leaks nothing about the org
// or origin into a filesystem path or a keychain item name.
func sessionKeyHandle(sessionKey string) string {
	sum := sha256.Sum256([]byte(sessionKey))
	return keyHandlePrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// enrollSessionKey writes key into backend under handle and returns the reference persisted
// next to the session.
func enrollSessionKey(backend keystore.Backend, handle string, key *dpop.Key) (store.KeyRef, error) {
	pem, err := key.ToPEM()
	if err != nil {
		return store.KeyRef{}, die("could not serialize the session key: %s", err)
	}
	if err := backend.Put(handle, pem); err != nil {
		return store.KeyRef{}, die("could not store the session key: %s", err)
	}
	return store.KeyRef{Backend: backend.Descriptor().ID, Handle: handle}, nil
}

// loadSessionKey resolves a stored session's DPoP key. The backend is looked up by the id
// the session recorded, not re-selected: reading back a key the operator already enrolled is
// not a new enrolment, so the opt-in gate does not apply.
func loadSessionKey(ref store.KeyRef) (*dpop.Key, error) {
	if !ref.Enrolled() {
		return nil, errors.New("session has no enrolled DPoP key")
	}
	backend, err := keystore.ByID(keystoreRegistry(), ref.Backend)
	if err != nil {
		return nil, err
	}
	pem, err := backend.Get(ref.Handle)
	if err != nil {
		return nil, err
	}
	return dpop.FromPEM(pem)
}

// forgetSessionKeys removes a batch of DPoP keys, e.g. the keys of every session a fresh
// login just invalidated. Nothing references them once the write that dropped their sessions
// has landed, so leaving them behind would accumulate a private key per login.
func forgetSessionKeys(refs []store.KeyRef) {
	for _, ref := range refs {
		forgetSessionKey(ref)
	}
}

// forgetSessionKey removes a session's DPoP key. It is best-effort: an unreachable store
// must not block a logout or a rotation that has already succeeded at the STS.
func forgetSessionKey(ref store.KeyRef) {
	if !ref.Enrolled() {
		return
	}
	backend, err := keystore.ByID(keystoreRegistry(), ref.Backend)
	if err != nil {
		return
	}
	_ = backend.Delete(ref.Handle)
}

// purgeSessionKeys removes every DPoP key this host holds for gasworks, across every
// registered store. Logout calls it so a sign-out leaves no key material behind even when
// the credentials file that referenced the keys is gone.
func purgeSessionKeys() {
	for _, backend := range keystoreRegistry() {
		if backend.Available() {
			_ = backend.Purge()
		}
	}
}
