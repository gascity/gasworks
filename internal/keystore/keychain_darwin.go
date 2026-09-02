//go:build darwin

package keystore

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// KeychainBackendID is the registry id of the macOS login-keychain backend.
const KeychainBackendID = "keychain"

// keychainService is the generic-password service every gasworks DPoP item is filed under,
// so Purge can find them all without a separate index.
const keychainService = "com.gascity.gasworks.dpop"

// securityPath is the system keychain tool. Shelling out to it keeps the CLI CGO-free (the
// release cross-builds static binaries), the same trade the Windows credential-file ACL
// lockdown already makes with icacls.
const securityPath = "/usr/bin/security"

// keychainNotFoundStatus is `security`'s errSecItemNotFound exit code.
const keychainNotFoundStatus = 44

// purgeLimit bounds the delete-until-empty loop so a `security` that keeps reporting success
// can never spin forever.
const purgeLimit = 4096

// Keychain stores each key as a generic-password item in the user's login keychain.
//
// The PEM is base64-encoded before it is handed to `security`: a generic password is an
// opaque blob and `security find-generic-password -w` appends its own newline, so a raw
// multi-line PEM could not be trimmed back unambiguously.
type Keychain struct{}

// NewKeychain returns the macOS login-keychain backend.
func NewKeychain() *Keychain { return &Keychain{} }

func (k *Keychain) Descriptor() Descriptor {
	return Descriptor{
		ID:      KeychainBackendID,
		Summary: "macOS login keychain (generic password, service " + keychainService + ")",
		// The login keychain releases the secret to this process once unlocked, so the key
		// is exportable by the owning user. A Secure Enclave item that signs in-place would
		// set NonExportable and sort ahead of this one.
		NonExportable: false,
		RequiresOptIn: false,
		Exportability: "readable by the owning user while the login keychain is unlocked; not hardware-bound",
		Backup:        "included in encrypted Time Machine / iCloud Keychain backups per the user's macOS settings",
		AccessControl: "login-keychain ACL; re-locks with the keychain (screen lock, logout, reboot)",
		Deletion:      "delete-generic-password on rotation; `gasworks logout` deletes every item under the service",
	}
}

// Available reports whether the system keychain tool is present.
func (k *Keychain) Available() bool {
	info, err := os.Stat(securityPath)
	return err == nil && info.Mode().IsRegular()
}

func (k *Keychain) Put(handle, pem string) error {
	if !ValidHandle(handle) {
		return fmt.Errorf("keystore: invalid handle %q", handle)
	}
	// -U updates an existing item instead of failing with errSecDuplicateItem, which is what
	// a key rotation needs (the handle is stable for a session).
	_, err := k.run("add-generic-password", "-U",
		"-s", keychainService, "-a", handle,
		"-D", "Gas City DPoP session key",
		"-w", base64.StdEncoding.EncodeToString([]byte(pem)))
	if err != nil {
		return fmt.Errorf("keystore: keychain enrolment failed: %w", err)
	}
	return nil
}

func (k *Keychain) Get(handle string) (string, error) {
	if !ValidHandle(handle) {
		return "", fmt.Errorf("keystore: invalid handle %q", handle)
	}
	out, err := k.run("find-generic-password", "-s", keychainService, "-a", handle, "-w")
	if err != nil {
		if exitStatus(err) == keychainNotFoundStatus {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keystore: keychain read failed: %w", err)
	}
	pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		return "", fmt.Errorf("keystore: keychain item is not a stored key: %w", err)
	}
	return string(pem), nil
}

func (k *Keychain) Delete(handle string) error {
	if !ValidHandle(handle) {
		return fmt.Errorf("keystore: invalid handle %q", handle)
	}
	if _, err := k.run("delete-generic-password", "-s", keychainService, "-a", handle); err != nil {
		if exitStatus(err) == keychainNotFoundStatus {
			return nil
		}
		return fmt.Errorf("keystore: keychain delete failed: %w", err)
	}
	return nil
}

// Purge deletes gasworks items one at a time until the keychain reports none left.
// `security` has no "delete all matching" mode, and each call removes exactly one item.
func (k *Keychain) Purge() error {
	for i := 0; i < purgeLimit; i++ {
		if _, err := k.run("delete-generic-password", "-s", keychainService); err != nil {
			if exitStatus(err) == keychainNotFoundStatus {
				return nil
			}
			return fmt.Errorf("keystore: keychain purge failed: %w", err)
		}
	}
	return fmt.Errorf("keystore: keychain purge did not converge after %d deletions", purgeLimit)
}

// run invokes `security` and returns its stdout. Stderr is dropped: `security` echoes the
// item's attributes there, and nothing in this package ever logs key material.
func (k *Keychain) run(args ...string) (string, error) {
	out, err := exec.Command(securityPath, args...).Output()
	return string(out), err
}

func exitStatus(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
