//go:build darwin

package keystore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// KeychainBackendID is the registry id of the macOS login-keychain backend.
const KeychainBackendID = "keychain"

// keychainServicePrefix is the generic-password service every gasworks DPoP item is filed
// under. A digest of the config dir is appended so Purge (what `logout` calls) can delete
// every item of ONE profile without touching another's: credentials.json is per
// GASWORKS_CONFIG_DIR, and the keychain items must follow the same isolation.
const keychainServicePrefix = "com.gascity.gasworks.dpop"

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
type Keychain struct {
	service string
	// keychain is the keychain file to operate on. Empty means the user's default (login)
	// keychain; the tests point it at a scratch keychain so they never touch the real one.
	keychain string
}

// NewKeychain returns the macOS login-keychain backend for one gasworks profile.
func NewKeychain(configDir string) *Keychain {
	return &Keychain{service: keychainService(configDir)}
}

// keychainService derives the per-profile service name. The digest keeps the config dir
// itself out of the keychain UI while still separating profiles.
func keychainService(configDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(configDir)))
	return keychainServicePrefix + "." + hex.EncodeToString(sum[:4])
}

func (k *Keychain) Descriptor() Descriptor {
	return Descriptor{
		ID:            KeychainBackendID,
		Summary:       "macOS login keychain (generic password, service " + k.service + ")",
		RequiresOptIn: false,
		Exportability: "readable by the owning user while the login keychain is unlocked; not hardware-bound",
		Backup:        "included in encrypted Time Machine / iCloud Keychain backups per the user's macOS settings",
		AccessControl: "login-keychain ACL; re-locks with the keychain (screen lock, logout, reboot)",
		Deletion:      "delete-generic-password on rotation; `gasworks logout` deletes every item under this profile's service",
	}
}

// Available reports whether the system keychain tool is present.
func (k *Keychain) Available() bool {
	info, err := os.Stat(securityPath)
	return err == nil && info.Mode().IsRegular()
}

// Put enrols the key. The item is added through `security -i`, which reads its command from
// stdin: process arguments are world-readable on macOS (`ps -ef`), so the key must never
// appear in an argv. Interactive mode reports failures on stderr rather than through the
// exit status, so the enrolment is confirmed by reading the item back.
func (k *Keychain) Put(handle, pem string) error {
	if !ValidHandle(handle) {
		return fmt.Errorf("keystore: invalid handle %q", handle)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	// -U updates an existing item instead of failing with errSecDuplicateItem, which is what
	// a key rotation needs (the handle is stable for a session). Every field below is either
	// a constant or validated (handle, base64), so none of them can break the interactive
	// parser's tokenization.
	command := strings.Join(append([]string{
		"add-generic-password", "-U",
		"-s", k.service, "-a", handle,
		"-D", "Gas-City-DPoP-session-key",
		"-w", encoded,
	}, k.keychainArgs()...), " ")
	cmd := exec.Command(securityPath, "-i")
	cmd.Stdin = strings.NewReader(command + "\n")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keystore: keychain enrolment failed: %w", err)
	}
	stored, err := k.Get(handle)
	if err != nil {
		return fmt.Errorf("keystore: keychain enrolment could not be confirmed: %w", err)
	}
	if stored != pem {
		return errors.New("keystore: keychain enrolment did not store this key")
	}
	return nil
}

func (k *Keychain) Get(handle string) (string, error) {
	if !ValidHandle(handle) {
		return "", fmt.Errorf("keystore: invalid handle %q", handle)
	}
	out, err := k.run(append([]string{"find-generic-password", "-s", k.service, "-a", handle, "-w"}, k.keychainArgs()...)...)
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
	args := append([]string{"delete-generic-password", "-s", k.service, "-a", handle}, k.keychainArgs()...)
	if _, err := k.run(args...); err != nil {
		if exitStatus(err) == keychainNotFoundStatus {
			return nil
		}
		return fmt.Errorf("keystore: keychain delete failed: %w", err)
	}
	return nil
}

// Purge deletes this profile's items one at a time until the keychain reports none left.
// `security` has no "delete all matching" mode, and each call removes exactly one item.
func (k *Keychain) Purge() error {
	args := append([]string{"delete-generic-password", "-s", k.service}, k.keychainArgs()...)
	for i := 0; i < purgeLimit; i++ {
		if _, err := k.run(args...); err != nil {
			if exitStatus(err) == keychainNotFoundStatus {
				return nil
			}
			return fmt.Errorf("keystore: keychain purge failed: %w", err)
		}
	}
	return fmt.Errorf("keystore: keychain purge did not converge after %d deletions", purgeLimit)
}

// keychainArgs is the trailing [keychain] positional `security` accepts, or nothing for the
// user's default keychain.
func (k *Keychain) keychainArgs() []string {
	if k.keychain == "" {
		return nil
	}
	return []string{k.keychain}
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
