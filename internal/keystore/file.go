package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// FileBackendID is the registry id of the plaintext-file backend.
const FileBackendID = "file"

// keyDirName is the subdirectory of the config dir the file backend owns. It is deliberately
// NOT credentials.json: Auth Access v1 requires the opaque session and the private key it is
// bound to never to be stored together, so a stolen credentials file carries no key and a
// stolen key file carries no session.
const keyDirName = "dpop-keys"

// File stores each key as its own 0600 PKCS#8 PEM file inside a 0700 directory. One file per
// handle means enrolment is a plain atomic create — no read-modify-write, so two concurrent
// `gasworks getToken` runs cannot lose each other's key and no lock is needed.
//
// It is registered on every platform and ALWAYS requires an explicit opt-in: this is the
// plaintext dotfile the custody clause forbids falling back to silently.
type File struct{ dir string }

// NewFile returns the file backend rooted at the gasworks config dir.
func NewFile(configDir string) *File { return &File{dir: filepath.Join(configDir, keyDirName)} }

func (f *File) Descriptor() Descriptor {
	return Descriptor{
		ID:            FileBackendID,
		Summary:       "plaintext PKCS#8 PEM under the gasworks config dir (opt-in)",
		NonExportable: false,
		RequiresOptIn: true,
		Exportability: "fully exportable: the PEM is readable by the owning user and by root",
		Backup:        "copied by anything that backs up the config dir (dotfile sync, disk image) — exclude " + keyDirName + "/",
		AccessControl: "0600 file in a 0700 directory; the OS never prompts and never re-locks",
		Deletion:      "unlink on rotation and `gasworks logout`; no secure erase on a copy-on-write filesystem",
	}
}

// Available reports true on every platform: the config dir is created on demand.
func (f *File) Available() bool { return true }

func (f *File) Put(handle, pem string) error {
	path, err := f.path(handle)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("keystore: create key dir: %w", err)
	}
	if runtime.GOOS != "windows" {
		// MkdirAll honours umask; re-assert 0700 like the credential store does.
		_ = os.Chmod(f.dir, 0o700)
	}
	tmp, err := os.CreateTemp(f.dir, ".key-*.tmp")
	if err != nil {
		return fmt.Errorf("keystore: create key file: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			return fail(fmt.Errorf("keystore: chmod key file: %w", err))
		}
	}
	if _, err := tmp.WriteString(pem); err != nil {
		return fail(fmt.Errorf("keystore: write key file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("keystore: close key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("keystore: install key file: %w", err)
	}
	return nil
}

func (f *File) Get(handle string) (string, error) {
	path, err := f.path(handle)
	if err != nil {
		return "", err
	}
	// Lstat first so a symlink planted at the path is refused rather than followed. The key
	// dir is 0700, so only the owning user (who already holds the key) could plant one; this
	// is defence in depth, not a boundary against a same-uid attacker.
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keystore: stat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("keystore: %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("keystore: %s is group/world-accessible (chmod 600)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keystore: read key file: %w", err)
	}
	return string(raw), nil
}

func (f *File) Delete(handle string) error {
	path, err := f.path(handle)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("keystore: remove key file: %w", err)
	}
	return nil
}

// Purge removes the whole key directory, so a logout leaves no PEM behind even for a session
// whose reference was lost with a corrupt credentials file.
func (f *File) Purge() error {
	if err := os.RemoveAll(f.dir); err != nil {
		return fmt.Errorf("keystore: purge key dir: %w", err)
	}
	return nil
}

func (f *File) path(handle string) (string, error) {
	if !ValidHandle(handle) {
		return "", fmt.Errorf("keystore: invalid handle %q", handle)
	}
	return filepath.Join(f.dir, handle+".pem"), nil
}

// Dir is the directory this backend keeps keys in (reported by `gasworks inspect`).
func (f *File) Dir() string { return f.dir }
