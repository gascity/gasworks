//go:build windows

package saauth

import "errors"

// TokenFromFile is unsupported on Windows: the hardening contract (uid ownership +
// POSIX 0o077 mode bits + O_NOFOLLOW fstat) has no faithful Windows equivalent, and
// the forwarder is a Linux/macOS pack service. Use TokenFromEnv on Windows for dev.
func TokenFromFile(path string) (string, error) {
	return "", errors.New("saauth: token files are not supported on Windows; use the env token (dev-only)")
}
