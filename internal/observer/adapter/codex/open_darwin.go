//go:build darwin

package codex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openValidatedTranscript walks every relative path component from a stable approved-root
// descriptor. O_NOFOLLOW rejects symlinks at every step, held directory descriptors close the
// parent-swap race, and the final fstat confirms the tracked device/inode identity.
func openValidatedTranscript(root, locator string, dev, ino uint64) (*os.File, int64, int64, error) {
	clean := filepath.Clean(locator)
	if locator == "" || filepath.IsAbs(locator) || clean != locator || clean == "." || hasDotDotPrefix(clean) {
		return nil, 0, 0, errRefusedResolve
	}

	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = unix.Close(rootFD) }()

	parts := strings.Split(clean, string(os.PathSeparator))
	dirFD := rootFD
	ownsDirFD := false
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			if ownsDirFD {
				_ = unix.Close(dirFD)
			}
			return nil, 0, 0, errRefusedResolve
		}
		final := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if final {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := unix.Openat(dirFD, part, flags, 0)
		if ownsDirFD {
			_ = unix.Close(dirFD)
		}
		if openErr != nil {
			switch {
			case errors.Is(openErr, unix.ENOENT):
				return nil, 0, 0, os.ErrNotExist
			case errors.Is(openErr, unix.ELOOP), errors.Is(openErr, unix.ENOTDIR):
				return nil, 0, 0, errRefusedResolve
			default:
				return nil, 0, 0, openErr
			}
		}
		if final {
			return validateOpenFile(os.NewFile(uintptr(fd), locator), dev, ino)
		}
		dirFD = fd
		ownsDirFD = true
	}
	return nil, 0, 0, errRefusedResolve
}
