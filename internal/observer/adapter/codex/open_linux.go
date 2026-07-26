//go:build linux

package codex

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openValidatedTranscript opens relative to a stable root descriptor with openat2 containment,
// then fstat-validates the tracked file identity. Kernels without openat2 retain the existing
// final-component O_NOFOLLOW fallback.
func openValidatedTranscript(root, locator string, dev, ino uint64) (f *os.File, size, modNanos int64, err error) {
	rootFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = unix.Close(rootFd) }()
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(rootFd, locator, how)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS):
			return openValidatedFallback(filepath.Join(root, locator), dev, ino)
		case errors.Is(err, unix.ENOENT):
			return nil, 0, 0, os.ErrNotExist
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
			return nil, 0, 0, errRefusedResolve
		default:
			return nil, 0, 0, err
		}
	}
	return validateOpenFile(os.NewFile(uintptr(fd), locator), dev, ino)
}

func openValidatedFallback(path string, dev, ino uint64) (*os.File, int64, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	return validateOpenFile(f, dev, ino)
}
