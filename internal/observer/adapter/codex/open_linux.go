//go:build linux

package codex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// openGCMetaSidecar opens an adjacent metadata sidecar through the same approved-root anchor and
// no-symlink resolution as transcript reads. Unlike transcripts, sidecars are not identity-keyed;
// their regular-file check happens in readGCSessionIDSidecar after this trusted open.
func openGCMetaSidecar(root, locator string) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(rootFD) }()
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(rootFD, locator, how)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS):
			return openGCMetaSidecarFallback(root, locator)
		case errors.Is(err, unix.ENOENT):
			return nil, os.ErrNotExist
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
			return nil, errRefusedResolve
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), locator), nil
}

// openGCMetaSidecarFallback preserves the no-symlink boundary on kernels without openat2 by
// retaining descriptors for every directory component. Unlike the transcript compatibility
// fallback, this new sidecar reader never falls back to a path re-resolution through a parent
// directory that could be replaced by a symlink.
func openGCMetaSidecarFallback(root, locator string) (*os.File, error) {
	clean := filepath.Clean(locator)
	if locator == "" || filepath.IsAbs(locator) || clean != locator || clean == "." || hasDotDotPrefix(clean) {
		return nil, errRefusedResolve
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
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
			return nil, errRefusedResolve
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
				return nil, os.ErrNotExist
			case errors.Is(openErr, unix.ELOOP), errors.Is(openErr, unix.ENOTDIR):
				return nil, errRefusedResolve
			default:
				return nil, openErr
			}
		}
		if final {
			return os.NewFile(uintptr(fd), locator), nil
		}
		dirFD = fd
		ownsDirFD = true
	}
	return nil, errRefusedResolve
}
