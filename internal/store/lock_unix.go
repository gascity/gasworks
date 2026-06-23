//go:build !windows

package store

import (
	"os"

	"golang.org/x/sys/unix"
)

// lock acquires an exclusive advisory flock on the .lock file in the config dir, mirroring
// the Python store's fcntl.flock(LOCK_EX). The returned func releases the lock and closes
// the fd. The lock file is created 0600.
func lock() (func(), error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
