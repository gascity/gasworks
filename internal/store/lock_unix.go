//go:build !windows

package store

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// openLockFile opens (creating 0600) the config-dir .lock file.
func openLockFile() (*os.File, error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	return os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
}

// lock acquires an exclusive advisory flock on the .lock file in the config dir, mirroring
// the Python store's fcntl.flock(LOCK_EX). The returned func releases the lock and closes
// the fd. The lock file is created 0600.
func lock() (func(), error) {
	f, err := openLockFile()
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

// lockDeadline acquires the exclusive flock NON-BLOCKING (LOCK_EX|LOCK_NB), retrying with a
// small capped backoff until deadline. It returns ErrLockTimeout if the lock is still held at
// the deadline, so a waiter fails fast instead of blocking unboundedly (FIX 5).
func lockDeadline(deadline time.Time) (func(), error) {
	f, err := openLockFile()
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	backoff := 5 * time.Millisecond
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(fd, unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if err != unix.EWOULDBLOCK {
			_ = f.Close()
			return nil, err
		}
		if !time.Now().Add(backoff).Before(deadline) {
			_ = f.Close()
			return nil, ErrLockTimeout
		}
		time.Sleep(backoff)
		if backoff < 50*time.Millisecond {
			backoff *= 2
		}
	}
}
