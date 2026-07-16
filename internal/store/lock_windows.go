//go:build windows

package store

import (
	"os"
	"syscall"
	"unsafe"
)

const lockfileExclusiveLock = 0x00000002

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc   = kernel32.NewProc("LockFileEx")
	unlockFileExProc = kernel32.NewProc("UnlockFileEx")
)

// lock takes an exclusive, process-scoped lock on one byte of the lock file. Windows releases
// the lock when the handle closes, including after process termination, so a crashed CLI cannot
// strand a stale lock. LockFileEx blocks until the current refresh transaction completes.
func lock() (func(), error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := &syscall.Overlapped{}
	result, _, callErr := lockFileExProc.Call(
		file.Fd(),
		lockfileExclusiveLock,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		return nil, windowsCallError(callErr)
	}
	return func() {
		_, _, _ = unlockFileExProc.Call(
			file.Fd(),
			0,
			1,
			0,
			uintptr(unsafe.Pointer(overlapped)),
		)
		_ = file.Close()
	}, nil
}

func windowsCallError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	return err
}
