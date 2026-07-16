//go:build windows

package store

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

// This branch makes the credential lock LOAD-BEARING for §5.5 cross-process refresh
// serialization (every bd/gc command spawns a fresh `gasworks getToken` process, and N racers
// presenting the same rotating Keycloak refresh token can get the whole offline-session family
// revoked). The former Windows no-op therefore had to become a real advisory lock: this uses
// kernel32 LockFileEx/UnlockFileEx on the .lock file handle — the Windows equivalent of the
// POSIX flock — via the syscall package (no new dependency). It is cross-compile verified;
// runtime-tested on Windows only via the build-tagged lock test.
var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
	// errLockViolation (ERROR_LOCK_VIOLATION) is returned by LockFileEx with
	// LOCKFILE_FAIL_IMMEDIATELY when the range is already locked by another handle.
	errLockViolation = syscall.Errno(33)
	// errIOPending (ERROR_IO_PENDING) can surface for a would-block; treated as retryable.
	errIOPending = syscall.Errno(997)
)

// overlapped mirrors the Windows OVERLAPPED struct LockFileEx requires. We lock a single byte
// at offset 0; only the offset fields are meaningful here.
type overlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       syscall.Handle
}

func lockFileEx(h syscall.Handle, flags uint32) error {
	var ol overlapped
	r1, _, err := procLockFileEx.Call(
		uintptr(h),
		uintptr(flags),
		0,
		1, // nNumberOfBytesToLockLow: lock one byte
		0, // nNumberOfBytesToLockHigh
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func unlockFileEx(h syscall.Handle) error {
	var ol overlapped
	r1, _, err := procUnlockFileEx.Call(
		uintptr(h),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

// openLockFile opens (creating 0600) the config-dir .lock file.
func openLockFile() (*os.File, error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	return os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
}

// lock acquires a BLOCKING exclusive advisory lock via LockFileEx, giving Windows the same
// cross-process serialization the POSIX flock provides.
func lock() (func(), error) {
	f, err := openLockFile()
	if err != nil {
		return nil, err
	}
	h := syscall.Handle(f.Fd())
	if err := lockFileEx(h, lockfileExclusiveLock); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unlockFileEx(h)
		_ = f.Close()
	}, nil
}

// lockDeadline acquires the exclusive lock NON-BLOCKING (LOCKFILE_FAIL_IMMEDIATELY), retrying
// with a small capped backoff until deadline, returning ErrLockTimeout if still contended (FIX
// 5).
func lockDeadline(deadline time.Time) (func(), error) {
	f, err := openLockFile()
	if err != nil {
		return nil, err
	}
	h := syscall.Handle(f.Fd())
	backoff := 5 * time.Millisecond
	for {
		err := lockFileEx(h, lockfileExclusiveLock|lockfileFailImmediately)
		if err == nil {
			return func() {
				_ = unlockFileEx(h)
				_ = f.Close()
			}, nil
		}
		if err != errLockViolation && err != errIOPending {
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
