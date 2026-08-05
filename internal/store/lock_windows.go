//go:build windows

package store

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const lockfileExclusiveLock = 0x00000002

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	createEventProc   = kernel32.NewProc("CreateEventW")
	getOverlappedProc = kernel32.NewProc("GetOverlappedResult")
	lockFileExProc    = kernel32.NewProc("LockFileEx")
	unlockFileExProc  = kernel32.NewProc("UnlockFileEx")
)

// lock takes an exclusive, process-scoped lock on one byte of the lock file. Windows releases
// the lock when the handle closes, including after process termination, so a crashed CLI cannot
// strand a stale lock. A contended LockFileEx completes asynchronously with
// ERROR_IO_PENDING, so lock waits for the associated OVERLAPPED event before
// returning the release closure.
func lock() (func(), error) {
	if _, err := ensureDir(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	event, _, callErr := createEventProc.Call(0, 0, 0, 0)
	if event == 0 {
		_ = file.Close()
		return nil, windowsCallError(callErr)
	}
	overlapped := &syscall.Overlapped{HEvent: syscall.Handle(event)}
	cleanup := func() {
		_ = syscall.CloseHandle(overlapped.HEvent)
		_ = file.Close()
	}
	result, _, callErr := lockFileExProc.Call(
		file.Fd(),
		lockfileExclusiveLock,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(overlapped)),
	)
	if result == 0 {
		if windowsCallError(callErr) != syscall.ERROR_IO_PENDING {
			cleanup()
			return nil, windowsCallError(callErr)
		}
		waitResult, waitErr := syscall.WaitForSingleObject(overlapped.HEvent, syscall.INFINITE)
		if waitErr != nil {
			cleanup()
			return nil, waitErr
		}
		if waitResult != syscall.WAIT_OBJECT_0 {
			cleanup()
			return nil, fmt.Errorf("LockFileEx wait returned %#x", waitResult)
		}
		var bytesTransferred uint32
		result, _, callErr = getOverlappedProc.Call(
			file.Fd(),
			uintptr(unsafe.Pointer(overlapped)),
			uintptr(unsafe.Pointer(&bytesTransferred)),
			0,
		)
		if result == 0 {
			cleanup()
			return nil, windowsCallError(callErr)
		}
	}
	return func() {
		_, _, _ = unlockFileExProc.Call(
			file.Fd(),
			0,
			1,
			0,
			uintptr(unsafe.Pointer(overlapped)),
		)
		_ = syscall.CloseHandle(overlapped.HEvent)
		_ = file.Close()
	}, nil
}

func windowsCallError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return syscall.EINVAL
	}
	return err
}
