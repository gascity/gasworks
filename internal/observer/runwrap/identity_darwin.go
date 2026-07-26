//go:build darwin

package runwrap

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// readSelfIdentity reads the shim's own boot-scoped process identity. execve preserves both PID
// and start time, so this remains the observed child's identity after the same-PID handoff.
func readSelfIdentity() (wire.ProcessIdentity, error) {
	boot, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return wire.ProcessIdentity{}, fmt.Errorf("read boot time: %w", err)
	}
	if boot.Sec <= 0 || boot.Usec < 0 || boot.Usec >= 1_000_000 {
		return wire.ProcessIdentity{}, errors.New("invalid boot time")
	}
	bootID := fmt.Sprintf("darwin-boottime-%d-%06d", boot.Sec, boot.Usec)

	pid := os.Getpid()
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return wire.ProcessIdentity{}, fmt.Errorf("read process identity: %w", err)
	}
	if int(info.Proc.P_pid) != pid {
		return wire.ProcessIdentity{}, fmt.Errorf("process snapshot pid is %d, want %d", info.Proc.P_pid, pid)
	}
	start := info.Proc.P_starttime
	if start.Sec <= 0 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return wire.ProcessIdentity{}, errors.New("invalid process start time")
	}
	startTime := start.Sec*1_000_000 + int64(start.Usec)
	if startTime <= 0 {
		return wire.ProcessIdentity{}, errors.New("invalid process start time")
	}
	return wire.ProcessIdentity{
		BootId:           bootID,
		Pid:              int64(pid),
		ProcessStartTime: startTime,
	}, nil
}
