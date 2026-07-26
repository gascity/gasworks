//go:build darwin

package codex

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// hostBootID derives an opaque, boot-scoped identifier from kern.boottime. The wrapper uses the
// identical representation, so registered and walked identities compare byte-for-byte.
func hostBootID() (string, error) {
	boot, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return "", fmt.Errorf("codex lineage: read boot time: %w", err)
	}
	if boot.Sec <= 0 || boot.Usec < 0 || boot.Usec >= 1_000_000 {
		return "", errors.New("codex lineage: invalid boot time")
	}
	return fmt.Sprintf("darwin-boottime-%d-%06d", boot.Sec, boot.Usec), nil
}

// readProcStat returns a process's parent and absolute start timestamp from one kern.proc.pid
// snapshot. Unix microseconds retain Darwin's full timeval precision and preserve ancestry
// monotonicity while disambiguating PID reuse.
func readProcStat(pid int) (ppid int, startTime int64, err error) {
	if pid <= 0 {
		return 0, 0, fmt.Errorf("codex lineage: invalid pid %d", pid)
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: read process %d: %w", pid, err)
	}
	if int(info.Proc.P_pid) != pid {
		return 0, 0, fmt.Errorf("codex lineage: process snapshot pid is %d, want %d", info.Proc.P_pid, pid)
	}
	ppid = int(info.Eproc.Ppid)
	start := info.Proc.P_starttime
	if ppid < 0 || start.Sec <= 0 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return 0, 0, fmt.Errorf("codex lineage: invalid process snapshot for pid %d", pid)
	}
	startTime = start.Sec*1_000_000 + int64(start.Usec)
	if startTime <= 0 {
		return 0, 0, fmt.Errorf("codex lineage: invalid start time for pid %d", pid)
	}
	return ppid, startTime, nil
}
