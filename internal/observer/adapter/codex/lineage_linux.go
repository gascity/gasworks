//go:build linux

package codex

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	procStartTimeFieldAfterComm = 19
	procPPIDFieldAfterComm      = 1
)

func hostBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("codex lineage: read boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if bootID == "" {
		return "", errors.New("codex lineage: empty boot id")
	}
	return bootID, nil
}

// readProcStat parses ppid and starttime from one /proc/<pid>/stat read so the two fields refer
// to the same process generation.
func readProcStat(pid int) (ppid int, startTime int64, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: read stat: %w", err)
	}
	lastParen := bytes.LastIndexByte(data, ')')
	if lastParen < 0 || lastParen+2 >= len(data) {
		return 0, 0, fmt.Errorf("codex lineage: malformed stat for pid %d", pid)
	}
	fields := strings.Fields(string(data[lastParen+2:]))
	if len(fields) <= procStartTimeFieldAfterComm {
		return 0, 0, fmt.Errorf("codex lineage: stat for pid %d has too few fields", pid)
	}
	ppid, err = strconv.Atoi(fields[procPPIDFieldAfterComm])
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: parse ppid for pid %d: %w", pid, err)
	}
	startTime, err = strconv.ParseInt(fields[procStartTimeFieldAfterComm], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: parse start time for pid %d: %w", pid, err)
	}
	if ppid < 0 || startTime < 0 {
		return 0, 0, fmt.Errorf("codex lineage: negative field in stat for pid %d", pid)
	}
	return ppid, startTime, nil
}
