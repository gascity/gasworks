//go:build linux

package runwrap

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// readSelfIdentity reads the shim's own boot-scoped process identity. execve preserves both PID
// and kernel start time, so this is exactly the eventual child's identity.
func readSelfIdentity() (wire.ProcessIdentity, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return wire.ProcessIdentity{}, fmt.Errorf("read boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" {
		return wire.ProcessIdentity{}, errors.New("empty boot id")
	}
	start, err := readProcessStartTime("/proc/self/stat")
	if err != nil {
		return wire.ProcessIdentity{}, err
	}
	return wire.ProcessIdentity{
		BootId:           bootID,
		Pid:              int64(os.Getpid()),
		ProcessStartTime: start,
	}, nil
}

// readProcessStartTime parses field 22 from one /proc stat file. Parsing resumes after the last
// ')' because the comm field may itself contain spaces or parentheses.
func readProcessStartTime(statPath string) (int64, error) {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", statPath, err)
	}
	lastParen := bytes.LastIndexByte(data, ')')
	if lastParen < 0 || lastParen+2 >= len(data) {
		return 0, fmt.Errorf("malformed stat file %s", statPath)
	}
	fields := strings.Fields(string(data[lastParen+2:]))
	const startTimeIndexAfterComm = 19
	if len(fields) <= startTimeIndexAfterComm {
		return 0, fmt.Errorf("stat file %s has too few fields", statPath)
	}
	start, err := strconv.ParseInt(fields[startTimeIndexAfterComm], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse start time in %s: %w", statPath, err)
	}
	if start < 0 {
		return 0, fmt.Errorf("negative start time in %s", statPath)
	}
	return start, nil
}
