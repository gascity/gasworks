//go:build windows

package runwrap

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// ErrObservedUnsupported is returned for an observed run on Windows. An observed run registers the
// child's OS process-start identity BEFORE the child image runs, which the same-PID shim achieves
// with execve (the pid and start time survive the exec). Windows has no exec that keeps the
// process, so there is no race-free identity to register and the wrapper refuses rather than
// guess. --allow-unobserved still runs the target.
var ErrObservedUnsupported = errors.New("observer runwrap: observed runs need the same-PID shim, which requires a Unix host; use --allow-unobserved on Windows")

// launchObserved always fails on Windows (see ErrObservedUnsupported). No child is started, so the
// caller's launch-failure terminal sequence closes the run with no process identity.
func launchObserved(Config, []string, func(wire.ProcessIdentity) error) (*childProc, *launchError) {
	return nil, &launchError{stage: "shim-setup", err: ErrObservedUnsupported}
}

// launchUnobserved spawns the child directly with the wrapper's stdio and the sanitized
// environment. Console control events (Ctrl+C, Ctrl+Break) are delivered by Windows to every
// process attached to the console, so the child receives them without forwarding.
func launchUnobserved(cfg Config, childEnv []string) (*childProc, error) {
	path, err := exec.LookPath(cfg.Target[0])
	if err != nil {
		return nil, fmt.Errorf("observer runwrap: resolve %q: %w", cfg.Target[0], err)
	}
	cmd := &exec.Cmd{
		Path:   path,
		Args:   cfg.Target,
		Env:    childEnv,
		Stdin:  cfg.stdin(),
		Stdout: cfg.stdout(),
		Stderr: cfg.stderr(),
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("observer runwrap: start %q: %w", cfg.Target[0], err)
	}
	return &childProc{cmd: cmd}, nil
}

// interpretState reports the child's exit code. Windows has no signal deaths; a process ended by
// TerminateProcess reports the exit code it was terminated with.
func interpretState(st *os.ProcessState, _ error) (exitCode int, signaled bool, signal int) {
	if st == nil {
		return -1, false, 0
	}
	return st.ExitCode(), false, 0
}

// RunShim is the Unix same-PID shim entry point; there is no shim on Windows.
func RunShim() error { return ErrObservedUnsupported }
