package runwrap

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// Platform-neutral launch plumbing shared by process_unix.go (the same-PID shim) and
// process_windows.go (unobserved launches only).

// controlEnvPrefix marks environment variables the shim strips before exec-ing the child, so a
// test-mode trigger (or any future wrapper control variable) never leaks into the child.
const controlEnvPrefix = "RUNWRAP_"

// launchError is a typed launch failure carrying the stage and, when known, the proven child
// identity so the caller can stamp PROCESS_LAUNCH_FAILED.
type launchError struct {
	stage    string
	identity wire.ProcessIdentity
	err      error
}

func (e *launchError) Error() string {
	return fmt.Sprintf("observer runwrap: launch failed at %s: %v", e.stage, e.err)
}

// childProc is a launched child with signal forwarding attached.
type childProc struct {
	cmd      *exec.Cmd
	identity wire.ProcessIdentity
	stopFwd  func()
}

// wait blocks for the child to exit, stops signal forwarding, and translates its wait status
// into an exit code / signal. A signal death reports the conventional 128+signal exit code
// plus signaled=true so the terminal sequence records it as a signal, not an exit code.
func (c *childProc) wait() (exitCode int, signaled bool, signal int) {
	waitErr := c.cmd.Wait()
	if c.stopFwd != nil {
		c.stopFwd()
	}
	return interpretState(c.cmd.ProcessState, waitErr)
}

func (c Config) stdin() io.Reader {
	if c.Stdin != nil {
		return c.Stdin
	}
	return os.Stdin
}

func (c Config) stdout() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

func (c Config) stderr() io.Writer {
	if c.Stderr != nil {
		return c.Stderr
	}
	return os.Stderr
}

// sanitizeUnobservedEnv is the --allow-unobserved counterpart of shimChildEnv: it strips the
// wrapper's run-id variable AND every RUNWRAP_-prefixed control variable, so the unobserved child
// sees the same sanitized environment the observed child gets. The observed path launches through
// the shim, which strips RUNWRAP_ via shimChildEnv before exec; the unobserved path has no shim, so
// without this strip an inherited RUNWRAP_* (e.g. a nested wrapper's RUNWRAP_SHIM) would leak into
// the child. The inherited outer run id is dropped so an independently captured native session stays
// its own inferred run rather than referencing an unknown boundary.
func sanitizeUnobservedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if k == RunIDEnvVar || strings.HasPrefix(k, controlEnvPrefix) {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}
