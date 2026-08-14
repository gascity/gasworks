//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
)

// sessionUUIDPattern matches the trailing native-session UUID of a provider transcript filename —
// both the Codex rollout shape (rollout-<ts>-<uuid>.jsonl) and the Claude shape (<uuid>.jsonl). It
// is how the wrapper derives the child's native session id from the file NAME alone (no content
// read), to bind that session to the run.
var sessionUUIDPattern = regexp.MustCompile(`([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$`)

// nativeSessionIDFromPath extracts a native session id from a transcript path, recognizing the
// Codex rollout and Claude transcript filename shapes. It is the provider-specific extractor the
// `run` adapter injects into runwrap so the wrapper itself stays provider-agnostic.
func nativeSessionIDFromPath(path string) (string, bool) {
	m := sessionUUIDPattern.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// runRun wraps a child command as an observed explicit run. It dials the daemon socket, hands
// runwrap the WrapperDaemonClient seam, and lets the wrapper own the durable boundary, the same-PID
// identity shim (re-execing THIS binary via the RUNWRAP_SHIM guard), signal forwarding, and the
// pass-through exit code. -allow-unobserved contacts the daemon ZERO times and runs the child bare.
//
// The child command follows a "--" terminator so it can carry its own flags:
//
//	gasworks-companion run [flags] -- CMD [args...]
func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("dir", "", "observer state directory (to locate the daemon socket)")
	socket := fs.String("socket", "", "daemon Unix socket path; default <dir>/socket")
	allowUnobserved := fs.Bool("allow-unobserved", false, "run the child WITHOUT observation (emergency bypass)")
	beadsProject := fs.String("beads-project", "", "beads project id (with -work-item)")
	workItem := fs.String("work-item", "", "work item bead id (with -beads-project)")
	var sessionRoots multiFlag
	fs.Var(&sessionRoots, "session-root", "a provider transcript root to scan for the child's native session id and bind it to this run (repeatable); enables explicit-run usage binding")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := fs.Args()
	if len(target) == 0 {
		fmt.Fprintln(os.Stderr, "gasworks-companion run: no child command (use: run [flags] -- CMD [args...])")
		return 2
	}

	cfg := runwrap.Config{
		Target:          target,
		BeadsProjectID:  *beadsProject,
		WorkItemBeadID:  *workItem,
		AllowUnobserved: *allowUnobserved,
		// Re-exec THIS binary as the same-PID identity shim, triggered by the RUNWRAP_SHIM env the
		// shim strips before exec-ing the child. The empty PrefixArgs keeps the shim argv pristine
		// ([self, "--", CMD...]); main's shim guard dispatches it before any flag parsing.
		Shim: runwrap.ShimSpec{PrefixArgs: []string{}, ExtraEnv: []string{shimEnvVar + "=1"}},
		// Explicit-run usage binding: scan these provider transcript roots for the child's native
		// session file and bind that session to this run so its real usage lands on the bead's run.
		SessionRoots:    sessionRoots,
		NativeSessionID: nativeSessionIDFromPath,
	}
	if len(sessionRoots) > 0 {
		// With binding active, let the always-running watcher capture the finished session's final
		// USAGE before RUN_ENDED is sequenced, so the platform does not quarantine it as an
		// association after RUN_ENDED (which would leave the run's usage_totals empty).
		cfg.DrainSettle = 3 * time.Second
	}

	var dc runwrap.DaemonClient
	if !*allowUnobserved {
		stateDir, err := observerDir(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion run:", err)
			return 1
		}
		socketPath, err := observerSocketPath(*socket, stateDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion run:", err)
			return 2
		}
		dc = daemon.NewWrapperDaemonClient(local.NewClient(socketPath))
	}

	// The wrapper forwards signals to the child and runs the terminal sequence on exit, so the run
	// process itself uses a background context rather than a signal-cancelled one.
	res, err := runwrap.Run(context.Background(), dc, cfg)

	// If the child actually ran, its exit code/signal is the authoritative result and MUST pass
	// through EVEN IF a terminal-sequence append (PROCESS_EXITED / partial diag / RUN_ENDED /
	// release) failed afterward: an observer-side durability hiccup must never turn a green child
	// red. The terminal-append error is still surfaced to stderr as an operator signal.
	if res.Launched {
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion run: terminal sequence not fully durable:", err)
		}
		if res.Signaled {
			return 128 + res.Signal
		}
		return res.ExitCode
	}

	// The child never launched: this is a genuine pre-launch failure (capacity refusal, non-durable
	// RUN_STARTED, launch failure, or a usage error) with no child exit code to report.
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion run:", err)
		return exitCodeForRunError(err)
	}
	return res.ExitCode
}

// exitCodeForRunError maps a pre-launch wrapper lifecycle error to a process exit code. Usage errors
// are 2; every other pre-launch failure (capacity refusal, non-durable boundary, launch failure) is
// 1. It is consulted ONLY when the child never launched — a launched child's own code always wins.
func exitCodeForRunError(err error) int {
	switch {
	case errors.Is(err, runwrap.ErrNoTarget), errors.Is(err, runwrap.ErrIncompleteWorkRef):
		return 2
	default:
		return 1
	}
}
