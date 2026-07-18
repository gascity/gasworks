//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
)

// runRun wraps a child command as an observed explicit run. It dials the daemon socket, hands
// runwrap the WrapperDaemonClient seam, and lets the wrapper own the durable boundary, the same-PID
// identity shim (re-execing THIS binary via the RUNWRAP_SHIM guard), signal forwarding, and the
// pass-through exit code. -allow-unobserved contacts the daemon ZERO times and runs the child bare.
//
// The child command follows a "--" terminator so it can carry its own flags:
//
//	gasworks-observer run [flags] -- CMD [args...]
func runRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("dir", "", "observer state directory (to locate the daemon socket)")
	allowUnobserved := fs.Bool("allow-unobserved", false, "run the child WITHOUT observation (emergency bypass)")
	beadsProject := fs.String("beads-project", "", "beads project id (with -work-item)")
	workItem := fs.String("work-item", "", "work item bead id (with -beads-project)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := fs.Args()
	if len(target) == 0 {
		fmt.Fprintln(os.Stderr, "gasworks-observer run: no child command (use: run [flags] -- CMD [args...])")
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
	}

	var dc runwrap.DaemonClient
	if !*allowUnobserved {
		stateDir, err := observerDir(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-observer run:", err)
			return 1
		}
		dc = daemon.NewWrapperDaemonClient(local.NewClient(socketPathFor(stateDir)))
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
			fmt.Fprintln(os.Stderr, "gasworks-observer run: terminal sequence not fully durable:", err)
		}
		if res.Signaled {
			return 128 + res.Signal
		}
		return res.ExitCode
	}

	// The child never launched: this is a genuine pre-launch failure (capacity refusal, non-durable
	// RUN_STARTED, launch failure, or a usage error) with no child exit code to report.
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer run:", err)
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
