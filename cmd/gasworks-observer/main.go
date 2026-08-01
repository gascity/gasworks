//go:build linux || darwin

// Command gasworks-observer is the standalone Gas City Observer endpoint binary. It ties the
// committed observer subsystems into a working daemon and its interactive surfaces:
//
//	gasworks-observer daemon   — run the endpoint (WAL spool + socket server + uploader + watcher)
//	gasworks-observer run CMD  — run a child command as an observed explicit run
//	gasworks-observer hook codex — the Codex SessionStart hook handler (stdin -> durable capture)
//
// GOVERNING RULE: this binary has ZERO Gas City dependency. It imports ONLY internal/observer/*
// (which is Gas-City-free), the standard library, and golang.org/x/sys/unix. It must never import
// cmd/gasworks or any Gas City package.
//
// The same-PID identity shim (the wrapper's re-exec of this binary) is dispatched FIRST in main,
// before any flag parsing, so the shim's argv and inherited fds stay pristine.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
)

// shimEnvVar marks a process re-exec'd by the wrapper as its same-PID identity shim. main
// dispatches to runwrap.RunShim() the instant it is set, before flags or subcommands are looked at.
// It is a RUNWRAP_-prefixed variable, which the shim strips before exec-ing the observed child, so
// it never leaks into the child environment.
const shimEnvVar = "RUNWRAP_SHIM"

// socketFilename mirrors internal/observer/local's default runtime socket name.
const socketFilename = "socket"

func main() {
	// The shim guard MUST be first: a re-exec'd shim reads its handshake fds and target argv and
	// must not have them disturbed by flag parsing or subcommand routing.
	if os.Getenv(shimEnvVar) != "" {
		if err := runwrap.RunShim(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(dispatch(os.Args[1:]))
}

// dispatch routes the root subcommand.
func dispatch(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "daemon":
		return runDaemon(args[1:])
	case "run":
		return runRun(args[1:])
	case "declare-work":
		return runDeclareWork(args[1:])
	case "hook":
		return runHook(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "gasworks-observer: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gasworks-observer — Gas City Observer endpoint

Usage:
  gasworks-observer daemon   [flags]      run the endpoint daemon
  gasworks-observer run      [flags] -- CMD [args...]  run a child as an observed run
  gasworks-observer declare-work [flags]  declare work on the current explicit run
  gasworks-observer hook codex [flags]    Codex SessionStart hook handler (reads stdin)
`)
}

// observerDir resolves the observer state directory: the -dir flag, else GASWORKS_OBSERVER_DIR,
// else ${XDG_STATE_HOME:-$HOME/.local/state}/gasworks-observer.
func observerDir(flagDir string) (string, error) {
	if flagDir != "" {
		return flagDir, nil
	}
	if d := os.Getenv("GASWORKS_OBSERVER_DIR"); d != "" {
		return d, nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve observer state dir: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "gasworks-observer"), nil
}

// socketPathFor returns the daemon socket path under the observer state directory.
func socketPathFor(dir string) string { return filepath.Join(dir, socketFilename) }

// observerSocketPath resolves an explicit runtime socket or the state-directory default.
func observerSocketPath(flagSocket, stateDir string) (string, error) {
	return local.ValidateServerPaths(stateDir, flagSocket)
}

// multiFlag collects a repeatable string flag (e.g. -approved-root a -approved-root b).
type multiFlag []string

func (m *multiFlag) String() string {
	if m == nil {
		return ""
	}
	return fmt.Sprint([]string(*m))
}

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
