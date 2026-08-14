//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
)

// runHook is the `hook codex` handler: it decodes a Codex SessionStart event from stdin, resolves
// the session's run attachment through the daemon seam, and durably captures a SESSION_LIFECYCLE
// observation — writing a bounded, content-free systemMessage to stdout on any capture failure so
// Codex startup is never stalled. The 2s hook budget is enforced inside codex.Run.
func runHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "gasworks-companion hook: expected a provider (codex)")
		return 2
	}
	if args[0] != "codex" {
		fmt.Fprintf(os.Stderr, "gasworks-companion hook: unsupported provider %q (want: codex)\n", args[0])
		return 2
	}

	fs := flag.NewFlagSet("hook codex", flag.ContinueOnError)
	dir := fs.String("dir", "", "observer state directory (to locate the daemon socket)")
	socket := fs.String("socket", "", "daemon Unix socket path; default <dir>/socket")
	sourceID := fs.String("source-id", "", "observer source id")
	var approvedRoots multiFlag
	fs.Var(&approvedRoots, "approved-root", "an approved transcript root (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	stateDir, err := observerDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion hook:", err)
		return 1
	}
	socketPath, err := observerSocketPath(*socket, stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion hook:", err)
		return 2
	}

	// Bound the socket round-trip to the same 2s hook budget so a stalled or unreachable daemon can
	// never outlast the hook's hard deadline.
	client := local.NewClient(socketPath, local.WithTimeout(codex.DefaultHookTimeout))
	seam := daemon.NewDaemonSeamAdapter(client)

	cfg := codex.HookConfig{
		SourceID:       *sourceID,
		ApprovedRoots:  approvedRoots,
		InheritedRunID: os.Getenv(runwrap.RunIDEnvVar),
	}

	if err := codex.Run(context.Background(), seam, cfg, os.Stdin, os.Stdout); err != nil {
		// A returned error is reserved for a stdout write failure; every capture/decode problem is
		// already handled inside codex.Run by emitting the content-free response.
		fmt.Fprintln(os.Stderr, "gasworks-companion hook:", err)
		return 1
	}
	return 0
}
