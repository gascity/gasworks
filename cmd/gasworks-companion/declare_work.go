//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
)

// runDeclareWork appends one DECLARED work reference to the explicit run inherited from
// gasworks-companion run. It intentionally has no run-id flag: callers may extend only their
// current wrapper-authored boundary, never name an arbitrary run.
func runDeclareWork(args []string) int {
	fs := flag.NewFlagSet("declare-work", flag.ContinueOnError)
	dir := fs.String("dir", "", "observer state directory (to locate the daemon socket)")
	socket := fs.String("socket", "", "daemon Unix socket path; default <dir>/socket")
	beadsProject := fs.String("beads-project", "", "beads team-server project id (required)")
	workItem := fs.String("work-item", "", "work item bead id (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*beadsProject) == "" || strings.TrimSpace(*workItem) == "" {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work: -beads-project and -work-item are required")
		return 2
	}
	runID := strings.TrimSpace(os.Getenv(runwrap.RunIDEnvVar))
	if runID == "" {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work: no current explicit run")
		return 1
	}

	stateDir, err := observerDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work:", err)
		return 1
	}
	socketPath, err := observerSocketPath(*socket, stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work:", err)
		return 2
	}
	obs, err := runwrap.NewDeclaredWorkReference(
		runID,
		strings.TrimSpace(*beadsProject),
		strings.TrimSpace(*workItem),
		time.Now().UTC(),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work:", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), local.DefaultClientTimeout)
	defer cancel()
	if _, err := local.NewClient(socketPath).AppendObservation(ctx, obs); err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion declare-work:", err)
		return 1
	}
	return 0
}
