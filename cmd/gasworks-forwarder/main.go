// Command gasworks-forwarder ships coding-agent transcripts (recall), redacted city
// events (events), and usage facts (usage) to their hosted ingest endpoints. Each
// AXIS — recall, events, usage — has its OWN config and OWN bearer credential: one
// axis's token is never shared with another (axis isolation). The dispatch below
// builds each axis independently so a misconfigured or compromised axis cannot leak
// its peer's credential.
//
// Subcommands:
//
//	recall   run the recall transcript forwarder (RECALL_FORWARDER_* env)
//	events   run the events forwarder (GASWORKS_EVENTS_* env)
//	usage    run the usage forwarder, tailing .gc/usage.jsonl (GASWORKS_USAGE_* env)
//	all      run every axis as independently-restartable goroutines (own config + bearer)
//
// Add --once to run a single scan pass and exit (recall only); default is the daemon
// loop until SIGINT/SIGTERM.
//
// "all" reinstates in-process the isolation the two axes have as separate systemd
// units today: each runs under its own goroutine with a recover() + backoff, so one
// axis panicking — or its source dying — never tears down the other.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/eventsaxis"
	"github.com/gascity/gasworks/internal/recallaxis"
	"github.com/gascity/gasworks/internal/usageaxis"
	"github.com/gascity/gasworks/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	if len(argv) == 0 {
		usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := argv[0], argv[1:]
	switch cmd {
	case "recall":
		return runRecall(ctx, rest)
	case "events":
		return runEvents(ctx, rest)
	case "usage":
		return runUsage(ctx, rest)
	case "all":
		return runAll(ctx, rest)
	case "version", "--version":
		fmt.Fprintln(os.Stdout, "gasworks-forwarder "+version.String())
		return 0
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		eprintf("gasworks-forwarder: unknown command %q", cmd)
		usage()
		return 2
	}
}

// runRecall wires the recall axis from RECALL_FORWARDER_* env. It builds the axis's OWN
// config + bearer (never touching any other axis's credential). With --once it performs
// a single scan pass; otherwise it runs the daemon loop.
func runRecall(ctx context.Context, args []string) int {
	once := false
	for _, a := range args {
		switch a {
		case "--once":
			once = true
		case "-h", "--help":
			eprintln("usage: gasworks-forwarder recall [--once]")
			return 0
		default:
			eprintf("gasworks-forwarder recall: unknown flag %q", a)
			return 2
		}
	}

	cfg, warn := recallaxis.ConfigFromEnv()
	if warn != "" {
		eprintf("gasworks-forwarder: warning: %s", warn)
	}

	// Warn if a custom RECALL_FORWARDER_ROOTS entry is NOT under a known provider home
	// (.claude/.codex/.gemini): it bypasses the narrow per-provider scoping guarantee.
	// scanRoots still refuses to forward files it can't attach a provider to, so such a
	// root is inert — but the operator should know their override won't ship anything.
	for _, r := range recallaxis.NonProviderRoots(cfg.Roots) {
		eprintf("gasworks-forwarder: warning: recall root %q is not under a known provider home (.claude/.codex/.gemini); it bypasses per-provider scoping and nothing under it will be forwarded", r)
	}

	// Validate the destination scheme up front so a plain-http misconfig fails loudly
	// instead of silently idling. An unconfigured (idle) axis is fine — that is the
	// safe default — so only validate when a URL was actually provided.
	if cfg.URL != "" && !recallaxis.URLOK(cfg.URL, cfg.AllowHTTP) {
		eprintln("gasworks-forwarder recall: RECALL_FORWARDER_URL must be https:// (or localhost http with RECALL_FORWARDER_ALLOW_HTTP=1)")
		return 1
	}
	if !cfg.Enabled() {
		eprintln("gasworks-forwarder recall: idle — RECALL_FORWARDER_URL / _SOURCE_ID / token not all set (opt in to enable)")
		if once {
			return 0
		}
		// Daemon with nothing to do: stay up so a later credential rotation can enable
		// it, but the axis never dials while disabled.
	}

	runner := recallaxis.NewRunner(cfg, logf)
	if once {
		st, _ := recallaxis.LoadState(cfg.StatePath)
		stats := runner.ScanOnce(ctx, st)
		if stats.Sent != 0 || stats.Failed != 0 || stats.Skipped != 0 {
			if err := recallaxis.SaveState(cfg.StatePath, st); err != nil {
				logf("recall: state save failed: %v", err)
			}
		}
		logf("recall: scan sent=%d failed=%d skipped=%d", stats.Sent, stats.Failed, stats.Skipped)
		return 0
	}
	if err := runner.Run(ctx); err != nil {
		eprintf("gasworks-forwarder recall: %v", err)
		return 1
	}
	return 0
}

// runEvents wires the events axis from GASWORKS_EVENTS_* env. It builds the axis's
// OWN config + bearer (never touching any other axis's credential) and runs the
// daemon loop. The events axis has no --once mode: it tails a long-lived SSE stream.
func runEvents(ctx context.Context, args []string) int {
	for _, a := range args {
		switch a {
		case "-h", "--help":
			eprintln("usage: gasworks-forwarder events")
			return 0
		default:
			eprintf("gasworks-forwarder events: unknown flag %q", a)
			return 2
		}
	}

	cfg, warn := eventsaxis.ConfigFromEnv()
	if warn != "" {
		eprintf("gasworks-forwarder: warning: %s", warn)
	}

	// Validate the destination scheme up front so a plain-http misconfig fails loudly
	// instead of silently idling — but only when a URL was actually provided (an
	// unconfigured, idle axis is the safe default).
	if cfg.URL != "" && !eventsaxis.URLOK(cfg.URL, cfg.AllowHTTP) {
		eprintln("gasworks-forwarder events: GASWORKS_EVENTS_INGEST_URL must be https:// (or localhost http with GASWORKS_EVENTS_ALLOW_HTTP=1)")
		return 1
	}
	if !cfg.Enabled() {
		eprintln("gasworks-forwarder events: idle — GASWORKS_EVENTS_INGEST_URL / _CITIES / token not all set (opt in to enable)")
	}

	runner := eventsaxis.NewRunner(cfg, logf)
	if err := runner.Run(ctx); err != nil {
		eprintf("gasworks-forwarder events: %v", err)
		return 1
	}
	return 0
}

// runUsage wires the usage axis from GASWORKS_USAGE_* env. It builds the axis's OWN
// config + bearer and tails the gc usage ledger (.gc/usage.jsonl), forwarding model
// facts to usage-ingest. With --once it drains to EOF and exits; otherwise it runs
// the daemon loop.
func runUsage(ctx context.Context, args []string) int {
	once := false
	for _, a := range args {
		switch a {
		case "--once":
			once = true
		case "-h", "--help":
			eprintln("usage: gasworks-forwarder usage [--once]")
			return 0
		default:
			eprintf("gasworks-forwarder usage: unknown flag %q", a)
			return 2
		}
	}

	cfg, warn := usageaxis.ConfigFromEnv()
	if warn != "" {
		eprintf("gasworks-forwarder: warning: %s", warn)
	}

	// Validate the destination scheme up front so a plain-http misconfig fails loudly
	// instead of silently idling — but only when a URL was actually provided.
	if cfg.URL != "" && !usageaxis.URLOK(cfg.URL, cfg.AllowHTTP) {
		eprintln("gasworks-forwarder usage: GASWORKS_USAGE_INGEST_URL must be https:// (or localhost http with GASWORKS_USAGE_ALLOW_HTTP=1)")
		return 1
	}
	if !cfg.Enabled() {
		eprintln("gasworks-forwarder usage: idle — GASWORKS_USAGE_INGEST_URL / _SOURCE_ID / _LEDGER / token not all set (opt in to enable)")
	}

	runner := usageaxis.NewRunner(cfg, logf)
	run := runner.Run
	if once {
		run = runner.RunOnce
	}
	if err := run(ctx); err != nil {
		eprintf("gasworks-forwarder usage: %v", err)
		return 1
	}
	return 0
}

// runAll runs recall AND events concurrently, each in its own goroutine with a
// per-axis recover() + backoff supervisor. This reinstates in-process the isolation
// the two axes have as separate systemd units: one axis panicking, or its source
// dying, restarts only that axis and never tears down its peer. Each axis builds its
// OWN config + bearer inside its goroutine. runAll returns once ctx is cancelled
// (SIGINT/SIGTERM); the worst per-axis exit code is propagated.
func runAll(ctx context.Context, args []string) int {
	// recall accepts --once; events does not. We pass recall's args through and reject
	// anything events can't honor so a typo isn't silently swallowed.
	for _, a := range args {
		switch a {
		case "--once":
			// --once is recall-only; "all" is a daemon, so a single-shot "all" makes no
			// sense (events has no bounded pass). Reject it rather than half-honor it.
			eprintln("gasworks-forwarder all: --once is not supported (events tails a long-lived stream); run 'recall --once' instead")
			return 2
		case "-h", "--help":
			eprintln("usage: gasworks-forwarder all")
			return 0
		default:
			eprintf("gasworks-forwarder all: unknown flag %q", a)
			return 2
		}
	}

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		worst      int
		recordCode = func(code int) {
			mu.Lock()
			if code > worst {
				worst = code
			}
			mu.Unlock()
		}
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		recordCode(superviseAxis(ctx, "recall", func() int { return runRecall(ctx, nil) }))
	}()
	go func() {
		defer wg.Done()
		recordCode(superviseAxis(ctx, "events", func() int { return runEvents(ctx, nil) }))
	}()
	go func() {
		defer wg.Done()
		recordCode(superviseAxis(ctx, "usage", func() int { return runUsage(ctx, nil) }))
	}()
	wg.Wait()
	return worst
}

// superviseAxis runs one axis under a crash-isolating supervisor: it invokes run in
// a recover()-guarded goroutine and, if run panics, logs it and restarts the axis
// after a capped backoff. A normal return (the axis exited because ctx was cancelled,
// or it is idle and returned) ends supervision and propagates the axis's exit code.
// One axis crash-looping never affects its peer — they share nothing but the parent
// ctx. Returns the last code the axis returned (0 if it only ever panicked before
// ctx cancel).
// axisBaseBackoff is the initial restart delay after an axis panic; doubled up to
// axisMaxBackoff. A package var so tests can shrink it (production stays at 1s).
var axisBaseBackoff = time.Second

const axisMaxBackoff = 30 * time.Second

func superviseAxis(ctx context.Context, name string, run func() int) int {
	backoff := axisBaseBackoff
	lastCode := 0
	for ctx.Err() == nil {
		code, panicked := runGuarded(name, run)
		if !panicked {
			return code // clean axis return (ctx-cancel shutdown or idle exit)
		}
		lastCode = code
		if ctx.Err() != nil {
			break
		}
		logf("%s: axis restarting in %s after panic", name, backoff)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return lastCode
		case <-t.C:
		}
		backoff *= 2
		if backoff > axisMaxBackoff {
			backoff = axisMaxBackoff
		}
	}
	return lastCode
}

// runGuarded invokes run, converting a panic into (code=1, panicked=true) and
// logging it (never the panic value verbatim to a credential channel — logf goes to
// stderr only). A clean return yields (code, panicked=false).
func runGuarded(name string, run func() int) (code int, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			logf("%s: axis panicked: %v", name, r)
			code, panicked = 1, true
		}
	}()
	return run(), false
}

// logf is the structured logger handed to the axis. It MUST never be called with a
// token value; the axis upholds that contract.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[gasworks-forwarder] "+format+"\n", args...)
}

func eprintf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
func eprintln(s string)                  { fmt.Fprintln(os.Stderr, s) }

func usage() {
	const u = `gasworks-forwarder: ship coding-agent transcripts (recall), redacted city events (events), and usage facts (usage) to hosted ingest.

Usage:
  gasworks-forwarder recall [--once]   run the recall transcript forwarder
  gasworks-forwarder events            run the events forwarder (tails the supervisor SSE)
  gasworks-forwarder usage  [--once]   run the usage forwarder (tails .gc/usage.jsonl)
  gasworks-forwarder all               run every axis (own goroutine + recover + backoff)

Each axis has its OWN config + bearer credential (axis isolation): one axis's token is
never usable by another. recall is configured via RECALL_FORWARDER_* env; events via
GASWORKS_EVENTS_* env; usage via GASWORKS_USAGE_* env (see the package docs).`
	fmt.Fprintln(os.Stderr, u)
}
