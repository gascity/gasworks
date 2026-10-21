//go:build linux || darwin

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
)

// runContentReupload is the one-shot, paced content re-upload (daemon.RunContentReupload): it
// re-sends the transcripts whose markers predate a cutoff and/or name a listed native session id,
// through the same collector client and credential the daemon uses, and prints a counts-only JSON
// report. -dry-run reads no content and sends nothing.
func runContentReupload(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("content-reupload", flag.ContinueOnError)
	cursorDir := fs.String("cursor-dir", "", "the producer's transcript cursor dir, which holds its content markers (required)")
	var roots multiFlag
	fs.Var(&roots, "approved-root", "a transcript root the producer watches (repeatable; required)")
	collector := fs.String("collector", "", "Collector base URL (required unless -dry-run)")
	sourceID := fs.String("source-id", "", "the producer's observer source id (required unless -dry-run)")
	tokenFile := fs.String("token-file", "", "the producer's bearer token file (required unless -dry-run)")
	allowLoopbackHTTP := fs.Bool("allow-loopback-http", false, "permit a plain-http loopback collector (dev only)")
	var caFiles multiFlag
	fs.Var(&caFiles, "ca-file", "additive collector-TLS CA bundle PEM file (repeatable)")
	before := fs.String("before", daemon.ContentReuploadCutover.Format(time.RFC3339), `re-send markers uploaded before this RFC 3339 time; "none" disables (the default applies unless -ids-file is given alone)`)
	idsFile := fs.String("ids-file", "", "file of native session ids to re-send, one per line (# comments)")
	provider := fs.String("provider", "", "restrict to one provider: claude or codex")
	progressFile := fs.String("progress-file", "", "append-only progress journal; a rerun skips what it records (required unless -dry-run)")
	interval := fs.Duration("interval", daemon.DefaultReuploadInterval, "pause between uploads (the rate limit)")
	limit := fs.Int("limit", 0, "stop after this many uploads (0 = all)")
	maxFailures := fs.Int("max-consecutive-failures", daemon.DefaultReuploadMaxConsecutiveFailures, "stop after this many consecutive failed uploads")
	dryRun := fs.Bool("dry-run", false, "select and locate only; print counts, read no content, send nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usageErr := func(msg string) int {
		fmt.Fprintln(os.Stderr, "gasworks-companion content-reupload:", msg)
		return 2
	}
	if *cursorDir == "" || len(roots) == 0 {
		return usageErr("-cursor-dir and at least one -approved-root are required")
	}
	if *provider != "" && *provider != "claude" && *provider != "codex" {
		return usageErr("-provider must be claude or codex")
	}
	if *interval <= 0 {
		return usageErr("-interval must be positive")
	}
	beforeSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "before" {
			beforeSet = true
		}
	})
	cfg := daemon.ReuploadConfig{
		StateDir:               *cursorDir,
		Roots:                  roots,
		Provider:               *provider,
		ProgressFile:           *progressFile,
		Interval:               *interval,
		Limit:                  *limit,
		MaxConsecutiveFailures: *maxFailures,
		DryRun:                 *dryRun,
		Log:                    func(s string) { fmt.Fprintln(os.Stderr, "gasworks-companion", s) },
	}
	if *idsFile != "" {
		ids, err := readIDsFile(*idsFile)
		if err != nil {
			return usageErr(err.Error())
		}
		cfg.IDs = ids
	}
	// An id list alone re-sends exactly those ids; the default cutoff applies only without one.
	if *before != "none" && (beforeSet || *idsFile == "") {
		t, err := time.Parse(time.RFC3339, *before)
		if err != nil {
			return usageErr("-before: " + err.Error())
		}
		cfg.Before = t
	}
	if !*dryRun {
		if *collector == "" || *sourceID == "" || *progressFile == "" {
			return usageErr("-collector, -source-id, -token-file and -progress-file are required unless -dry-run")
		}
		client, err := buildCollectorClient(*collector, *sourceID, *tokenFile, *allowLoopbackHTTP, caFiles)
		if err != nil {
			return usageErr(err.Error())
		}
		cfg.Sender = client
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rep, runErr := daemon.RunContentReupload(ctx, cfg)
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Fprintln(stdout, string(out))
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion content-reupload:", runErr)
		if errors.Is(runErr, context.Canceled) {
			return 130
		}
		return 1
	}
	return 0
}

// readIDsFile reads one native session id per line; blank lines and # comments are skipped.
func readIDsFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("-ids-file: %w", err)
	}
	defer f.Close()
	ids := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("-ids-file: %w", err)
	}
	if len(ids) == 0 {
		return nil, errors.New("-ids-file lists no ids")
	}
	return ids, nil
}
