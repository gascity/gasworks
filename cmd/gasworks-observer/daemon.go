//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// defaultCeilingBytes is the default spool byte ceiling (1 GiB) when unset. It must comfortably
// exceed one max segment plus scratch so the capacity model has usable headroom.
const defaultCeilingBytes int64 = 1 << 30

// runDaemon builds and runs the assembled endpoint until it receives SIGINT/SIGTERM, then drains
// gracefully. The uploader is enabled by -collector; the watcher is enabled by -approved-root.
func runDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	dir := fs.String("dir", "", "observer state directory (socket + WAL); default XDG state dir")
	sourceID := fs.String("source-id", "", "durable spool source id (required)")
	workspace := fs.String("workspace", "", "registry workspace scope")
	ceiling := fs.Int64("ceiling-bytes", defaultCeilingBytes, "spool byte ceiling")

	collector := fs.String("collector", "", "Collector base URL; enables the uploader")
	tokenFile := fs.String("token-file", "", "bearer token file (rotating), required with -collector")
	allowLoopbackHTTP := fs.Bool("allow-loopback-http", false, "permit a plain-http loopback collector (dev only)")

	var approvedRoots multiFlag
	fs.Var(&approvedRoots, "approved-root", "an approved transcript root (repeatable); enables the watcher")
	cursorDir := fs.String("cursor-dir", "", "transcript cursor state dir (required with -approved-root)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sourceID == "" {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -source-id is required")
		return 2
	}
	stateDir, err := observerDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
		return 1
	}

	cfg := daemon.ServiceConfig{
		Dir:               stateDir,
		SourceID:          *sourceID,
		Capacity:          defaultCapacity(*ceiling),
		RegistrySource:    *sourceID,
		RegistryWorkspace: *workspace,
		Log:               func(s string) { fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", s) },
	}

	if *collector != "" {
		up, err := buildUploadConfig(*collector, *sourceID, *tokenFile, *allowLoopbackHTTP)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
			return 2
		}
		cfg.Upload = up
	}
	if len(approvedRoots) > 0 {
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -cursor-dir is required with -approved-root")
			return 2
		}
		cfg.Watch = &daemon.WatchLoopConfig{
			ApprovedRoots: approvedRoots,
			StateDir:      *cursorDir,
			Policy:        watcherPolicy(),
		}
	}

	svc, err := daemon.NewService(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "gasworks-observer daemon: serving at %s\n", svc.SocketPath())
	if err := svc.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
		return 1
	}
	return 0
}

// buildUploadConfig constructs the uploader loop config from the collector endpoint and a rotating
// token file. The credential is read fresh per attempt by the E1.9 client.
func buildUploadConfig(endpoint, sourceID, tokenFile string, allowLoopbackHTTP bool) (*daemon.UploadLoopConfig, error) {
	if tokenFile == "" {
		return nil, fmt.Errorf("-token-file is required with -collector")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse -collector: %w", err)
	}
	client, err := upload.NewClient(upload.Config{
		Endpoint:          u,
		SourceID:          sourceID,
		Credential:        upload.TokenFileSource{Path: tokenFile},
		AllowLoopbackHTTP: allowLoopbackHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("build collector client: %w", err)
	}
	return &daemon.UploadLoopConfig{Sender: client}, nil
}

// watcherPolicy is the daemon-constant METADATA_ONLY transform policy every parsed candidate is
// stripped through before it becomes a durable observation.
func watcherPolicy() evidence.Policy {
	return evidence.Policy{
		Adapter:        codex.AdapterName,
		AdapterVersion: codex.AdapterVersion,
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
}

// defaultCapacity derives a spool capacity config from a byte ceiling, leaving the reserve/scratch
// geometry at conservative defaults the capacity model validates.
func defaultCapacity(ceiling int64) spool.CapacityConfig {
	if ceiling <= 0 {
		ceiling = defaultCeilingBytes
	}
	return spool.CapacityConfig{
		CeilingBytes:         ceiling,
		TerminalReserveBytes: 1 << 20,
		MaxSegmentBytes:      spool.DefaultSegmentCeiling,
		ScratchBytes:         1 << 20,
		SafetyMarginRatio:    spool.MinSafetyMarginRatio,
	}
}
