//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
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
	dir := fs.String("dir", "", "observer durable state directory; default XDG state dir")
	socket := fs.String("socket", "", "owner-only Unix socket path; default <dir>/socket")
	sourceID := fs.String("source-id", "", "durable spool source id (required)")
	workspace := fs.String("workspace", "", "registry workspace scope")
	ceiling := fs.Int64("ceiling-bytes", defaultCeilingBytes, "spool byte ceiling")

	collector := fs.String("collector", "", "Collector base URL; enables the uploader")
	tokenFile := fs.String("token-file", "", "bearer token file (rotating), required with -collector")
	allowLoopbackHTTP := fs.Bool("allow-loopback-http", false, "permit a plain-http loopback collector (dev only)")
	// Content upload (Phase 1b) is opt-in and OFF by default: with it off the daemon is metadata-only,
	// exactly as before. It reuses the -collector base + -token-file credential (no second endpoint or
	// credential) and requires an explicitly configured watcher. OBSERVER_CONTENT_UPLOAD=1 sets the default.
	contentUpload := fs.Bool("content-upload", envTrue("OBSERVER_CONTENT_UPLOAD"), "upload whole raw transcripts to the collector content endpoint (opt-in; requires -collector and an explicit root policy/root)")

	var approvedRoots multiFlag
	fs.Var(&approvedRoots, "approved-root", "an approved transcript root (repeatable); enables the watcher")
	rootPolicyFile := fs.String("root-policy", "", "owner-supplied companion transcript root policy (mutually exclusive with -approved-root)")
	cursorDir := fs.String("cursor-dir", "", "transcript cursor state dir (required with -approved-root)")
	// The watcher re-walks and stats every file under the approved roots on each poll (change
	// detection is a bounded poll, not fsnotify), so its steady-state CPU is O(files under the roots)
	// × poll frequency — independent of how many files match the transcript filter. On a host with
	// tens of thousands of transcripts, the default 500ms cadence pins a core; this flag trades tail
	// latency for CPU. 0 keeps the watcher default.
	pollInterval := fs.Duration("poll-interval", 0, "transcript watcher poll cadence (e.g. 2s); 0 uses the watcher default")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sourceID == "" {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -source-id is required")
		return 2
	}
	if *rootPolicyFile != "" && len(approvedRoots) > 0 {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -root-policy and -approved-root are mutually exclusive")
		return 2
	}
	var policyRecords []rootpolicy.Record
	if *rootPolicyFile != "" {
		var err error
		policyRecords, err = rootpolicy.Load(*rootPolicyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
			return 2
		}
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -cursor-dir is required with -root-policy")
			return 2
		}
	}
	stateDir, err := observerDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
		return 1
	}
	socketPath, err := observerSocketPath(*socket, stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
		return 2
	}

	cfg := daemon.ServiceConfig{
		Dir:               stateDir,
		SocketPath:        socketPath,
		SourceID:          *sourceID,
		Capacity:          defaultCapacity(*ceiling),
		RegistrySource:    *sourceID,
		RegistryWorkspace: *workspace,
		Log:               func(s string) { fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", s) },
	}

	if *collector != "" {
		client, err := buildCollectorClient(*collector, *sourceID, *tokenFile, *allowLoopbackHTTP)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
			return 2
		}
		cfg.Upload = &daemon.UploadLoopConfig{Sender: client}
		if *contentUpload {
			if len(approvedRoots) == 0 && len(policyRecords) == 0 {
				fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -content-upload requires -approved-root or -root-policy; running metadata-only")
			} else {
				// Reuse the SAME collector client (base URL + source-bound bearer) for content upload.
				cfg.ContentUpload = &daemon.ContentUploadLoopConfig{Sender: client}
			}
		}
	} else if *contentUpload {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -content-upload requires -collector; running metadata-only")
	}
	if *rootPolicyFile != "" {
		cfg.Watch = newPolicyWatchLoopConfig(policyRecords, *cursorDir, *pollInterval)
	} else if len(approvedRoots) > 0 {
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -cursor-dir is required with -approved-root")
			return 2
		}
		cfg.Watch = newWatchLoopConfig(approvedRoots, *cursorDir, *pollInterval)
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

// buildCollectorClient constructs the authenticated collector client from the endpoint and a
// rotating token file. The credential is read fresh per attempt by the E1.9 client. The same client
// serves both the observation-batch uploader and the whole-transcript content side channel, so
// content upload never introduces a second endpoint or credential.
func buildCollectorClient(endpoint, sourceID, tokenFile string, allowLoopbackHTTP bool) (*upload.Client, error) {
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
	return client, nil
}

// envTrue reports whether an environment variable is set to a truthy value (1/true/yes/on), used to
// derive a flag's default from the environment.
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// newWatchLoopConfig builds the transcript watcher config from the approved roots, the durable
// cursor directory, and the poll cadence. It always installs transcriptNameMatch so the watcher only
// ever PARSES real session transcripts and never turns the non-transcript sidecars (tool-results,
// meta, source files) that share the roots into observations — the filter that stops the diagnostic
// flood. interval<=0 leaves the watcher default cadence.
//
// Note the filter bounds what is parsed, not what is walked: the poll still re-walks and stats the
// whole tree to detect changes and to keep a renamed-past-filter file tracked, so steady-state poll
// CPU scales with total files under the roots. poll-interval is the lever for that cost.
func newWatchLoopConfig(roots []string, cursorDir string, interval time.Duration) *daemon.WatchLoopConfig {
	return &daemon.WatchLoopConfig{
		ApprovedRoots: roots,
		StateDir:      cursorDir,
		Policy:        watcherPolicy(),
		Match:         transcriptNameMatch,
		Interval:      interval,
	}
}

// newPolicyWatchLoopConfig keeps companion consent records intact until the watcher, where the
// generation fence and root-local baseline are applied. It intentionally does not infer any
// provider home/root; every path arrived explicitly in the owner policy.
func newPolicyWatchLoopConfig(records []rootpolicy.Record, cursorDir string, interval time.Duration) *daemon.WatchLoopConfig {
	return &daemon.WatchLoopConfig{
		RootPolicies: records,
		StateDir:     cursorDir,
		Policy:       watcherPolicy(),
		Match:        transcriptNameMatch,
		Interval:     interval,
	}
}

// transcriptNameMatch reports whether a regular-file basename under an approved root is a real
// session transcript the watcher should tail. Both providers write their transcripts as JSON Lines
// and NOTHING else under their roots is .jsonl: a Claude session is <uuid>.jsonl under
// ~/.claude/projects and a Codex rollout is rollout-*.jsonl under ~/.codex/sessions, while every
// non-transcript sidecar is a different extension — tool-results *.txt, *.meta.json /
// sessions-index.json, source *.js, *.md, *.pdf. Matching on the .jsonl suffix is therefore the
// exact, provider-agnostic predicate: it admits every real transcript under either root and refuses
// all the junk that otherwise floods capture with "malformed transcript line" diagnostics, sets
// has_partial_capture on real runs, and burns a core polling tens of thousands of files. The
// watcher passes the basename only (a rooted glob is not available at this seam), so the predicate
// is deliberately name-based.
func transcriptNameMatch(name string) bool {
	return strings.HasSuffix(name, ".jsonl")
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
