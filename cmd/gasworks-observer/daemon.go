//go:build linux || darwin

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	// -ca-file adds additive TLS trust anchors for the collector (a customer/enterprise CA or an
	// intercepting egress proxy's CA). Repeatable. Anchors are MERGED on top of the system roots
	// (upload.buildTLSConfig) — TLS verification stays on; these only widen trust, never disable it.
	var caFiles multiFlag
	fs.Var(&caFiles, "ca-file", "additive collector-TLS CA bundle PEM file (repeatable); merged on top of the system roots")
	// Content upload (Phase 1b) is opt-in and OFF by default: with it off the daemon is metadata-only,
	// exactly as before. It reuses the -collector base + -token-file credential (no second endpoint or
	// credential) and requires an explicitly configured watcher. OBSERVER_CONTENT_UPLOAD=1 sets the default.
	contentUpload := fs.Bool("content-upload", envTrue("OBSERVER_CONTENT_UPLOAD"), "upload whole raw transcripts to the collector content endpoint (opt-in; requires -collector and an explicit root policy/root)")

	var approvedRoots multiFlag
	fs.Var(&approvedRoots, "approved-root", "an approved transcript root (repeatable); enables the watcher")
	rootPolicyFile := fs.String("root-policy-file", "", "owner-supplied companion transcript root policy (mutually exclusive with -approved-root)")
	cursorDir := fs.String("cursor-dir", "", "transcript cursor state dir (required with -approved-root)")
	// The watcher re-walks and stats every file under the approved roots on each poll (change
	// detection is a bounded poll, not fsnotify), so its steady-state CPU is O(files under the roots)
	// × poll frequency — independent of how many files match the transcript filter. On a host with
	// tens of thousands of transcripts, the default 500ms cadence pins a core; this flag trades tail
	// latency for CPU. 0 keeps the watcher default.
	pollInterval := fs.Duration("poll-interval", 0, "transcript watcher poll cadence (e.g. 2s); 0 uses the watcher default")

	// -bead-prefix enables PASSIVE work-reference extraction: a session that runs bd/git/gh with a
	// bead id carrying one of these prefixes links that run to the bead with no per-session action.
	// Prefixes are matched verbatim and must include the trailing dash (e.g. bd-). Repeatable; an
	// empty set leaves extraction off (the daemon stays metadata-only for beads, as before).
	var beadPrefixes multiFlag
	fs.Var(&beadPrefixes, "bead-prefix", "bead id prefix to extract as a work reference from bd/git/gh tool calls (repeatable; include the trailing dash, e.g. bd-)")
	// -beads-project is the team-server project id every extracted bead reference resolves to — the
	// same project identity the wrapper's declare-work verb takes. Required whenever -bead-prefix is
	// set: the captured bead id is opaque, so the project is supplied here, not parsed out of the id.
	beadsProject := fs.String("beads-project", "", "team-server project id that extracted bead references resolve to (required with -bead-prefix)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sourceID == "" {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -source-id is required")
		return 2
	}
	if *rootPolicyFile != "" && len(approvedRoots) > 0 {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -root-policy-file and -approved-root are mutually exclusive")
		return 2
	}
	// Fail loud on a half-configured extractor: -bead-prefix without -beads-project would resolve
	// every captured reference to no project and drop it as unresolvable (a silent INFO diagnostic),
	// so the linkage would appear wired but produce nothing. -beads-project alone is a harmless no-op
	// (no prefixes ⇒ no extraction), matching declare-work's independent use of the same project id.
	if len(beadPrefixes) > 0 && *beadsProject == "" {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -bead-prefix requires -beads-project (the team-server project extracted references resolve to)")
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
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -cursor-dir is required with -root-policy-file")
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
		client, err := buildCollectorClient(*collector, *sourceID, *tokenFile, *allowLoopbackHTTP, caFiles)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon:", err)
			return 2
		}
		cfg.Upload = &daemon.UploadLoopConfig{Sender: client}
		if *contentUpload {
			if len(approvedRoots) == 0 && len(policyRecords) == 0 {
				fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -content-upload requires -approved-root or -root-policy-file; running metadata-only")
			} else {
				// Reuse the SAME collector client (base URL + source-bound bearer) for content upload.
				cfg.ContentUpload = &daemon.ContentUploadLoopConfig{Sender: client}
			}
		}
	} else if *contentUpload {
		fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -content-upload requires -collector; running metadata-only")
	}
	// Build the extraction configuration once and hand the same value to whichever watcher config is
	// selected. Empty prefixes yield a nil bead pattern downstream (extraction off); a non-empty set
	// carries the default-project resolver validated above.
	references := newReferenceConfig(beadPrefixes, *beadsProject)
	if *rootPolicyFile != "" {
		cfg.Watch = newPolicyWatchLoopConfig(policyRecords, *cursorDir, *pollInterval, references)
	} else if len(approvedRoots) > 0 {
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-observer daemon: -cursor-dir is required with -approved-root")
			return 2
		}
		cfg.Watch = newWatchLoopConfig(approvedRoots, *cursorDir, *pollInterval, references)
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
func buildCollectorClient(endpoint, sourceID, tokenFile string, allowLoopbackHTTP bool, caFiles []string) (*upload.Client, error) {
	if tokenFile == "" {
		return nil, fmt.Errorf("-token-file is required with -collector")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse -collector: %w", err)
	}
	customCAs, err := loadCAFiles(caFiles)
	if err != nil {
		return nil, err
	}
	client, err := upload.NewClient(upload.Config{
		Endpoint:          u,
		SourceID:          sourceID,
		Credential:        upload.TokenFileSource{Path: tokenFile},
		CustomCAs:         customCAs,
		AllowLoopbackHTTP: allowLoopbackHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("build collector client: %w", err)
	}
	return client, nil
}

// loadCAFiles parses each -ca-file PEM bundle into additive x509 trust anchors for the collector
// client. It FAILS CLOSED: a path the operator passed that is missing, unreadable, or that yields
// no certificate is an error, never a silent fallback to system-only trust — the operator's intent
// to trust a specific CA must not be dropped (that would connect to an unintended endpoint or fail
// opaquely). The anchors are additive: upload.buildTLSConfig merges them on top of the system roots
// and keeps verification on. An empty list yields no anchors (system trust only), no error.
func loadCAFiles(paths []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read -ca-file %q: %w", p, err)
		}
		fileCerts, err := parseCAPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse -ca-file %q: %w", p, err)
		}
		if len(fileCerts) == 0 {
			return nil, fmt.Errorf("-ca-file %q contained no certificates", p)
		}
		certs = append(certs, fileCerts...)
	}
	return certs, nil
}

// parseCAPEM decodes every CERTIFICATE block in a PEM bundle. A non-certificate block (e.g. a stray
// private key) is skipped so a combined bundle is tolerated; a malformed certificate block is a hard
// error so a truncated or corrupt bundle never yields partial, silently-narrowed trust.
func parseCAPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
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
func newWatchLoopConfig(roots []string, cursorDir string, interval time.Duration, references codex.ReferenceConfig) *daemon.WatchLoopConfig {
	return &daemon.WatchLoopConfig{
		ApprovedRoots: roots,
		StateDir:      cursorDir,
		References:    references,
		Policy:        watcherPolicy(),
		Match:         transcriptNameMatch,
		Interval:      interval,
	}
}

// newPolicyWatchLoopConfig keeps companion consent records intact until the watcher, where the
// generation fence and root-local baseline are applied. It intentionally does not infer any
// provider home/root; every path arrived explicitly in the owner policy.
func newPolicyWatchLoopConfig(records []rootpolicy.Record, cursorDir string, interval time.Duration, references codex.ReferenceConfig) *daemon.WatchLoopConfig {
	return &daemon.WatchLoopConfig{
		RootPolicies: records,
		StateDir:     cursorDir,
		References:   references,
		Policy:       watcherPolicy(),
		Match:        transcriptNameMatch,
		Interval:     interval,
	}
}

// newReferenceConfig builds the passive-extraction configuration from the -bead-prefix set and the
// -beads-project default project. The prefixes select which bead identifiers to capture from bd/git/gh
// tool calls; the resolver supplies the team_server_project_id every captured reference resolves to.
// DistinctRefs is left nil (no caller-owned cross-observation cap). An empty prefix set yields a config
// whose bead pattern is nil downstream — extraction stays off, exactly as before this flag existed.
func newReferenceConfig(beadPrefixes []string, beadsProject string) codex.ReferenceConfig {
	return codex.ReferenceConfig{
		BeadPrefixes: beadPrefixes,
		Resolver:     evidence.ProjectResolver{DefaultProjectID: beadsProject},
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
