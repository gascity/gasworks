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
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/prefixmap"
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
	// With -root-policy-file the flag is only the starting point: a v3 policy states content consent
	// itself, and the daemon follows the policy file live.
	contentUpload := fs.Bool("content-upload", envTrue("OBSERVER_CONTENT_UPLOAD"), "upload whole raw transcripts to the collector content endpoint (opt-in; requires -collector and an explicit root policy/root); with -root-policy-file a v3 policy's content_upload decides instead, live")

	var approvedRoots multiFlag
	fs.Var(&approvedRoots, "approved-root", "an approved transcript root (repeatable); enables the watcher")
	// -root-policy-file is the live consent policy: the daemon re-reads it before every content
	// upload, every observation batch, and every transcript poll, so a consent change written to it
	// (atomically: temp file + rename) applies without a restart.
	rootPolicyFile := fs.String("root-policy-file", "", "owner-supplied companion transcript root policy, re-read while the daemon runs so consent changes apply without a restart (mutually exclusive with -approved-root)")
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
	// -bead-prefix-map-file is the multi-project form: a JSON array of {prefix, project_id} (bd writes
	// it from the team server's project list). Every listed prefix is captured and each captured id
	// resolves to the project of its longest matching prefix, so cross-project references survive.
	// The file is re-read when it changes (polled at the watcher cadence), so a new project is picked
	// up without a restart. A missing or invalid file never stops the daemon (bead capture idles,
	// logged, until bd writes a valid one). Mutually exclusive with the single-project
	// -bead-prefix/-beads-project.
	beadPrefixMapFile := fs.String("bead-prefix-map-file", "", "multi-project bead prefix map: JSON array of {prefix, project_id}, hot-reloaded on change (mutually exclusive with -bead-prefix/-beads-project)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sourceID == "" {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -source-id is required")
		return 2
	}
	if *rootPolicyFile != "" && len(approvedRoots) > 0 {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -root-policy-file and -approved-root are mutually exclusive")
		return 2
	}
	// Fail loud on a half-configured extractor: -bead-prefix without -beads-project would resolve
	// every captured reference to no project and drop it as unresolvable (a silent INFO diagnostic),
	// so the linkage would appear wired but produce nothing. -beads-project alone is a harmless no-op
	// (no prefixes ⇒ no extraction), matching declare-work's independent use of the same project id.
	if len(beadPrefixes) > 0 && *beadsProject == "" {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -bead-prefix requires -beads-project (the team-server project extracted references resolve to)")
		return 2
	}
	if *beadPrefixMapFile != "" && (len(beadPrefixes) > 0 || *beadsProject != "") {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -bead-prefix-map-file is mutually exclusive with -bead-prefix/-beads-project")
		return 2
	}
	logf := func(s string) { fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", s) }
	var policySource *consent.Source
	if *rootPolicyFile != "" {
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -cursor-dir is required with -root-policy-file")
			return 2
		}
		var err error
		policySource, err = openConsentPolicy(*rootPolicyFile, *contentUpload, logf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
			return 2
		}
	}
	stateDir, err := observerDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
		return 1
	}
	socketPath, err := observerSocketPath(*socket, stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
		return 2
	}

	cfg := daemon.ServiceConfig{
		Dir:               stateDir,
		SocketPath:        socketPath,
		SourceID:          *sourceID,
		Capacity:          defaultCapacity(*ceiling),
		RegistrySource:    *sourceID,
		RegistryWorkspace: *workspace,
		Log:               logf,
	}

	if *collector != "" {
		client, err := buildCollectorClient(*collector, *sourceID, *tokenFile, *allowLoopbackHTTP, caFiles)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
			return 2
		}
		cfg.Upload = &daemon.UploadLoopConfig{Sender: client}
		switch {
		case policySource != nil:
			// Under the live policy the content channel is always wired, reusing the SAME collector
			// client (base URL + source-bound bearer); the policy decides, before every upload,
			// whether anything is sent.
			cfg.ContentUpload = newContentUploadLoopConfig(client, *tokenFile)
		case *contentUpload && len(approvedRoots) == 0:
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -content-upload requires -approved-root or -root-policy-file; running metadata-only")
		case *contentUpload:
			// Reuse the SAME collector client (base URL + source-bound bearer) for content upload.
			cfg.ContentUpload = newContentUploadLoopConfig(client, *tokenFile)
		}
	} else if *contentUpload && policySource == nil {
		// Under the live policy the daemon itself reports a content grant it cannot act on.
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -content-upload requires -collector; running metadata-only")
	}
	// Build the extraction configuration once and hand the same value to whichever watcher config is
	// selected. Empty prefixes yield a nil bead pattern downstream (extraction off); a non-empty set
	// carries the default-project resolver validated above.
	references := newReferenceConfig(beadPrefixes, *beadsProject)
	if *beadPrefixMapFile != "" {
		prefixMap, err := openPrefixMap(*beadPrefixMapFile, *pollInterval, cfg.Log)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
			return 2
		}
		references.PrefixMap = prefixMap
	}
	if policySource != nil {
		// The watcher's roots come from the live policy, applied before every poll: a policy with no
		// capturable root (only project roots, until the membership engine lands) leaves capture idle
		// until it consents to one.
		cfg.Consent = policySource
		cfg.Watch = newConsentWatchLoopConfig(*cursorDir, *pollInterval, references)
	} else if len(approvedRoots) > 0 {
		if *cursorDir == "" {
			fmt.Fprintln(os.Stderr, "gasworks-companion daemon: -cursor-dir is required with -approved-root")
			return 2
		}
		cfg.Watch = newWatchLoopConfig(approvedRoots, *cursorDir, *pollInterval, references)
	}

	svc, err := daemon.NewService(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
		return 1
	}
	// A live policy decides content consent itself (and the daemon applies it); otherwise the
	// -content-upload flag is the consent.
	discardWithdrawnContent(policySource != nil || *contentUpload, cfg.Watch, logf)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "gasworks-companion daemon: serving at %s\n", svc.SocketPath())
	if err := svc.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "gasworks-companion daemon:", err)
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

// newContentUploadLoopConfig wires the whole-transcript content channel over the shared collector
// client. It follows the client's -token-file, so while the collector refuses content upload a
// renewed credential is retried at once rather than after the back-off.
func newContentUploadLoopConfig(client *upload.Client, tokenFile string) *daemon.ContentUploadLoopConfig {
	return &daemon.ContentUploadLoopConfig{Sender: client, TokenFile: tokenFile}
}

// discardWithdrawnContent drops the content an earlier run queued for upload and never had accepted
// when this run has no content consent. Switching content upload off withdraws consent for that
// queue, so a later run that uploads content again must not send it. A run that has consent — or
// that cannot upload for want of a -collector, which withdraws nothing — keeps it.
func discardWithdrawnContent(contentConsented bool, watch *daemon.WatchLoopConfig, log func(string)) {
	if contentConsented || watch == nil {
		return
	}
	n, err := daemon.DiscardQueuedContent(watch.StateDir)
	if err != nil {
		log(fmt.Sprintf("content upload is off: discard the content an earlier run queued: %v", err))
		return
	}
	if n > 0 {
		log(fmt.Sprintf("content upload is off: discarded the queued content of %d transcripts an earlier run had not sent", n))
	}
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

// captureProjectRoots gates capture for kind=project roots. A project root's path is the owner's
// PROJECT folder, not a transcript directory: its sessions live in the policy's recorded stores and
// are selected by the C2-prime membership engine, which has not landed yet. Until it does, project
// roots are parsed, validated, and carried in the policy but never reach the watcher — walking a
// project folder would capture arbitrary user files. Flipping this to true is the membership
// engine's job, together with the store-side session selection.
const captureProjectRoots = false

// capturableRecord reports whether the watcher may see a record yet. It is a silent filter by
// design: a project root is a valid, accepted registration, not a fault, so it earns no per-poll
// diagnostic.
func capturableRecord(r rootpolicy.Record) bool {
	return captureProjectRoots || !r.IsProject()
}

// openConsentPolicy opens the live consent policy: the root policy file, re-read while the daemon
// runs. contentDefault is the -content-upload flag (default OBSERVER_CONTENT_UPLOAD); it decides
// content upload only for a v1/v2 document, which states no content consent, while a v3 document's
// content_upload always decides. Records the watcher cannot act on yet are filtered out.
func openConsentPolicy(path string, contentDefault bool, log func(string)) (*consent.Source, error) {
	return consent.Open(consent.Config{Path: path, ContentDefault: contentDefault, Capturable: capturableRecord, Log: log})
}

// newConsentWatchLoopConfig is the watcher configuration under the live consent policy: everything
// but the roots, which the daemon takes from the policy (and keeps taking from it) with their
// explicit per-root consent records — generation, mode, tombstones — intact, so the generation
// fence and root-local baseline apply in the watcher. It intentionally does not infer any provider
// home/root; every path arrives explicitly in the owner policy.
func newConsentWatchLoopConfig(cursorDir string, interval time.Duration, references codex.ReferenceConfig) *daemon.WatchLoopConfig {
	return &daemon.WatchLoopConfig{
		StateDir:   cursorDir,
		References: references,
		Policy:     watcherPolicy(),
		Match:      transcriptNameMatch,
		Interval:   interval,
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

// openPrefixMap loads the -bead-prefix-map-file and arms its hot reload at the transcript watcher's
// poll cadence (pollInterval, or the watcher default when unset), so a rewritten map takes effect
// within one poll of the next bead-bearing tool call. The map is enrichment, so its file never fails
// startup: a missing, unreadable or invalid file is logged and bead capture of mapped prefixes stays
// idle until bd writes a valid one (a daemon that exited here would crash-loop under launchd/systemd
// and stop ALL transcript capture over a bad map).
func openPrefixMap(path string, pollInterval time.Duration, log func(string)) (*prefixmap.File, error) {
	if pollInterval <= 0 {
		pollInterval = codex.DefaultPollInterval
	}
	return prefixmap.Open(prefixmap.Config{Path: path, CheckInterval: pollInterval, Log: log})
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
