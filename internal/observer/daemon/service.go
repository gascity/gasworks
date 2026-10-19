//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// ErrAlreadyRunning reports that another daemon already owns this state directory. It is returned
// when the exclusive WAL-directory advisory lock is already held, or when a live daemon still
// answers the socket. The endpoint MUST be a serialized single writer (spec §"Durable endpoint
// spool"): a second daemon on the same directory would share the WAL and ack sidecar and produce
// duplicate delivery plus an ack-watermark regression, so it fails closed rather than hijacking.
var ErrAlreadyRunning = errors.New("observer daemon: another daemon already owns this state directory")

// Service is the assembled observer endpoint. It composes the committed subsystems into one running
// daemon:
//
//   - the durable WAL spool (E1.2/E1.3, via local.SpoolWriter) — the single-writer durability seam;
//   - the boundary/ancestry projection (E1.10a Registry), rebuilt by replaying the WAL BEFORE the
//     socket serves, so a restart reconstructs the same projection it held before;
//   - the owner-only local socket server (E1.5), which folds every durable append into the registry
//     and answers ancestry/boundary queries from it;
//   - the batch uploader loop (E1.9), draining the durable spool to the authenticated Collector on a
//     bounded ticker and advancing the local acknowledgement only on a valid capped-contiguous ack
//     (never advancing on failure; honoring the delivery hold classification); and
//   - optionally the Codex transcript watcher (E1.8), tailing the approved roots and delivering
//     parsed candidates through the daemon's candidate sink (with the partial-commit refinement).
//
// Boot order is fixed: open WAL -> ReplayWAL(dir, registry) -> start server -> start uploader ->
// start watcher. Liveness is discovered from the socket and the process table only; the Service
// writes NO PID/status/liveness files (design rule "No status files — query live state").
type Service struct {
	dir      string
	sourceID string

	spool    *local.SpoolWriter
	registry *Registry
	server   *local.Server

	upload         *uploadLoop
	uploadInterval time.Duration

	// watchMu serializes transcript-watcher passes (the watch loop and PollTranscripts) and guards
	// the watcher fields below: the watcher is not safe for concurrent use, and under a live consent
	// policy a pass may replace it.
	watchMu       sync.Mutex
	watcher       *codex.Watcher
	watchInterval time.Duration

	content         *contentUploader
	contentInterval time.Duration

	// consent is the live consent policy (nil: the static configuration). Under it the watcher is
	// built from the policy and rebuilt whenever its shape changes, and fence keeps every captured
	// observation inside the consent it was captured under through upload. consentInterval is the
	// cadence of the dedicated consent loop.
	consent         *consent.Source
	consentInterval time.Duration
	fence           *consentFence
	// watchCfg and sink are kept to rebuild the watcher; watchShape is the shape the current
	// watcher was built for (valid when watchShapeSet), and watchBuildErr de-duplicates the log of a
	// policy the watcher cannot be built for.
	watchCfg      *WatchLoopConfig
	sink          *CandidateSinkAdapter
	watchShape    watchShape
	watchShapeSet bool
	watchBuildErr string
	// contentUnavailableNoted de-duplicates the log that the policy grants content upload this daemon
	// cannot perform (no collector).
	contentUnavailableNoted bool

	now func() time.Time
	log func(string)

	// lock is the held exclusive advisory lock on the state directory (the live-writer proof). It
	// is released — and only released — when its fd is closed, on Shutdown or process exit; it is
	// never a stale PID/status file.
	lock *os.File

	mu         sync.Mutex
	started    bool
	ready      bool
	loopCtx    context.Context
	loopCancel context.CancelFunc
	wg         sync.WaitGroup
}

// Default loop cadences and shutdown bound.
const (
	// DefaultUploadInterval is the uploader ticker cadence when unset. It substitutes for a push
	// signal; the delivery flush budget tunes it.
	DefaultUploadInterval = time.Second
	// DefaultShutdownTimeout bounds Run's graceful drain when ctx is cancelled.
	DefaultShutdownTimeout = 10 * time.Second
	// watchRestartBackoff paces the next watcher pass after a transient poll/sink failure so a
	// persistent failure does not busy-spin the poll loop.
	watchRestartBackoff = 250 * time.Millisecond
	// DefaultConsentInterval is how often the live consent policy is re-checked on its own, apart
	// from the checks before every content upload, observation batch, and transcript poll: it bounds
	// how long a narrowing waits while every other loop is busy.
	DefaultConsentInterval = 250 * time.Millisecond
	// dirLockFilename is the advisory-lock file under the state directory. The held flock — never
	// the file's mere existence — is the live-writer proof.
	dirLockFilename = "daemon.lock"
	// aliveProbeTimeout bounds the pre-flight "is a live daemon already answering the socket?" probe.
	aliveProbeTimeout = 500 * time.Millisecond
)

// ServiceConfig configures the assembled endpoint.
type ServiceConfig struct {
	// Dir is the observer state directory; the WAL and durable sidecars live here.
	Dir string
	// SocketPath is the owner-only runtime socket. Empty defaults to Dir/socket.
	SocketPath string
	// SourceID is the durable spool source id stamped into every segment header and every batch.
	SourceID string
	// Capacity is the spool byte-ceiling model input (validated by the spool writer).
	Capacity spool.CapacityConfig

	// RegistrySource / RegistryWorkspace scope the boundary/ancestry projection to this install.
	RegistrySource    string
	RegistryWorkspace string

	// Upload, when non-nil, enables the batch uploader loop; its Sender is required.
	Upload *UploadLoopConfig
	// Watch, when non-nil, enables the Codex transcript watcher.
	Watch *WatchLoopConfig
	// ContentUpload, when non-nil AND Watch is set, enables the whole-transcript content side
	// channel. It reuses the watcher (for per-transcript observations + native-session lookup) and
	// its Sender must be the same authenticated collector client the observation uploader uses.
	// It is opt-in and never changes the metadata-only behavior when nil. Under Consent it is the
	// content channel's wiring only: whether content is uploaded follows the live policy.
	ContentUpload *ContentUploadLoopConfig

	// Consent, when non-nil, is the live consent policy and requires Watch. The watcher's roots come
	// from it (Watch.ApprovedRoots and Watch.RootPolicies must be empty), content upload follows its
	// content consent, and it is re-checked before every observation batch, every content upload,
	// and every transcript poll, and on its own every ConsentInterval: a narrowing stops capture and
	// upload of what it withdraws at once (queued content is dropped, an upload in flight cancelled,
	// queued observations withheld), and a widening takes effect at the next poll. nil keeps the
	// static configuration.
	Consent *consent.Source
	// ConsentInterval is the cadence of the dedicated consent check under Consent; 0 selects
	// DefaultConsentInterval.
	ConsentInterval time.Duration

	// PeerUID overrides the socket peer-uid reader (a test seam). nil selects the native
	// Linux or Darwin credential API.
	PeerUID func(*net.UnixConn) (uint32, error)
	// Now overrides the clock; nil selects time.Now.
	Now func() time.Time
	// Log receives content-free operational lines (e.g. a held upload). nil discards them.
	Log func(string)
}

// UploadLoopConfig configures the batch uploader loop.
type UploadLoopConfig struct {
	// Sender performs the HTTP round trips (the E1.9 *upload.Client, or a test double). Required.
	Sender upload.Sender
	// Caps are the per-batch ceilings; zero fields select the delivery defaults.
	Caps upload.Caps
	// Retry bounds the delivery retry loop.
	Retry upload.RetryPolicy
	// Interval is the ticker cadence; 0 selects DefaultUploadInterval.
	Interval time.Duration
}

// ContentUploadLoopConfig configures the whole-transcript content side channel. Sender is required
// (the shared collector client). StateDir defaults to the watcher's cursor state dir; the numeric
// bounds fall back to their package defaults when zero.
type ContentUploadLoopConfig struct {
	// Sender POSTs whole-file snapshots to the collector content route (the shared *upload.Client).
	Sender ContentSender
	// StateDir persists the per-transcript last-uploaded markers; "" reuses WatchLoopConfig.StateDir.
	StateDir string
	// MaxBytes bounds a single whole-file upload; 0 selects DefaultMaxContentBytes.
	MaxBytes int64
	// Debounce is how long a transcript must be stable before its content is uploaded; 0 selects
	// DefaultContentDebounce.
	Debounce time.Duration
	// Interval is the content-loop ticker cadence; 0 selects DefaultContentInterval.
	Interval time.Duration
	// TokenFile is the rotating bearer token file Sender reads its credential from (the daemon's
	// -token-file). While the collector refuses content upload, a change to it — a renewed or rotated
	// credential — retries at once instead of waiting out the back-off. "" relies on the back-off.
	TokenFile string
}

// WatchLoopConfig configures the Codex transcript watcher and its candidate sink.
type WatchLoopConfig struct {
	// ApprovedRoots are the absolute transcript roots the watcher may tail.
	ApprovedRoots []string
	// RootPolicies are explicit owner consent records for the private Companion runtime. They are
	// mutually exclusive with ApprovedRoots, which remains the legacy watcher configuration.
	RootPolicies []rootpolicy.Record
	// StateDir is the owner-only durable cursor directory (outside the approved roots).
	StateDir string
	// References is the extraction configuration passed to every parse.
	References codex.ReferenceConfig
	// Policy is the sink's METADATA_ONLY transform policy (validated at construction).
	Policy evidence.Policy
	// Provider stamps provenance; "" selects codex.Provider.
	Provider string
	// ParserVersion stamps provenance; "" selects codex.ParserVersion.
	ParserVersion string
	// TransformVersion stamps provenance.
	TransformVersion string
	// Interval overrides the watcher poll cadence; 0 uses codex.DefaultPollInterval.
	Interval time.Duration
	// Match selects which regular-file names under a root are transcripts; nil tracks all.
	Match func(name string) bool
}

// NewService opens the WAL spool, rebuilds the boundary/ancestry projection from the WAL, and
// builds the socket server, uploader, and watcher — all WITHOUT starting them. Start begins serving.
// The projection replay runs before the server is even built, so the server never folds a live
// append into a half-rebuilt projection.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Dir == "" {
		return nil, errors.New("observer daemon: service dir is required")
	}
	if cfg.SourceID == "" {
		return nil, errors.New("observer daemon: service source id is required")
	}
	socketPath, err := local.ValidateServerPaths(cfg.Dir, cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("observer daemon: validate paths: %w", err)
	}
	cfg.SocketPath = socketPath
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// 0. Acquire the exclusive advisory lock on the state directory BEFORE opening the spool, so a
	// raced (or relative-path) second writer fails fast — before it ever touches the WAL — rather
	// than sharing the single-writer durability seam. The held flock is the live-writer proof.
	lock, err := acquireDirLock(cfg.Dir)
	if err != nil {
		return nil, err
	}
	// Release the lock on any failed construction so a caller can retry cleanly.
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()

	// 1. Open (or recover) the durable WAL spool.
	sp, err := local.NewSpoolWriter(local.SpoolConfig{
		Dir:      cfg.Dir,
		SourceID: cfg.SourceID,
		Capacity: cfg.Capacity,
	})
	if err != nil {
		return nil, fmt.Errorf("observer daemon: open spool: %w", err)
	}

	// 2. Rebuild the projection from the WAL BEFORE serving.
	reg := NewRegistry(cfg.RegistrySource, cfg.RegistryWorkspace)
	if err := ReplayWAL(cfg.Dir, reg); err != nil {
		_ = sp.Close()
		return nil, fmt.Errorf("observer daemon: replay wal: %w", err)
	}

	// 3. Build the owner-only socket server (unstarted).
	srv, err := local.NewServer(local.ServerConfig{
		Dir:        cfg.Dir,
		SocketPath: cfg.SocketPath,
		Spool:      sp,
		Registry:   reg,
		PeerUID:    cfg.PeerUID,
	})
	if err != nil {
		_ = sp.Close()
		return nil, fmt.Errorf("observer daemon: build server: %w", err)
	}

	s := &Service{
		dir:      cfg.Dir,
		sourceID: cfg.SourceID,
		spool:    sp,
		registry: reg,
		server:   srv,
		now:      now,
		log:      cfg.Log,
		lock:     lock,
		consent:  cfg.Consent,

		consentInterval: durationOr(cfg.ConsentInterval, DefaultConsentInterval),
	}

	// 3b. Under a live consent policy, load the consent fence for the spool as recovered: it must
	// know every withheld decision before the uploader can form a batch.
	if cfg.Consent != nil {
		if cfg.Watch == nil {
			_ = sp.Close()
			return nil, errors.New("observer daemon: a live consent policy requires the transcript watcher configuration")
		}
		if len(cfg.Watch.ApprovedRoots) > 0 || len(cfg.Watch.RootPolicies) > 0 {
			_ = sp.Close()
			return nil, errors.New("observer daemon: under a live consent policy the watcher's roots come from the policy, not the watch configuration")
		}
		health, err := sp.Health()
		if err != nil {
			_ = sp.Close()
			return nil, fmt.Errorf("observer daemon: spool health: %w", err)
		}
		fence, err := newConsentFence(cfg.Dir, cfg.Consent, health.HighestDurable, s.log)
		if err != nil {
			_ = sp.Close()
			return nil, err
		}
		s.fence = fence
	} else if exists, err := ledgerExists(cfg.Dir); err != nil || exists {
		// A ledger left by a run under a live policy is honored even without one (see consentFence).
		if err != nil {
			_ = sp.Close()
			return nil, err
		}
		health, err := sp.Health()
		if err != nil {
			_ = sp.Close()
			return nil, fmt.Errorf("observer daemon: spool health: %w", err)
		}
		fence, err := newConsentFence(cfg.Dir, nil, health.HighestDurable, s.log)
		if err != nil {
			_ = sp.Close()
			return nil, err
		}
		s.fence = fence
	}

	// 4. Prepare the uploader loop.
	if cfg.Upload != nil {
		if cfg.Upload.Sender == nil {
			_ = sp.Close()
			return nil, errors.New("observer daemon: upload loop requires a sender")
		}
		s.upload = &uploadLoop{
			dir:      cfg.Dir,
			sourceID: cfg.SourceID,
			spool:    sp,
			sender:   cfg.Upload.Sender,
			caps:     cfg.Upload.Caps,
			retry:    cfg.Upload.Retry,
			fence:    s.fence,
		}
		s.uploadInterval = durationOr(cfg.Upload.Interval, DefaultUploadInterval)
	}

	// 5. Prepare the transcript watcher (it dials the same socket the server listens on). When
	// content upload is enabled, its uploader is wired in as the watcher's content observer so the
	// same per-poll pass that drains the tail also feeds the whole-file side channel.
	if cfg.Watch != nil {
		sink, err := s.buildSink(cfg.Watch, srv.SocketPath())
		if err != nil {
			_ = sp.Close()
			return nil, err
		}
		var obs codex.ContentObserver
		if cfg.ContentUpload != nil {
			cu, err := s.buildContentUploader(cfg, sink)
			if err != nil {
				_ = sp.Close()
				return nil, err
			}
			s.content = cu
			s.contentInterval = durationOr(cfg.ContentUpload.Interval, DefaultContentInterval)
			obs = cu
		}
		s.watchInterval = durationOr(cfg.Watch.Interval, codex.DefaultPollInterval)
		if s.consent != nil {
			// The watcher is built from the live policy, and rebuilt by every later pass whose policy
			// changed its shape. A policy the watcher cannot be built for fails startup, as a static
			// configuration would.
			s.watchCfg, s.sink = cfg.Watch, sink
			pol := s.consent.Latest()
			if err := s.rebuildWatcherLocked(pol, shapeOf(pol, s.content != nil)); err != nil {
				_ = sp.Close()
				return nil, err
			}
		} else {
			w, err := s.buildWatcher(cfg.Watch, NewPartialCandidateSinkAdapter(sink), obs)
			if err != nil {
				_ = sp.Close()
				return nil, err
			}
			s.watcher = w
		}
	}

	// A consent change cancels and drops content the new policy no longer covers, on whichever loop
	// observes it. Subscribed last, so only a fully built service is ever notified.
	if s.consent != nil && s.content != nil {
		s.consent.Subscribe(s.content.onConsentChange)
	}
	// Without a content channel (no collector) this run uploads no content, but the content an
	// earlier run queued still follows the live policy.
	if s.consent != nil && s.content == nil && cfg.Watch != nil {
		followQueuedContentConsent(s.consent, cfg.Watch.StateDir, s.log)
	}

	ok = true
	return s, nil
}

// acquireDirLock takes the exclusive, non-blocking advisory lock on the state directory. The lock
// is released automatically when the returned file is closed or the process exits, so it is never a
// stale liveness artifact. EWOULDBLOCK (another live daemon holds it) maps to ErrAlreadyRunning.
func acquireDirLock(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("observer daemon: create state dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, dirLockFilename), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("observer daemon: open lock file: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("observer daemon: acquire directory lock: %w", err)
	}
	return f, nil
}

// releaseLock closes the held advisory lock (releasing the flock). It is idempotent.
func (s *Service) releaseLock() {
	if s.lock != nil {
		_ = s.lock.Close()
		s.lock = nil
	}
}

// daemonAlive reports whether a live daemon already answers the socket with a Status round-trip. A
// missing socket or a refused/failed dial (a stale socket left by a crashed daemon) reports false.
func daemonAlive(socketPath string) bool {
	if _, err := os.Stat(socketPath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), aliveProbeTimeout)
	defer cancel()
	_, err := local.NewClient(socketPath, local.WithTimeout(aliveProbeTimeout)).Status(ctx)
	return err == nil
}

// buildSink constructs the committed candidate sink over a local client. It is split from the
// watcher build so the content uploader can share the same sink's native-session threading (its
// SessionFor read seam) rather than re-parsing transcripts.
func (s *Service) buildSink(cfg *WatchLoopConfig, socketPath string) (*CandidateSinkAdapter, error) {
	provider := cfg.Provider
	if provider == "" {
		provider = codex.Provider
	}
	parserVersion := cfg.ParserVersion
	if parserVersion == "" {
		parserVersion = codex.ParserVersion
	}
	sink, err := NewCandidateSinkAdapter(SinkConfig{
		Client:           local.NewClient(socketPath),
		Policy:           cfg.Policy,
		Provider:         provider,
		ParserVersion:    parserVersion,
		TransformVersion: cfg.TransformVersion,
		Now:              s.now,
		// The sink stamps run_context by reading the daemon's own session→run index in-process, so a
		// wrapper-bound explicit run carries its child agent session's usage natively.
		RunResolver: s.registry,
	})
	if err != nil {
		return nil, fmt.Errorf("observer daemon: build candidate sink: %w", err)
	}
	return sink, nil
}

// buildWatcher wires a candidate sink (with the partial-commit refinement) onto a codex watcher, plus
// the optional whole-file content observer (nil when content upload is disabled).
func (s *Service) buildWatcher(cfg *WatchLoopConfig, sink codex.PartialCandidateSink, obs codex.ContentObserver) (*codex.Watcher, error) {
	w, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots:   cfg.ApprovedRoots,
		RootPolicies:    cfg.RootPolicies,
		StateDir:        cfg.StateDir,
		References:      cfg.References,
		Sink:            sink,
		ContentObserver: obs,
		Match:           cfg.Match,
		Interval:        cfg.Interval,
		Now:             s.now,
	})
	if err != nil {
		return nil, fmt.Errorf("observer daemon: build watcher: %w", err)
	}
	return w, nil
}

// buildContentUploader wires the whole-transcript content side channel over the shared collector
// sender and the sink's native-session lookup. Its markers persist in the content state dir, which
// defaults to the watcher's cursor state dir (outside the approved roots, so they are never tailed).
func (s *Service) buildContentUploader(cfg ServiceConfig, sink *CandidateSinkAdapter) (*contentUploader, error) {
	if cfg.ContentUpload.Sender == nil {
		return nil, errors.New("observer daemon: content upload requires a sender")
	}
	stateDir := cfg.ContentUpload.StateDir
	if stateDir == "" {
		stateDir = cfg.Watch.StateDir
	}
	cu, err := newContentUploader(contentUploaderConfig{
		sender:    cfg.ContentUpload.Sender,
		sessions:  sink,
		stateDir:  stateDir,
		maxBytes:  cfg.ContentUpload.MaxBytes,
		debounce:  cfg.ContentUpload.Debounce,
		read:      codex.ReadValidatedTranscript,
		now:       s.now,
		log:       s.log,
		consent:   cfg.Consent,
		tokenFile: cfg.ContentUpload.TokenFile,
	})
	if err != nil {
		return nil, fmt.Errorf("observer daemon: build content uploader: %w", err)
	}
	return cu, nil
}

// Start begins serving on the socket and launches the uploader and watcher loops. It is safe to
// call once; a second call errors.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("observer daemon: service already started")
	}
	// Pre-flight: if a live daemon still answers the socket, refuse rather than let the server
	// unlink and rebind the path out from under it. The flock is the primary guard; this also
	// catches the (pathological) case where flock is a no-op on the underlying filesystem. Only a
	// socket proven stale (no live answer) is left for the server to unlink and recreate.
	if daemonAlive(s.server.SocketPath()) {
		s.releaseLock()
		return ErrAlreadyRunning
	}
	if err := s.server.Start(); err != nil {
		s.releaseLock()
		return fmt.Errorf("observer daemon: start server: %w", err)
	}
	s.loopCtx, s.loopCancel = context.WithCancel(context.Background())
	s.started = true

	if s.upload != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runUploadLoop(s.loopCtx)
		}()
	}
	if s.watcher != nil || s.watchCfg != nil {
		// Under a live consent policy the loop runs even while no root is consented: a later policy
		// can consent to one, and the loop is what applies it.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runWatchLoop(s.loopCtx)
		}()
	}
	if s.content != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runContentLoop(s.loopCtx)
		}()
	}
	if s.consent != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runConsentLoop(s.loopCtx)
		}()
	}
	s.ready = true
	return nil
}

// Ready reports whether the endpoint is serving and its loops are running. Readiness is withdrawn
// at the start of Shutdown.
func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// SocketPath returns the runtime socket path the server listens on.
func (s *Service) SocketPath() string { return s.server.SocketPath() }

// Run starts the service and blocks until ctx is cancelled, then drains gracefully within
// DefaultShutdownTimeout.
func (s *Service) Run(ctx context.Context) error {
	if err := s.Start(); err != nil {
		return err
	}
	<-ctx.Done()
	shCtx, cancel := context.WithTimeout(context.Background(), DefaultShutdownTimeout)
	defer cancel()
	return s.Shutdown(shCtx)
}

// Shutdown withdraws readiness, stops the loops, drains in-flight socket handlers, performs a final
// best-effort upload flush of already-durable frames, closes the spool, and releases the directory
// lock (so a legitimate restart succeeds). It is idempotent.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		// Never started (or already shut down): still release a held construction lock so a retry
		// after a failed Start is not blocked by our own lock.
		s.releaseLock()
		s.mu.Unlock()
		return nil
	}
	s.ready = false
	cancel := s.loopCancel
	s.started = false
	s.mu.Unlock()

	// Stop the uploader and watcher loops and wait for them to exit (bounded by ctx).
	if cancel != nil {
		cancel()
	}
	drained := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-ctx.Done():
	}

	// Record the content still owed for upload, so the next start resumes it: content first owed since
	// the content loop last planned would otherwise be lost, as the next start never parses a
	// transcript this run consumed to its end again.
	if s.content != nil {
		s.content.recordOwed()
	}

	// Withdraw the socket and drain any in-flight durable appends.
	srvErr := s.server.Shutdown(ctx)

	// Hand the next start the consent origins of what this run captured but has not sent, so a
	// withdrawal written while the daemon is stopped still withholds it. The record is written before
	// the final drain, so a collector that hangs the drain until the process is killed cannot lose
	// it, and every send of the drain keeps it exact.
	if s.fence != nil {
		if err := s.recordShutdownConsent(); err != nil {
			s.logf("record consent origins at shutdown: %v", err)
		}
	}
	// Final best-effort flush of freshly-durable frames (the uploader reads the WAL and the ack
	// sidecar directly, not the now-closed socket), then close the spool.
	if s.upload != nil && ctx.Err() == nil {
		if err := s.upload.drain(ctx); err != nil {
			s.logf("final upload drain: %v", err)
		}
		if s.fence != nil {
			// Rewrite the record without what the drain got acknowledged.
			if err := s.recordShutdownConsent(); err != nil {
				s.logf("record consent origins after the final drain: %v", err)
			}
		}
	}
	closeErr := s.spool.Close()

	// Release the exclusive directory lock last, so no window exists where a second daemon could
	// bind the socket while this one still holds the spool.
	s.mu.Lock()
	s.releaseLock()
	s.mu.Unlock()

	if srvErr != nil {
		return fmt.Errorf("observer daemon: shutdown server: %w", srvErr)
	}
	if closeErr != nil {
		return fmt.Errorf("observer daemon: close spool: %w", closeErr)
	}
	return nil
}

// DrainUploads runs one uploader pass now (the same pass the ticker drives), returning any hold or
// transient failure. It is the deterministic unit for tests and the on-demand flush.
func (s *Service) DrainUploads(ctx context.Context) error {
	if s.upload == nil {
		return nil
	}
	return s.upload.drain(ctx)
}

// runUploadLoop drains owed batches on a bounded ticker until ctx is cancelled. A drain failure is
// content-free-logged and retried on the next tick; it never advances the local acknowledgement.
func (s *Service) runUploadLoop(ctx context.Context) {
	t := time.NewTicker(s.uploadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.upload.drain(ctx); err != nil && ctx.Err() == nil {
				s.logf("upload drain: %v", err)
			}
		}
	}
}

// runWatchLoop runs a transcript-watcher pass on the poll cadence until ctx is cancelled, backing off
// briefly after a transient poll/sink failure. The durable cursor makes a retry at-least-once-safe:
// it resumes from the last committed offset and re-reads only the undelivered tail.
func (s *Service) runWatchLoop(ctx context.Context) {
	t := time.NewTicker(s.watchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := s.PollTranscripts(ctx)
		if err == nil || ctx.Err() != nil {
			continue
		}
		s.logf("watcher pass failed (retrying): %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRestartBackoff):
		}
	}
}

// PollTranscripts runs one transcript-watcher pass now — the pass the watch loop drives. Under a
// live consent policy it first re-checks the policy and, when the policy changed the watcher's
// shape (its consented roots or whether content is observed), rebuilds the watcher before polling:
// a withdrawn root is no longer tailed and a newly consented one is scanned on this very pass. It
// is the deterministic unit for tests and an on-demand rescan.
func (s *Service) PollTranscripts(ctx context.Context) error {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.consent != nil {
		if err := s.applyWatchConsentLocked(s.consent.Current()); err != nil {
			return nil // logged once by applyWatchConsentLocked; capture stays paused until it applies
		}
	}
	if s.watcher == nil {
		return nil
	}
	err := s.watcher.Poll(ctx)
	if errors.Is(err, errConsentWithdrawn) {
		// The policy changed during this pass and a transcript's consent is gone. Nothing past the
		// refusal was appended; the next pass rebuilds the watcher without the withdrawn root.
		return nil
	}
	return err
}

// runContentLoop drives the whole-transcript content side channel on a bounded ticker until ctx is
// cancelled. Each tick is best-effort and self-contained; a failure only backs the uploader off and
// never affects the watcher or the observation uploader.
func (s *Service) runContentLoop(ctx context.Context) {
	t := time.NewTicker(s.contentInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.TickContentUploads(ctx)
		}
	}
}

// runConsentLoop re-checks the live consent policy on its own cadence until ctx is cancelled, so a
// narrowing reaches what does not wait for the next batch, upload, or poll — an upload in flight is
// cancelled and queued content dropped (the content uploader's subscription), and every later
// watcher append is refused — within one interval even while every other loop is busy: a long
// transcript pass, or a batch being retried against a failing collector.
func (s *Service) runConsentLoop(ctx context.Context) {
	t := time.NewTicker(s.consentInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.consent.Current()
		}
	}
}

// TickContentUploads runs one content-upload pass now — the pass the content loop drives. It is the
// deterministic unit for tests and an on-demand flush; it is a no-op when content upload is not
// wired.
func (s *Service) TickContentUploads(ctx context.Context) {
	if s.content != nil {
		s.content.tick(ctx)
	}
}

func (s *Service) logf(format string, args ...any) {
	if s.log == nil {
		return
	}
	s.log(fmt.Sprintf(format, args...))
}

// uploadLoop owns one uploader pass. It shares nothing mutable with the writer: it reads the WAL
// through the spool's exported segment surface and the highest-durable ceiling through the writer's
// content-free Health snapshot, and it is the sole writer of the acknowledgement sidecar.
type uploadLoop struct {
	dir      string
	sourceID string
	spool    *local.SpoolWriter
	sender   upload.Sender
	caps     upload.Caps
	retry    upload.RetryPolicy
	// fence, when non-nil, applies the live consent policy before every batch (nil: no live policy).
	fence *consentFence

	// mu serializes every pass so at most one drainer touches the WAL and the ack sidecar at a
	// time. The background ticker and an on-demand DrainUploads both funnel through it; without it,
	// two concurrent passes would each LoadAckState from the same sidecar, form the same range, and
	// double-deliver or race the watermark write.
	mu sync.Mutex
}

// drain forms and delivers every owed batch, advancing the durable acknowledgement only through a
// validated ack. It stops on the first hold/transient failure (nothing advanced), which the next
// tick retries byte-for-byte. The ack state is re-loaded from the durable sidecar each pass and
// its advancement ceiling is seeded from the writer's current highest-durable sequence, so the
// uploader always sees the frames the writer has made durable without sharing in-memory state.
// Passes are serialized so exactly one drainer owns the WAL/ack sidecar at a time.
func (u *uploadLoop) drain(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	highest, err := u.highestDurable()
	if err != nil {
		return err
	}
	ack, err := spool.LoadAckState(u.dir, highest, spool.AckOptions{})
	if err != nil {
		return fmt.Errorf("observer daemon: load ack state: %w", err)
	}
	var store upload.FrameStore = upload.SpoolFrameStore{Dir: u.dir}
	if u.fence != nil {
		store = u.fence.frameStore(store)
	}
	planner := &upload.Planner{
		Store:    store,
		Ack:      ack,
		Caps:     u.caps,
		SourceID: u.sourceID,
	}
	deliverer := &upload.Deliverer{
		Sender:   u.sender,
		Ack:      ack,
		SourceID: u.sourceID,
		Policy:   u.retry,
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if u.fence != nil {
			// Re-checked before every batch: a narrowing written while this pass drains a backlog
			// withholds the rest of it.
			if err := u.fence.refresh(); err != nil {
				return err
			}
		}
		plan, ok, err := planner.Next()
		if err != nil {
			return fmt.Errorf("observer daemon: plan batch: %w", err)
		}
		if !ok {
			return nil // nothing owed
		}
		if u.fence != nil {
			if err := u.fence.beforeSend(plan.Range); err != nil {
				return err // the withheld decisions are not recorded, so nothing is sent
			}
		}
		if err := deliverer.Deliver(ctx, plan); err != nil {
			return err // hold / retries exhausted / transient: nothing advanced; retried next pass
		}
		if u.fence != nil {
			u.fence.acknowledged(ack.AcknowledgedThrough())
		}
	}
}

// highestDurable reads the spool's highest durable sequence — under the consent fence's gate when
// one is set, so every watcher frame at or below it already has its consent origin recorded.
func (u *uploadLoop) highestDurable() (int64, error) {
	read := func() (int64, error) {
		snap, err := u.spool.Health()
		if err != nil {
			return 0, fmt.Errorf("observer daemon: spool health: %w", err)
		}
		return snap.HighestDurable, nil
	}
	if u.fence == nil {
		return read()
	}
	return u.fence.ceiling(read)
}

// durationOr returns d when positive, else fallback.
func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}
