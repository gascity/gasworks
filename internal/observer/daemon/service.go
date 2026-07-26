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
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
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

	watcher       *codex.Watcher
	watchInterval time.Duration

	content         *contentUploader
	contentInterval time.Duration

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
	// watchRestartBackoff paces a watcher restart after a transient poll/sink failure so a
	// persistent failure does not busy-spin the poll loop.
	watchRestartBackoff = 250 * time.Millisecond
	// dirLockFilename is the advisory-lock file under the state directory. The held flock — never
	// the file's mere existence — is the live-writer proof.
	dirLockFilename = "daemon.lock"
	// aliveProbeTimeout bounds the pre-flight "is a live daemon already answering the socket?" probe.
	aliveProbeTimeout = 500 * time.Millisecond
)

// ServiceConfig configures the assembled endpoint.
type ServiceConfig struct {
	// Dir is the observer state directory; the socket, the WAL, and the durable sidecars live here.
	Dir string
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
	// It is opt-in and never changes the metadata-only behavior when nil.
	ContentUpload *ContentUploadLoopConfig

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
}

// WatchLoopConfig configures the Codex transcript watcher and its candidate sink.
type WatchLoopConfig struct {
	// ApprovedRoots are the absolute transcript roots the watcher may tail.
	ApprovedRoots []string
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
		Dir:      cfg.Dir,
		Spool:    sp,
		Registry: reg,
		PeerUID:  cfg.PeerUID,
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
		w, err := s.buildWatcher(cfg.Watch, sink, obs)
		if err != nil {
			_ = sp.Close()
			return nil, err
		}
		s.watcher = w
		s.watchInterval = cfg.Watch.Interval
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

// buildWatcher wires the committed candidate sink (with the partial-commit refinement) onto a codex
// watcher, plus the optional whole-file content observer (nil when content upload is disabled).
func (s *Service) buildWatcher(cfg *WatchLoopConfig, sink *CandidateSinkAdapter, obs codex.ContentObserver) (*codex.Watcher, error) {
	w, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots:   cfg.ApprovedRoots,
		StateDir:        cfg.StateDir,
		References:      cfg.References,
		Sink:            NewPartialCandidateSinkAdapter(sink),
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
		sender:   cfg.ContentUpload.Sender,
		sessions: sink,
		stateDir: stateDir,
		maxBytes: cfg.ContentUpload.MaxBytes,
		debounce: cfg.ContentUpload.Debounce,
		read:     codex.ReadValidatedTranscript,
		now:      s.now,
		log:      s.log,
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
	if s.watcher != nil {
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

	// Withdraw the socket and drain any in-flight durable appends.
	srvErr := s.server.Shutdown(ctx)

	// Final best-effort flush of freshly-durable frames (the uploader reads the WAL and the ack
	// sidecar directly, not the now-closed socket), then close the spool.
	if s.upload != nil && ctx.Err() == nil {
		if err := s.upload.drain(ctx); err != nil {
			s.logf("final upload drain: %v", err)
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

// runWatchLoop runs the transcript watcher until ctx is cancelled, restarting it after a transient
// poll/sink failure. The durable cursor makes a restart at-least-once-safe: it resumes from the
// last committed offset and re-reads only the undelivered tail.
func (s *Service) runWatchLoop(ctx context.Context) {
	for {
		err := s.watcher.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		s.logf("watcher restart: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRestartBackoff):
		}
	}
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
			s.content.tick(ctx)
		}
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
	snap, err := u.spool.Health()
	if err != nil {
		return fmt.Errorf("observer daemon: spool health: %w", err)
	}
	ack, err := spool.LoadAckState(u.dir, snap.HighestDurable, spool.AckOptions{})
	if err != nil {
		return fmt.Errorf("observer daemon: load ack state: %w", err)
	}
	planner := &upload.Planner{
		Store:    upload.SpoolFrameStore{Dir: u.dir},
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
		plan, ok, err := planner.Next()
		if err != nil {
			return fmt.Errorf("observer daemon: plan batch: %w", err)
		}
		if !ok {
			return nil // nothing owed
		}
		if err := deliverer.Deliver(ctx, plan); err != nil {
			return err // hold / retries exhausted / transient: nothing advanced; retried next pass
		}
	}
}

// durationOr returns d when positive, else fallback.
func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}
