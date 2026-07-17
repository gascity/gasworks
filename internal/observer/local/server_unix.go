//go:build linux

package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// socketFilename is the runtime socket under the observer state directory. It is a runtime
// artifact recreated on every start — never a status or liveness source.
const socketFilename = "socket"

// Owner-only modes: the state directory is 0700 and the socket file is 0600.
const (
	stateDirMode  os.FileMode = 0o700
	socketMode    os.FileMode = 0o600
	walSubdirName             = "wal"
)

// Default server bounds.
const (
	defaultMaxConcurrent = 16
	defaultReadTimeout   = 5 * time.Second
	defaultWriteTimeout  = 5 * time.Second
	// acceptRetryBackoff paces the accept loop after a transient (non-close) accept error so a
	// temporary fd exhaustion (EMFILE/ENFILE) does not busy-spin or permanently kill intake.
	acceptRetryBackoff = 5 * time.Millisecond
)

// Spool is the serialized single-writer durable seam the daemon appends through. Its
// implementation makes each write durable (fsync) before returning, so the server can reply
// success only after durability. It is the ONLY producer path into the WAL.
type Spool interface {
	// AppendObservation seals the observation with the next assigned sequence and a
	// daemon-assigned observation id, appends it durably, and returns the durable ack. The
	// observation arrives with a placeholder sequence/id that the implementation overwrites.
	AppendObservation(obs wire.Observation) (AppendAck, error)
	// ReserveRun preallocates a run's terminal reserve and returns the resulting capacity view.
	ReserveRun(runID string) (RunReserveAck, error)
	// ReleaseRun releases a run's terminal reserve and returns the resulting capacity view.
	ReleaseRun(runID string) (RunReserveAck, error)
	// Health returns a content-free health/capacity snapshot.
	Health() (HealthSnapshot, error)
}

// ServerConfig configures the daemon socket server.
type ServerConfig struct {
	// Dir is the observer state directory; the socket lives at Dir/socket.
	Dir string
	// Spool is the durable single-writer seam (required).
	Spool Spool
	// ExpectedUID is the peer UID the server accepts; nil defaults to the daemon's own euid.
	// A pointer distinguishes "unset" from a legitimate uid 0 (root).
	ExpectedUID *uint32
	// MaxConcurrent bounds the number of concurrently-serviced connections; <=0 selects the
	// default. Excess peers wait in the accept backlog until a slot frees.
	MaxConcurrent int
	// ReadTimeout bounds how long a single request may take to ARRIVE (peer check + request
	// read); <=0 selects the default. It deliberately does not bound the durable append or the
	// reply write — the read deadline is cleared once the request is fully read.
	ReadTimeout time.Duration
	// WriteTimeout bounds the reply write, set fresh after the durable append so a slow-but-
	// successful fsync never consumes the reply budget; <=0 selects the default.
	WriteTimeout time.Duration
	// MaxMessageBytes bounds a single request/response; <=0 selects DefaultMaxMessageBytes.
	MaxMessageBytes int
	// PeerUID reads the connected peer's UID; nil selects the Linux SO_PEERCRED reader. Tests
	// inject a seam to simulate a mismatched peer since they run as a single user.
	PeerUID func(*net.UnixConn) (uint32, error)
}

// Server is the owner-only Unix-domain socket daemon. It accepts bounded typed local requests,
// verifies peer identity fail-closed, services each through the single-writer spool, and
// drains in-flight work on graceful shutdown.
type Server struct {
	dir             string
	socketPath      string
	spool           Spool
	expectedUID     uint32
	peerUID         func(*net.UnixConn) (uint32, error)
	maxConcurrent   int
	readTimeout     time.Duration
	writeTimeout    time.Duration
	maxMessageBytes int

	ln   *net.UnixListener
	sem  chan struct{}
	quit chan struct{}
	wg   sync.WaitGroup

	// accept is the connection-accept function; Start binds it to the listener. Tests wrap it
	// via acceptMiddleware to inject transient errors and prove intake recovers.
	accept           func() (*net.UnixConn, error)
	acceptMiddleware func(base func() (*net.UnixConn, error)) func() (*net.UnixConn, error)

	mu      sync.Mutex
	started bool
	closed  bool
}

// NewServer validates the configuration and returns an unstarted server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Dir == "" {
		return nil, errors.New("observer local: server dir is required")
	}
	if cfg.Spool == nil {
		return nil, errors.New("observer local: server spool is required")
	}
	expected := uint32(os.Geteuid())
	if cfg.ExpectedUID != nil {
		expected = *cfg.ExpectedUID
	}
	peer := cfg.PeerUID
	if peer == nil {
		peer = peerUIDFromSocket
	}
	maxConc := cfg.MaxConcurrent
	if maxConc <= 0 {
		maxConc = defaultMaxConcurrent
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	maxMsg := cfg.MaxMessageBytes
	if maxMsg <= 0 {
		maxMsg = DefaultMaxMessageBytes
	}
	return &Server{
		dir:             cfg.Dir,
		socketPath:      filepath.Join(cfg.Dir, socketFilename),
		spool:           cfg.Spool,
		expectedUID:     expected,
		peerUID:         peer,
		maxConcurrent:   maxConc,
		readTimeout:     readTimeout,
		writeTimeout:    writeTimeout,
		maxMessageBytes: maxMsg,
	}, nil
}

// SocketPath returns the runtime socket path.
func (s *Server) SocketPath() string { return s.socketPath }

// Start creates the owner-only state directory and socket and begins accepting connections. It
// unconditionally unlinks any stale path at the socket location first: the socket is a runtime
// artifact recreated on every start and its presence is never treated as liveness.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("observer local: server already started")
	}
	if err := os.MkdirAll(s.dir, stateDirMode); err != nil {
		return fmt.Errorf("observer local: create state dir: %w", err)
	}
	if err := os.Chmod(s.dir, stateDirMode); err != nil {
		return fmt.Errorf("observer local: chmod state dir: %w", err)
	}
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("observer local: unlink stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("observer local: listen: %w", err)
	}
	if err := os.Chmod(s.socketPath, socketMode); err != nil {
		ln.Close()
		return fmt.Errorf("observer local: chmod socket: %w", err)
	}
	s.ln = ln.(*net.UnixListener)
	base := s.ln.AcceptUnix
	if s.acceptMiddleware != nil {
		s.accept = s.acceptMiddleware(base)
	} else {
		s.accept = base
	}
	s.sem = make(chan struct{}, s.maxConcurrent)
	s.quit = make(chan struct{})
	s.started = true
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// acceptLoop accepts connections and dispatches each to a bounded worker. Acquiring the
// concurrency slot before spawning the worker caps concurrent handlers; excess peers wait in
// the kernel accept backlog.
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed during shutdown — clean exit
			}
			// A transient error (e.g. EMFILE/ENFILE under fd exhaustion) must not permanently
			// kill intake: back off briefly and keep accepting, unless we are shutting down.
			select {
			case <-s.quit:
				return
			case <-time.After(acceptRetryBackoff):
				continue
			}
		}
		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.sem }()
				s.handle(conn)
			}()
		case <-s.quit:
			conn.Close()
			return
		}
	}
}

// handle services one connection: it bounds the request time with a deadline, verifies the
// peer UID fail-closed, reads a size-bounded request, and writes the typed response. Any
// framing/deadline/peer failure closes the connection without serving.
func (s *Server) handle(conn *net.UnixConn) {
	defer conn.Close()
	// The read deadline bounds only request ARRIVAL (peer check + request read).
	if s.readTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
	uid, err := s.peerUID(conn)
	if err != nil {
		return // cannot verify identity — fail closed
	}
	if uid != s.expectedUID {
		return // peer is not the owner — fail closed
	}
	reqBytes, err := readMessage(conn, s.maxMessageBytes)
	if err != nil {
		return // oversized / slow / short — fail closed
	}
	// The request is fully read: clear the read deadline so the durable append (a synchronous,
	// deadline-immune fsync) never runs against the arrival budget. A slow-but-successful fsync
	// must still be acknowledged, not dropped as a spurious failure that triggers a re-capture
	// duplicate downstream.
	_ = conn.SetReadDeadline(time.Time{})
	req, err := DecodeRequest(reqBytes)
	if err != nil {
		s.writeReply(conn, errorResponse(CodeBadRequest, "malformed request"))
		return
	}
	// dispatch may fsync inside the spool; the reply deadline is set fresh afterward.
	s.writeReply(conn, s.dispatch(req))
}

// writeReply sets a fresh write deadline immediately before writing the reply, so the reply
// budget is independent of however long the durable append took.
func (s *Server) writeReply(conn *net.UnixConn, resp Response) {
	respBytes, err := EncodeResponse(resp)
	if err != nil {
		return
	}
	if s.writeTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	_ = writeMessage(conn, respBytes, s.maxMessageBytes)
}

// dispatch routes a validated request to the spool and builds the typed response. Errors are
// mapped to content-free codes; the underlying error text (which may name paths) never reaches
// the wire.
func (s *Server) dispatch(req Request) Response {
	switch req.Kind {
	case KindAppendObservation:
		// Strict-decode against the closed wire schema BEFORE the observation reaches the
		// spool: wire.Observation.UnmarshalJSON stores raw union bytes, so an unmodelled field
		// or unknown discriminator would otherwise be canonicalized into a durable frame and
		// its WAL SHA would diverge from the platform's strict-decoded canonical hash (the
		// E1.1 CanonicalBytes precondition). Reject it fail-closed instead.
		if err := validateObservationSchema(req.Append.Observation); err != nil {
			return errorResponse(CodeInvalidObservation, "invalid observation")
		}
		ack, err := s.spool.AppendObservation(req.Append.Observation)
		if err != nil {
			return errorResponse(CodeAppendFailed, "append failed")
		}
		return Response{Status: StatusOK, Append: &ack}
	case KindReserveRun:
		ack, err := s.spool.ReserveRun(req.ReserveRun.RunID)
		if err != nil {
			return errorResponse(CodeReserveFailed, "reserve failed")
		}
		return Response{Status: StatusOK, Reserve: &ack}
	case KindReleaseRun:
		ack, err := s.spool.ReleaseRun(req.ReleaseRun.RunID)
		if err != nil {
			return errorResponse(CodeReleaseFailed, "release failed")
		}
		return Response{Status: StatusOK, Reserve: &ack}
	case KindStatus:
		h, err := s.spool.Health()
		if err != nil {
			return errorResponse(CodeHealthFailed, "health read failed")
		}
		return Response{Status: StatusOK, Health: &h}
	default:
		return errorResponse(CodeBadRequest, "unknown request kind")
	}
}

func errorResponse(code, message string) Response {
	return Response{Status: StatusError, Error: &ErrorBody{Code: code, Message: message}}
}

// validateObservationSchema strictly decodes one observation against the closed v1 wire
// schema by wrapping it in a minimal batch envelope and running the shared strict decoder
// (wire.DecodeObservationBatch), which rejects unknown fields, unknown discriminators, and
// out-of-range sequences with a typed error. It intentionally reuses the ingest-side strict
// decoder rather than a bespoke one so the endpoint and platform agree on what "valid" means.
// The batch decoder does not enforce contiguity, so the placeholder sequence the producer
// sealed with is accepted; the daemon re-stamps the authoritative sequence afterward.
func validateObservationSchema(obs wire.Observation) error {
	raw, err := obs.MarshalJSON()
	if err != nil {
		return fmt.Errorf("observer local: marshal observation: %w", err)
	}
	batch := make([]byte, 0, len(raw)+96)
	batch = append(batch, `{"schema_version":1,"source_id":"local","first_sequence":1,"last_sequence":1,"observations":[`...)
	batch = append(batch, raw...)
	batch = append(batch, `]}`...)
	if _, err := wire.DecodeObservationBatch(batch); err != nil {
		return err
	}
	return nil
}

// Shutdown stops accepting new connections, drains in-flight handlers, and removes the runtime
// socket. It blocks until all in-flight requests complete or ctx is cancelled.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.quit)
	ln := s.ln
	s.mu.Unlock()

	if ln != nil {
		ln.Close() // unblocks the accept loop
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("observer local: remove socket: %w", err)
	}
	return nil
}

// peerUIDFromSocket reads the connected peer's UID via Linux SO_PEERCRED. It uses the raw
// connection control seam so it never dups the fd or fights the runtime poller. A platform or
// syscall failure returns an error, which the handler treats as fail-closed.
func peerUIDFromSocket(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("observer local: raw conn: %w", err)
	}
	var ucred *syscall.Ucred
	var opErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		ucred, opErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctlErr != nil {
		return 0, fmt.Errorf("observer local: peer cred control: %w", ctlErr)
	}
	if opErr != nil {
		return 0, fmt.Errorf("observer local: peer cred: %w", opErr)
	}
	return ucred.Uid, nil
}

// ---- single-writer durable spool ----

// SpoolConfig configures the real durable spool writer.
type SpoolConfig struct {
	// Dir is the observer state directory; segments live under Dir/wal and sidecars under Dir.
	Dir string
	// SourceID is the durable source id stamped into the segment header (bounded 1..128).
	SourceID string
	// FormatVersion is the WAL format version written into new segment headers.
	FormatVersion uint32
	// Capacity is the byte-ceiling model input (validated by spool.NewCapacityModel).
	Capacity spool.CapacityConfig
	// Sync is the fsync seam threaded into every segment; nil selects (*os.File).Sync. Tests
	// inject a spy to prove a producer sees success only after fsync.
	Sync func(*os.File) error
	// Now supplies segment creation timestamps; nil selects time.Now.
	Now func() time.Time
}

// SpoolWriter composes the E1.2/E1.3 spool primitives (segment append, ack watermark, terminal
// reserves, capacity model) behind one mutex so the daemon is the serialized single writer. It
// assigns sequence and observation id, appends durably, and only then returns the ack.
type SpoolWriter struct {
	mu sync.Mutex

	dir             string
	walDir          string
	sourceID        string
	formatVersion   uint32
	terminalReserve int64
	sync            func(*os.File) error
	now             func() time.Time

	seg      *spool.Segment
	ack      *spool.AckState
	reserves *spool.Reserves
	capModel spool.CapacityModel
}

// NewSpoolWriter opens (or creates) the WAL and its sidecars and returns a ready single writer.
// It continues an existing WAL's sequence by opening the latest segment for append.
func NewSpoolWriter(cfg SpoolConfig) (*SpoolWriter, error) {
	if cfg.Dir == "" {
		return nil, errors.New("observer local: spool dir is required")
	}
	if cfg.SourceID == "" {
		return nil, errors.New("observer local: spool source id is required")
	}
	capModel, err := spool.NewCapacityModel(cfg.Capacity)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	walDir := filepath.Join(cfg.Dir, walSubdirName)
	if err := os.MkdirAll(walDir, stateDirMode); err != nil {
		return nil, fmt.Errorf("observer local: create wal dir: %w", err)
	}
	if err := os.Chmod(walDir, stateDirMode); err != nil {
		return nil, fmt.Errorf("observer local: chmod wal dir: %w", err)
	}
	// Boot recovery runs before any append: it validates the sidecars, truncates a partial
	// final frame (so OpenSegment sees a clean tail rather than bricking), reclaims an
	// interrupted CreateSegment slot, and reconstructs the authoritative next sequence for the
	// empty and fully-compacted-WAL cases. Interior corruption surfaces as a typed error and
	// refuses to start (the E1.4 quarantine path owns it), never a silent reset.
	rec, err := spool.Recover(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if rec.Outcome == spool.OutcomeInterruptedCreate {
		if _, err := spool.ReclaimInterruptedCreate(cfg.Dir, rec); err != nil {
			return nil, err
		}
	}
	seg, err := openOrCreateSegment(walDir, cfg, rec.NextSequence, now)
	if err != nil {
		return nil, err
	}
	ack, err := spool.LoadAckState(cfg.Dir, rec.HighestDurableSequence, spool.AckOptions{})
	if err != nil {
		seg.Close()
		return nil, err
	}
	reserves, err := spool.LoadReserves(cfg.Dir, cfg.Capacity.TerminalReserveBytes)
	if err != nil {
		seg.Close()
		return nil, err
	}
	return &SpoolWriter{
		dir:             cfg.Dir,
		walDir:          walDir,
		sourceID:        cfg.SourceID,
		formatVersion:   cfg.FormatVersion,
		terminalReserve: cfg.Capacity.TerminalReserveBytes,
		sync:            cfg.Sync,
		now:             now,
		seg:             seg,
		ack:             ack,
		reserves:        reserves,
		capModel:        capModel,
	}, nil
}

// openOrCreateSegment selects the active segment for append after recovery. It continues the
// latest segment only when its clean tail is exactly one below the recovered next sequence;
// otherwise (empty WAL, a fully-compacted WAL whose next sequence sits above the surviving
// frames, or an unopenable tail) it creates a fresh segment starting at the recovered next
// sequence, so the writer never reuses or skips a sequence.
func openOrCreateSegment(walDir string, cfg SpoolConfig, nextSequence int64, now func() time.Time) (*spool.Segment, error) {
	create := func() (*spool.Segment, error) {
		return spool.CreateSegment(walDir, spool.SegmentOptions{
			FormatVersion: cfg.FormatVersion,
			SourceID:      cfg.SourceID,
			FirstSequence: nextSequence,
			CreationTime:  now(),
			Sync:          cfg.Sync,
		})
	}
	segs, err := listSegmentFiles(walDir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return create()
	}
	last, err := spool.OpenSegment(segs[len(segs)-1], spool.SegmentOptions{Sync: cfg.Sync})
	if err != nil {
		return create()
	}
	if last.LastSequence()+1 == nextSequence {
		return last, nil
	}
	last.Close()
	return create()
}

// listSegmentFiles returns the wal directory's .seg files in ascending name order (which is
// ascending first-sequence order, given the zero-padded segment filenames).
func listSegmentFiles(walDir string) ([]string, error) {
	entries, err := os.ReadDir(walDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("observer local: list wal dir: %w", err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".seg" {
			continue
		}
		paths = append(paths, filepath.Join(walDir, e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// AppendObservation assigns the next sequence and a daemon observation id, seals them into the
// observation, appends the frame durably (fsync-before-return), advances the durable watermark,
// and returns the ack. It rotates to a fresh segment when the current one is full.
func (w *SpoolWriter) AppendObservation(obs wire.Observation) (AppendAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	seq := w.nextSequenceLocked()
	obsID := observationID(seq)
	stamped, err := restampObservation(obs, seq, obsID)
	if err != nil {
		return AppendAck{}, err
	}
	payload, err := wire.CanonicalBytes(stamped)
	if err != nil {
		return AppendAck{}, fmt.Errorf("observer local: canonical bytes: %w", err)
	}
	if err := w.appendFrameLocked(spool.Frame{Sequence: seq, Payload: payload}); err != nil {
		return AppendAck{}, err
	}
	w.ack.NoteDurable(seq)
	return AppendAck{Sequence: seq, ObservationID: obsID, DurableThrough: seq}, nil
}

// nextSequenceLocked is the sequence the next appended frame carries.
func (w *SpoolWriter) nextSequenceLocked() int64 {
	if last := w.seg.LastSequence(); last != 0 {
		return last + 1
	}
	return w.seg.FirstSequence()
}

// appendFrameLocked appends one frame, rotating to a fresh segment (starting at the frame's
// sequence) when the current segment is full. The single fsync inside spool.Segment.Append is
// the durable-before-reply boundary.
func (w *SpoolWriter) appendFrameLocked(f spool.Frame) error {
	err := w.seg.Append(f)
	if errors.Is(err, spool.ErrSegmentFull) {
		if cerr := w.seg.Close(); cerr != nil {
			return fmt.Errorf("observer local: close full segment: %w", cerr)
		}
		next, cerr := spool.CreateSegment(w.walDir, spool.SegmentOptions{
			FormatVersion: w.formatVersion,
			SourceID:      w.sourceID,
			FirstSequence: f.Sequence,
			CreationTime:  w.now(),
			Sync:          w.sync,
		})
		if cerr != nil {
			return fmt.Errorf("observer local: rotate segment: %w", cerr)
		}
		w.seg = next
		return w.seg.Append(f)
	}
	return err
}

// ReserveRun preallocates a run's terminal reserve and returns the resulting capacity view.
func (w *SpoolWriter) ReserveRun(runID string) (RunReserveAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reserves.Reserve(runID); err != nil {
		return RunReserveAck{}, err
	}
	return w.capacityAckLocked(runID)
}

// ReleaseRun releases a run's terminal reserve and returns the resulting capacity view.
func (w *SpoolWriter) ReleaseRun(runID string) (RunReserveAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reserves.Release(runID); err != nil {
		return RunReserveAck{}, err
	}
	return w.capacityAckLocked(runID)
}

func (w *SpoolWriter) capacityAckLocked(runID string) (RunReserveAck, error) {
	used, err := spool.WALBytes(w.dir)
	if err != nil {
		return RunReserveAck{}, err
	}
	open := w.reserves.OpenReserveBytes()
	st := w.capModel.Evaluate(used, open)
	return RunReserveAck{
		RunID:            runID,
		Open:             w.reserves.IsOpen(runID),
		OpenReserveBytes: open,
		Pressure:         st.Pressure.String(),
		AdmitNewRun:      st.AdmitNewExplicitRun,
	}, nil
}

// Health returns a content-free health/capacity snapshot.
func (w *SpoolWriter) Health() (HealthSnapshot, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	used, err := spool.WALBytes(w.dir)
	if err != nil {
		return HealthSnapshot{}, err
	}
	open := w.reserves.OpenReserveBytes()
	st := w.capModel.Evaluate(used, open)
	return HealthSnapshot{
		Healthy:             true,
		UsedBytes:           used,
		OpenReserveBytes:    open,
		OpenRuns:            len(w.reserves.OpenRuns()),
		AcknowledgedThrough: w.ack.AcknowledgedThrough(),
		HighestDurable:      w.ack.HighestDurable(),
		Pressure:            st.Pressure.String(),
		CeilingBytes:        st.CeilingBytes,
	}, nil
}

// Close closes the active segment. The sidecars are durable after each mutation.
func (w *SpoolWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seg == nil {
		return nil
	}
	return w.seg.Close()
}

// observationID is the daemon-assigned identity for the assigned sequence. It is deterministic
// and per-source unique (sequence is unique within a source), and bounded well under the
// observation-id ceiling.
func observationID(seq int64) string {
	return fmt.Sprintf("obs_%020d", seq)
}

// restampObservation overwrites the observation's sequence and observation_id with the
// daemon-assigned values. The producer sealed the observation with a placeholder pair for
// transport; single-writer sequence assignment is the daemon's invariant, so it re-stamps the
// envelope here. It edits only the two envelope fields via a localized JSON round-trip and
// leaves the concrete payload untouched.
func restampObservation(obs wire.Observation, seq int64, obsID string) (wire.Observation, error) {
	raw, err := obs.MarshalJSON()
	if err != nil {
		return wire.Observation{}, fmt.Errorf("observer local: marshal observation: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return wire.Observation{}, fmt.Errorf("observer local: observation is not a JSON object: %w", err)
	}
	if _, ok := fields["kind"]; !ok {
		return wire.Observation{}, errors.New("observer local: observation missing kind discriminator")
	}
	seqRaw, err := json.Marshal(seq)
	if err != nil {
		return wire.Observation{}, err
	}
	idRaw, err := json.Marshal(obsID)
	if err != nil {
		return wire.Observation{}, err
	}
	fields["sequence"] = seqRaw
	fields["observation_id"] = idRaw
	merged, err := json.Marshal(fields)
	if err != nil {
		return wire.Observation{}, err
	}
	var out wire.Observation
	if err := out.UnmarshalJSON(merged); err != nil {
		return wire.Observation{}, fmt.Errorf("observer local: reassemble observation: %w", err)
	}
	return out, nil
}
