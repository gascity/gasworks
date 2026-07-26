//go:build linux

package local

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// ---- helpers ----

func permissiveCapacity() spool.CapacityConfig {
	return spool.CapacityConfig{
		CeilingBytes:         1 << 30, // 1 GiB
		TerminalReserveBytes: 1 << 20, // 1 MiB
		MaxSegmentBytes:      spool.DefaultSegmentCeiling,
		ScratchBytes:         1 << 20,
		SafetyMarginRatio:    spool.MinSafetyMarginRatio,
	}
}

func newWriter(t *testing.T, dir string, sync func(*os.File) error) *SpoolWriter {
	t.Helper()
	w, err := NewSpoolWriter(SpoolConfig{
		Dir:      dir,
		SourceID: "src_test",
		Capacity: permissiveCapacity(),
		Sync:     sync,
	})
	if err != nil {
		t.Fatalf("NewSpoolWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func startServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv
}

func sealMessage(t *testing.T, seq int64, id string) wire.Observation {
	t.Helper()
	obs, err := pendingMessage(t).Seal(seq, id)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return obs
}

func pendingMessage(t *testing.T) evidence.PendingObservation {
	t.Helper()
	occ := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	c := evidence.Common{
		OccurredAt: occ,
		CapturedAt: occ.Add(25 * time.Millisecond),
		Provenance: wire.Provenance{
			Adapter:        "codex-hook",
			AdapterVersion: "1.0.0",
			ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		},
	}
	p, err := evidence.NewMessage(c, evidence.MessageInput{Role: wire.MessagePayloadRoleUSER})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	return p
}

func readFrames(t *testing.T, dir string) []spool.Frame {
	t.Helper()
	walDir := filepath.Join(dir, "wal")
	entries, err := os.ReadDir(walDir)
	if err != nil {
		t.Fatalf("read wal dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".seg" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var frames []spool.Frame
	for _, n := range names {
		seg, err := spool.OpenSegment(filepath.Join(walDir, n), spool.SegmentOptions{})
		if err != nil {
			t.Fatalf("OpenSegment %s: %v", n, err)
		}
		fr, err := seg.ReadAll()
		seg.Close()
		if err != nil {
			t.Fatalf("ReadAll %s: %v", n, err)
		}
		frames = append(frames, fr...)
	}
	return frames
}

func uidPtr(u uint32) *uint32 { return &u }

func managedRuntimeDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "gasworks-observer-"+strconv.Itoa(os.Geteuid()))
}

// ---- round-trip append proves durable ack with an assigned sequence ----

func TestAppendRoundTripAssignsSequence(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})
	c := NewClient(srv.SocketPath())
	ctx := context.Background()

	ack1, err := c.AppendObservation(ctx, pendingMessage(t))
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if ack1.Sequence != 1 || ack1.ObservationID != observationID(1) {
		t.Fatalf("ack1 = %+v, want seq 1 id %s", ack1, observationID(1))
	}
	ack2, err := c.AppendObservation(ctx, pendingMessage(t))
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if ack2.Sequence != 2 {
		t.Fatalf("ack2 seq = %d, want 2", ack2.Sequence)
	}

	// Prove the durable payload carries the daemon-assigned sequence and id (re-stamp worked).
	frames := readFrames(t, dir)
	if len(frames) != 2 {
		t.Fatalf("durable frames = %d, want 2", len(frames))
	}
	for i, f := range frames {
		wantSeq := int64(i + 1)
		if f.Sequence != wantSeq {
			t.Fatalf("frame %d sequence = %d, want %d", i, f.Sequence, wantSeq)
		}
		var env struct {
			Sequence      int64  `json:"sequence"`
			ObservationID string `json:"observation_id"`
			Kind          string `json:"kind"`
		}
		if err := json.Unmarshal(f.Payload, &env); err != nil {
			t.Fatalf("frame %d payload: %v", i, err)
		}
		if env.Sequence != wantSeq {
			t.Fatalf("frame %d payload sequence = %d, want %d", i, env.Sequence, wantSeq)
		}
		if env.ObservationID != observationID(wantSeq) {
			t.Fatalf("frame %d payload id = %q, want %q", i, env.ObservationID, observationID(wantSeq))
		}
		if env.Kind == "" {
			t.Fatalf("frame %d payload missing kind", i)
		}
	}
}

func TestServerSeparatesRuntimeSocketFromDurableState(t *testing.T) {
	stateDir := t.TempDir()
	runtimeDir := managedRuntimeDir(t)
	socketPath := filepath.Join(runtimeDir, "socket")
	w := newWriter(t, stateDir, nil)
	srv := startServer(t, ServerConfig{
		Dir:        stateDir,
		SocketPath: socketPath,
		Spool:      w,
	})

	if srv.SocketPath() != socketPath {
		t.Fatalf("SocketPath = %q, want %q", srv.SocketPath(), socketPath)
	}
	if info, err := os.Stat(runtimeDir); err != nil {
		t.Fatalf("stat runtime dir: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir mode = %04o, want 0700", info.Mode().Perm())
	}
	if _, err := NewClient(socketPath).AppendObservation(context.Background(), pendingMessage(t)); err != nil {
		t.Fatalf("append through separate socket: %v", err)
	}
	if got := len(readFrames(t, stateDir)); got != 1 {
		t.Fatalf("durable frames in state dir = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "wal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WAL was written under runtime dir: %v", err)
	}
}

func TestServerRejectsSymlinkedRuntimeSocketDirectory(t *testing.T) {
	stateDir := t.TempDir()
	parent := t.TempDir()
	actualRuntime := filepath.Join(parent, "actual")
	if err := os.Mkdir(actualRuntime, 0o700); err != nil {
		t.Fatalf("mkdir actual runtime: %v", err)
	}
	symlinkRuntime := filepath.Join(parent, "gasworks-observer-"+strconv.Itoa(os.Geteuid()))
	if err := os.Symlink(actualRuntime, symlinkRuntime); err != nil {
		t.Fatalf("symlink runtime: %v", err)
	}
	w := newWriter(t, stateDir, nil)
	srv, err := NewServer(ServerConfig{
		Dir:        stateDir,
		SocketPath: filepath.Join(symlinkRuntime, "socket"),
		Spool:      w,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err == nil || !strings.Contains(err.Error(), "runtime directory") {
		t.Fatalf("Start error = %v, want symlinked runtime directory refusal", err)
	}
}

func TestServerRejectsRootAsManagedStateOrRuntimeDirectory(t *testing.T) {
	stateDir := t.TempDir()
	w := newWriter(t, stateDir, nil)
	for _, cfg := range []ServerConfig{
		{Dir: string(filepath.Separator), Spool: w},
		{Dir: stateDir, SocketPath: filepath.Join(string(filepath.Separator), "socket"), Spool: w},
	} {
		if _, err := NewServer(cfg); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("NewServer(%+v) error = %v, want unsafe directory refusal", cfg, err)
		}
	}
}

func TestServerRejectsUnmanagedExplicitRuntimeDirectory(t *testing.T) {
	stateDir := t.TempDir()
	w := newWriter(t, stateDir, nil)
	_, err := NewServer(ServerConfig{
		Dir:        stateDir,
		SocketPath: filepath.Join(t.TempDir(), "socket"),
		Spool:      w,
	})
	if err == nil || !strings.Contains(err.Error(), "dedicated runtime directory") {
		t.Fatalf("NewServer error = %v, want dedicated runtime directory refusal", err)
	}
}

func TestServerRefusesNonSocketAtRuntimePath(t *testing.T) {
	stateDir := t.TempDir()
	runtimeDir := managedRuntimeDir(t)
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	socketPath := filepath.Join(runtimeDir, "socket")
	if err := os.WriteFile(socketPath, []byte("preserve me"), 0o600); err != nil {
		t.Fatalf("write runtime file: %v", err)
	}
	w := newWriter(t, stateDir, nil)
	srv, err := NewServer(ServerConfig{Dir: stateDir, SocketPath: socketPath, Spool: w})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Start error = %v, want non-socket refusal", err)
	}
	data, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatalf("read preserved runtime file: %v", err)
	}
	if string(data) != "preserve me" {
		t.Fatalf("runtime file changed to %q", data)
	}
}

func TestServerShutdownPreservesReplacementAtRuntimePath(t *testing.T) {
	stateDir := t.TempDir()
	runtimeDir := managedRuntimeDir(t)
	w := newWriter(t, stateDir, nil)
	srv := startServer(t, ServerConfig{
		Dir:        stateDir,
		SocketPath: filepath.Join(runtimeDir, socketFilename),
		Spool:      w,
	})
	socketPath := srv.SocketPath()
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("unlink live socket path: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("preserve me"), 0o600); err != nil {
		t.Fatalf("write replacement runtime file: %v", err)
	}

	err := srv.Shutdown(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Shutdown error = %v, want replacement refusal", err)
	}
	data, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatalf("read preserved replacement: %v", readErr)
	}
	if string(data) != "preserve me" {
		t.Fatalf("replacement changed to %q", data)
	}
}

func TestSpoolWriterBindsDurableSourceIdentity(t *testing.T) {
	dir := t.TempDir()
	first, err := NewSpoolWriter(SpoolConfig{
		Dir:      dir,
		SourceID: "src_original",
		Capacity: permissiveCapacity(),
	})
	if err != nil {
		t.Fatalf("first NewSpoolWriter: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first writer: %v", err)
	}

	rec, err := spool.Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.SourceID != "src_original" || rec.FormatVersion != 1 {
		t.Fatalf("durable identity = %q/v%d, want src_original/v1", rec.SourceID, rec.FormatVersion)
	}

	second, err := NewSpoolWriter(SpoolConfig{
		Dir:      dir,
		SourceID: "src_reattributed",
		Capacity: permissiveCapacity(),
	})
	if second != nil {
		_ = second.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "source identity") {
		t.Fatalf("second NewSpoolWriter error = %v, want source identity mismatch", err)
	}
	rec, err = spool.Recover(dir)
	if err != nil {
		t.Fatalf("Recover after rejected reopen: %v", err)
	}
	if rec.SourceID != "src_original" {
		t.Fatalf("identity changed after rejected reopen: %q", rec.SourceID)
	}
}

// TestAppendDurableBeforeReply proves a producer sees success only after the WAL fsync fires.
func TestAppendDurableBeforeReply(t *testing.T) {
	dir := t.TempDir()
	var armed atomic.Bool
	fsyncStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	sync := func(f *os.File) error {
		if armed.Load() {
			select {
			case fsyncStarted <- struct{}{}:
			default:
			}
			<-release
		}
		return f.Sync()
	}
	w := newWriter(t, dir, sync)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})
	c := NewClient(srv.SocketPath())

	armed.Store(true)
	ackCh := make(chan AppendAck, 1)
	errCh := make(chan error, 1)
	go func() {
		ack, err := c.AppendObservation(context.Background(), pendingMessage(t))
		if err != nil {
			errCh <- err
			return
		}
		ackCh <- ack
	}()

	// The fsync must begin.
	select {
	case <-fsyncStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("fsync did not start")
	}
	// The reply must NOT have arrived while fsync is still blocked.
	select {
	case a := <-ackCh:
		t.Fatalf("received ack %+v before fsync completed", a)
	case err := <-errCh:
		t.Fatalf("received error before fsync completed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	// Complete the fsync; only now may the ack arrive.
	close(release)
	select {
	case ack := <-ackCh:
		if ack.Sequence != 1 {
			t.Fatalf("ack seq = %d, want 1", ack.Sequence)
		}
	case err := <-errCh:
		t.Fatalf("append failed after fsync: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("no ack after fsync completed")
	}
}

// ---- peer-UID validation ----

func TestWrongPeerUIDRejectedRealCred(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	wrong := uint32(os.Geteuid()) + 1 // our real SO_PEERCRED uid will not match
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w, ExpectedUID: uidPtr(wrong)})
	c := NewClient(srv.SocketPath(), WithTimeout(2*time.Second))
	_, err := c.AppendObservation(context.Background(), pendingMessage(t))
	if err == nil {
		t.Fatal("expected rejection for mismatched peer uid")
	}
}

func TestPeerUIDComparisonSeam(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	// Inject a peer-cred reader that reports a uid distinct from the expected owner.
	srv := startServer(t, ServerConfig{
		Dir:         dir,
		Spool:       w,
		ExpectedUID: uidPtr(1000),
		PeerUID:     func(*net.UnixConn) (uint32, error) { return 4242, nil },
	})
	c := NewClient(srv.SocketPath(), WithTimeout(2*time.Second))
	if _, err := c.AppendObservation(context.Background(), pendingMessage(t)); err == nil {
		t.Fatal("expected rejection when peer uid != expected uid")
	}
}

func TestMatchingPeerUIDAccepted(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{
		Dir:         dir,
		Spool:       w,
		ExpectedUID: uidPtr(777),
		PeerUID:     func(*net.UnixConn) (uint32, error) { return 777, nil },
	})
	c := NewClient(srv.SocketPath())
	if _, err := c.AppendObservation(context.Background(), pendingMessage(t)); err != nil {
		t.Fatalf("expected acceptance for matching uid: %v", err)
	}
}

// ---- oversized / slow / malformed fail closed ----

func TestOversizedRequestFailsClosed(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w, MaxMessageBytes: 1024})
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 4096) // over the 1024 cap
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server to close an oversized request")
	}
}

func TestSlowRequestHitsReadDeadline(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w, ReadTimeout: 100 * time.Millisecond})
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Send a partial length prefix and then stall past the deadline.
	if _, err := conn.Write([]byte{0, 0}); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the server to close a stalled request on its read deadline")
	}
}

func TestMalformedDiscriminatorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})
	conn, err := net.Dial("unix", srv.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeMessage(conn, []byte(`{"kind":"WAT"}`), DefaultMaxMessageBytes); err != nil {
		t.Fatalf("write: %v", err)
	}
	respBytes, err := readMessage(conn, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp, err := DecodeResponse(respBytes)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeBadRequest {
		t.Fatalf("want BAD_REQUEST error, got %+v", resp)
	}
	// The append path must not have run: nothing durable.
	if frames := readFrames(t, dir); len(frames) != 0 {
		t.Fatalf("malformed request appended %d frames", len(frames))
	}
}

// ---- restart recreates and unlinks a stale socket ----

func TestRestartRecreatesSocketAndContinuesSequence(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	w1 := newWriter(t, dir, nil)
	srv1, err := NewServer(ServerConfig{Dir: dir, Spool: w1})
	if err != nil {
		t.Fatalf("NewServer 1: %v", err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatalf("Start 1: %v", err)
	}
	c1 := NewClient(srv1.SocketPath())
	ack1, err := c1.AppendObservation(ctx, pendingMessage(t))
	if err != nil {
		t.Fatalf("append on srv1: %v", err)
	}
	if ack1.Sequence != 1 {
		t.Fatalf("ack1 seq = %d, want 1", ack1.Sequence)
	}
	if err := srv1.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown srv1: %v", err)
	}
	_ = w1.Close()

	// Simulate a stale socket the crashed daemon never cleaned up.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: filepath.Join(dir, socketFilename),
		Net:  "unix",
	})
	if err != nil {
		t.Fatalf("listen stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}

	w2 := newWriter(t, dir, nil) // OpenSegment continues from sequence 1
	srv2 := startServer(t, ServerConfig{Dir: dir, Spool: w2})
	c2 := NewClient(srv2.SocketPath())
	ack2, err := c2.AppendObservation(ctx, pendingMessage(t))
	if err != nil {
		t.Fatalf("append on srv2 (stale socket should be unlinked): %v", err)
	}
	if ack2.Sequence != 2 {
		t.Fatalf("ack2 seq = %d, want 2 (sequence should continue across restart)", ack2.Sequence)
	}
}

// ---- bounded concurrency ----

type blockingSpool struct {
	active  int32
	maxSeen int32
	enter   chan struct{}
	release chan struct{}
}

func (b *blockingSpool) AppendObservation(wire.Observation) (AppendAck, error) {
	n := atomic.AddInt32(&b.active, 1)
	for {
		m := atomic.LoadInt32(&b.maxSeen)
		if n <= m || atomic.CompareAndSwapInt32(&b.maxSeen, m, n) {
			break
		}
	}
	b.enter <- struct{}{}
	<-b.release
	atomic.AddInt32(&b.active, -1)
	return AppendAck{Sequence: int64(n)}, nil
}

func (b *blockingSpool) ReserveRun(runID string) (RunReserveAck, error) {
	return RunReserveAck{RunID: runID}, nil
}
func (b *blockingSpool) ReleaseRun(runID string) (RunReserveAck, error) {
	return RunReserveAck{RunID: runID}, nil
}
func (b *blockingSpool) Health() (HealthSnapshot, error) { return HealthSnapshot{Healthy: true}, nil }

func TestBoundedConcurrency(t *testing.T) {
	dir := t.TempDir()
	const limit = 3
	const clients = 6
	bs := &blockingSpool{enter: make(chan struct{}, clients), release: make(chan struct{})}
	srv := startServer(t, ServerConfig{
		Dir:           dir,
		Spool:         bs,
		MaxConcurrent: limit,
		PeerUID:       func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	c := NewClient(srv.SocketPath(), WithTimeout(10*time.Second))

	for i := 0; i < clients; i++ {
		go func() { _, _ = c.AppendObservation(context.Background(), pendingMessage(t)) }()
	}
	// Exactly `limit` handlers should enter concurrently.
	for i := 0; i < limit; i++ {
		select {
		case <-bs.enter:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d handlers entered, want %d", i, limit)
		}
	}
	// No additional handler may enter while the limit is saturated.
	select {
	case <-bs.enter:
		t.Fatal("a handler entered beyond the concurrency limit")
	case <-time.After(250 * time.Millisecond):
	}
	if got := atomic.LoadInt32(&bs.maxSeen); got != limit {
		t.Fatalf("max concurrent handlers = %d, want %d", got, limit)
	}
	// Release; the remaining clients now proceed as slots free.
	close(bs.release)
	for i := 0; i < clients-limit; i++ {
		select {
		case <-bs.enter:
		case <-time.After(3 * time.Second):
			t.Fatal("remaining handlers did not proceed after release")
		}
	}
	if got := atomic.LoadInt32(&bs.maxSeen); got != limit {
		t.Fatalf("max concurrent handlers grew to %d after release, want %d", got, limit)
	}
}

// ---- graceful shutdown drains in-flight work ----

type gateSpool struct {
	enter   chan struct{}
	release chan struct{}
}

func (g *gateSpool) AppendObservation(wire.Observation) (AppendAck, error) {
	g.enter <- struct{}{}
	<-g.release
	return AppendAck{Sequence: 1, ObservationID: observationID(1), DurableThrough: 1}, nil
}
func (g *gateSpool) ReserveRun(runID string) (RunReserveAck, error) {
	return RunReserveAck{RunID: runID}, nil
}
func (g *gateSpool) ReleaseRun(runID string) (RunReserveAck, error) {
	return RunReserveAck{RunID: runID}, nil
}
func (g *gateSpool) Health() (HealthSnapshot, error) { return HealthSnapshot{Healthy: true}, nil }

func TestGracefulShutdownDrainsInFlight(t *testing.T) {
	dir := t.TempDir()
	gs := &gateSpool{enter: make(chan struct{}, 1), release: make(chan struct{})}
	srv, err := NewServer(ServerConfig{
		Dir:     dir,
		Spool:   gs,
		PeerUID: func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c := NewClient(srv.SocketPath(), WithTimeout(10*time.Second))

	ackCh := make(chan AppendAck, 1)
	errCh := make(chan error, 1)
	go func() {
		ack, err := c.AppendObservation(context.Background(), pendingMessage(t))
		if err != nil {
			errCh <- err
			return
		}
		ackCh <- ack
	}()

	select {
	case <-gs.enter: // an append is in flight
	case <-time.After(3 * time.Second):
		t.Fatal("append never reached the handler")
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- srv.Shutdown(context.Background()) }()

	// Shutdown must block while the in-flight request drains.
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before the in-flight request drained")
	case <-time.After(150 * time.Millisecond):
	}

	close(gs.release)
	select {
	case ack := <-ackCh:
		if ack.Sequence != 1 {
			t.Fatalf("drained ack seq = %d, want 1", ack.Sequence)
		}
	case err := <-errCh:
		t.Fatalf("in-flight request was dropped: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request never completed")
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown never returned")
	}
	// The socket is unlinked after shutdown.
	if _, err := os.Stat(srv.SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket not removed after shutdown: %v", err)
	}
}

// ---- owner-only modes ----

func TestOwnerOnlyModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != stateDirMode {
		t.Fatalf("state dir mode = %#o, want %#o", di.Mode().Perm(), stateDirMode)
	}
	si, err := os.Stat(srv.SocketPath())
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if si.Mode().Perm() != socketMode {
		t.Fatalf("socket mode = %#o, want %#o", si.Mode().Perm(), socketMode)
	}
	if si.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket path is not a socket: %v", si.Mode())
	}
	// The wal subdirectory is owner-only too.
	wi, err := os.Stat(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("stat wal dir: %v", err)
	}
	if wi.Mode().Perm() != stateDirMode {
		t.Fatalf("wal dir mode = %#o, want %#o", wi.Mode().Perm(), stateDirMode)
	}
}

// ---- reserve / release / status ----

func TestReserveReleaseAndStatus(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})
	c := NewClient(srv.SocketPath())
	ctx := context.Background()

	res, err := c.ReserveRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("ReserveRun: %v", err)
	}
	if !res.Open || res.OpenReserveBytes <= 0 {
		t.Fatalf("reserve ack = %+v, want open with reserve bytes", res)
	}
	h, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !h.Healthy || h.OpenRuns != 1 {
		t.Fatalf("status = %+v, want healthy with 1 open run", h)
	}
	rel, err := c.ReleaseRun(ctx, "run_1")
	if err != nil {
		t.Fatalf("ReleaseRun: %v", err)
	}
	if rel.Open {
		t.Fatalf("release ack still open: %+v", rel)
	}
	h2, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status after release: %v", err)
	}
	if h2.OpenRuns != 0 {
		t.Fatalf("open runs after release = %d, want 0", h2.OpenRuns)
	}
}

// ---- hook durable-capture-ack surfaces a clear failure ----

func TestCaptureObservationSurfacesUnacknowledged(t *testing.T) {
	// A client pointed at a nonexistent socket cannot obtain a durable ack.
	c := NewClient(filepath.Join(t.TempDir(), "absent.sock"), WithTimeout(500*time.Millisecond))
	_, err := c.CaptureObservation(context.Background(), pendingMessage(t))
	if !errors.Is(err, ErrCaptureUnacknowledged) {
		t.Fatalf("want ErrCaptureUnacknowledged, got %v", err)
	}
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("want ErrDaemonUnreachable in the cause chain, got %v", err)
	}
	// The surfaced error must not leak the absolute socket path (spec: errors carry no paths).
	if strings.ContainsRune(err.Error(), '/') {
		t.Fatalf("capture-failure error leaks a path: %q", err.Error())
	}
}

func TestCaptureObservationDurableAck(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})
	c := NewClient(srv.SocketPath())
	ack, err := c.CaptureObservation(context.Background(), pendingMessage(t))
	if err != nil {
		t.Fatalf("CaptureObservation: %v", err)
	}
	if ack.Sequence != 1 {
		t.Fatalf("capture ack seq = %d, want 1", ack.Sequence)
	}
}

// ---- red-team regressions ----

func rawRoundTrip(t *testing.T, socketPath string, req Request) Response {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := writeMessage(conn, payload, DefaultMaxMessageBytes); err != nil {
		t.Fatalf("write: %v", err)
	}
	respBytes, err := readMessage(conn, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	resp, err := DecodeResponse(respBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// Finding 0+2 (MAJOR): a slow-but-successful fsync that exceeds the read timeout must still be
// acknowledged — the read deadline bounds only request arrival, never the durable append or the
// reply. Before the deadline split, the single conn deadline expired during the fsync and the
// durable, sequence-assigned observation was reported to the producer as a failure.
func TestSlowFsyncBeyondReadTimeoutStillAcknowledged(t *testing.T) {
	dir := t.TempDir()
	var armed atomic.Bool
	sync := func(f *os.File) error {
		if armed.Load() {
			time.Sleep(400 * time.Millisecond) // fsync outlasts the 150ms read timeout
		}
		return f.Sync()
	}
	w := newWriter(t, dir, sync)
	srv := startServer(t, ServerConfig{
		Dir:          dir,
		Spool:        w,
		ReadTimeout:  150 * time.Millisecond,
		WriteTimeout: 3 * time.Second,
	})
	c := NewClient(srv.SocketPath(), WithTimeout(5*time.Second))

	armed.Store(true)
	ack, err := c.AppendObservation(context.Background(), pendingMessage(t))
	if err != nil {
		t.Fatalf("a durable slow-fsync append must be acknowledged, got: %v", err)
	}
	if ack.Sequence != 1 {
		t.Fatalf("ack seq = %d, want 1", ack.Sequence)
	}
	if frames := readFrames(t, dir); len(frames) != 1 {
		t.Fatalf("durable frames = %d, want 1", len(frames))
	}
}

// Finding 3 (MINOR): an observation carrying an unmodelled field is strict-decode rejected
// before it can be canonicalized into a frame, so the WAL SHA cannot diverge from the
// platform's strict-decoded canonical hash.
func TestUnmodelledObservationFieldRejectedBeforeAppend(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w})

	valid := sealMessage(t, 1, "obs_pending")
	raw, err := valid.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["totally_unmodelled"] = json.RawMessage(`"x"`)
	merged, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	var tampered wire.Observation
	if err := tampered.UnmarshalJSON(merged); err != nil {
		t.Fatalf("reassemble: %v", err)
	}

	resp := rawRoundTrip(t, srv.SocketPath(), Request{
		Kind:   KindAppendObservation,
		Append: &AppendObservationRequest{Observation: tampered},
	})
	if resp.Status != StatusError || resp.Error == nil || resp.Error.Code != CodeInvalidObservation {
		t.Fatalf("want INVALID_OBSERVATION error, got %+v", resp)
	}
	if frames := readFrames(t, dir); len(frames) != 0 {
		t.Fatalf("a tampered observation was appended (%d frames)", len(frames))
	}
}

// Finding 4 (MINOR): a transient accept error (fd exhaustion) must not permanently kill intake;
// the accept loop backs off and continues.
func TestAcceptLoopSurvivesTransientError(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv, err := NewServer(ServerConfig{Dir: dir, Spool: w})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	var injected atomic.Bool
	srv.acceptMiddleware = func(base func() (*net.UnixConn, error)) func() (*net.UnixConn, error) {
		return func() (*net.UnixConn, error) {
			if injected.CompareAndSwap(false, true) {
				return nil, syscall.EMFILE // one transient fd-exhaustion error
			}
			return base()
		}
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	c := NewClient(srv.SocketPath(), WithTimeout(3*time.Second))
	ack, err := c.AppendObservation(context.Background(), pendingMessage(t))
	if err != nil {
		t.Fatalf("intake did not recover after a transient accept error: %v", err)
	}
	if ack.Sequence != 1 {
		t.Fatalf("ack seq = %d, want 1", ack.Sequence)
	}
	if !injected.Load() {
		t.Fatal("the transient accept error was never injected")
	}
}

// Finding 5 (MINOR): a handler slot held by an idle connection is reclaimed when its read
// deadline fires, so a later legitimate request blocks then succeeds rather than starving.
func TestIdleSlotsReclaimedByReadDeadline(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	const limit = 2
	readTimeout := 300 * time.Millisecond
	srv := startServer(t, ServerConfig{Dir: dir, Spool: w, MaxConcurrent: limit, ReadTimeout: readTimeout})

	// Saturate every handler slot with connections that never send a request.
	var idle []net.Conn
	for i := 0; i < limit; i++ {
		conn, err := net.Dial("unix", srv.SocketPath())
		if err != nil {
			t.Fatalf("dial idle %d: %v", i, err)
		}
		idle = append(idle, conn)
	}
	t.Cleanup(func() {
		for _, conn := range idle {
			_ = conn.Close()
		}
	})
	time.Sleep(50 * time.Millisecond) // let the idle conns park in handlers

	c := NewClient(srv.SocketPath(), WithTimeout(5*time.Second))
	start := time.Now()
	ack, err := c.AppendObservation(context.Background(), pendingMessage(t))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("append never serviced after idle reclamation: %v", err)
	}
	if ack.Sequence != 1 {
		t.Fatalf("ack seq = %d, want 1", ack.Sequence)
	}
	if elapsed < readTimeout/2 {
		t.Fatalf("append served in %v; expected to wait ~%v for idle-slot reclamation", elapsed, readTimeout)
	}
}

// Boot recovery: a partial final frame (torn tail) is truncated at startup so the writer opens
// cleanly and continues, rather than bricking on an unopenable segment.
func TestBootRecoveryTruncatesTornTail(t *testing.T) {
	dir := t.TempDir()

	// Durably append one frame, then close.
	w1 := newWriter(t, dir, nil)
	srv1 := startServer(t, ServerConfig{Dir: dir, Spool: w1})
	c1 := NewClient(srv1.SocketPath())
	if _, err := c1.AppendObservation(context.Background(), pendingMessage(t)); err != nil {
		t.Fatalf("append: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv1.Shutdown(ctx)
	cancel()
	_ = w1.Close()

	// Corrupt the segment tail with a partial (torn) frame write.
	walDir := filepath.Join(dir, "wal")
	entries, err := os.ReadDir(walDir)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	var segPath string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".seg" {
			segPath = filepath.Join(walDir, e.Name())
		}
	}
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open seg: %v", err)
	}
	// A few bytes short of a full frame header: a genuine torn tail recovery must truncate.
	if _, err := f.Write([]byte{0x4F, 0x46, 0x52}); err != nil {
		t.Fatalf("write torn bytes: %v", err)
	}
	f.Close()

	// A fresh writer must recover (truncate the torn tail) and continue at sequence 2.
	w2 := newWriter(t, dir, nil)
	srv2 := startServer(t, ServerConfig{Dir: dir, Spool: w2})
	c2 := NewClient(srv2.SocketPath())
	ack, err := c2.AppendObservation(context.Background(), pendingMessage(t))
	if err != nil {
		t.Fatalf("boot recovery did not heal the torn tail: %v", err)
	}
	if ack.Sequence != 2 {
		t.Fatalf("post-recovery seq = %d, want 2", ack.Sequence)
	}
}
