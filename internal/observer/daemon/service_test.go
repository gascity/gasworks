//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

const testSourceID = "src_service_test"

func euidPeer(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil }

// serviceWatchPolicy mirrors the daemon's METADATA_ONLY sink policy.
func serviceWatchPolicy() evidence.Policy {
	return evidence.Policy{
		Adapter:        codex.AdapterName,
		AdapterVersion: codex.AdapterVersion,
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
}

// seedWAL appends sealed observations into a fresh WAL under dir and closes the writer, so a later
// NewService recovers them and ReplayWAL rebuilds the projection from them.
func seedWAL(t *testing.T, dir string, obs ...wire.Observation) {
	t.Helper()
	w, err := local.NewSpoolWriter(local.SpoolConfig{Dir: dir, SourceID: testSourceID, Capacity: permissiveCapacity()})
	if err != nil {
		t.Fatalf("seed NewSpoolWriter: %v", err)
	}
	for _, o := range obs {
		if _, err := w.AppendObservation(o); err != nil {
			t.Fatalf("seed AppendObservation: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}
}

// walKinds reads every durable frame under dir and returns its observation kinds in sequence order.
// It tolerates a transient torn tail (a frame the writer is mid-appending) by returning an error the
// caller retries.
func walKinds(dir string) ([]string, error) {
	store := upload.SpoolFrameStore{Dir: dir}
	recs, err := store.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		return nil, err
	}
	kinds := make([]string, 0, len(recs))
	for _, rec := range recs {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(rec.Payload); err != nil {
			return nil, err
		}
		kind, err := obs.Discriminator()
		if err != nil {
			return nil, err
		}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

func countKind(kinds []string, kind wire.ObservationEnvelopeKind) int {
	n := 0
	for _, k := range kinds {
		if k == string(kind) {
			n++
		}
	}
	return n
}

// eventually polls cond until it is true or the deadline elapses.
func eventually(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// ---- fake Collector (the E1.9 delivery endpoint) ----

type fixedToken struct{ tok string }

func (f fixedToken) Token(context.Context) (string, error) { return f.tok, nil }

type collector struct {
	sourceID string
	mu       sync.Mutex
	received int
	batches  int
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.received
}

func newCollector(t *testing.T, sourceID string) (*collector, *upload.Client) {
	t.Helper()
	c := &collector{sourceID: sourceID}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/observation-batches" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var env struct {
			FirstSequence int64             `json:"first_sequence"`
			LastSequence  int64             `json:"last_sequence"`
			SourceID      string            `json:"source_id"`
			Observations  []json.RawMessage `json:"observations"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.received += len(env.Observations)
		c.batches++
		c.mu.Unlock()
		ack := wire.IngestAck{
			SourceId:                    c.sourceID,
			AcknowledgedThroughSequence: env.LastSequence,
			Accepted:                    env.LastSequence - env.FirstSequence + 1,
			Duplicates:                  0,
		}
		b, _ := json.Marshal(ack)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse collector url: %v", err)
	}
	client, err := upload.NewClient(upload.Config{
		Endpoint:          u,
		SourceID:          sourceID,
		Credential:        fixedToken{"tok"},
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("upload.NewClient: %v", err)
	}
	return c, client
}

// TestServiceBoot proves the assembled endpoint boots in the required order and every subsystem is
// live: the WAL replay rebuilds the boundary/ancestry projection (queried back over the socket), the
// server serves, the uploader loop drains the seeded WAL to the fake Collector, and the watcher
// tails a temp transcript into durable WAL appends. It then proves graceful drain removes the socket.
func TestServiceBoot(t *testing.T) {
	stateDir := t.TempDir()
	transcriptRoot := t.TempDir()
	cursorDir := t.TempDir()

	// Seed the WAL BEFORE boot: a RUN_STARTED opens a boundary and a REGISTERED indexes an identity,
	// so ReplayWAL has real projection state to rebuild.
	id := wire.ProcessIdentity{BootId: "boot-seed", Pid: 4242, ProcessStartTime: 991}
	const seedRun = "run_seed_0001"
	seedWAL(t, stateDir,
		sealObs(t, runStartedPending(t, seedRun), 1),
		sealObs(t, registeredPending(t, id, seedRun), 2),
	)

	coll, uploadClient := newCollector(t, testSourceID)

	svc, err := NewService(ServiceConfig{
		Dir:               stateDir,
		SourceID:          testSourceID,
		Capacity:          permissiveCapacity(),
		RegistrySource:    testSourceID,
		RegistryWorkspace: "ws-1",
		Upload:            &UploadLoopConfig{Sender: uploadClient, Interval: 20 * time.Millisecond},
		Watch: &WatchLoopConfig{
			ApprovedRoots: []string{transcriptRoot},
			StateDir:      cursorDir,
			Policy:        serviceWatchPolicy(),
			Interval:      20 * time.Millisecond,
		},
		PeerUID: euidPeer,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !svc.Ready() {
		t.Fatal("service not ready after Start")
	}

	// (a) WAL replay rebuilt the registry — query it back over the socket.
	client := local.NewClient(svc.SocketPath())
	runID, found, err := client.LookupRegisteredProcess(context.Background(), id)
	if err != nil {
		t.Fatalf("LookupRegisteredProcess: %v", err)
	}
	if !found || runID != seedRun {
		t.Fatalf("replayed registry lookup = (%q, %v), want (%q, true)", runID, found, seedRun)
	}
	status, err := client.ResolveInheritedRun(context.Background(), seedRun, "ws-1")
	if err != nil {
		t.Fatalf("ResolveInheritedRun: %v", err)
	}
	if status != local.InheritedRunOpenSameScope {
		t.Fatalf("ResolveInheritedRun = %q, want open-same-scope", status)
	}

	// (b) The watcher tails a temp transcript into durable WAL appends.
	transcript := filepath.Join(transcriptRoot, "session.jsonl")
	writeFile(t, transcript, ""+
		`{"type":"message","role":"user","text":"hello one"}`+"\n"+
		`{"type":"message","role":"assistant","text":"hello two"}`+"\n")

	if !eventually(t, 5*time.Second, func() bool {
		kinds, err := walKinds(stateDir)
		return err == nil && countKind(kinds, wire.ObservationEnvelopeKindMESSAGE) >= 2
	}) {
		kinds, _ := walKinds(stateDir)
		t.Fatalf("watcher did not durably append the transcript messages; wal kinds=%v", kinds)
	}

	// (c) The uploader loop drained everything durable (2 seeded + 2 messages) to the Collector.
	if !eventually(t, 5*time.Second, func() bool { return coll.count() >= 4 }) {
		t.Fatalf("uploader delivered %d observations, want >= 4", coll.count())
	}

	// (d) Graceful drain withdraws the socket.
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.Shutdown(shCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := os.Stat(svc.SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after graceful drain: err=%v", err)
	}
	if svc.Ready() {
		t.Fatal("service still ready after Shutdown")
	}
	// Shutdown is idempotent.
	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// flakySpool wraps a real SpoolWriter and fails the failAt-th AppendObservation exactly once
// without delegating, so that append never reaches the durable WAL. It is the fault injector for
// the mid-batch double-append regression.
type flakySpool struct {
	inner  *local.SpoolWriter
	mu     sync.Mutex
	count  int
	failAt int
	fired  bool
}

func (f *flakySpool) AppendObservation(obs wire.Observation) (local.AppendAck, error) {
	f.mu.Lock()
	f.count++
	fail := !f.fired && f.count == f.failAt
	if fail {
		f.fired = true
	}
	f.mu.Unlock()
	if fail {
		return local.AppendAck{}, errors.New("flakySpool: injected non-durable append")
	}
	return f.inner.AppendObservation(obs)
}

func (f *flakySpool) ReserveRun(runID string) (local.RunReserveAck, error) {
	return f.inner.ReserveRun(runID)
}
func (f *flakySpool) ReleaseRun(runID string) (local.RunReserveAck, error) {
	return f.inner.ReleaseRun(runID)
}
func (f *flakySpool) Health() (local.HealthSnapshot, error) { return f.inner.Health() }

// TestMidBatchNoDoubleAppend is the carried-forward E1.10a red-team finding 2 regression: when the
// first candidate of a poll is durable but the second fails, the retry must NOT re-append the first
// (no WAL duplicate) and must not skip the second. The partial-commit path advances the cursor over
// the fully-delivered leading LINE so the next poll re-reads only the undelivered record.
func TestMidBatchNoDoubleAppend(t *testing.T) {
	stateDir := t.TempDir()
	transcriptRoot := t.TempDir()
	cursorDir := t.TempDir()

	writer, err := local.NewSpoolWriter(local.SpoolConfig{Dir: stateDir, SourceID: testSourceID, Capacity: permissiveCapacity()})
	if err != nil {
		t.Fatalf("NewSpoolWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	sp := &flakySpool{inner: writer, failAt: 2} // fail the 2nd append (candidate 2) once

	reg := NewRegistry(testSourceID, "ws")
	srv := startDaemonServer(t, stateDir, sp, reg)

	sink, err := NewCandidateSinkAdapter(SinkConfig{
		Client:        local.NewClient(srv.SocketPath()),
		Policy:        serviceWatchPolicy(),
		Provider:      codex.Provider,
		ParserVersion: codex.ParserVersion,
	})
	if err != nil {
		t.Fatalf("NewCandidateSinkAdapter: %v", err)
	}
	watcher, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots: []string{transcriptRoot},
		StateDir:      cursorDir,
		Sink:          NewPartialCandidateSinkAdapter(sink),
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	transcript := filepath.Join(transcriptRoot, "session.jsonl")
	writeFile(t, transcript, ""+
		`{"type":"message","role":"user","text":"candidate one"}`+"\n"+
		`{"type":"message","role":"assistant","text":"candidate two"}`+"\n")

	// First poll: candidate 1 durable, candidate 2's append fails -> partial commit past line 1.
	if err := watcher.Poll(context.Background()); err == nil {
		t.Fatal("first Poll: expected the injected mid-batch delivery failure to surface")
	}
	kinds, err := walKinds(stateDir)
	if err != nil {
		t.Fatalf("walKinds after first poll: %v", err)
	}
	if got := countKind(kinds, wire.ObservationEnvelopeKindMESSAGE); got != 1 {
		t.Fatalf("after first poll: %d durable MESSAGE frames, want exactly 1 (candidate 1 only); kinds=%v", got, kinds)
	}

	// Second poll: only candidate 2 is re-read (candidate 1 was partial-committed) and now succeeds.
	if err := watcher.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	kinds, err = walKinds(stateDir)
	if err != nil {
		t.Fatalf("walKinds after second poll: %v", err)
	}
	if got := countKind(kinds, wire.ObservationEnvelopeKindMESSAGE); got != 2 {
		t.Fatalf("after retry: %d durable MESSAGE frames, want exactly 2 (no duplicate of candidate 1); kinds=%v", got, kinds)
	}
}

// TestServiceUploadLoopHold proves a held delivery (a 4xx the retry layer classifies as hold) never
// advances the acknowledgement: the frames stay durable and the loop keeps holding without loss.
func TestServiceUploadLoopHold(t *testing.T) {
	stateDir := t.TempDir()
	seedWAL(t, stateDir, sealObs(t, runStartedPending(t, "run_hold_1"), 1))

	// A Collector that always 403s -> DispositionHold.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	client, err := upload.NewClient(upload.Config{Endpoint: u, SourceID: testSourceID, Credential: fixedToken{"t"}, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	svc, err := NewService(ServiceConfig{
		Dir: stateDir, SourceID: testSourceID, Capacity: permissiveCapacity(),
		Upload:  &UploadLoopConfig{Sender: client, Retry: upload.RetryPolicy{MaxAttempts: 1}},
		PeerUID: euidPeer,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })

	// A drain pass holds and returns an operator error; nothing is acknowledged.
	err = svc.DrainUploads(context.Background())
	if err == nil {
		t.Fatal("DrainUploads: expected a hold error from the 403 Collector")
	}
	if !errors.Is(err, upload.ErrHeld) {
		t.Fatalf("DrainUploads error = %v, want ErrHeld", err)
	}
	ack, err := spool.LoadAckState(stateDir, 1, spool.AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	if ack.AcknowledgedThrough() != 0 {
		t.Fatalf("acknowledged_through = %d after a hold, want 0 (nothing advanced)", ack.AcknowledgedThrough())
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func singletonConfig(dir string) ServiceConfig {
	return ServiceConfig{
		Dir:            dir,
		SourceID:       testSourceID,
		Capacity:       permissiveCapacity(),
		RegistrySource: testSourceID,
		PeerUID:        euidPeer,
	}
}

// TestSingletonRejectsSecondDaemon proves the exclusive directory lock refuses a second daemon on
// the same state dir (no socket hijack / shared WAL / ack regression), and that the lock releases on
// Shutdown so a legitimate restart succeeds.
func TestSingletonRejectsSecondDaemon(t *testing.T) {
	dir := t.TempDir()

	svc1, err := NewService(singletonConfig(dir))
	if err != nil {
		t.Fatalf("NewService svc1: %v", err)
	}
	if err := svc1.Start(); err != nil {
		t.Fatalf("Start svc1: %v", err)
	}

	// A second daemon must fail fast at construction — the WAL-directory flock is held.
	svc2, err := NewService(singletonConfig(dir))
	if !errors.Is(err, ErrAlreadyRunning) {
		if svc2 != nil {
			_ = svc2.Shutdown(context.Background())
		}
		t.Fatalf("second NewService err = %v, want ErrAlreadyRunning", err)
	}

	// After the first daemon shuts down (releasing the flock), a legitimate restart succeeds.
	if err := svc1.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown svc1: %v", err)
	}
	svc3, err := NewService(singletonConfig(dir))
	if err != nil {
		t.Fatalf("restart NewService: %v", err)
	}
	if err := svc3.Start(); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	t.Cleanup(func() { _ = svc3.Shutdown(context.Background()) })
	if !svc3.Ready() {
		t.Fatal("restarted daemon not ready")
	}
}

// TestStaleSocketIsCleaned proves a socket path left behind by a crashed daemon (no live answer) is
// not treated as a live daemon: the new daemon starts and the server recreates the socket.
func TestStaleSocketIsCleaned(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A leftover, dead socket-path artifact (nothing listening behind it).
	writeFile(t, filepath.Join(dir, "socket"), "stale")

	svc, err := NewService(singletonConfig(dir))
	if err != nil {
		t.Fatalf("NewService over stale socket: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start over stale socket: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	if !svc.Ready() {
		t.Fatal("daemon not ready after cleaning a stale socket")
	}
	// The server now really answers.
	if _, err := local.NewClient(svc.SocketPath()).Status(context.Background()); err != nil {
		t.Fatalf("Status after stale-socket cleanup: %v", err)
	}
}

// TestConcurrentDrainDeliversOnce proves the uploader drain serialization: many concurrent passes
// deliver each seeded frame exactly once and never regress the watermark.
func TestConcurrentDrainDeliversOnce(t *testing.T) {
	dir := t.TempDir()
	const n = 5
	seeds := make([]wire.Observation, 0, n)
	for i := 0; i < n; i++ {
		seeds = append(seeds, sealObs(t, runStartedPending(t, fmt.Sprintf("run_%02d", i)), int64(i+1)))
	}
	seedWAL(t, dir, seeds...)

	coll, client := newCollector(t, testSourceID)
	svc, err := NewService(ServiceConfig{
		Dir: dir, SourceID: testSourceID, Capacity: permissiveCapacity(),
		Upload:  &UploadLoopConfig{Sender: client, Interval: time.Hour}, // ticker idle; drive drains manually
		PeerUID: euidPeer,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.DrainUploads(context.Background())
		}()
	}
	wg.Wait()

	if got := coll.count(); got != n {
		t.Fatalf("collector received %d observations from 8 concurrent drains, want exactly %d (each delivered once)", got, n)
	}
	ack, err := spool.LoadAckState(dir, n, spool.AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	if ack.AcknowledgedThrough() != n {
		t.Fatalf("acknowledged_through = %d, want %d (monotonic, no regression)", ack.AcknowledgedThrough(), n)
	}
}
