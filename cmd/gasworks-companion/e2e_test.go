//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/x509"
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
	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// This is the local end-to-end proof for Checkpoint 1: a REAL assembled daemon.Service (WAL
// spool + socket server + uploader loop + transcript watcher) is driven through the real
// `run` and `hook codex` subcommands and a tailed transcript, and its uploader delivers to a
// STRICT-DECODING httptest Collector that mirrors the platform ingest — it decodes each
// batch against the committed wire types, runs the endpoint-symmetric semantic validators
// (including the E1.11 defense-in-depth rules), verifies the body is canonical, and returns
// a valid capped-contiguous IngestAck. The tests assert the received observations, the
// durable WAL frames, AND the local acknowledgement watermark — not just HTTP success — and
// prove at-least-once delivery under a transient fault and the METADATA_ONLY content
// guarantee end to end.
//
// It is the in-repo proof. A TRUE cross-repo e2e (this binary vs the real platform Collector
// cmd/observer-ingest with Postgres/ClickHouse) is not attempted here — it needs the platform
// module, which is out of this module's dependency closure by construction (see
// boundary_test.go). That belongs in a nightly cross-repo job; the httptest Collector is the
// faithful in-repo stand-in for the wire contract.

// e2eSourceID is a pattern-valid source id (^src_[0-9a-zA-Z]{1,64}$) so the Collector's
// evidence.ValidateBatch source_id check accepts the daemon's batches.
const e2eSourceID = "src_019f7a1000observerpilote2e01"

// fixedToken is a static bearer source; the credential is source-bound but its value is
// irrelevant to the Collector, which only checks the source binding on the ack.
type fixedToken struct{ tok string }

func (f fixedToken) Token(context.Context) (string, error) { return f.tok, nil }

// strictCollector is the in-repo stand-in for the platform ingest endpoint. It records every
// received request body (for the byte-identical-replay and content-guarantee assertions),
// strict-decodes and validates each batch exactly like the platform, verifies canonical
// form, and returns a valid capped-contiguous ack. With faultOnce set it returns a single
// transient 503 before acking anything, so the same batch must replay.
type strictCollector struct {
	t         *testing.T
	mu        sync.Mutex
	bodies    [][]byte       // every request body in arrival order (incl. faulted attempts)
	kindCount map[string]int // observation kinds accepted on 200 responses
	accepted  int            // total observations accepted on 200 responses
	requests  int            // total requests (incl. the faulted one)
	faultOnce bool
	faulted   bool
}

func (c *strictCollector) snapshotBodies() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.bodies))
	copy(out, c.bodies)
	return out
}

func (c *strictCollector) acceptedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted
}

func (c *strictCollector) kind(k wire.ObservationEnvelopeKind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kindCount[string(k)]
}

func (c *strictCollector) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

func (c *strictCollector) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/observation-batches" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	c.requests++
	c.bodies = append(c.bodies, append([]byte(nil), body...))
	fault := c.faultOnce && !c.faulted
	if fault {
		c.faulted = true
	}
	c.mu.Unlock()

	if fault {
		// A transient failure: acknowledge nothing, hold nothing. The uploader must replay
		// the identical batch on the next attempt.
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	// Strict decode against the committed wire types (rejects an unmodelled field, an
	// unknown kind, an out-of-range sequence, ...).
	decoded, err := wire.DecodeObservationBatch(body)
	if err != nil {
		writeObserverError(w, http.StatusBadRequest, "INVALID_BATCH", "strict decode: "+err.Error())
		return
	}
	// Endpoint-symmetric semantic validation (contiguity, drain-pair, caps, and the E1.11
	// defense-in-depth constraints: source_id pattern, observation_id, model minLength).
	if err := evidence.ValidateBatch(decoded); err != nil {
		writeObserverError(w, http.StatusUnprocessableEntity, "SEMANTIC_VIOLATION", err.Error())
		return
	}
	// The body must equal its own canonical re-encoding — a non-canonical body (or a tampered
	// one) is rejected, mirroring the platform's canonical-hash dedup contract.
	if err := assertCanonicalBatch(body); err != nil {
		writeObserverError(w, http.StatusBadRequest, "NON_CANONICAL", err.Error())
		return
	}

	c.mu.Lock()
	for i := range decoded.Observations {
		c.kindCount[decoded.Observations[i].Kind]++
	}
	c.accepted += len(decoded.Observations)
	c.mu.Unlock()

	ack := wire.IngestAck{
		SourceId:                    decoded.SourceID,
		AcknowledgedThroughSequence: decoded.LastSequence,
		Accepted:                    decoded.LastSequence - decoded.FirstSequence + 1,
		Duplicates:                  0,
	}
	b, _ := json.Marshal(ack)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// writeObserverError emits the typed ObserverError envelope the client decodes on a hold.
func writeObserverError(w http.ResponseWriter, status int, code, msg string) {
	oe := wire.ObserverError{Error: wire.ObserverErrorBody{
		Code:      wire.ObserverErrorBodyCode(code),
		Message:   msg,
		Retryable: false,
	}}
	b, _ := json.Marshal(oe)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// assertCanonicalBatch confirms a batch body is in the version-1 canonical form: it must
// equal wire.CanonicalBytes of its own decoded value.
func assertCanonicalBatch(body []byte) error {
	var batch wire.ObservationBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		return fmt.Errorf("unmarshal batch: %w", err)
	}
	canon, err := wire.CanonicalBytes(batch)
	if err != nil {
		return fmt.Errorf("canonical re-encode: %w", err)
	}
	if !bytes.Equal(canon, body) {
		return errors.New("batch body is not canonical")
	}
	return nil
}

// newStrictCollector stands up the httptest HTTPS Collector and a REAL upload.Client that
// trusts the server's self-signed cert additively (exercising the genuine TLS delivery path:
// HTTPS floor, additive customer CA, per-attempt credential read, typed response decode).
func newStrictCollector(t *testing.T, faultOnce bool) (*strictCollector, *upload.Client) {
	t.Helper()
	c := &strictCollector{t: t, kindCount: map[string]int{}, faultOnce: faultOnce}
	srv := httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse collector url: %v", err)
	}
	client, err := upload.NewClient(upload.Config{
		Endpoint:   u,
		SourceID:   e2eSourceID,
		Credential: fixedToken{"e2e-token"},
		CustomCAs:  []*x509.Certificate{srv.Certificate()},
	})
	if err != nil {
		t.Fatalf("upload.NewClient: %v", err)
	}
	return c, client
}

// e2eWatchPolicy mirrors the daemon's METADATA_ONLY sink policy (daemon.go watcherPolicy).
func e2eWatchPolicy() evidence.Policy {
	return evidence.Policy{
		Adapter:        codex.AdapterName,
		AdapterVersion: codex.AdapterVersion,
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
}

// durableKinds reads every durable WAL frame under dir and classifies it by transition/kind,
// tolerating a transient torn-tail read (returned as an error the caller retries).
func durableKinds(dir string) ([]string, error) {
	recs, err := upload.SpoolFrameStore{Dir: dir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(recs))
	for i := range recs {
		out = append(out, classify(recs[i].Payload))
	}
	return out, nil
}

// waitUntil polls cond until true or the deadline elapses.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestObserverEndToEndFullCapturePath is the Checkpoint 1 full-pipe proof: capture (run +
// hook + transcript) -> durable WAL -> canonical bytes -> HTTPS batch -> ack -> local
// cursor-advance, with the METADATA_ONLY content guarantee held through the whole pipe.
func TestObserverEndToEndFullCapturePath(t *testing.T) {
	sh := shPath(t)
	stateDir := t.TempDir()
	transcriptRoot := t.TempDir()
	cursorDir := t.TempDir()

	coll, client := newStrictCollector(t, false)

	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:               stateDir,
		SourceID:          e2eSourceID,
		Capacity:          permissiveCap(),
		RegistrySource:    e2eSourceID,
		RegistryWorkspace: "ws-e2e",
		Upload:            &daemon.UploadLoopConfig{Sender: client, Interval: 15 * time.Millisecond},
		Watch: &daemon.WatchLoopConfig{
			ApprovedRoots: []string{transcriptRoot},
			StateDir:      cursorDir,
			Policy:        e2eWatchPolicy(),
			Interval:      15 * time.Millisecond,
		},
		PeerUID: euidPeerE2E,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})

	const argvSentinel = "GWXSENTINELARGVe2e"
	const transcriptSentinel = "GWXSENTINELTRANSCRIPTe2e"

	// (a) run-wrap a real child. The argv carries a sentinel (a no-op ":" argument); the
	// child exits 7. RUN_STARTED / PROCESS_EXITED / RUN_ENDED must land durably.
	code := runRun([]string{"-dir", stateDir, "--", sh, "-c", ": " + argvSentinel + "; exit 7"})
	if code != 7 {
		t.Fatalf("run exit code = %d, want 7 (child exit passes through)", code)
	}

	// (b) hook codex: a SessionStart on stdin -> a durable SESSION_LIFECYCLE.
	sessionStart := `{"session_id":"sess-e2e","cwd":"/tmp/work","source":"startup"}`
	var hookCode int
	out := withStdio(t, sessionStart, func() {
		hookCode = runHook([]string{"codex", "-dir", stateDir, "-source-id", e2eSourceID})
	})
	if hookCode != 0 || len(out) != 0 {
		t.Fatalf("hook exit=%d out=%q, want 0/empty", hookCode, out)
	}

	// (c) a transcript the watcher tails -> parsed MESSAGE observations. The message text
	// carries a sentinel that METADATA_ONLY must strip.
	transcript := filepath.Join(transcriptRoot, "session.jsonl")
	writeFile(t, transcript, ""+
		`{"type":"message","role":"user","text":"`+transcriptSentinel+` one"}`+"\n"+
		`{"type":"message","role":"assistant","text":"`+transcriptSentinel+` two"}`+"\n")

	// The durable WAL holds the whole capture set: the run boundary sequence, the session
	// lifecycle, and both transcript messages.
	if !waitUntil(8*time.Second, func() bool {
		kinds, err := durableKinds(stateDir)
		if err != nil {
			return false
		}
		return containsLabel(kinds, "RUN_STARTED") &&
			containsLabel(kinds, "PROCESS_EXITED") &&
			containsLabel(kinds, "RUN_ENDED") &&
			containsLabel(kinds, string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE)) &&
			countLabel(kinds, string(wire.ObservationEnvelopeKindMESSAGE)) >= 2
	}) {
		kinds, _ := durableKinds(stateDir)
		t.Fatalf("durable WAL missing part of the capture set; kinds=%v", kinds)
	}

	// The uploader delivered every durable frame to the Collector AND the local ack advanced
	// through the whole range (cursor-advance): received == durable and ack == highest durable.
	if !waitUntil(8*time.Second, func() bool {
		kinds, err := durableKinds(stateDir)
		if err != nil {
			return false
		}
		n := int64(len(kinds))
		ack, err := spool.LoadAckState(stateDir, n, spool.AckOptions{})
		if err != nil {
			return false
		}
		return coll.acceptedCount() >= int(n) && ack.AcknowledgedThrough() == n
	}) {
		kinds, _ := durableKinds(stateDir)
		ack, _ := spool.LoadAckState(stateDir, int64(len(kinds)), spool.AckOptions{})
		t.Fatalf("delivery/ack did not converge: durable=%d accepted=%d ack=%d",
			len(kinds), coll.acceptedCount(), ack.AcknowledgedThrough())
	}

	// Received-vs-durable: the Collector saw each observation kind the pipe produced.
	if coll.kind(wire.ObservationEnvelopeKindRUNBOUNDARY) < 2 {
		t.Fatalf("Collector received %d RUN_BOUNDARY, want >= 2 (RUN_STARTED + RUN_ENDED)", coll.kind(wire.ObservationEnvelopeKindRUNBOUNDARY))
	}
	if coll.kind(wire.ObservationEnvelopeKindSESSIONLIFECYCLE) < 1 {
		t.Fatalf("Collector received no SESSION_LIFECYCLE from the hook path")
	}
	if coll.kind(wire.ObservationEnvelopeKindMESSAGE) < 2 {
		t.Fatalf("Collector received %d MESSAGE, want >= 2 from the transcript path", coll.kind(wire.ObservationEnvelopeKindMESSAGE))
	}
	if coll.kind(wire.ObservationEnvelopeKindPROCESSLIFECYCLE) < 1 {
		t.Fatalf("Collector received no PROCESS_LIFECYCLE from the run path")
	}

	// (e) Content guarantee end to end: the input carried sentinels (proven present in the
	// transcript on disk), but NONE reach the Collector-received canonical bytes.
	assertSentinelPresentInFile(t, transcript, transcriptSentinel)
	for i, body := range coll.snapshotBodies() {
		for _, sentinel := range []string{argvSentinel, transcriptSentinel} {
			if bytes.Contains(body, []byte(sentinel)) {
				t.Fatalf("METADATA_ONLY breach: sentinel %q leaked into Collector batch #%d:\n%s", sentinel, i, body)
			}
		}
	}
}

// TestObserverEndToEndAtLeastOnceUnderFault proves at-least-once delivery across a transient
// 503: the SAME batch replays byte-identically, the ack advances only on the 200, and no
// observation is lost or double-acked.
func TestObserverEndToEndAtLeastOnceUnderFault(t *testing.T) {
	sh := shPath(t)
	stateDir := t.TempDir()

	coll, client := newStrictCollector(t, true) // 503 the first delivery attempt, then 200

	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:            stateDir,
		SourceID:       e2eSourceID,
		Capacity:       permissiveCap(),
		RegistrySource: e2eSourceID,
		Upload: &daemon.UploadLoopConfig{
			Sender:   client,
			Interval: time.Hour, // ticker idle; we drive the drain deterministically
			// A no-op sleep keeps the retry loop instant; the 503 -> 200 replay is exercised
			// without real backoff delay.
			Retry: upload.RetryPolicy{MaxAttempts: 4, Sleep: func(context.Context, time.Duration) error { return nil }},
		},
		PeerUID: euidPeerE2E,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })

	// A real observed run produces a contiguous 4-frame boundary sequence (1..4).
	if code := runRun([]string{"-dir", stateDir, "--", sh, "-c", "exit 0"}); code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	kinds, err := durableKinds(stateDir)
	if err != nil {
		t.Fatalf("durableKinds: %v", err)
	}
	n := int64(len(kinds))
	if n < 1 {
		t.Fatalf("expected durable frames from the run, got %d", n)
	}

	// One drain: attempt 1 gets a 503 (retry, nothing advanced), attempt 2 gets a 200 that
	// acknowledges. Within a single drain the whole owed range is delivered.
	if err := svc.DrainUploads(context.Background()); err != nil {
		t.Fatalf("DrainUploads under transient fault: %v", err)
	}

	// The transient fault forced a replay: the Collector saw at least two requests, and the
	// first two request bodies are byte-identical (the same batch resent verbatim).
	bodies := coll.snapshotBodies()
	if len(bodies) < 2 {
		t.Fatalf("expected a replayed batch (>= 2 requests), got %d", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("replayed batch not byte-identical:\n#0: %s\n#1: %s", bodies[0], bodies[1])
	}
	if coll.requestCount() < 2 {
		t.Fatalf("expected >= 2 requests (1 faulted + >= 1 accepted), got %d", coll.requestCount())
	}

	// The ack advanced only on the 200 — exactly once, through the whole range — and the
	// Collector accepted each observation exactly once (no double-ack, no loss).
	ack, err := spool.LoadAckState(stateDir, n, spool.AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	if ack.AcknowledgedThrough() != n {
		t.Fatalf("acknowledged_through = %d, want %d (advance only on the 200)", ack.AcknowledgedThrough(), n)
	}
	if got := coll.acceptedCount(); int64(got) != n {
		t.Fatalf("Collector accepted %d observations, want exactly %d (delivered once, not double-acked)", got, n)
	}

	// A second drain has nothing owed: no new request, ack unchanged — the watermark did not
	// regress and the batch was not re-delivered.
	before := coll.requestCount()
	if err := svc.DrainUploads(context.Background()); err != nil {
		t.Fatalf("second DrainUploads: %v", err)
	}
	if coll.requestCount() != before {
		t.Fatalf("second drain re-sent a batch (requests %d -> %d); nothing should have been owed", before, coll.requestCount())
	}
	if got := coll.acceptedCount(); int64(got) != n {
		t.Fatalf("Collector accepted count changed to %d after an empty drain, want %d (no double-ack)", got, n)
	}
}

// assertSentinelPresentInFile proves the negative test is meaningful: the sentinel really is
// present in the captured input, so its absence downstream is a genuine guarantee.
func assertSentinelPresentInFile(t *testing.T, path, sentinel string) {
	t.Helper()
	b, err := readFileE2E(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Contains(b, []byte(sentinel)) {
		t.Fatalf("test precondition: sentinel %q not present in the captured input %s", sentinel, path)
	}
}

// euidPeerE2E accepts the connecting client as the daemon owner (the test process), the same
// deterministic peer-uid seam the other cmd tests use.
func euidPeerE2E(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil }

// countLabel counts occurrences of want in labels.
func countLabel(labels []string, want string) int {
	n := 0
	for _, l := range labels {
		if l == want {
			n++
		}
	}
	return n
}

// writeFile writes content to path with owner-only permissions, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// readFileE2E reads a file for the content-guarantee precondition check.
func readFileE2E(path string) ([]byte, error) { return os.ReadFile(path) }
