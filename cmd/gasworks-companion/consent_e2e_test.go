//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// This is the end-to-end proof that the companion follows its consent policy file live: a REAL
// assembled daemon, wired by the same helpers runDaemon uses (openConsentPolicy +
// newConsentWatchLoopConfig over -root-policy-file), uploads through the real HTTPS client to a
// stub collector that strictly decodes and validates every batch (the strictCollector) and also
// serves the content route. The owner's policy file is rewritten while the daemon runs, exactly as
// bd writes it (temp file + rename), and the collector's view is asserted after each change.

// contentPost is one whole-transcript upload the stub collector received.
type contentPost struct {
	sourcePath string
	session    string
	bytes      int
}

// consentStub is the stub collector: strictCollector for batches, plus the content route.
type consentStub struct {
	*strictCollector
	url     string
	cert    *x509.Certificate
	mu      sync.Mutex
	posts   []contentPost
	arrived chan struct{}
}

func (c *consentStub) serve(w http.ResponseWriter, r *http.Request) {
	defer c.signal()
	if r.URL.Path != "/v1/artifacts/content" {
		c.strictCollector.serve(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.posts = append(c.posts, contentPost{
		sourcePath: r.Header.Get("X-Observer-Source-Path"),
		session:    r.Header.Get("X-Observer-Native-Session-Id"),
		bytes:      len(body),
	})
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"gc_session_id":"gcs_e2e","receipt_id":"rcpt_e2e","status":"stored"}`))
}

// signal wakes a waiter after every request, without ever blocking the handler.
func (c *consentStub) signal() {
	select {
	case c.arrived <- struct{}{}:
	default:
	}
}

// contentFor returns the content uploads of one transcript path.
func (c *consentStub) contentFor(path string) []contentPost {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []contentPost
	for _, p := range c.posts {
		if p.sourcePath == path {
			out = append(out, p)
		}
	}
	return out
}

// e2eObservation is the part of an uploaded observation these tests read.
type e2eObservation struct {
	Kind       string `json:"kind"`
	Sequence   int64  `json:"sequence"`
	Provenance struct {
		SourceLocator string `json:"source_locator"`
	} `json:"provenance"`
	Diagnostic *struct {
		Context string `json:"context"`
	} `json:"capture_diagnostic"`
}

// uploaded returns every observation the collector received, by sequence.
func (c *consentStub) uploaded(t *testing.T) map[int64]e2eObservation {
	t.Helper()
	out := map[int64]e2eObservation{}
	for _, body := range c.snapshotBodies() {
		var batch struct {
			Observations []e2eObservation `json:"observations"`
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Fatalf("decode uploaded batch: %v", err)
		}
		for _, o := range batch.Observations {
			out[o.Sequence] = o
		}
	}
	return out
}

// countLocator counts uploaded observations of one transcript locator.
func (c *consentStub) countLocator(t *testing.T, locator string) int {
	t.Helper()
	n := 0
	for _, o := range c.uploaded(t) {
		if o.Provenance.SourceLocator == locator {
			n++
		}
	}
	return n
}

// withheldCount counts uploaded withheld placeholders.
func (c *consentStub) withheldCount(t *testing.T) int {
	t.Helper()
	n := 0
	for _, o := range c.uploaded(t) {
		if o.Kind == "CAPTURE_DIAGNOSTIC" && o.Diagnostic != nil && strings.Contains(o.Diagnostic.Context, "withdrew consent") {
			n++
		}
	}
	return n
}

func newConsentStub(t *testing.T) (*consentStub, *upload.Client) {
	t.Helper()
	c := &consentStub{strictCollector: &strictCollector{t: t, kindCount: map[string]int{}}, arrived: make(chan struct{}, 1)}
	srv := httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)
	c.url, c.cert = srv.URL, srv.Certificate()
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

// e2eClock is the daemon's clock, advanced by the test so the content debounce is deterministic.
type e2eClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *e2eClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *e2eClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// e2eRoot is one consent record of the policy the test writes.
type e2eRoot struct {
	path       string
	generation uint64
	active     bool
}

func e2ePolicy(content bool, roots ...e2eRoot) string {
	records := make([]string, 0, len(roots))
	for _, r := range roots {
		mode := `""`
		if r.active {
			mode = `"backfill"`
		}
		records = append(records, fmt.Sprintf(`{"path":%q,"generation":%d,"active":%t,"mode":%s}`, r.path, r.generation, r.active, mode))
	}
	return fmt.Sprintf(`{"schema_version":"gasworks.companion.root-policy/v3","content_upload":%t,"roots":[%s]}`, content, strings.Join(records, ","))
}

// rollout renders a Codex rollout: its session record, the model record that keys content upload,
// and n responses.
func rollout(session string, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"timestamp":"2026-09-01T10:00:00.000Z","type":"session_meta","payload":{"id":%q,"timestamp":"2026-09-01T09:59:59.281Z","cli_version":"0.153.4","originator":"codex-tui","source":"cli"}}`+"\n", session)
	b.WriteString(`{"timestamp":"2026-09-01T10:00:01.000Z","type":"turn_context","payload":{"model":"gpt-5.4","effort":"high"}}` + "\n")
	b.WriteString(rolloutResponses(n))
	return b.String()
}

// responseSeq numbers rollout responses so every one carries a distinct response id (the parser
// counts each response once per transcript).
var responseSeq struct {
	sync.Mutex
	n int
}

// rolloutResponses renders n completed responses, each one USAGE observation.
func rolloutResponses(n int) string {
	var b strings.Builder
	for range n {
		responseSeq.Lock()
		responseSeq.n++
		id := responseSeq.n
		responseSeq.Unlock()
		usage := `{"input_tokens":100,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110}`
		fmt.Fprintf(&b, `{"timestamp":"2026-09-01T10:00:02.000Z","type":"token_usage_record","payload":{"response_id":"resp_e2e%d","usage":%s,"turn_token_usage":%s,"thread_token_usage":%s}}`+"\n", id, usage, usage, usage)
	}
	return b.String()
}

// lineLog records log lines and wakes waiters on each one, so a test waits for a specific line —
// a fact — instead of for elapsed time, and never loses a line to a full buffer.
type lineLog struct {
	mu      sync.Mutex
	lines   []string
	arrived chan struct{}
}

func newLineLog() *lineLog { return &lineLog{arrived: make(chan struct{}, 1)} }

func (l *lineLog) add(s string) {
	l.mu.Lock()
	l.lines = append(l.lines, s)
	l.mu.Unlock()
	select {
	case l.arrived <- struct{}{}:
	default:
	}
}

func (l *lineLog) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// dump renders every line logged so far.
func (l *lineLog) dump() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// waitFor blocks until a line containing sub has been logged, failing the test at the deadline.
func (l *lineLog) waitFor(t *testing.T, sub string, deadline <-chan time.Time) {
	t.Helper()
	for !l.has(sub) {
		select {
		case <-l.arrived:
		case <-deadline:
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("never logged %q; log:\n%s", sub, strings.Join(l.lines, "\n"))
		}
	}
}

// consentE2E is the assembled daemon under a live policy file, with its loops idle so the test
// drives every pass deterministically.
type consentE2E struct {
	t          *testing.T
	policyPath string
	stateDir   string
	stub       *consentStub
	clock      *e2eClock
	svc        *daemon.Service
	logs       *lineLog
}

// startConsentE2E wires the daemon the way runDaemon does for -root-policy-file -collector.
// interval is the cadence of every loop; time.Hour leaves them idle.
func startConsentE2E(t *testing.T, policyBody string, interval time.Duration, now func() time.Time) *consentE2E {
	t.Helper()
	e := &consentE2E{t: t, policyPath: filepath.Join(t.TempDir(), "root-policy.json"), stateDir: t.TempDir(), logs: newLineLog()}
	writePolicy(t, e.policyPath, policyBody)
	stub, client := newConsentStub(t)
	e.stub = stub
	logf := e.logs.add
	src, err := openConsentPolicy(e.policyPath, false, logf)
	if err != nil {
		t.Fatalf("openConsentPolicy: %v", err)
	}
	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:               e.stateDir,
		SourceID:          e2eSourceID,
		Capacity:          permissiveCap(),
		RegistrySource:    e2eSourceID,
		RegistryWorkspace: "ws-e2e",
		Upload:            &daemon.UploadLoopConfig{Sender: client, Interval: interval},
		ContentUpload:     &daemon.ContentUploadLoopConfig{Sender: client, Interval: interval, Debounce: 30 * time.Second},
		Watch:             newConsentWatchLoopConfig(t.TempDir(), interval, newReferenceConfig(nil, "")),
		Consent:           src,
		PeerUID:           euidPeerE2E,
		Now:               now,
		Log:               logf,
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
	e.svc = svc
	return e
}

// writePolicy replaces the policy file atomically, as bd does.
func writePolicy(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// pass runs one watcher pass, one content pass after the debounce, and one upload pass.
func (e *consentE2E) pass() {
	e.t.Helper()
	e.poll()
	e.tick()
	e.drain()
}

// poll runs one watcher pass: it captures new transcript bytes and queues content for upload.
func (e *consentE2E) poll() {
	e.t.Helper()
	if err := e.svc.PollTranscripts(context.Background()); err != nil {
		e.t.Fatalf("PollTranscripts: %v", err)
	}
}

// tick runs one content pass once the queued transcripts have been stable for the debounce.
func (e *consentE2E) tick() {
	e.clock.advance(31 * time.Second)
	e.svc.TickContentUploads(context.Background())
}

// drain runs one observation upload pass.
func (e *consentE2E) drain() {
	e.t.Helper()
	if err := e.svc.DrainUploads(context.Background()); err != nil {
		e.t.Fatalf("DrainUploads: %v", err)
	}
}

// TestCompanionFollowsContentConsentLive walks content consent through every transition while the
// daemon runs. Each change is written after the watcher has queued a grown transcript for upload
// and before the content pass runs, so it is the content lane's own consent check that is proven:
// a malformed policy file stops uploads (fail closed) while metadata keeps flowing; a repaired
// policy resumes them; content withdrawn mid-session stops them again.
func TestCompanionFollowsContentConsentLive(t *testing.T) {
	root := t.TempDir()
	clock := &e2eClock{t: time.Unix(1_800_000_000, 0)}
	consented := e2ePolicy(true, e2eRoot{root, 1, true})
	e := startConsentE2E(t, consented, time.Hour, clock.now)
	e.clock = clock
	transcript := filepath.Join(root, "rollout-session.jsonl")
	writeFile(t, transcript, rollout("01a0f1f1-0000-7000-8000-0000000000e1", 2))

	e.pass()
	if got := len(e.stub.contentFor(transcript)); got != 1 {
		t.Fatalf("content uploads with consent = %d, want 1", got)
	}
	metadata := e.stub.countLocator(t, "rollout-session.jsonl")
	if metadata == 0 {
		t.Fatal("no transcript metadata reached the collector")
	}

	// A malformed policy file: content stops at once, metadata keeps flowing.
	appendLine(t, transcript, rolloutResponses(1))
	e.poll()
	writePolicy(t, e.policyPath, `{"schema_version":"gasworks.companion.root-policy/v3","content_upload":true,"roots":[`)
	e.tick()
	appendLine(t, transcript, rolloutResponses(1))
	e.pass()
	if got := len(e.stub.contentFor(transcript)); got != 1 {
		t.Fatalf("content was uploaded under a malformed policy (%d uploads)", got)
	}
	if now := e.stub.countLocator(t, "rollout-session.jsonl"); now != metadata+2 {
		t.Fatalf("metadata under a malformed policy: %d -> %d, want both new responses", metadata, now)
	}
	metadata += 2

	// The repaired policy resumes content upload.
	writePolicy(t, e.policyPath, consented)
	e.pass()
	if got := len(e.stub.contentFor(transcript)); got != 2 {
		t.Fatalf("content uploads after the policy was repaired = %d, want 2", got)
	}

	// Content withdrawn mid-session: the transcript keeps growing, no content is uploaded again,
	// and metadata keeps flowing.
	appendLine(t, transcript, rolloutResponses(1))
	e.poll()
	writePolicy(t, e.policyPath, e2ePolicy(false, e2eRoot{root, 1, true}))
	e.tick()
	appendLine(t, transcript, rolloutResponses(1))
	e.pass()
	if got := len(e.stub.contentFor(transcript)); got != 2 {
		t.Fatalf("content was uploaded after content consent was withdrawn (%d uploads)", got)
	}
	if now := e.stub.countLocator(t, "rollout-session.jsonl"); now != metadata+2 {
		t.Fatalf("metadata after content consent was withdrawn: %d -> %d, want both new responses", metadata, now)
	}
}

// TestCompanionFollowsRootConsentLive walks root consent through withdrawal and widening while the
// daemon runs: observations queued from a withdrawn root are withheld (content-free placeholders),
// nothing further is captured or uploaded from it, the other root is untouched, and a root consented
// later is picked up by the next scan, content included.
func TestCompanionFollowsRootConsentLive(t *testing.T) {
	rootA, rootB, rootC := t.TempDir(), t.TempDir(), t.TempDir()
	clock := &e2eClock{t: time.Unix(1_800_000_000, 0)}
	a1, b1 := e2eRoot{rootA, 1, true}, e2eRoot{rootB, 1, true}
	e := startConsentE2E(t, e2ePolicy(true, a1, b1), time.Hour, clock.now)
	e.clock = clock
	transcriptA := filepath.Join(rootA, "rollout-a.jsonl")
	transcriptB := filepath.Join(rootB, "rollout-b.jsonl")
	transcriptC := filepath.Join(rootC, "rollout-c.jsonl")
	writeFile(t, transcriptA, rollout("01a0f1f1-0000-7000-8000-0000000000a1", 2))
	writeFile(t, transcriptB, rollout("01a0f1f1-0000-7000-8000-0000000000b1", 2))
	writeFile(t, transcriptC, rollout("01a0f1f1-0000-7000-8000-0000000000c1", 2))
	e.pass()
	uploadedA := e.stub.countLocator(t, "rollout-a.jsonl")
	if uploadedA == 0 || e.stub.countLocator(t, "rollout-b.jsonl") == 0 || len(e.stub.contentFor(transcriptA)) != 1 {
		t.Fatal("baseline capture of both consented roots did not reach the collector")
	}
	if e.stub.countLocator(t, "rollout-c.jsonl") != 0 || len(e.stub.contentFor(transcriptC)) != 0 {
		t.Fatal("an unconsented root reached the collector")
	}

	// Root A grows: its new observations and its grown content are queued (captured, not yet
	// uploaded). Then its consent is withdrawn, and the content and upload passes run before the
	// watcher's next pass.
	appendLine(t, transcriptA, rolloutResponses(3))
	appendLine(t, transcriptB, rolloutResponses(1))
	e.poll()
	writePolicy(t, e.policyPath, e2ePolicy(true, e2eRoot{rootA, 2, false}, b1))
	e.tick()
	e.drain()
	for range 2 {
		appendLine(t, transcriptA, rolloutResponses(1))
		appendLine(t, transcriptB, rolloutResponses(1))
		writeFile(t, filepath.Join(rootA, "rollout-a-new.jsonl"), rollout("01a0f1f1-0000-7000-8000-0000000000a2", 1))
		e.pass()
	}
	if now := e.stub.countLocator(t, "rollout-a.jsonl"); now != uploadedA {
		t.Fatalf("observations of the withdrawn root reached the collector: %d -> %d", uploadedA, now)
	}
	if e.stub.withheldCount(t) == 0 {
		t.Fatal("the withdrawn root's queued observations were not withheld as placeholders")
	}
	if e.stub.countLocator(t, "rollout-a-new.jsonl") != 0 || len(e.stub.contentFor(filepath.Join(rootA, "rollout-a-new.jsonl"))) != 0 {
		t.Fatal("a transcript created under the withdrawn root reached the collector")
	}
	if got := len(e.stub.contentFor(transcriptA)); got != 1 {
		t.Fatalf("content of the withdrawn root was uploaded again (%d uploads)", got)
	}
	if got := len(e.stub.contentFor(transcriptB)); got < 2 {
		t.Fatalf("the consented root's content stopped: %d uploads", got)
	}

	// Widening: root C is consented while the daemon runs and is captured on the next scan.
	writePolicy(t, e.policyPath, e2ePolicy(true, e2eRoot{rootA, 2, false}, b1, e2eRoot{rootC, 1, true}))
	e.pass()
	if e.stub.countLocator(t, "rollout-c.jsonl") == 0 {
		t.Fatal("a newly consented root's metadata did not reach the collector after the rescan")
	}
	if len(e.stub.contentFor(transcriptC)) != 1 {
		t.Fatal("a newly consented root's content did not reach the collector after the rescan")
	}
}

// TestCompanionAppliesRootWithdrawalFromItsOwnLoops proves the running loops — not only the
// deterministic passes above — apply a withdrawal: once the watch loop reports the new policy, a
// transcript created under the withdrawn root never reaches the WAL or the collector, while one
// created under the consented root does. It waits on facts (the daemon's log line and the
// collector's receipts), never on elapsed time.
func TestCompanionAppliesRootWithdrawalFromItsOwnLoops(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	b1 := e2eRoot{rootB, 1, true}
	e := startConsentE2E(t, e2ePolicy(false, e2eRoot{rootA, 1, true}, b1), 10*time.Millisecond, nil)
	deadline := time.After(15 * time.Second)
	writePolicy(t, e.policyPath, e2ePolicy(false, e2eRoot{rootA, 2, false}, b1))
	e.logs.waitFor(t, "transcript watcher applied consent policy version 2", deadline)

	const locatorA, locatorB = "rollout-a-after.jsonl", "rollout-b-after.jsonl"
	writeFile(t, filepath.Join(rootA, locatorA), rollout("01a0f1f1-0000-7000-8000-0000000000a9", 2))
	writeFile(t, filepath.Join(rootB, locatorB), rollout("01a0f1f1-0000-7000-8000-0000000000b9", 2))
	for e.stub.countLocator(t, locatorB) == 0 {
		select {
		case <-e.stub.arrived:
		case <-deadline:
			t.Fatal("the consented root's new transcript never reached the collector")
		}
	}
	if n := e.stub.countLocator(t, locatorA); n != 0 {
		t.Fatalf("%d observations of a transcript under the withdrawn root reached the collector", n)
	}
	// One more full pass after both files exist (serialized with the watch loop), then stop the
	// daemon so the WAL is read at rest: had A still been tailed, that pass would have captured it.
	if err := e.svc.PollTranscripts(context.Background()); err != nil {
		t.Fatalf("PollTranscripts: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	recs, err := upload.SpoolFrameStore{Dir: e.stateDir}.ReadRange(1, 1<<40)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	for _, r := range recs {
		if strings.Contains(string(r.Payload), locatorA) {
			t.Fatalf("a transcript under the withdrawn root was captured into the WAL: %s", r.Payload)
		}
	}
}
