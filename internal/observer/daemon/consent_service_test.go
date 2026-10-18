//go:build linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// laneCollector is the batch lane's collector double. Like the platform it strict-decodes and
// validates every batch, and it binds each sequence to the first payload it ever received for it —
// even on an attempt it then fails — answering 409 (a hold) to any attempt that re-sends a sequence
// with a different payload. That binding is what makes "a decision is never revisited" observable.
type laneCollector struct {
	mu        sync.Mutex
	failNext  int
	attempts  int
	bound     map[int64][32]byte
	conflicts int
	accepted  map[int64]sentObservation
}

// sentObservation is what the collector accepted at one sequence.
type sentObservation struct {
	Kind       string `json:"kind"`
	Sequence   int64  `json:"sequence"`
	Provenance struct {
		SourceLocator string `json:"source_locator"`
	} `json:"provenance"`
	Diagnostic *struct {
		Context string `json:"context"`
	} `json:"capture_diagnostic"`
	raw []byte
}

func (o sentObservation) withheld() bool {
	return o.Kind == string(wire.ObservationEnvelopeKindCAPTUREDIAGNOSTIC) && o.Diagnostic != nil && o.Diagnostic.Context == withheldContext
}

func newLaneCollector() *laneCollector {
	return &laneCollector{bound: map[int64][32]byte{}, accepted: map[int64]sentObservation{}}
}

func (c *laneCollector) Send(_ context.Context, plan upload.Plan) (*upload.Attempt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	decoded, err := wire.DecodeObservationBatch(plan.Body)
	if err != nil {
		return &upload.Attempt{StatusCode: 400}, nil
	}
	if err := evidence.ValidateBatch(decoded); err != nil {
		return &upload.Attempt{StatusCode: 422}, nil
	}
	var batch struct {
		Observations []json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal(plan.Body, &batch); err != nil {
		return &upload.Attempt{StatusCode: 400}, nil
	}
	sent := make([]sentObservation, 0, len(batch.Observations))
	for _, raw := range batch.Observations {
		var o sentObservation
		if err := json.Unmarshal(raw, &o); err != nil {
			return &upload.Attempt{StatusCode: 400}, nil
		}
		o.raw = append([]byte(nil), raw...)
		sum := sha256.Sum256(raw)
		if prev, ok := c.bound[o.Sequence]; ok && prev != sum {
			c.conflicts++
			return &upload.Attempt{StatusCode: 409}, nil
		}
		sent = append(sent, o)
	}
	for _, o := range sent {
		c.bound[o.Sequence] = sha256.Sum256(o.raw)
	}
	if c.failNext > 0 {
		c.failNext--
		return &upload.Attempt{StatusCode: 503}, nil
	}
	for _, o := range sent {
		c.accepted[o.Sequence] = o
	}
	return &upload.Attempt{StatusCode: 200, Ack: &wire.IngestAck{
		SourceId:                    decoded.SourceID,
		AcknowledgedThroughSequence: decoded.LastSequence,
		Accepted:                    decoded.LastSequence - decoded.FirstSequence + 1,
	}}, nil
}

// failNextAttempts makes the next n attempts fail with 503 after binding their payloads.
func (c *laneCollector) failNextAttempts(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failNext = n
}

// byLocator splits what the collector accepted into the originals per transcript locator and the
// withheld placeholders.
func (c *laneCollector) byLocator() (originals map[string][]int64, withheld []int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	originals = map[string][]int64{}
	for seq, o := range c.accepted {
		if o.withheld() {
			withheld = append(withheld, seq)
			continue
		}
		originals[o.Provenance.SourceLocator] = append(originals[o.Provenance.SourceLocator], seq)
	}
	return originals, withheld
}

func (c *laneCollector) conflictCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conflicts
}

func (c *laneCollector) acceptedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.accepted)
}

// logLines is a concurrency-safe log sink.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) log(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}

func (l *logLines) containing(sub string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			out = append(out, s)
		}
	}
	return out
}

// consentRoot is one root the test consents to.
type consentRoot struct {
	path       string
	generation uint64
	active     bool
}

// consentPolicyBody renders a v3 root policy.
func consentPolicyBody(content bool, roots ...consentRoot) string {
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

// writePolicyAtomic replaces the policy file the way bd does: a temporary file renamed over it.
func writePolicyAtomic(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// consentDaemon is a REAL assembled daemon under a live consent policy with its loops idle, so the
// test drives every pass — PollTranscripts, DrainUploads — deterministically.
type consentDaemon struct {
	t          *testing.T
	stateDir   string
	cursorDir  string
	policyPath string
	coll       *laneCollector
	logs       *logLines
	svc        *Service
	// noUploader starts the next run without an uploader (no collector configured).
	noUploader bool
	// sender, when set, replaces the collector double as the batch lane's sender.
	sender upload.Sender
	// content, when set, wires the content channel with this sender (debounce of one tick of now).
	content ContentSender
	// now is the daemon's clock; nil is the real one.
	now func() time.Time
	// consentInterval is the dedicated consent loop's cadence; 0 leaves it idle (an hour), so only
	// the passes a test drives check the policy.
	consentInterval time.Duration
}

func startConsentDaemon(t *testing.T, policyBody string) *consentDaemon {
	t.Helper()
	d := &consentDaemon{
		t:          t,
		stateDir:   t.TempDir(),
		cursorDir:  t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(),
		logs:       &logLines{},
	}
	writePolicyAtomic(t, d.policyPath, policyBody)
	d.start()
	return d
}

func (d *consentDaemon) start() {
	d.t.Helper()
	src, err := consent.Open(consent.Config{Path: d.policyPath, Log: d.logs.log})
	if err != nil {
		d.t.Fatalf("consent.Open: %v", err)
	}
	var up *UploadLoopConfig
	if !d.noUploader {
		var sender upload.Sender = d.coll
		if d.sender != nil {
			sender = d.sender
		}
		up = &UploadLoopConfig{Sender: sender, Interval: time.Hour, Retry: upload.RetryPolicy{MaxAttempts: 1}}
	}
	var content *ContentUploadLoopConfig
	if d.content != nil {
		content = &ContentUploadLoopConfig{Sender: d.content, Interval: time.Hour, Debounce: time.Nanosecond}
	}
	interval := d.consentInterval
	if interval == 0 {
		interval = time.Hour
	}
	svc, err := NewService(ServiceConfig{
		Dir:             d.stateDir,
		SourceID:        consentSourceID,
		Capacity:        permissiveCapacity(),
		RegistrySource:  consentSourceID,
		Upload:          up,
		ContentUpload:   content,
		Watch:           &WatchLoopConfig{StateDir: d.cursorDir, Policy: serviceWatchPolicy(), Interval: time.Hour},
		Consent:         src,
		ConsentInterval: interval,
		PeerUID:         euidPeer,
		Now:             d.now,
		Log:             d.logs.log,
	})
	if err != nil {
		d.t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		d.t.Fatalf("Start: %v", err)
	}
	d.svc = svc
	d.t.Cleanup(func() { d.stop() })
}

func (d *consentDaemon) stop() {
	if d.svc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.svc.Shutdown(ctx); err != nil {
		d.t.Errorf("Shutdown: %v", err)
	}
	d.svc = nil
}

// restart stops the daemon gracefully and starts a new one over the same directories and collector.
func (d *consentDaemon) restart() {
	d.t.Helper()
	d.stop()
	d.start()
}

func (d *consentDaemon) setPolicy(body string) {
	d.t.Helper()
	writePolicyAtomic(d.t, d.policyPath, body)
}

func (d *consentDaemon) poll() {
	d.t.Helper()
	if err := d.svc.PollTranscripts(context.Background()); err != nil {
		d.t.Fatalf("PollTranscripts: %v", err)
	}
}

func (d *consentDaemon) drain() error {
	return d.svc.DrainUploads(context.Background())
}

// walLocators returns the source locator of every durable WAL frame, by sequence.
func (d *consentDaemon) walLocators() map[int64]string {
	d.t.Helper()
	recs, err := upload.SpoolFrameStore{Dir: d.stateDir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		d.t.Fatalf("read WAL: %v", err)
	}
	out := map[int64]string{}
	for _, r := range recs {
		var o sentObservation
		if err := json.Unmarshal(r.Payload, &o); err != nil {
			d.t.Fatal(err)
		}
		out[r.Sequence] = o.Provenance.SourceLocator
	}
	return out
}

// framesOf returns the WAL sequences captured from one transcript locator.
func (d *consentDaemon) framesOf(locator string) []int64 {
	var out []int64
	for seq, loc := range d.walLocators() {
		if loc == locator {
			out = append(out, seq)
		}
	}
	return out
}

// messageLines renders n generic transcript message records.
func messageLines(tag string, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, `{"type":"message","role":"user","text":"%s %d"}`+"\n", tag, i)
	}
	return b.String()
}

func appendTranscript(t *testing.T, path, lines string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(lines); err != nil {
		t.Fatal(err)
	}
}

func sameSeqs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[int64]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestConsentRootWithdrawalStopsCaptureAndWithholdsQueuedObservations is the root-withdrawal
// acceptance: observations captured from a root and still queued when its consent is withdrawn are
// uploaded only as content-free placeholders, the other root's observations upload intact, and the
// withdrawn root is no longer tailed — without a restart.
func TestConsentRootWithdrawalStopsCaptureAndWithholdsQueuedObservations(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 3))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 3))
	d.poll()
	queuedA, queuedB := d.framesOf("a.jsonl"), d.framesOf("b.jsonl")
	if len(queuedA) == 0 || len(queuedB) == 0 {
		t.Fatalf("capture before the withdrawal: a=%v b=%v, want frames from both roots", queuedA, queuedB)
	}

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	originals, withheld := d.coll.byLocator()
	if len(originals["a.jsonl"]) != 0 {
		t.Fatalf("queued observations of the withdrawn root were uploaded: %v", originals["a.jsonl"])
	}
	if !sameSeqs(withheld, queuedA) {
		t.Fatalf("withheld placeholders at %v, want exactly the withdrawn root's queued frames %v", withheld, queuedA)
	}
	if !sameSeqs(originals["b.jsonl"], queuedB) {
		t.Fatalf("the consented root's observations = %v, want %v intact", originals["b.jsonl"], queuedB)
	}
	if len(d.logs.containing("withholding")) != 1 {
		t.Fatalf("withholding was not logged exactly once: %q", d.logs.containing("withholding"))
	}

	// The withdrawn root is no longer tailed: new lines under it are never captured, while the
	// consented root keeps flowing.
	before := len(d.walLocators())
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha-late", 2))
	appendTranscript(t, filepath.Join(rootA, "a2.jsonl"), messageLines("alpha-new", 2))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta-late", 2))
	d.poll()
	if got := d.framesOf("a.jsonl"); !sameSeqs(got, queuedA) {
		t.Fatalf("withdrawn root captured more frames: %v, want only %v", got, queuedA)
	}
	if got := d.framesOf("a2.jsonl"); len(got) != 0 {
		t.Fatalf("a new transcript under the withdrawn root was captured: %v", got)
	}
	if after := len(d.walLocators()); after <= before {
		t.Fatalf("the consented root stopped flowing: WAL %d -> %d frames", before, after)
	}
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if originals, _ := d.coll.byLocator(); len(originals["a.jsonl"]) != 0 || len(originals["a2.jsonl"]) != 0 {
		t.Fatalf("withdrawn root reached the collector: %v", originals)
	}
	if d.coll.conflictCount() != 0 {
		t.Fatalf("collector saw %d conflicting re-sends", d.coll.conflictCount())
	}
}

// TestConsentWithdrawalNeverRewritesAnAttemptedBatch: a sequence already sent is never withheld
// afterwards — re-sending it with a different payload would conflict at the collector and wedge the
// lane — while everything queued behind the attempt is withheld.
func TestConsentWithdrawalNeverRewritesAnAttemptedBatch(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 2))
	d.poll()
	attemptedA := d.framesOf("a.jsonl")

	d.coll.failNextAttempts(1)
	if err := d.drain(); err == nil {
		t.Fatal("drain against a failing collector succeeded")
	}
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha-queued", 2))
	d.poll()
	queuedA := minus(d.framesOf("a.jsonl"), attemptedA)
	if len(queuedA) == 0 {
		t.Fatal("no frames queued behind the attempted batch")
	}

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	if err := d.drain(); err != nil {
		t.Fatalf("drain after the withdrawal: %v", err)
	}
	if d.coll.conflictCount() != 0 {
		t.Fatalf("an attempted sequence was re-sent with a different payload (%d conflicts)", d.coll.conflictCount())
	}
	originals, withheld := d.coll.byLocator()
	if !sameSeqs(originals["a.jsonl"], attemptedA) {
		t.Fatalf("attempted frames of the withdrawn root = %v, want them replayed unchanged %v", originals["a.jsonl"], attemptedA)
	}
	if !sameSeqs(withheld, queuedA) {
		t.Fatalf("withheld = %v, want the frames queued behind the attempt %v", withheld, queuedA)
	}
}

// minus returns the elements of a not in b.
func minus(a, b []int64) []int64 {
	drop := map[int64]bool{}
	for _, x := range b {
		drop[x] = true
	}
	var out []int64
	for _, x := range a {
		if !drop[x] {
			out = append(out, x)
		}
	}
	return out
}

// TestWithheldDecisionsSurviveRestart: a withheld decision is durable. The batch carrying it was
// attempted before the restart, and after the restart it is re-sent byte-identically — still a
// placeholder, and no conflict at the collector.
func TestWithheldDecisionsSurviveRestart(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 2))
	d.poll()
	queuedA := d.framesOf("a.jsonl")

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	// The collector is down for the explicit drain and for the final drain at shutdown, so nothing
	// is acknowledged before the restart.
	d.coll.failNextAttempts(2)
	if err := d.drain(); err == nil {
		t.Fatal("drain against a failing collector succeeded")
	}
	d.restart()
	if d.coll.acceptedCount() != 0 {
		t.Fatalf("the collector accepted %d observations before the restart; want none", d.coll.acceptedCount())
	}
	if err := d.drain(); err != nil {
		t.Fatalf("drain after restart: %v", err)
	}
	originals, withheld := d.coll.byLocator()
	if len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) {
		t.Fatalf("after restart: originals %v, withheld %v; want the withdrawn root's %v withheld", originals, withheld, queuedA)
	}
	if d.coll.conflictCount() != 0 {
		t.Fatalf("the replay after restart conflicted %d times", d.coll.conflictCount())
	}
}

// TestShutdownRecordWithholdsWhatTheStoppedRunHadNotSent: a withdrawal written while the daemon is
// stopped still withholds what the previous run captured but never sent — the graceful shutdown
// handed those origins to this start, which consumed them.
func TestShutdownRecordWithholdsWhatTheStoppedRunHadNotSent(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(), logs: &logLines{}, noUploader: true,
	}
	d.setPolicy(consentPolicyBody(false, a1, b1))
	d.start() // the first run has no collector, so it sends nothing
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 2))
	d.poll()
	queuedA, queuedB := d.framesOf("a.jsonl"), d.framesOf("b.jsonl")
	d.stop()

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.noUploader = false
	d.start()
	ledger, err := readConsentLedger(d.stateDir)
	if err != nil {
		t.Fatalf("readConsentLedger: %v", err)
	}
	if ledger.Shutdown == nil {
		t.Fatal("the shutdown record was retired before this run sent anything")
	}
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if ledger, err := readConsentLedger(d.stateDir); err != nil || ledger.Shutdown != nil {
		t.Fatalf("ledger after the first send = %+v, %v; want the shutdown record retired", ledger, err)
	}
	originals, withheld := d.coll.byLocator()
	if len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) || !sameSeqs(originals["b.jsonl"], queuedB) {
		t.Fatalf("originals %v withheld %v; want %v withheld and %v intact", originals, withheld, queuedA, queuedB)
	}
}

// TestStartWithoutAShutdownRecordNeverGuessesAnOrigin: after a crash the origins of what the dead
// run queued are unknown; the next start uploads those frames as captured rather than guess which
// consent they fell under (the documented residual), and still fences everything it captures itself.
func TestStartWithoutAShutdownRecordNeverGuessesAnOrigin(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	crashedA := d.framesOf("a.jsonl")
	// A crash: the spool and lock are released with no graceful shutdown (no final drain, no record).
	d.svc.loopCancel()
	d.svc.wg.Wait()
	_ = d.svc.server.Shutdown(context.Background())
	_ = d.svc.spool.Close()
	d.svc.releaseLock()
	d.svc = nil

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.start()
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if originals, withheld := d.coll.byLocator(); !sameSeqs(originals["a.jsonl"], crashedA) || len(withheld) != 0 {
		t.Fatalf("after a crash: originals %v withheld %v; want the unattributable frames %v uploaded as captured", originals, withheld, crashedA)
	}
}

// TestConsentWideningTakesEffectOnTheNextPoll: a root consented while the daemon runs is scanned on
// the very next pass.
func TestConsentWideningTakesEffectOnTheNextPoll(t *testing.T) {
	rootA, rootC := t.TempDir(), t.TempDir()
	a1 := consentRoot{rootA, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1))
	appendTranscript(t, filepath.Join(rootC, "c.jsonl"), messageLines("gamma", 2))
	d.poll()
	if got := d.framesOf("c.jsonl"); len(got) != 0 {
		t.Fatalf("an unconsented root was captured: %v", got)
	}
	// The upload lane applies the policy before the widening, so it is one version behind when the
	// new root's frames are appended; they must still upload as captured.
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	d.setPolicy(consentPolicyBody(false, a1, consentRoot{rootC, 1, true}))
	d.poll()
	captured := d.framesOf("c.jsonl")
	if len(captured) == 0 {
		t.Fatal("a newly consented root was not captured on the next poll")
	}
	if len(d.logs.containing("consented "+rootC+" (generation 1, backfill)")) != 1 {
		t.Fatalf("the widening was not logged: %q", d.logs.containing("consent policy"))
	}
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if originals, withheld := d.coll.byLocator(); !sameSeqs(originals["c.jsonl"], captured) || len(withheld) != 0 {
		t.Fatalf("newly consented root: originals %v withheld %v, want %v uploaded as captured", originals["c.jsonl"], withheld, captured)
	}
}

// TestUnbuildableConsentPolicyPausesCapture: a policy the watcher cannot be built for pauses ALL
// transcript capture — failing closed rather than carrying on under the previous consent, even for a
// root the new policy still consents to — and capture resumes once a valid policy is written. Here
// the new policy also consents to the cursor directory, which the watcher refuses to tail.
func TestUnbuildableConsentPolicyPausesCapture(t *testing.T) {
	rootA := t.TempDir()
	a5 := consentRoot{rootA, 5, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a5))
	transcript := filepath.Join(rootA, "a.jsonl")
	appendTranscript(t, transcript, messageLines("alpha", 1))
	d.poll()
	captured := len(d.framesOf("a.jsonl"))

	d.setPolicy(consentPolicyBody(false, a5, consentRoot{d.cursorDir, 1, true}))
	appendTranscript(t, transcript, messageLines("alpha-paused", 1))
	d.poll()
	d.poll()
	if got := len(d.framesOf("a.jsonl")); got != captured {
		t.Fatalf("capture continued under a policy that cannot be applied: %d -> %d frames", captured, got)
	}
	if n := len(d.logs.containing("cannot be applied to the transcript watcher")); n != 1 {
		t.Fatalf("the paused capture was logged %d times, want once", n)
	}

	d.setPolicy(consentPolicyBody(false, a5))
	d.poll()
	if got := len(d.framesOf("a.jsonl")); got <= captured {
		t.Fatal("capture did not resume once a valid policy was written")
	}
}

// TestWithdrawalIsRecordedForTheWholeBacklog: the moment the upload lane applies a withdrawal it
// records the decision for EVERY queued frame of the withdrawn root, not only those in the next
// batch, so a crash right after cannot release the rest of the backlog as captured.
func TestWithdrawalIsRecordedForTheWholeBacklog(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 5))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 1))
	d.poll()
	queuedA := d.framesOf("a.jsonl")

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.svc.upload.caps = upload.Caps{MaxObservations: 1} // each batch carries one frame
	d.coll.failNextAttempts(1)
	if err := d.drain(); err == nil {
		t.Fatal("drain against a failing collector succeeded")
	}
	ledger, err := readConsentLedger(d.stateDir)
	if err != nil {
		t.Fatalf("readConsentLedger: %v", err)
	}
	var recorded []int64
	for _, r := range ledger.Withheld {
		for seq := r[0]; seq <= r[1]; seq++ {
			recorded = append(recorded, seq)
		}
	}
	if !sameSeqs(recorded, queuedA) {
		t.Fatalf("ledger records %v withheld after one single-frame batch; want the whole backlog %v", recorded, queuedA)
	}
}

// TestConsentSinkRefusesAWithdrawnRootMidPass covers the race the per-pass rebuild cannot: consent
// withdrawn after the pass began. The sink checks every append and refuses it, appending nothing.
func TestConsentSinkRefusesAWithdrawnRootMidPass(t *testing.T) {
	rootA := t.TempDir()
	d := startConsentDaemon(t, consentPolicyBody(false, consentRoot{rootA, 1, true}))
	sink := &consentSink{inner: d.svc.sink, fence: d.svc.fence, generations: map[string]uint64{rootA: 1}}
	ref := codex.TranscriptRef{Locator: "a.jsonl", Device: 1, Inode: 2, ConsentRoot: rootA}

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}))
	d.svc.consent.Current() // another loop observed the change
	before := len(d.walLocators())
	n, err := sink.DeliverCandidatesPartial(context.Background(), ref, []*codex.Candidate{messageCandidate("late")})
	if err != errConsentWithdrawn || n != 0 {
		t.Fatalf("DeliverCandidatesPartial = %d, %v; want 0, errConsentWithdrawn", n, err)
	}
	if after := len(d.walLocators()); after != before {
		t.Fatalf("a refused candidate was appended: %d -> %d frames", before, after)
	}
}

// TestReRegistrationFencesQueuedObservationsOfTheEarlierGeneration: re-registering a root mints a
// new consent generation; what was captured under the earlier generation and is still queued is
// withheld, and capture continues under the new generation.
func TestReRegistrationFencesQueuedObservationsOfTheEarlierGeneration(t *testing.T) {
	rootA := t.TempDir()
	d := startConsentDaemon(t, consentPolicyBody(false, consentRoot{rootA, 1, true}))
	transcript := filepath.Join(rootA, "a.jsonl")
	appendTranscript(t, transcript, messageLines("alpha", 2))
	d.poll()
	firstGeneration := d.framesOf("a.jsonl")

	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, true}))
	d.poll() // rebuilt for generation 2: the backfill root is captured again under its new consent
	secondGeneration := minus(d.framesOf("a.jsonl"), firstGeneration)
	if len(secondGeneration) == 0 {
		t.Fatal("nothing was captured under the new generation")
	}
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	originals, withheld := d.coll.byLocator()
	if !sameSeqs(withheld, firstGeneration) || !sameSeqs(originals["a.jsonl"], secondGeneration) {
		t.Fatalf("originals %v withheld %v; want generation 1's %v withheld and generation 2's %v uploaded", originals["a.jsonl"], withheld, firstGeneration, secondGeneration)
	}
}

// TestAttemptedBoundarySurvivesAGracefulRestart: what the previous run already sent is replayed
// unchanged after a restart even when its root was withdrawn in between, while what it queued but
// never sent is withheld — the shutdown record carries the exact boundary between the two.
func TestAttemptedBoundarySurvivesAGracefulRestart(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	// Two frames per batch, so a failed pass — including the final drain at shutdown — attempts
	// only the range already sent and never reaches the frames queued behind it.
	d.svc.upload.caps = upload.Caps{MaxObservations: 2}
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	sentA := d.framesOf("a.jsonl")
	if len(sentA) != 2 {
		t.Fatalf("captured %v, want two frames", sentA)
	}
	d.coll.failNextAttempts(1) // the collector binds the batch, then fails it
	if err := d.drain(); err == nil {
		t.Fatal("drain against a failing collector succeeded")
	}
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha-queued", 2))
	d.poll()
	queuedA := minus(d.framesOf("a.jsonl"), sentA)

	// The final drain at shutdown fails too, so the stop leaves both parts unacknowledged.
	d.coll.failNextAttempts(1)
	d.stop()
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.start()
	if err := d.drain(); err != nil {
		t.Fatalf("drain after restart: %v", err)
	}
	if d.coll.conflictCount() != 0 {
		t.Fatalf("a sent sequence was re-sent with a different payload after the restart (%d conflicts)", d.coll.conflictCount())
	}
	originals, withheld := d.coll.byLocator()
	if !sameSeqs(originals["a.jsonl"], sentA) || !sameSeqs(withheld, queuedA) {
		t.Fatalf("after restart: originals %v withheld %v; want %v replayed and %v withheld", originals["a.jsonl"], withheld, sentA, queuedA)
	}
}

// TestShutdownRecordSurvivesAStartThatFails: a start that fails before it sends anything leaves
// the shutdown record for the next start, so a withdrawal made while the daemon was stopped is not
// lost to a start that failed on the same policy edit.
func TestShutdownRecordSurvivesAStartThatFails(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(), logs: &logLines{}, noUploader: true,
	}
	d.setPolicy(consentPolicyBody(false, a1, b1))
	d.start()
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	queuedA := d.framesOf("a.jsonl")
	d.stop()

	// The owner withdraws A and, in the same edit, consents to a root the watcher refuses (the
	// cursor directory): this start fails.
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1, consentRoot{d.cursorDir, 1, true}))
	src, err := consent.Open(consent.Config{Path: d.policyPath})
	if err != nil {
		t.Fatalf("consent.Open: %v", err)
	}
	if _, err := NewService(ServiceConfig{
		Dir: d.stateDir, SourceID: consentSourceID, Capacity: permissiveCapacity(), RegistrySource: consentSourceID,
		Upload:  &UploadLoopConfig{Sender: d.coll, Interval: time.Hour, Retry: upload.RetryPolicy{MaxAttempts: 1}},
		Watch:   &WatchLoopConfig{StateDir: d.cursorDir, Policy: serviceWatchPolicy(), Interval: time.Hour},
		Consent: src, PeerUID: euidPeer,
	}); err == nil {
		t.Fatal("a start under a policy the watcher cannot apply succeeded")
	}

	// Repaired, the next start still withholds what the stopped run had queued.
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.noUploader = false
	d.start()
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if originals, withheld := d.coll.byLocator(); len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) {
		t.Fatalf("after a failed start: originals %v withheld %v; want %v withheld", originals, withheld, queuedA)
	}
}

// TestShutdownRecordIsDroppedWhenTheSpoolLostFrames: an operator who moves WAL segments aside makes
// the spool reuse sequences; a shutdown record describing the old frames is dropped, not applied
// to the new ones.
func TestShutdownRecordIsDroppedWhenTheSpoolLostFrames(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "root-policy.json")
	root := t.TempDir()
	writePolicyAtomic(t, policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	src, err := consent.Open(consent.Config{Path: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	f, err := newConsentFence(dir, src, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.recordAppend(1, consentOrigin{root: root, generation: 1})
	f.recordAppend(2, consentOrigin{root: root, generation: 1})
	if err := f.recordShutdown(2); err != nil {
		t.Fatal(err)
	}

	logs := &logLines{}
	again, err := newConsentFence(dir, src, 1, logs.log) // the spool is now durable only through 1
	if err != nil {
		t.Fatalf("newConsentFence: %v", err)
	}
	if again.pending != nil || len(again.origins.runs) != 0 || again.attempted != 1 {
		t.Fatalf("fence applied a record for frames that no longer exist: pending %+v origins %+v attempted %d", again.pending, again.origins.runs, again.attempted)
	}
	if ledger, err := readConsentLedger(dir); err != nil || ledger.Shutdown != nil {
		t.Fatalf("ledger = %+v, %v; want the stale record dropped from disk", ledger, err)
	}
	if len(logs.containing("dropping the shutdown record")) != 1 {
		t.Fatalf("the dropped record was not logged: %q", logs.containing("consent ledger"))
	}
}

// TestLedgerIsHonoredWithoutALivePolicy: a daemon restarted without -root-policy-file over the same
// state directory still uploads every withheld sequence only as its placeholder — replaying it
// byte-identically to what the policy run sent — instead of sending withdrawn evidence as captured.
func TestLedgerIsHonoredWithoutALivePolicy(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 2))
	d.poll()
	queuedA, queuedB := d.framesOf("a.jsonl"), d.framesOf("b.jsonl")
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.coll.failNextAttempts(2) // the placeholders are bound at the collector but nothing is acked
	if err := d.drain(); err == nil {
		t.Fatal("drain against a failing collector succeeded")
	}
	d.stop()

	svc, err := NewService(ServiceConfig{
		Dir: d.stateDir, SourceID: consentSourceID, Capacity: permissiveCapacity(), RegistrySource: consentSourceID,
		Upload:  &UploadLoopConfig{Sender: d.coll, Interval: time.Hour, Retry: upload.RetryPolicy{MaxAttempts: 1}},
		PeerUID: euidPeer,
	})
	if err != nil {
		t.Fatalf("NewService without a policy: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Shutdown(context.Background()) }()
	if err := svc.DrainUploads(context.Background()); err != nil {
		t.Fatalf("drain without a policy: %v", err)
	}
	if d.coll.conflictCount() != 0 {
		t.Fatalf("a withheld sequence was re-sent with a different payload (%d conflicts)", d.coll.conflictCount())
	}
	originals, withheld := d.coll.byLocator()
	if len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) || !sameSeqs(originals["b.jsonl"], queuedB) {
		t.Fatalf("without a policy: originals %v withheld %v; want %v withheld and %v intact", originals, withheld, queuedA, queuedB)
	}
}

// rolloutLines renders a Codex rollout: its session record (which keys content upload) and n
// completed responses.
func rolloutLines(session string, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"timestamp":"2026-09-01T10:00:00.000Z","type":"session_meta","payload":{"id":%q,"timestamp":"2026-09-01T09:59:59.281Z","cli_version":"0.153.4","originator":"codex-tui","source":"cli"}}`+"\n", session)
	for i := range n {
		usage := `{"input_tokens":100,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":10,"reasoning_output_tokens":0,"total_tokens":110}`
		fmt.Fprintf(&b, `{"timestamp":"2026-09-01T10:00:02.000Z","type":"token_usage_record","payload":{"response_id":"resp_%s_%d","usage":%s,"turn_token_usage":%s,"thread_token_usage":%s}}`+"\n", session[len(session)-4:], i, usage, usage, usage)
	}
	return b.String()
}

// TestBatchDecisionsFollowTheNewestPolicy (review R1): a withdrawal another loop publishes after the
// upload lane's per-batch check, but before the batch is read, still governs that batch — the
// withdrawn root's frames are read as placeholders, and the decisions are recorded before the send.
func TestBatchDecisionsFollowTheNewestPolicy(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 3))
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 3))
	d.poll()
	queuedA, queuedB := d.framesOf("a.jsonl"), d.framesOf("b.jsonl")
	f := d.svc.fence
	high, err := f.ceiling(func() (int64, error) {
		snap, err := d.svc.spool.Health()
		return snap.HighestDurable, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.refresh(); err != nil { // the lane's per-batch check: A still consented
		t.Fatal(err)
	}
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	d.svc.consent.Current() // another loop publishes the withdrawal
	recs, err := f.frameStore(upload.SpoolFrameStore{Dir: d.stateDir}).ReadRange(1, high)
	if err != nil {
		t.Fatal(err)
	}
	placeholders := map[int64]bool{}
	for _, r := range recs {
		placeholders[r.Sequence] = bytes.Contains(r.Payload, []byte(withheldContext))
	}
	for _, seq := range queuedA {
		if !placeholders[seq] {
			t.Fatalf("frame %d of the withdrawn root was read as captured after the withdrawal was published", seq)
		}
	}
	for _, seq := range queuedB {
		if placeholders[seq] {
			t.Fatalf("frame %d of the consented root was withheld", seq)
		}
	}
	if err := f.beforeSend(wire.SequenceRange{FirstSequence: 1, LastSequence: high}); err != nil {
		t.Fatal(err)
	}
	ledger, err := readConsentLedger(d.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	var recorded []int64
	for _, r := range ledger.Withheld {
		for seq := r[0]; seq <= r[1]; seq++ {
			recorded = append(recorded, seq)
		}
	}
	if !sameSeqs(recorded, queuedA) {
		t.Fatalf("ledger records %v withheld, want %v before the send", recorded, queuedA)
	}
}

// TestPolicyLessRestartWithholdsWhatThePolicyRunHadNotSent (review R3): a daemon restarted without
// -root-policy-file can confirm no consent, so what the stopped policy run captured but had not
// sent is withheld rather than uploaded as captured.
func TestPolicyLessRestartWithholdsWhatThePolicyRunHadNotSent(t *testing.T) {
	rootA := t.TempDir()
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(), logs: &logLines{}, noUploader: true,
	}
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 1, true}))
	d.start()
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	queuedA := d.framesOf("a.jsonl")
	d.stop()

	logs := &logLines{}
	svc, err := NewService(ServiceConfig{
		Dir: d.stateDir, SourceID: consentSourceID, Capacity: permissiveCapacity(), RegistrySource: consentSourceID,
		Upload:  &UploadLoopConfig{Sender: d.coll, Interval: time.Hour, Retry: upload.RetryPolicy{MaxAttempts: 1}},
		PeerUID: euidPeer, Log: logs.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Shutdown(context.Background()) }()
	if err := svc.DrainUploads(context.Background()); err != nil {
		t.Fatal(err)
	}
	originals, withheld := d.coll.byLocator()
	if len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) {
		t.Fatalf("policy-less restart: originals %v withheld %v; want %v withheld", originals, withheld, queuedA)
	}
	if len(logs.containing("no live consent policy can confirm their consent")) != 1 {
		t.Fatalf("the fail-closed withholding was not logged: %q", logs.containing("consent"))
	}
}

// TestDeletingTheLedgerAfterTheWithheldRangeIsAcknowledgedIsSafe (review R2, the documented
// recovery): once the collector has acknowledged every withheld sequence, the ledger guards nothing,
// and a daemon started without it re-sends nothing and conflicts with nothing.
func TestDeletingTheLedgerAfterTheWithheldRangeIsAcknowledgedIsSafe(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := startConsentDaemon(t, consentPolicyBody(false, a1, b1))
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	queuedA := d.framesOf("a.jsonl")
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	d.stop()
	if err := os.Remove(filepath.Join(d.stateDir, consentLedgerFilename)); err != nil {
		t.Fatal(err)
	}
	accepted := d.coll.acceptedCount()
	d.start()
	appendTranscript(t, filepath.Join(rootB, "b.jsonl"), messageLines("beta", 1))
	d.poll()
	if err := d.drain(); err != nil {
		t.Fatalf("drain after deleting the ledger: %v", err)
	}
	originals, withheld := d.coll.byLocator()
	if d.coll.conflictCount() != 0 || len(originals["a.jsonl"]) != 0 || !sameSeqs(withheld, queuedA) {
		t.Fatalf("after deleting an acknowledged ledger: %d conflicts, originals %v, withheld %v", d.coll.conflictCount(), originals, withheld)
	}
	if d.coll.acceptedCount() <= accepted {
		t.Fatal("the restarted daemon stopped uploading")
	}
}

// TestDeletingTheLedgerBeforeTheWithheldRangeIsAcknowledgedReleasesIt (review R2) pins the hazard the
// release runbook warns about: withheld sequences never acknowledged by the collector are uploaded as
// captured by a daemon that starts without the ledger. If this ever stops holding, update the
// runbook.
func TestDeletingTheLedgerBeforeTheWithheldRangeIsAcknowledgedReleasesIt(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	a1, b1 := consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(), logs: &logLines{},
		sender: transportDown{},
	}
	d.setPolicy(consentPolicyBody(false, a1, b1))
	d.start()
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 2))
	d.poll()
	queuedA := d.framesOf("a.jsonl")
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 2, false}, b1))
	if err := d.drain(); err == nil {
		t.Fatal("drain with the collector unreachable succeeded")
	}
	d.stop()
	if err := os.Remove(filepath.Join(d.stateDir, consentLedgerFilename)); err != nil {
		t.Fatal(err)
	}
	d.sender = nil
	d.start()
	if err := d.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if originals, _ := d.coll.byLocator(); !sameSeqs(originals["a.jsonl"], queuedA) {
		t.Fatalf("withdrawn root's frames after deleting an unacknowledged ledger = %v, want %v uploaded as captured (the documented hazard)", originals["a.jsonl"], queuedA)
	}
}

// transportDown is a batch sender whose collector is unreachable: every attempt fails at the
// transport, so nothing reaches (or is bound by) the collector.
type transportDown struct{}

func (transportDown) Send(context.Context, upload.Plan) (*upload.Attempt, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// stallingSender passes its first `pass` sends to next, then blocks every later send until released
// (or its context ends), reporting the first blocked send on stalled.
type stallingSender struct {
	next        upload.Sender
	release     chan struct{}
	releaseOnce sync.Once
	stalled     chan struct{}
	once        sync.Once
	mu          sync.Mutex
	pass        int
}

// releaseAll lets every blocked and later send through. It is safe to call more than once.
func (s *stallingSender) releaseAll() { s.releaseOnce.Do(func() { close(s.release) }) }

func newStallingSender(next upload.Sender, pass int) *stallingSender {
	return &stallingSender{next: next, pass: pass, release: make(chan struct{}), stalled: make(chan struct{})}
}

func (s *stallingSender) Send(ctx context.Context, plan upload.Plan) (*upload.Attempt, error) {
	s.mu.Lock()
	passNow := s.pass > 0
	if passNow {
		s.pass--
	}
	s.mu.Unlock()
	if !passNow {
		s.once.Do(func() { close(s.stalled) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.next.Send(ctx, plan)
}

// TestShutdownRecordIsOnDiskWhileTheFinalDrainHangs (item 4): the shutdown record is written before
// the final drain and kept exact by each of its sends, so while the drain hangs on the collector —
// the moment a service manager kills the process — the record on disk describes exactly what has
// and has not been sent.
func TestShutdownRecordIsOnDiskWhileTheFinalDrainHangs(t *testing.T) {
	rootA := t.TempDir()
	coll := newLaneCollector()
	stalling := newStallingSender(coll, 1) // the drain's first batch goes through, the second hangs
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       coll, logs: &logLines{}, sender: stalling,
	}
	d.setPolicy(consentPolicyBody(false, consentRoot{rootA, 1, true}))
	d.start()
	t.Cleanup(stalling.releaseAll)
	d.svc.upload.caps = upload.Caps{MaxObservations: 1}
	appendTranscript(t, filepath.Join(rootA, "a.jsonl"), messageLines("alpha", 3))
	d.poll()
	queuedA := d.framesOf("a.jsonl")
	if len(queuedA) != 3 {
		t.Fatalf("captured %v, want three frames", queuedA)
	}

	svc := d.svc
	d.svc = nil // shut down here, not by the harness
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		done <- svc.Shutdown(ctx)
	}()
	select {
	case <-stalling.stalled:
	case <-time.After(20 * time.Second):
		t.Fatal("the final drain never reached its second batch")
	}
	ledger, err := readConsentLedger(d.stateDir)
	if err != nil {
		t.Fatalf("readConsentLedger while the drain hangs: %v", err)
	}
	want := &consentLedgerShutdown{HighestDurable: 3, AttemptedThrough: 2, Origins: []consentLedgerOrigin{{First: 3, Last: 3, Root: rootA, Generation: 1}}}
	if !reflect.DeepEqual(ledger.Shutdown, want) {
		t.Fatalf("record while the drain hangs = %+v, want %+v", ledger.Shutdown, want)
	}
	stalling.releaseAll()
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	ledger, err = readConsentLedger(d.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if want := (&consentLedgerShutdown{HighestDurable: 3, AttemptedThrough: 3, Origins: []consentLedgerOrigin{}}); !reflect.DeepEqual(ledger.Shutdown, want) {
		t.Fatalf("record after the drain = %+v, want %+v", ledger.Shutdown, want)
	}
}

// blockingContent is a content sender whose every request blocks until its context is cancelled.
type blockingContent struct {
	started   chan struct{}
	once      sync.Once
	cancelled chan error
}

func newBlockingContent() *blockingContent {
	return &blockingContent{started: make(chan struct{}), cancelled: make(chan error, 1)}
}

func (b *blockingContent) PostContent(ctx context.Context, _ upload.ContentRequest) (*upload.ContentResult, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-ctx.Done():
		b.cancelled <- ctx.Err()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second): // a safety deadline: a request never cancelled fails the test
		return nil, errors.New("the in-flight request was never cancelled")
	}
}

// TestServiceCancelsAnInFlightContentUploadOnItsOwn (items 2 and 5): through the assembled daemon, a
// content withdrawal written while an upload is in flight cancels it — although no transcript pass,
// content pass, or batch observes the change (the upload lane is even stuck sending a batch): the
// daemon's own consent loop does, and the content uploader's subscription cancels the request.
func TestServiceCancelsAnInFlightContentUploadOnItsOwn(t *testing.T) {
	root := t.TempDir()
	clock := newClock()
	content := newBlockingContent()
	coll := newLaneCollector()
	stuck := newStallingSender(coll, 0)
	d := &consentDaemon{
		t: t, stateDir: t.TempDir(), cursorDir: t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       coll, logs: &logLines{}, sender: stuck, content: content, now: clock.now,
		consentInterval: 5 * time.Millisecond,
	}
	d.setPolicy(consentPolicyBody(true, consentRoot{root, 1, true}))
	d.start()
	t.Cleanup(stuck.releaseAll) // runs before the harness stops the daemon
	appendTranscript(t, filepath.Join(root, "rollout-session.jsonl"), rolloutLines("01a0f1f1-0000-7000-8000-0000000000c5", 2))
	d.poll()
	clock.advance(time.Second)

	drained := make(chan error, 1)
	go func() { drained <- d.svc.DrainUploads(context.Background()) }() // the upload lane is stuck sending
	select {
	case <-stuck.stalled:
	case <-time.After(20 * time.Second):
		t.Fatal("the batch never reached the collector")
	}
	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		d.svc.TickContentUploads(context.Background())
	}()
	select {
	case <-content.started:
	case <-time.After(20 * time.Second):
		t.Fatal("the content upload never started")
	}

	d.setPolicy(consentPolicyBody(false, consentRoot{root, 1, true})) // nothing but the consent loop checks it
	select {
	case err := <-content.cancelled:
		if err == nil {
			t.Fatal("the in-flight upload ended without being cancelled")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the in-flight content upload was not cancelled after content consent was withdrawn")
	}
	<-ticked
	if len(d.logs.containing("withdrew the in-flight upload")) != 1 {
		t.Fatalf("the withdrawal was not logged: %q", d.logs.containing("content upload"))
	}
	stuck.releaseAll()
	if err := <-drained; err != nil {
		t.Fatalf("the stuck batch failed once released: %v", err)
	}
}
