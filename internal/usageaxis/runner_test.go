package usageaxis

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/saauth"
)

// logCapture collects the axis's log lines so a test can assert on them.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, ln := range l.lines {
		if strings.Contains(ln, substr) {
			n++
		}
	}
	return n
}

func testCfg(t *testing.T, ledger string) Config {
	t.Helper()
	return Config{
		URL:           "https://usage-ingest.example/v0/usage-ingest",
		SourceID:      "city-1",
		Ledger:        ledger,
		Token:         saauth.EnvProvider("tok"),
		StatePath:     filepath.Join(t.TempDir(), "cursors.json"),
		BatchMax:      100,
		BatchInterval: time.Hour, // irrelevant: tests drive RunOnce
	}
}

// fakePoster records the batches it received and returns a scripted result.
type fakePoster struct {
	mu      sync.Mutex
	batches []Batch
	result  postResult
}

func (f *fakePoster) post(_ context.Context, b Batch) postResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, b)
	return f.result
}

func TestRunOnceForwardsAndCommitsCursor(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m")+factLine("r2", "m"))
	cfg := testCfg(t, ledger)
	r := NewRunner(cfg, nil)
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.batches) != 1 || len(fp.batches[0].Facts) != 2 {
		t.Fatalf("want one batch of 2 facts, got %+v", fp.batches)
	}
	if fp.batches[0].SourceID != "city-1" || fp.batches[0].SchemaVersion != SchemaVersion {
		t.Fatalf("batch envelope wrong: %+v", fp.batches[0])
	}
	if fp.batches[0].Facts[0].Seq != 1 || fp.batches[0].Facts[1].Seq != 2 {
		t.Fatalf("seq must be 1-based monotonic: %+v", fp.batches[0].Facts)
	}
	// Cursor persisted at EOF / NextSeq 3.
	st, _ := LoadState(cfg.StatePath)
	cur, ok := st.Get("city-1")
	if !ok || cur.NextSeq != 3 {
		t.Fatalf("cursor not committed: %+v ok=%v", cur, ok)
	}
}

func TestRetryableHoldsCursorAndReplays(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m"))
	cfg := testCfg(t, ledger)
	r := NewRunner(cfg, nil)
	fp := &fakePoster{result: postResult{retryable: true}} // POST fails: hold cursor
	r.post = fp.post

	_ = r.RunOnce(context.Background())
	// Cursor must NOT be committed.
	st, _ := LoadState(cfg.StatePath)
	if _, ok := st.Get("city-1"); ok {
		t.Fatal("a failed POST must not commit the cursor")
	}
	// Next pass succeeds -> the SAME fact (seq 1) is re-POSTed (idempotent replay).
	fp.result = postResult{advance: true}
	_ = r.RunOnce(context.Background())
	last := fp.batches[len(fp.batches)-1]
	if len(last.Facts) != 1 || last.Facts[0].Seq != 1 {
		t.Fatalf("replay must re-send the same fact/seq: %+v", last.Facts)
	}
}

func TestRunOnceNoFactsNoBatch(t *testing.T) {
	ledger := writeLedger(t, "") // empty ledger
	cfg := testCfg(t, ledger)
	r := NewRunner(cfg, nil)
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post
	_ = r.RunOnce(context.Background())
	if len(fp.batches) != 0 {
		t.Fatalf("empty ledger must POST nothing, got %d batches", len(fp.batches))
	}
}

func TestHeartbeatReportsProgressOnCatchUp(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m")+factLine("r2", "m"))
	lc := &logCapture{}
	r := NewRunner(testCfg(t, ledger), lc.logf)
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := lc.count("caught up"); got != 1 {
		t.Fatalf("want exactly one heartbeat, got %d: %v", got, lc.lines)
	}
	if got := lc.count("2 forwarded since last report"); got != 1 {
		t.Fatalf("heartbeat must report the forwarded count: %v", lc.lines)
	}
}

func TestHeartbeatIsThrottled(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m"))
	lc := &logCapture{}
	r := NewRunner(testCfg(t, ledger), lc.logf)
	r.heartbeatEvery = time.Hour
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post

	for i := 0; i < 3; i++ {
		_ = r.RunOnce(context.Background())
	}
	if got := lc.count("caught up"); got != 1 {
		t.Fatalf("heartbeat must be throttled to one per interval, got %d: %v", got, lc.lines)
	}
}

func TestHeartbeatResumesAfterInterval(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m"))
	lc := &logCapture{}
	r := NewRunner(testCfg(t, ledger), lc.logf)
	r.heartbeatEvery = 0 // interval always elapsed: every healthy drain reports
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post

	_ = r.RunOnce(context.Background())
	_ = r.RunOnce(context.Background())
	if got := lc.count("caught up"); got != 2 {
		t.Fatalf("want a heartbeat per drain once the interval elapses, got %d: %v", got, lc.lines)
	}
}

func TestHeartbeatSilentWhileHoldingCursor(t *testing.T) {
	ledger := writeLedger(t, factLine("r1", "m"))
	lc := &logCapture{}
	r := NewRunner(testCfg(t, ledger), lc.logf)
	r.heartbeatEvery = 0 // even unthrottled, a held batch must never claim progress
	fp := &fakePoster{result: postResult{retryable: true}}
	r.post = fp.post

	_ = r.RunOnce(context.Background())
	if got := lc.count("caught up"); got != 0 {
		t.Fatalf("a held batch must not emit a progress heartbeat: %v", lc.lines)
	}
}

func TestDisabledAxisIsIdle(t *testing.T) {
	cfg := testCfg(t, writeLedger(t, factLine("r1", "m")))
	cfg.URL = "" // disable: egress gate closed
	if cfg.Enabled() {
		t.Fatal("cfg with no URL must be disabled")
	}
	r := NewRunner(cfg, nil)
	fp := &fakePoster{result: postResult{advance: true}}
	r.post = fp.post
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("disabled axis must return nil, got %v", err)
	}
	if len(fp.batches) != 0 {
		t.Fatal("disabled axis must never POST")
	}
}
