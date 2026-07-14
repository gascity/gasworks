package eventsaxis

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/saauth"
	"github.com/gastownhall/gascity/pkg/eventexport"
)

// captureIngest is a fake events ingest: it records every decoded batch and can
// inject a bounded run of retryable failures before accepting.
type captureIngest struct {
	mu       sync.Mutex
	batches  []eventexport.Batch
	failWith int // HTTP status to fail with while failures > 0
	failures int
}

func (c *captureIngest) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		var b eventexport.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.failures > 0 {
			c.failures--
			w.WriteHeader(c.failWith)
			return
		}
		c.batches = append(c.batches, b)
		var through uint64
		if n := len(b.Events); n > 0 {
			through = b.Events[n-1].Seq
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted_through_seq": through,
			"accepted":             len(b.Events),
			"rejected":             0,
			"dupes":                0,
		})
	}
}

func (c *captureIngest) all() []eventexport.Batch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]eventexport.Batch(nil), c.batches...)
}

// fileEventLine builds one recorded events.jsonl line in the FLAT payload shape
// the FileRecorder writes (payload IS the bead — unlike the SSE stream's
// payload.bead wrapper).
func fileEventLine(seq uint64, typ, actor, subject, runID string, payload map[string]any) string {
	m := map[string]any{
		"seq": seq, "type": typ, "ts": time.Date(2026, 7, 1, 0, 0, int(seq%60), 0, time.UTC).Format(time.RFC3339Nano),
		"actor": actor,
	}
	if subject != "" {
		m["subject"] = subject
	}
	if runID != "" {
		m["run_id"] = runID
	}
	if payload != nil {
		m["payload"] = payload
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func writeCityHistory(t *testing.T, dir string, archives map[string][]string, live []string) {
	t.Helper()
	gcDir := filepath.Join(dir, ".gc")
	coldDir := filepath.Join(gcDir, "events-archive-cold")
	if err := os.MkdirAll(coldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, lines := range archives {
		target := gcDir
		if len(lines) > 0 && lines[0] == "cold" {
			target, lines = coldDir, lines[1:]
		}
		f, err := os.Create(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		for _, l := range lines {
			fmt.Fprintln(gz, l)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var buf []byte
	for _, l := range live {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(filepath.Join(gcDir, "events.jsonl"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func backfillConfig(url string, batchMax int) Config {
	return Config{
		URL:             url,
		Token:           saauth.EnvProvider("test-token"),
		Salt:            []byte("0123456789abcdef"),
		ExportRef:       true,
		EmitCorrelation: true,
		EmitContent:     true,
		BatchMax:        batchMax,
		AllowHTTP:       true,
	}
}

// TestBackfill_ReplaysArchivesAndLiveInChunks is the end-to-end backfill path:
// archives (cold + warm) plus the live file, flat-payload content lift, allowlist
// filtering, seq-window bounds, and BatchMax chunking.
func TestBackfill_ReplaysArchivesAndLiveInChunks(t *testing.T) {
	dir := t.TempDir()
	writeCityHistory(t, dir,
		map[string][]string{
			"events.jsonl.archive-20260701T000000Z-seq-100-102.gz": {"cold",
				fileEventLine(100, "bead.created", "dispatch", "mc-wisp-root1", "mc-wisp-root1", map[string]any{
					"id": "mc-wisp-root1", "title": "adopt PR 42",
					"metadata": map[string]string{"gc.formula_name": "mol-adopt-pr-v2"},
				}),
				fileEventLine(101, "bead.updated", "dispatch", "mc-wisp-root1", "mc-wisp-root1", nil), // not allowlisted
				fileEventLine(102, "session.woke", "patrol", "", "", nil),
			},
			"events.jsonl.archive-20260701T010000Z-seq-103-104.gz": {
				fileEventLine(103, "bead.closed", "worker", "mc-wisp-root1.2", "mc-wisp-root1", map[string]any{
					"id": "mc-wisp-root1.2", "title": "review step",
					"metadata": map[string]string{"gc.step_id": "review", "gc.step_ref": "mol-adopt-pr-v2.review", "gc.root_bead_id": "mc-wisp-root1"},
				}),
				fileEventLine(104, "mail.sent", "worker", "mc-mail-1", "", nil),
			},
		},
		[]string{
			fileEventLine(105, "convoy.closed", "controller", "mc-convoy-9", "", nil),
			fileEventLine(106, "order.fired", "controller", "pr-merge-patrol", "", nil),
			fileEventLine(107, "bead.created", "dispatch", "OUT-OF-WINDOW", "", nil),
		},
	)

	ing := &captureIngest{}
	srv := httptest.NewServer(ing.handler(t))
	defer srv.Close()

	cfg := backfillConfig(srv.URL, 2)
	files, err := DiscoverEventFiles(dir, 100, 106)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("DiscoverEventFiles = %v, want 3 entries", files)
	}

	res, err := Backfill(context.Background(), cfg, "testcity", files, 100, 106, false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}

	// Window (100,106]: seqs 101-106 read; 101 (bead.updated) dropped by the
	// allowlist; 102,103,104,105,106 projected => 3 chunks at BatchMax=2.
	if res.Read != 6 || res.Projected != 5 || res.Posted != 5 {
		t.Fatalf("res = %+v, want read=6 projected=5 posted=5", res)
	}
	if res.LastSeq != 106 {
		t.Fatalf("LastSeq = %d, want 106", res.LastSeq)
	}
	batches := ing.all()
	if len(batches) != 3 {
		t.Fatalf("got %d batches, want 3", len(batches))
	}
	var envs []eventexport.Envelope
	for _, b := range batches {
		if b.CityID != "testcity" || b.SchemaVersion != eventexport.SchemaVersion {
			t.Fatalf("bad batch header: %+v", b)
		}
		if len(b.Events) > 2 {
			t.Fatalf("chunk exceeds BatchMax: %d", len(b.Events))
		}
		envs = append(envs, b.Events...)
	}
	byType := map[string]eventexport.Envelope{}
	for _, e := range envs {
		byType[e.Type] = e
		// mail.sent deliberately reduces to {seq,type,ts} — no actor hash.
		if e.ActorHash == "" && e.Type != "mail.sent" {
			t.Errorf("seq %d: empty actor_hash", e.Seq)
		}
	}
	// Formula derives from gc.step_ref "mol-<formula>.<step>" (no gc.formula_name
	// on this step bead), so the "mol-" prefix is stripped.
	closed := byType["bead.closed"]
	if closed.Title != "review step" || closed.Formula != "adopt-pr-v2" || closed.StepID != "review" || closed.RunID != "mc-wisp-root1" {
		t.Errorf("flat-payload lift missing on bead.closed: %+v", closed)
	}
	if m := byType["mail.sent"]; m.Ref != "" || m.ActorHash != "" || m.Title != "" {
		t.Errorf("mail.sent must reduce to {seq,type,ts}: %+v", m)
	}
	if _, ok := byType["bead.updated"]; ok {
		t.Error("bead.updated escaped the allowlist")
	}
	for _, e := range envs {
		if e.Seq == 107 {
			t.Error("seq 107 escaped the to-seq bound")
		}
	}
}

// TestBackfill_RetriesRateLimit pins the 429 path: the same chunk is retried
// with backoff until accepted, and nothing is skipped.
func TestBackfill_RetriesRateLimit(t *testing.T) {
	dir := t.TempDir()
	writeCityHistory(t, dir, nil, []string{
		fileEventLine(10, "session.woke", "patrol", "", "", nil),
		fileEventLine(11, "session.stopped", "patrol", "", "", nil),
	})
	ing := &captureIngest{failWith: http.StatusTooManyRequests, failures: 2}
	srv := httptest.NewServer(ing.handler(t))
	defer srv.Close()

	files, err := DiscoverEventFiles(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Backfill(context.Background(), backfillConfig(srv.URL, 100), "testcity", files, 0, 0, false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Posted != 2 || res.LastSeq != 11 {
		t.Fatalf("res = %+v, want posted=2 last=11", res)
	}
	if got := len(ing.all()); got != 1 {
		t.Fatalf("accepted batches = %d, want 1 (after 2 rate-limited retries)", got)
	}
}

// TestBackfill_DryRunNeverDials pins the audit mode: projection and counting
// happen, but no request leaves.
func TestBackfill_DryRunNeverDials(t *testing.T) {
	dir := t.TempDir()
	writeCityHistory(t, dir, nil, []string{
		fileEventLine(10, "bead.created", "dispatch", "mc-a", "mc-a", nil),
	})
	files, err := DiscoverEventFiles(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := backfillConfig("https://ingest.invalid/v0/ingest", 100)
	res, err := Backfill(context.Background(), cfg, "testcity", files, 0, 0, true, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Projected != 1 || res.Posted != 1 || res.LastSeq != 10 {
		t.Fatalf("res = %+v", res)
	}
}

// TestExporter_DrainsBacklogInBatchMaxChunks pins the flushCity livelock fix in
// the vendored pkg/eventexport: a pending backlog larger than the ingest's
// per-request budget drains in BatchMax-bounded POSTs, each advancing the
// cursor, instead of retrying one oversized batch forever.
func TestExporter_DrainsBacklogInBatchMaxChunks(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	var lastSeqs []uint64
	const budget = 3 // per-request row budget, like the ingest's per-org limiter
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b eventexport.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(b.Events) > budget {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		mu.Lock()
		sizes = append(sizes, len(b.Events))
		lastSeqs = append(lastSeqs, b.Events[len(b.Events)-1].Seq)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := eventexport.New(eventexport.Config{
		Endpoint:      srv.URL,
		Salt:          []byte("0123456789abcdef"),
		ExportRef:     true,
		BatchMax:      budget,
		BatchInterval: 10 * time.Millisecond,
	})
	src := &sliceSource{}
	for i := uint64(1); i <= 10; i++ {
		src.events = append(src.events, eventexport.TaggedEvent{
			City: "c", Seq: i, Type: "session.woke", Ts: time.Now().UTC(), Actor: "patrol",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Run(ctx, src); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	var total int
	for i, n := range sizes {
		if n > budget {
			t.Fatalf("POST %d carried %d events, over the %d budget", i, n, budget)
		}
		total += n
	}
	if total != 10 {
		t.Fatalf("delivered %d events, want 10 (sizes=%v)", total, sizes)
	}
	for i := 1; i < len(lastSeqs); i++ {
		if lastSeqs[i] <= lastSeqs[i-1] {
			t.Fatalf("chunk seqs not ascending: %v", lastSeqs)
		}
	}
	if got := exp.Cursors()["c"]; got != 10 {
		t.Fatalf("cursor = %d, want 10", got)
	}
}

// sliceSource yields a fixed set of events then EOF (io.EOF ends Run cleanly).
type sliceSource struct {
	mu     sync.Mutex
	events []eventexport.TaggedEvent
	i      int
}

func (s *sliceSource) Next(ctx context.Context) (eventexport.TaggedEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.i >= len(s.events) {
		return eventexport.TaggedEvent{}, errEOF
	}
	te := s.events[s.i]
	s.i++
	return te, nil
}

var errEOF = io.EOF
