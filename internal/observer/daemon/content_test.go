//go:build linux

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/contentguard"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// Valid transcript paths for the always-on content-lane allowlist (contentguard): a codex
// rollout and a claude session uuid. The uploader keys transcripts by (device,inode), not by
// path, so the mechanics tests below reuse these shapes freely — only the content guard reads
// the basename, and a non-transcript-shaped name would now be refused before upload.
const (
	testCodexPath  = "/root/rollout-2026-06.jsonl"
	testClaudePath = "/root/01234567-89ab-cdef-0123-456789abcdef.jsonl"
)

// --- test doubles -------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fakeContentSender struct {
	mu      sync.Mutex
	reqs    []upload.ContentRequest
	respond func(n int, r upload.ContentRequest) (*upload.ContentResult, error)
}

func (f *fakeContentSender) PostContent(_ context.Context, r upload.ContentRequest) (*upload.ContentResult, error) {
	f.mu.Lock()
	n := len(f.reqs)
	f.reqs = append(f.reqs, r)
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		return respond(n, r)
	}
	return &upload.ContentResult{StatusCode: 200, GCSessionID: "gcs", ReceiptID: "r", Status: "accepted"}, nil
}

func (f *fakeContentSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeContentSender) at(i int) upload.ContentRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[i]
}

type fakeSessions struct {
	mu     sync.Mutex
	m      map[transcriptIdentity][2]string
	forgot []transcriptIdentity
}

func newSessions() *fakeSessions { return &fakeSessions{m: map[transcriptIdentity][2]string{}} }

func (f *fakeSessions) set(dev, ino uint64, native, provider string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[transcriptIdentity{device: dev, inode: ino}] = [2]string{native, provider}
}

func (f *fakeSessions) SessionFor(dev, ino uint64) (string, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.m[transcriptIdentity{device: dev, inode: ino}]
	if !ok {
		return "", "", false
	}
	return s[0], s[1], true
}

func (f *fakeSessions) Forget(dev, ino uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := transcriptIdentity{device: dev, inode: ino}
	if _, ok := f.m[id]; ok {
		delete(f.m, id)
		f.forgot = append(f.forgot, id)
	}
}

type fakeReader struct {
	mu    sync.Mutex
	reads int
	m     map[transcriptIdentity]struct {
		content []byte
		mod     int64
	}
}

func newReader() *fakeReader {
	return &fakeReader{m: map[transcriptIdentity]struct {
		content []byte
		mod     int64
	}{}}
}

func (r *fakeReader) set(dev, ino uint64, content string, mod int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[transcriptIdentity{device: dev, inode: ino}] = struct {
		content []byte
		mod     int64
	}{content: []byte(content), mod: mod}
}

func (r *fakeReader) readCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads
}

func (r *fakeReader) del(dev, ino uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, transcriptIdentity{device: dev, inode: ino})
}

func (r *fakeReader) read(_, _ string, dev, ino uint64, maxBytes int64) ([]byte, int64, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	f, ok := r.m[transcriptIdentity{device: dev, inode: ino}]
	if !ok {
		return nil, 0, 0, os.ErrNotExist
	}
	size := int64(len(f.content))
	if maxBytes > 0 && size > maxBytes {
		return nil, size, f.mod, codex.ErrTranscriptTooLarge
	}
	return append([]byte(nil), f.content...), size, f.mod, nil
}

// --- harness ------------------------------------------------------------------

type contentHarness struct {
	u        *contentUploader
	sender   *fakeContentSender
	sessions *fakeSessions
	reader   *fakeReader
	clock    *fakeClock
	stateDir string
	logMu    sync.Mutex
	logs     []string
}

func (h *contentHarness) appendLog(s string) {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	h.logs = append(h.logs, s)
}

func (h *contentHarness) logLines() []string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return append([]string(nil), h.logs...)
}

func newContentHarness(t *testing.T, cfg contentUploaderConfig) *contentHarness {
	t.Helper()
	h := &contentHarness{
		sender:   &fakeContentSender{},
		sessions: newSessions(),
		reader:   newReader(),
		clock:    newClock(),
		stateDir: t.TempDir(),
	}
	base := contentUploaderConfig{
		sender:   h.sender,
		sessions: h.sessions,
		stateDir: h.stateDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
		log:      h.appendLog,
	}
	if cfg.maxBytes != 0 {
		base.maxBytes = cfg.maxBytes
	}
	if cfg.debounce != 0 {
		base.debounce = cfg.debounce
	}
	if cfg.sender != nil {
		base.sender = cfg.sender
		h.sender = cfg.sender.(*fakeContentSender)
	}
	u, err := newContentUploader(base)
	if err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	h.u = u
	return h
}

// observe records one watcher content observation for a transcript identity.
func (h *contentHarness) observe(dev, ino uint64, path string, size, mod int64) {
	h.u.ObserveContent(context.Background(), codex.ContentObservation{
		Root:     "/root",
		Locator:  "s.jsonl",
		Path:     path,
		Device:   dev,
		Inode:    ino,
		Size:     size,
		ModNanos: mod,
	})
}

func (h *contentHarness) observeWithGCSessionID(dev, ino uint64, path string, size, mod int64, gcSessionID string) {
	h.u.ObserveContent(context.Background(), codex.ContentObservation{
		Root:        "/root",
		Locator:     "s.jsonl",
		Path:        path,
		Device:      dev,
		Inode:       ino,
		Size:        size,
		ModNanos:    mod,
		GCSessionID: gcSessionID,
	})
}

// --- tests --------------------------------------------------------------------

func TestContentUploadPostsWholeFileWithHeaders(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 7, 42
	content := "hello\nworld\n"
	h.reader.set(dev, ino, content, 100)
	h.sessions.set(dev, ino, "sess-1", "claude")

	h.observe(dev, ino, testClaudePath, int64(len(content)), 100)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())

	if h.sender.count() != 1 {
		t.Fatalf("uploads = %d, want 1", h.sender.count())
	}
	req := h.sender.at(0)
	if string(req.Body) != content {
		t.Fatalf("body = %q, want whole file %q", req.Body, content)
	}
	if req.NativeSessionID != "sess-1" || req.Provider != "claude" || req.SourcePath != testClaudePath {
		t.Fatalf("headers wrong: %+v", req)
	}
}

func TestContentUploadRearmsUnchangedTranscriptWhenGCSessionIDArrives(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 70, 420
	h.sessions.set(dev, ino, "native-1", "codex")
	h.reader.set(dev, ino, "unchanged transcript", 100)

	// The sidecar is absent on the first stable observation, so this remains a plain upload.
	h.observeWithGCSessionID(dev, ino, testCodexPath, int64(len("unchanged transcript")), 100, "")
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 || h.sender.at(0).GCSessionID != "" {
		t.Fatalf("first upload = %+v, want exactly one plain upload", h.sender.at(0))
	}

	// A late authoritative sidecar must re-arm the exact same bytes once.
	h.observeWithGCSessionID(dev, ino, testCodexPath, int64(len("unchanged transcript")), 100, "gc_exact_1")
	h.u.tick(context.Background())
	if h.sender.count() != 2 {
		t.Fatalf("uploads after sidecar arrival = %d, want 2", h.sender.count())
	}
	if got := h.sender.at(1).GCSessionID; got != "gc_exact_1" {
		t.Fatalf("second upload GC session id = %q, want authoritative sidecar id", got)
	}

	// The binding is now durable dedup state: identical bytes + metadata post no further uploads.
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 2 {
		t.Fatalf("duplicate upload after GC metadata dedup = %d, want 2", h.sender.count())
	}

	// A restart must recover the GC binding from the durable marker rather than re-send the same
	// content. This pins the marker schema as part of the dedup key, not merely in-memory state.
	u2, err := newContentUploader(contentUploaderConfig{
		sender:   h.sender,
		sessions: h.sessions,
		stateDir: h.stateDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
		log:      h.appendLog,
	})
	if err != nil {
		t.Fatalf("new restarted uploader: %v", err)
	}
	u2.ObserveContent(context.Background(), codex.ContentObservation{
		Root:        "/root",
		Locator:     "s.jsonl",
		Path:        testCodexPath,
		Device:      dev,
		Inode:       ino,
		Size:        int64(len("unchanged transcript")),
		ModNanos:    100,
		GCSessionID: "gc_exact_1",
	})
	h.clock.advance(31 * time.Second)
	u2.tick(context.Background())
	if h.sender.count() != 2 {
		t.Fatalf("restart re-uploaded already bound content: %d, want 2", h.sender.count())
	}
}

func TestContentUploadLegacyPlainMarkerStaysDeduplicatedUntilBindingArrives(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 71, 421
	const body = "legacy transcript"
	h.sessions.set(dev, ino, "native-legacy", "codex")
	h.reader.set(dev, ino, body, 100)
	h.u.persistMarker(transcriptIdentity{device: dev, inode: ino}, contentMarker{
		Version:         legacyContentMarkerVersion,
		Device:          dev,
		Inode:           ino,
		ContentSHA256:   "c55360d8885a9ca4be51dede54a18cd7fc26711b770e8f966b77a9c0b5830f13",
		Size:            int64(len(body)),
		ModNanos:        100,
		NativeSessionID: "native-legacy",
		Provider:        "codex",
		UploadedAt:      h.clock.now().UTC().Format(time.RFC3339Nano),
	})

	u2, err := newContentUploader(contentUploaderConfig{
		sender: h.sender, sessions: h.sessions, stateDir: h.stateDir, read: h.reader.read,
		now: h.clock.now, debounce: 30 * time.Second, log: h.appendLog,
	})
	if err != nil {
		t.Fatalf("new restarted uploader: %v", err)
	}
	u2.ObserveContent(context.Background(), codex.ContentObservation{
		Root: "/root", Locator: "s.jsonl", Path: testCodexPath, Device: dev, Inode: ino,
		Size: int64(len(body)), ModNanos: 100,
	})
	h.clock.advance(31 * time.Second)
	u2.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("legacy plain marker caused re-upload: %d", h.sender.count())
	}
}

func TestContentUploadDebounceWaitsForStability(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 1, 2
	h.sessions.set(dev, ino, "s", "codex")
	final := "0123456789" // 10 bytes
	h.reader.set(dev, ino, final, 5)

	// First observation (still small); a tick before the window passes uploads nothing.
	h.observe(dev, ino, testCodexPath, 5, 1)
	h.clock.advance(15 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded before stable: %d", h.sender.count())
	}

	// File grows (size+mtime change) — resets the stability clock.
	h.observe(dev, ino, testCodexPath, 10, 5)
	h.clock.advance(15 * time.Second) // only 15s since the growth
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded while still within debounce after growth: %d", h.sender.count())
	}

	// Now stable for the full window.
	h.clock.advance(20 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("uploads after stabilizing = %d, want 1", h.sender.count())
	}
	if string(h.sender.at(0).Body) != final {
		t.Fatalf("uploaded body = %q, want %q", h.sender.at(0).Body, final)
	}
}

func TestContentUploadDedupUnchangedNotReuploadedGrownReuploaded(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 3, 4
	h.sessions.set(dev, ino, "s", "codex")
	h.reader.set(dev, ino, "aaa", 1)

	h.observe(dev, ino, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("first upload count = %d, want 1", h.sender.count())
	}

	// Unchanged: another tick uploads nothing.
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("re-uploaded unchanged file: %d", h.sender.count())
	}

	// Grown: a later, larger, stable snapshot supersedes and is re-uploaded once.
	h.reader.set(dev, ino, "aaabbb", 2)
	h.observe(dev, ino, testCodexPath, 6, 2)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 2 {
		t.Fatalf("grown-file uploads = %d, want 2", h.sender.count())
	}
	if string(h.sender.at(1).Body) != "aaabbb" {
		t.Fatalf("second upload body = %q", h.sender.at(1).Body)
	}
}

func TestContentUpload501StopsUploads(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 501}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	h.sessions.set(1, 1, "s1", "codex")
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.reader.set(2, 2, "bbb", 1)

	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("first (501) attempt count = %d, want 1", sender.count())
	}

	// A second, different, stable-and-changed transcript is NOT attempted: content upload latched off.
	h.observe(2, 2, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("attempted after 501 disable: %d", sender.count())
	}
}

func TestContentUpload429HonorsRetryAfter(t *testing.T) {
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			return &upload.ContentResult{StatusCode: 429, RetryAfter: 10 * time.Second}, nil
		}
		return &upload.ContentResult{StatusCode: 200}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 5, 6
	h.sessions.set(dev, ino, "s", "codex")
	h.reader.set(dev, ino, "aaa", 1)

	h.observe(dev, ino, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background()) // 429; holdUntil = now + 10s
	if sender.count() != 1 {
		t.Fatalf("first attempt count = %d, want 1", sender.count())
	}

	// Within the Retry-After window: no attempt.
	h.clock.advance(5 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("attempted during Retry-After hold: %d", sender.count())
	}

	// After the hold expires: retried and accepted.
	h.clock.advance(6 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 2 {
		t.Fatalf("uploads after hold = %d, want 2", sender.count())
	}
}

func TestContentUploadOversizeSkipped(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{maxBytes: 4})
	const dev, ino = 8, 9
	h.sessions.set(dev, ino, "s", "codex")
	h.reader.set(dev, ino, "way too large", 1) // 13 bytes > 4

	h.observe(dev, ino, testCodexPath, 13, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded oversize file: %d", h.sender.count())
	}

	// A repeat tick does not hot-loop the oversize read/skip either.
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("oversize hot-looped: %d", h.sender.count())
	}
}

func TestContentUpload409LogsAndAdvances(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 409}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 10, 11
	h.sessions.set(dev, ino, "s", "codex")
	h.reader.set(dev, ino, "aaa", 1)

	h.observe(dev, ino, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("first (409) attempt count = %d, want 1", sender.count())
	}

	// Same content on the next tick is NOT re-POSTed (marker advanced; no hot-loop).
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("409 hot-looped: %d", sender.count())
	}
}

func TestContentUploadMarkerSurvivesRestart(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 12, 13
	h.sessions.set(dev, ino, "s", "codex")
	h.reader.set(dev, ino, "stable-body", 1)

	h.observe(dev, ino, testCodexPath, 11, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("initial upload count = %d, want 1", h.sender.count())
	}

	// "Restart": a fresh uploader over the SAME state dir, with a fresh sender.
	sender2 := &fakeContentSender{}
	u2, err := newContentUploader(contentUploaderConfig{
		sender:   sender2,
		sessions: h.sessions,
		stateDir: h.stateDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("restart newContentUploader: %v", err)
	}

	// Same content, but the mtime moved (forces the hash comparison rather than the cheap size/mtime
	// gate). The persisted marker's hash makes this an idempotent no-op — nothing is re-shipped.
	u2.ObserveContent(context.Background(), codex.ContentObservation{
		Root: "/root", Locator: "s.jsonl", Path: testCodexPath, Device: dev, Inode: ino, Size: 11, ModNanos: 2,
	})
	h.clock.advance(31 * time.Second)
	u2.tick(context.Background())
	if sender2.count() != 0 {
		t.Fatalf("re-shipped after restart: %d", sender2.count())
	}
}

// noopCandidateSink is a codex.CandidateSink that discards candidates, so the end-to-end test can
// drive a real watcher for its content-observation side effect without a daemon socket.
type noopCandidateSink struct{}

func (noopCandidateSink) DeliverCandidates(context.Context, codex.TranscriptRef, []*codex.Candidate) error {
	return nil
}

// TestContentUploadEndToEndThroughRealWatcher wires a real codex.Watcher (real temp transcript file
// + the real ReadValidatedTranscript reader) onto the real contentUploader as its ContentObserver,
// and proves a poll-then-tick ships the whole file's true bytes to the sender.
func TestContentUploadEndToEndThroughRealWatcher(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	sender := &fakeContentSender{}
	sessions := newSessions()
	clock := newClock()

	cu, err := newContentUploader(contentUploaderConfig{
		sender:   sender,
		sessions: sessions,
		stateDir: state,
		read:     codex.ReadValidatedTranscript, // the real symlink-safe whole-file reader
		now:      clock.now,
		debounce: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}

	w, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            noopCandidateSink{},
		ContentObserver: cu,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	body := "line-1\nline-2\nline-3\n"
	path := filepath.Join(root, "rollout-e2e.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	if err := w.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}

	// The poll gave us the real (dev,ino); thread the session id for that identity as the parser would.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	st := info.Sys().(*syscall.Stat_t)
	sessions.set(uint64(st.Dev), uint64(st.Ino), "native-xyz", "codex")

	clock.advance(31 * time.Second)
	cu.tick(context.Background())

	if sender.count() != 1 {
		t.Fatalf("uploads = %d, want 1", sender.count())
	}
	req := sender.at(0)
	if string(req.Body) != body {
		t.Fatalf("uploaded body = %q, want the whole real file %q", req.Body, body)
	}
	if req.NativeSessionID != "native-xyz" || req.Provider != "codex" || req.SourcePath != path {
		t.Fatalf("provenance headers wrong: %+v", req)
	}
}

func TestContentUploadSkipsUnknownSessionThenRetries(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 14, 15
	h.reader.set(dev, ino, "body", 1)
	// Session not known yet.

	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded with unknown session: %d", h.sender.count())
	}

	// Once the session id is threaded, the next tick uploads (the skip did not advance state).
	h.sessions.set(dev, ino, "late-sess", "codex")
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("did not retry after session known: %d", h.sender.count())
	}
	if h.sender.at(0).NativeSessionID != "late-sess" {
		t.Fatalf("native id = %q, want late-sess", h.sender.at(0).NativeSessionID)
	}
}

// Theme A: an unknown-session transcript is never whole-file read/hashed — the session id is
// resolved before any read, so the hot loop that re-read a stable file every tick is gone.
func TestContentUploadUnknownSessionNotRead(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 31, 32
	h.reader.set(dev, ino, "body", 1)
	// Session deliberately unknown.
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	h.clock.advance(1 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded with unknown session: %d", h.sender.count())
	}
	if h.reader.readCount() != 0 {
		t.Fatalf("whole-file read %d times for unknown-session transcript; want 0", h.reader.readCount())
	}
}

// Theme A: a codex transcript whose session id is known only from the persisted marker (the sink's
// in-memory threading is empty after a restart) still uploads its grown content — no permanent loss.
func TestContentUploadCodexRestartUsesMarkerSession(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 21, 22
	h.sessions.set(dev, ino, "codex-sess", "codex")
	h.reader.set(dev, ino, "body-v1", 1)
	h.observe(dev, ino, testCodexPath, 7, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("initial upload = %d, want 1", h.sender.count())
	}

	// Restart: a fresh uploader with EMPTY session threading (the codex head SESSION_LIFECYCLE line
	// is behind the durable cursor and never re-parsed), same state dir + reader. The transcript grew.
	sender2 := &fakeContentSender{}
	u2, err := newContentUploader(contentUploaderConfig{
		sender:   sender2,
		sessions: newSessions(), // empty
		stateDir: h.stateDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("restart newContentUploader: %v", err)
	}
	h.reader.set(dev, ino, "body-v1-and-then-some", 2) // grew → new hash, not a no-op
	u2.ObserveContent(context.Background(), codex.ContentObservation{
		Root: "/root", Locator: "s.jsonl", Path: testCodexPath, Device: dev, Inode: ino, Size: 21, ModNanos: 2,
	})
	h.clock.advance(31 * time.Second)
	u2.tick(context.Background())
	if sender2.count() != 1 {
		t.Fatalf("post-restart grown transcript not uploaded (data loss): %d", sender2.count())
	}
	if got := sender2.at(0).NativeSessionID; got != "codex-sess" {
		t.Fatalf("native id = %q, want codex-sess recovered from the persisted marker", got)
	}
}

// Theme B: a permanent 4xx (422) advances state and is not re-POSTed with identical bytes, and does
// not arm the global hold or disable the whole feature.
func TestContentUploadPermanentStatusAdvancesNoLoop(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 422}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 41, 42
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "s", "codex")
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("permanent 422 re-POSTed identical bytes: %d, want 1", sender.count())
	}
	if h.u.disabled {
		t.Fatal("permanent 422 wrongly disabled all content upload")
	}
	if !h.u.holdUntil.IsZero() {
		t.Fatal("permanent 422 wrongly armed the global hold")
	}
}

// Theme C: a structurally invalid native session id is skipped client-side (never POSTed, never
// read), so the server's 422 loop cannot arise.
func TestContentUploadInvalidSessionSkipped(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 51, 52
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "bad/session id", "codex") // '/' and space violate the contract
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("sent an invalid session id: %d", h.sender.count())
	}
	if h.reader.readCount() != 0 {
		t.Fatalf("read a transcript with invalid provenance: %d reads", h.reader.readCount())
	}
}

// Theme D: ForgetContent (fired by the watcher on drop) evicts in-memory state, removes the durable
// marker, and clears the sink's session mapping.
func TestContentUploadForgetContentEvictsStateAndMarker(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 61, 62
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "s", "codex")
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	markerPath := contentMarkerPath(h.stateDir, dev, ino)
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("marker not written: %v", err)
	}

	h.u.ForgetContent(dev, ino)

	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker not removed on forget: %v", err)
	}
	h.u.mu.Lock()
	_, present := h.u.files[transcriptIdentity{device: dev, inode: ino}]
	h.u.mu.Unlock()
	if present {
		t.Fatal("files entry not evicted on forget")
	}
	if _, _, ok := h.sessions.SessionFor(dev, ino); ok {
		t.Fatal("sink session mapping not forgotten")
	}
}

// Theme D: a vanished transcript's read error is logged at most once per streak, not every tick.
func TestContentUploadReadErrorLoggedOnce(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 101, 102
	h.sessions.set(dev, ino, "s", "codex")
	// No reader content set → read returns os.ErrNotExist.
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	h.clock.advance(1 * time.Second)
	h.u.tick(context.Background())
	n := 0
	for _, l := range h.logLines() {
		if strings.Contains(l, "content upload: read ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("read-error logged %d times across two ticks, want 1", n)
	}
}

// Theme D: a marker temp file left by a crash mid-persist is swept on startup.
func TestContentUploadBootSweepsOrphanTemps(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, ".tmp-content-marker-abc123")
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newContentUploader(contentUploaderConfig{
		sender:   &fakeContentSender{},
		sessions: newSessions(),
		stateDir: dir,
		read:     newReader().read,
		now:      newClock().now,
		debounce: 30 * time.Second,
	}); err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan temp marker not swept: %v", err)
	}
}

// Theme E: after the watcher drops an identity, a new file reusing the same (device,inode) uploads
// under its OWN session id, not the previous file's — no stale marker or session resurrection.
func TestContentUploadInodeReuseUsesNewSession(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 71, 72
	h.reader.set(dev, ino, "aaa", 1)
	h.sessions.set(dev, ino, "sessA", "codex")
	h.observe(dev, ino, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 || h.sender.at(0).NativeSessionID != "sessA" {
		t.Fatalf("file A upload wrong: count=%d", h.sender.count())
	}

	// Watcher drops A (fully rotated); a new file reuses the identity.
	h.u.ForgetContent(dev, ino)
	h.reader.set(dev, ino, "bbbbb", 5)
	h.sessions.set(dev, ino, "sessB", "codex")
	h.observe(dev, ino, testCodexPath, 5, 5)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 2 {
		t.Fatalf("reused-inode new file not uploaded: %d", h.sender.count())
	}
	if got := h.sender.at(1).NativeSessionID; got != "sessB" {
		t.Fatalf("reused inode uploaded under %q, want sessB", got)
	}
}

// Theme G: a 429 shed recorded while processing the first job in a tick stops the remaining jobs in
// that same tick (the hold is re-checked before each POST, not only at tick entry).
func TestContentUploadMidTickShedStopsRemaining(t *testing.T) {
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			return &upload.ContentResult{StatusCode: 429, RetryAfter: 60 * time.Second}, nil
		}
		return &upload.ContentResult{StatusCode: 200}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	for i, id := range []uint64{81, 82} {
		h.reader.set(1, id, "body", int64(i+1))
		h.sessions.set(1, id, "s", "codex")
		h.observe(1, id, testCodexPath, 4, int64(i+1))
	}
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("mid-tick 429 did not stop remaining jobs: %d POSTs, want 1", sender.count())
	}
}

// Theme H: an absurd server Retry-After is capped so it cannot silently disable content upload for
// the whole process lifetime.
func TestContentUploadCapsRetryAfter(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 429, RetryAfter: 1000 * time.Hour}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 91, 92
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "s", "codex")
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	want := h.clock.now().Add(maxContentHold)
	h.u.mu.Lock()
	got := h.u.holdUntil
	h.u.mu.Unlock()
	if !got.Equal(want) {
		t.Fatalf("holdUntil = %v, want capped at %v", got, want)
	}
}

// Theme B residual: a permanent-4xx rejection is never durably persisted, even when a later
// mtime-only bump routes the identical bytes through the idempotent no-op path — so a restart still
// re-probes the transcript.
func TestContentUploadPermanent422NeverPersistedViaNoOp(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 422}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 111, 112
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "s", "codex")
	h.observe(dev, ino, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background()) // POST → 422: in-memory dedup only, no marker persisted
	markerPath := contentMarkerPath(h.stateDir, dev, ino)
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("422 rejection persisted a marker: %v", err)
	}

	// mtime-only bump, identical content: the no-op path must NOT promote the rejected hash to disk.
	h.reader.set(dev, ino, "body", 2)
	h.observe(dev, ino, testCodexPath, 4, 2)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("mtime-bump no-op durably persisted 422-rejected bytes: %v", err)
	}
	if sender.count() != 1 {
		t.Fatalf("re-POSTed rejected bytes: %d", sender.count())
	}
}

// Theme F residual: a snapshot that keeps failing to POST (e.g. too slow to finish within the
// content timeout) is given up on after a bounded number of attempts instead of being re-read +
// re-hashed + re-POSTed forever; a content change re-arms retries.
func TestContentUploadGivesUpAfterRepeatedPostFailures(t *testing.T) {
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return nil, errors.New("transport timeout")
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const dev, ino = 121, 122
	h.reader.set(dev, ino, "body", 1)
	h.sessions.set(dev, ino, "s", "codex")
	h.observe(dev, ino, testCodexPath, 4, 1)

	for i := 0; i < 10; i++ {
		h.clock.advance(31 * time.Second) // past the transient hold each time
		h.u.tick(context.Background())
	}
	if got := h.reader.readCount(); got > maxContentPostAttempts {
		t.Fatalf("kept re-reading a doomed snapshot: %d reads, want <= %d", got, maxContentPostAttempts)
	}
	n := 0
	for _, l := range h.logLines() {
		if strings.Contains(l, "giving up on") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("give-up logged %d times, want 1", n)
	}

	// A content change is a new snapshot: retries re-arm.
	before := h.reader.readCount()
	h.reader.set(dev, ino, "body-grown-more", 2)
	h.observe(dev, ino, testCodexPath, 15, 2)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.reader.readCount() <= before {
		t.Fatalf("content change did not re-arm retry: reads stayed at %d", before)
	}
}

// TestContentUploadGuardsRefuseSecretsBeforeAnyRequest is the bd-63vj1 acceptance: the always-on
// content guards (contentguard) refuse a secrets-named file, an env file, a PEM-bodied transcript,
// and a non-allowlisted .jsonl AT THE DAEMON — NO upload request is constructed for any of them —
// while a real allowlisted transcript authored alongside them still uploads. The drops are counted
// (per reason) and logged, never silent.
func TestContentUploadGuardsRefuseSecretsBeforeAnyRequest(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})

	// Each refused fixture is a distinct (device,inode) with a VALID session threaded, so the ONLY
	// thing that can stop it is the content guard (not the unknown-session or invalid-header skips).
	pemBody := "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END PRIVATE KEY-----\n"
	fixtures := []struct {
		dev, ino uint64
		path     string
		body     string
		reason   contentguard.Reason
	}{
		{1, 1, "/root/proj/credentials.json", `{"token":"sekret"}`, contentguard.ReasonDenylistedName}, // exact denylist
		{2, 2, "/root/proj/x.env", "SECRET=1\n", contentguard.ReasonDenylistedName},                    // deny-glob *.env
		{3, 3, "/root/proj/agent-abc123.jsonl", pemBody, contentguard.ReasonPEMContent},                // allowlisted name, PEM body
		{4, 4, "/root/proj/notes.jsonl", `{"type":"user"}`, contentguard.ReasonNotAllowlisted},         // off-shape name
	}
	for _, f := range fixtures {
		h.reader.set(f.dev, f.ino, f.body, 1)
		h.sessions.set(f.dev, f.ino, "sess", "claude")
		h.observe(f.dev, f.ino, f.path, int64(len(f.body)), 1)
	}
	// A real transcript that MUST still upload, proving the guard is a filter, not a kill-switch.
	realBody := `{"type":"user","text":"hi"}` + "\n"
	h.reader.set(9, 9, realBody, 1)
	h.sessions.set(9, 9, "sess-ok", "claude")
	h.observe(9, 9, testClaudePath, int64(len(realBody)), 1)

	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())

	// Exactly one upload — the allowlisted transcript. No request was constructed for any refusal.
	if h.sender.count() != 1 {
		t.Fatalf("uploads = %d, want exactly 1 (only the allowlisted transcript); a guarded file produced a request", h.sender.count())
	}
	if got := h.sender.at(0).SourcePath; got != testClaudePath {
		t.Fatalf("uploaded transcript = %q, want the allowlisted %q", got, testClaudePath)
	}

	// Every refusal is counted by reason (deny x2, not-allowlisted x1, PEM x1).
	h.u.mu.Lock()
	deny := h.u.guardRefusals[contentguard.ReasonDenylistedName]
	notAllow := h.u.guardRefusals[contentguard.ReasonNotAllowlisted]
	pem := h.u.guardRefusals[contentguard.ReasonPEMContent]
	h.u.mu.Unlock()
	if deny != 2 || notAllow != 1 || pem != 1 {
		t.Fatalf("guard refusal counts = deny:%d not-allowlisted:%d pem:%d, want 2/1/1", deny, notAllow, pem)
	}

	// The refusals were logged, not silent — one line per refused fixture.
	var logged int
	for _, l := range h.logLines() {
		if strings.Contains(l, "refusing") && strings.Contains(l, "guard") {
			logged++
		}
	}
	if logged != 4 {
		t.Fatalf("guard refusals logged %d times, want 4 (one per refused fixture); logs=%v", logged, h.logLines())
	}

	// A repeat tick does not re-count, re-log, or hot-loop the refusals (eval advanced).
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("a refused fixture produced a request on the second tick: uploads = %d", h.sender.count())
	}
	h.u.mu.Lock()
	total := h.u.guardRefusals[contentguard.ReasonDenylistedName] + h.u.guardRefusals[contentguard.ReasonNotAllowlisted] + h.u.guardRefusals[contentguard.ReasonPEMContent]
	h.u.mu.Unlock()
	if total != 4 {
		t.Fatalf("guard refusals re-counted on a second tick: total = %d, want 4", total)
	}
}
