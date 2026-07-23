//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/upload"
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
	mu sync.Mutex
	m  map[transcriptIdentity][2]string
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

type fakeReader struct {
	mu sync.Mutex
	m  map[transcriptIdentity]struct {
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

func (r *fakeReader) read(_, _ string, dev, ino uint64, maxBytes int64) ([]byte, int64, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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

// --- tests --------------------------------------------------------------------

func TestContentUploadPostsWholeFileWithHeaders(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 7, 42
	content := "hello\nworld\n"
	h.reader.set(dev, ino, content, 100)
	h.sessions.set(dev, ino, "sess-1", "claude")

	h.observe(dev, ino, "/abs/s.jsonl", int64(len(content)), 100)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())

	if h.sender.count() != 1 {
		t.Fatalf("uploads = %d, want 1", h.sender.count())
	}
	req := h.sender.at(0)
	if string(req.Body) != content {
		t.Fatalf("body = %q, want whole file %q", req.Body, content)
	}
	if req.NativeSessionID != "sess-1" || req.Provider != "claude" || req.SourcePath != "/abs/s.jsonl" {
		t.Fatalf("headers wrong: %+v", req)
	}
}

func TestContentUploadDebounceWaitsForStability(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 1, 2
	h.sessions.set(dev, ino, "s", "codex")
	final := "0123456789" // 10 bytes
	h.reader.set(dev, ino, final, 5)

	// First observation (still small); a tick before the window passes uploads nothing.
	h.observe(dev, ino, "/p", 5, 1)
	h.clock.advance(15 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 0 {
		t.Fatalf("uploaded before stable: %d", h.sender.count())
	}

	// File grows (size+mtime change) — resets the stability clock.
	h.observe(dev, ino, "/p", 10, 5)
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

	h.observe(dev, ino, "/p", 3, 1)
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
	h.observe(dev, ino, "/p", 6, 2)
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

	h.observe(1, 1, "/p1", 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("first (501) attempt count = %d, want 1", sender.count())
	}

	// A second, different, stable-and-changed transcript is NOT attempted: content upload latched off.
	h.observe(2, 2, "/p2", 3, 1)
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

	h.observe(dev, ino, "/p", 3, 1)
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

	h.observe(dev, ino, "/p", 13, 1)
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

	h.observe(dev, ino, "/p", 3, 1)
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

	h.observe(dev, ino, "/p", 11, 1)
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
		Root: "/root", Locator: "s.jsonl", Path: "/p", Device: dev, Inode: ino, Size: 11, ModNanos: 2,
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
	path := filepath.Join(root, "session.jsonl")
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

	h.observe(dev, ino, "/p", 4, 1)
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
