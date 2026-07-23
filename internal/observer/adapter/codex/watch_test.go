//go:build unix

package codex

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// recordingSink is the in-memory CandidateSink test double. It records every delivered batch and
// can inject a one-shot delivery failure to exercise the watcher's at-least-once ordering.
type recordingSink struct {
	mu       sync.Mutex
	batches  []recordedBatch
	failNext bool
	failErr  error
}

type recordedBatch struct {
	ref   TranscriptRef
	cands []*Candidate
}

func (s *recordingSink) DeliverCandidates(_ context.Context, ref TranscriptRef, cands []*Candidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return s.failErr
	}
	cp := make([]*Candidate, len(cands))
	copy(cp, cands)
	s.batches = append(s.batches, recordedBatch{ref: ref, cands: cp})
	return nil
}

func (s *recordingSink) all() []*Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Candidate
	for _, b := range s.batches {
		out = append(out, b.cands...)
	}
	return out
}

func (s *recordingSink) messages() []string { return messageBodies(s.all()) }

func mustWatcher(t *testing.T, cfg WatchConfig) *Watcher {
	t.Helper()
	if cfg.References.Resolver.DefaultProjectID == "" && cfg.References.BeadPrefixes == nil {
		cfg.References = defaultRefConfig()
	}
	w, err := NewWatcher(cfg)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	return w
}

func writeFileString(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendString(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open-append %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	_, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatalf("no identity for %s", path)
	}
	return ino
}

func hasDiagnosticWithCode(cands []*Candidate, code wire.CaptureDiagnosticPayloadCode) bool {
	for _, c := range diagnostics(cands) {
		if c.Diagnostic.Code == code {
			return true
		}
	}
	return false
}

func TestWatcherGrowingFileReadsOnlyNewBytes(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}

	var mu sync.Mutex
	type readRec struct{ off, length int64 }
	var reads []readRec
	rr := func(f *os.File, off, length int64) ([]byte, error) {
		mu.Lock()
		reads = append(reads, readRec{off, length})
		mu.Unlock()
		return readRangeAt(f, off, length)
	}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, ReadRange: rr})

	lineA := msgLine("a") + "\n"
	lineB := msgLine("b") + "\n"
	lineC := msgLine("c") + "\n"

	writeFileString(t, p, lineA)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	appendString(t, p, lineB)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	appendString(t, p, lineC)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 3: %v", err)
	}

	want := []readRec{
		{0, int64(len(lineA))},
		{int64(len(lineA)), int64(len(lineB))},
		{int64(len(lineA) + len(lineB)), int64(len(lineC))},
	}
	if len(reads) != len(want) {
		t.Fatalf("want %d reads, got %d: %+v", len(want), len(reads), reads)
	}
	var total int64
	for i, r := range reads {
		if r != want[i] {
			t.Fatalf("read %d: want %+v, got %+v (a full re-read would start at 0)", i, want[i], r)
		}
		total += r.length
	}
	if total != int64(len(lineA)+len(lineB)+len(lineC)) {
		t.Fatalf("total bytes read %d != file size %d (each byte must be read once)", total, len(lineA)+len(lineB)+len(lineC))
	}
	if got := sink.messages(); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("messages: want [a b c], got %v", got)
	}
}

func TestWatcherPartialLineAcrossPollsParsesRecordOnce(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	full := msgLine("hello")
	writeFileString(t, p, full[:len(full)/2]) // partial: no newline
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("partial line should not deliver a record yet, got %v", got)
	}
	appendString(t, p, full[len(full)/2:]+"\n") // completes the line
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "hello" {
		t.Fatalf("completed line: want [hello] exactly once, got %v", got)
	}
}

func TestWatcherDurableCursorSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")

	writeFileString(t, p, msgLine("a")+"\n"+msgLine("b")+"\n")
	sink1 := &recordingSink{}
	w1 := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink1})
	if err := w1.Poll(ctx); err != nil {
		t.Fatalf("poll w1: %v", err)
	}
	if got := sink1.messages(); len(got) != 2 {
		t.Fatalf("w1 should deliver a,b, got %v", got)
	}

	// A fresh watcher over the SAME state dir + root is a process restart: it must resume at the
	// durable offset and deliver only the newly appended record, never re-delivering a or b.
	sink2 := &recordingSink{}
	w2 := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink2})
	appendString(t, p, msgLine("c")+"\n")
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("poll w2: %v", err)
	}
	if got := sink2.messages(); len(got) != 1 || got[0] != "c" {
		t.Fatalf("restarted watcher: want [c] only, got %v", got)
	}
}

func TestWatcherFileReplacementRestartsAtZero(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	oldIno := inodeOf(t, p)

	// Replace the file with a guaranteed-distinct inode: create the replacement alongside the old
	// (so it cannot reuse the old inode number) and rename it over the path. The old inode is
	// unlinked; the path now resolves to a new identity.
	repl := filepath.Join(root, "session.jsonl.new")
	writeFileString(t, repl, msgLine("b")+"\n")
	if inodeOf(t, repl) == oldIno {
		t.Fatal("replacement file unexpectedly shares the old inode while both exist")
	}
	if err := os.Rename(repl, p); err != nil {
		t.Fatalf("rename replacement: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("replacement: want [a b] (b read from 0, a not re-read), got %v", got)
	}
}

func TestWatcherTruncationRestartsAtZeroWithDiagnostic(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine(strings.Repeat("a", 40))+"\n"+msgLine(strings.Repeat("b", 40))+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	before := inodeOf(t, p)

	// Rewrite in place (O_TRUNC keeps the inode) with strictly smaller content: size < offset.
	writeFileString(t, p, msgLine("c")+"\n")
	if inodeOf(t, p) != before {
		t.Skip("filesystem changed the inode on truncate; in-place truncation not exercised")
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if !hasDiagnosticWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS) {
		t.Fatalf("truncation must emit a CAPTURE_LOSS diagnostic; got %v", sink.all())
	}
	got := sink.messages()
	if len(got) < 1 || got[len(got)-1] != "c" {
		t.Fatalf("truncation should read c from 0, got %v", got)
	}
}

func TestWatcherRotationPicksUpNewFileByIdentity(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	active := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, active, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	// Rotate: the active transcript moves aside (same inode), a fresh one appears at the path.
	if err := os.Rename(active, active+".1"); err != nil {
		t.Fatalf("rotate rename: %v", err)
	}
	writeFileString(t, active, msgLine("b")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("rotation: want [a b] (new identity picked up, rotated file not re-read), got %v", got)
	}
}

func TestWatcherRefusesSymlinkSwappedTranscript(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("real")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	// Swap the transcript for a symlink pointing at secret content outside the root.
	if err := os.Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "secret.jsonl")
	writeFileString(t, secret, msgLine("SECRET")+"\n")
	if err := os.Symlink(secret, p); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	for _, m := range sink.messages() {
		if m == "SECRET" {
			t.Fatal("watcher followed a symlink-swapped transcript and read secret content")
		}
	}
	if !hasDiagnosticWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS) {
		t.Fatalf("a refused symlink swap should emit a diagnostic; got %v", sink.all())
	}
}

func TestWatcherRefusesParentSymlinkSwap(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	day := filepath.Join(root, "day")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatalf("mkdir day: %v", err)
	}
	p := filepath.Join(day, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("real")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "real" {
		t.Fatalf("nested real transcript should be discovered, got %v", got)
	}

	// Swap the parent directory for a symlink escaping the root: WalkDir must not descend it.
	if err := os.RemoveAll(day); err != nil {
		t.Fatalf("remove day: %v", err)
	}
	outside := t.TempDir()
	writeFileString(t, filepath.Join(outside, "session.jsonl"), msgLine("SECRET")+"\n")
	if err := os.Symlink(outside, day); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	for _, m := range sink.messages() {
		if m == "SECRET" {
			t.Fatal("watcher descended a symlink-swapped parent and read secret content")
		}
	}
}

func TestWatcherRemainderCapOverflowDiagnostic(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, MaxPartialLine: 32})

	// A single line far past the cap with no newline: overflow to a diagnostic, bounded memory.
	writeFileString(t, p, strings.Repeat("x", 200))
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if !hasDiagnosticWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE) {
		t.Fatalf("over-long partial line should emit a PARTIAL_CAPTURE diagnostic; got %v", sink.all())
	}

	// Terminate the poison line and append a clean record: the watcher resynchronizes.
	appendString(t, p, "\n"+msgLine("after")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	found := false
	for _, m := range sink.messages() {
		if m == "after" {
			found = true
		}
	}
	if !found {
		t.Fatalf("watcher should resynchronize and deliver 'after', got %v", sink.messages())
	}
}

// TestWatcherInodeReuseCorroborationReReadsFromZero seeds a stale cursor state file at a live
// file's exact (device,inode) — modelling the on-disk residue a deleted transcript leaves when a
// new file reuses its inode across a watcher restart. LoadCursor's size/mtime corroboration must
// reject the stale offset and re-read the new file from 0, delivering all its records rather than
// skipping its leading bytes (silent evidence loss).
func TestWatcherInodeReuseCorroborationReReadsFromZero(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("first")+"\n"+msgLine("second")+"\n")

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	dev, ino, _ := fileIdentityOf(info)
	// Seed a stale state file with a huge consumed/size/mtime — inconsistent with the small live
	// file (a reused-inode landmine). Corroboration (live size < persisted size) must reject it.
	seed := persistedCursor{Version: cursorStateVersion, Device: dev, Inode: ino, Consumed: 1 << 20, Size: 1 << 20, ModNanos: 1 << 40}
	b, _ := json.Marshal(seed)
	if err := os.WriteFile(cursorStatePath(state, dev, ino), b, 0o600); err != nil {
		t.Fatalf("seed stale state: %v", err)
	}

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("reused-inode cursor must re-read from 0 (both records), got %v", got)
	}
}

// TestWatcherInPlaceRewriteGrowsPastOffsetReReads exercises the O_TRUNC-then-grow-past-offset
// silent-loss BLOCKER: a same-inode rewrite whose new content already exceeds the old cursor offset
// passes the shrink guard, so the watcher must detect the rewrite by the newline-boundary check
// (the byte before the consumed offset is no longer the newline that ended the last line) and
// re-read from 0 with a CAPTURE_LOSS diagnostic — not mis-parse the new leading content as an append.
func TestWatcherInPlaceRewriteGrowsPastOffsetReReads(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("a")+"\n") // short: consumed advances to a small offset
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	before := inodeOf(t, p)

	// Rewrite in place (O_TRUNC keeps the inode) with a single LONGER record, so the new size
	// exceeds the old offset but the byte at old-consumed-1 is interior JSON, not a newline.
	writeFileString(t, p, msgLine(strings.Repeat("z", 120))+"\n")
	if inodeOf(t, p) != before {
		t.Skip("filesystem changed the inode on rewrite; in-place rewrite not exercised")
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if !hasDiagnosticWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS) {
		t.Fatalf("in-place rewrite past the offset must emit a CAPTURE_LOSS diagnostic; got %v", sink.all())
	}
	got := sink.messages()
	if len(got) < 2 || got[len(got)-1] != strings.Repeat("z", 120) {
		t.Fatalf("rewrite must re-read the new record from 0, got %v", got)
	}
}

// TestWatcherStateFileGCdOnDeparture proves the durable state file is removed when its identity
// leaves the roots, so a later file reusing that (device,inode) cannot resurrect a stale cursor.
func TestWatcherStateFileGCdOnDeparture(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	info, _ := os.Stat(p)
	dev, ino, _ := fileIdentityOf(info)
	sp := cursorStatePath(state, dev, ino)
	if _, err := os.Stat(sp); err != nil {
		t.Fatalf("state file should exist after tracking: %v", err)
	}

	if err := os.Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Fatalf("departed identity's state file must be GC'd; stat err=%v", err)
	}
}

// TestWatcherStateDirInsideRootRejected proves NewWatcher refuses a state dir that is (or is nested
// in) an approved root — textually, and through a symlink whose target resolves into a root — so
// the watcher can never ingest its own cursor files as transcripts.
func TestWatcherStateDirInsideRootRejected(t *testing.T) {
	root := t.TempDir()
	for _, sd := range []string{root, filepath.Join(root, "state")} {
		if _, err := NewWatcher(WatchConfig{ApprovedRoots: []string{root}, StateDir: sd, Sink: &recordingSink{}, References: defaultRefConfig()}); err == nil {
			t.Fatalf("state dir %q inside root %q must be rejected", sd, root)
		}
	}

	// A StateDir that is a symlink whose target lands inside the root must also be rejected (the
	// textual check would miss it without symlink resolution).
	realInside := filepath.Join(root, "realstate")
	if err := os.MkdirAll(realInside, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(t.TempDir(), "statelink")
	if err := os.Symlink(realInside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := NewWatcher(WatchConfig{ApprovedRoots: []string{root}, StateDir: link, Sink: &recordingSink{}, References: defaultRefConfig()}); err == nil {
		t.Fatal("state dir symlinked into a root must be rejected")
	}

	// A genuine string-prefix sibling (root-state vs root) must NOT be over-rejected.
	sibling := root + "-state"
	if _, err := NewWatcher(WatchConfig{ApprovedRoots: []string{root}, StateDir: sibling, Sink: &recordingSink{}, References: defaultRefConfig()}); err != nil {
		t.Fatalf("a string-prefix sibling state dir must be accepted, got %v", err)
	}
}

// TestWatcherRenamePastMatchStillDrainsTail proves a tracked file renamed to a name the Match
// filter would reject on discovery keeps being drained (Match gates discovery only), so its unread
// tail written before the rename is not silently dropped.
func TestWatcherRenamePastMatchStillDrainsTail(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	match := func(name string) bool { return strings.HasSuffix(name, ".jsonl") }
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, Match: match})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	// Append a tail, then rename to a name the Match filter rejects, before the next poll.
	appendString(t, p, msgLine("b")+"\n")
	bak := filepath.Join(root, "session.bak")
	if err := os.Rename(p, bak); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if got := sink.messages(); len(got) != 2 || got[1] != "b" {
		t.Fatalf("renamed-past-Match file must still drain its tail [a b], got %v", got)
	}
}

// TestOpenValidatedTranscriptRefusesSymlinkAndMismatch covers the O_NOFOLLOW + fstat-identity read
// guard: a regular file opens and validates, a symlink is refused, and a wrong tracked identity is
// reported as a mismatch — all as skippable drain errors that never terminate Run.
func TestOpenValidatedTranscriptRefusesSymlinkAndMismatch(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "real.jsonl")
	writeFileString(t, p, "hello\n")
	info, _ := os.Stat(p)
	dev, ino, _ := fileIdentityOf(info)

	f, size, _, err := openValidatedTranscript(root, "real.jsonl", dev, ino)
	if err != nil {
		t.Fatalf("validated open of a regular file: %v", err)
	}
	if size != 6 {
		t.Fatalf("size: want 6, got %d", size)
	}
	f.Close()

	// Wrong tracked identity → mismatch (skippable).
	if _, _, _, err := openValidatedTranscript(root, "real.jsonl", dev, ino+1); !errors.Is(err, errIdentityMismatch) || !isSkippableDrainErr(err) {
		t.Fatalf("identity mismatch: want errIdentityMismatch+skippable, got %v", err)
	}

	// A symlink final component → refused (never followed), skippable.
	if err := os.Symlink(p, filepath.Join(root, "link.jsonl")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, _, _, err := openValidatedTranscript(root, "link.jsonl", dev, ino); err == nil || !isSkippableDrainErr(err) {
		t.Fatalf("symlink final component: want skippable refusal, got %v", err)
	}

	if isSkippableDrainErr(errors.New("some other error")) {
		t.Fatal("an unrelated error must not be treated as a skippable drain error")
	}
}

// TestOpenValidatedTranscriptRefusesParentSymlinkUnderInodeReuse proves the openat2
// RESOLVE_NO_SYMLINKS resolution refuses a PARENT-directory symlink swapped in after discovery —
// the residual the prior O_NOFOLLOW-only guard left open. Even when the redirect target reuses the
// tracked inode (so an fstat identity check alone would pass), the open is refused before any read.
func TestOpenValidatedTranscriptRefusesParentSymlinkUnderInodeReuse(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "day")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(realDir, "session.jsonl")
	writeFileString(t, p, "legit\n")
	info, _ := os.Stat(p)
	dev, ino, _ := fileIdentityOf(info)

	// Baseline: the honest nested path opens and validates.
	f, _, _, err := openValidatedTranscript(root, filepath.Join("day", "session.jsonl"), dev, ino)
	if err != nil {
		t.Fatalf("honest nested open: %v", err)
	}
	f.Close()

	// Swap the parent directory for a symlink pointing outside the root. openat2 resolving under the
	// root fd must refuse the symlinked "day" component regardless of what it targets or its inode.
	outside := t.TempDir()
	writeFileString(t, filepath.Join(outside, "session.jsonl"), "SECRET\n")
	if err := os.RemoveAll(realDir); err != nil {
		t.Fatalf("rm realDir: %v", err)
	}
	if err := os.Symlink(outside, realDir); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	if _, _, _, err := openValidatedTranscript(root, filepath.Join("day", "session.jsonl"), dev, ino); err == nil || !isSkippableDrainErr(err) {
		t.Fatalf("parent symlink swap: want skippable refusal (no read), got %v", err)
	}
}

func countDiagnosticsWithCode(cands []*Candidate, code wire.CaptureDiagnosticPayloadCode) int {
	n := 0
	for _, c := range diagnostics(cands) {
		if c.Diagnostic.Code == code {
			n++
		}
	}
	return n
}

// TestWatcherOverflowSkipDoesNotFalseResetEachPoll covers finding #1: after a remainder-cap
// overflow leaves consumed at a NON-newline-aligned offset (skip mode), a subsequent poll of the
// UNCHANGED file must not treat the non-newline boundary as a rewrite — the anchor fingerprint
// matches the unchanged bytes, so no spurious CAPTURE_LOSS flood and no re-read from 0.
func TestWatcherOverflowSkipDoesNotFalseResetEachPoll(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, MaxPartialLine: 32})

	writeFileString(t, p, strings.Repeat("x", 200)) // over-cap, no newline → overflow + skip mode
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if got := countDiagnosticsWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE); got != 1 {
		t.Fatalf("want 1 PARTIAL_CAPTURE after overflow, got %d", got)
	}
	// Two more polls of the UNCHANGED file: no false rewrite detection.
	for i := 0; i < 2; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("poll %d: %v", i+2, err)
		}
	}
	if got := countDiagnosticsWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS); got != 0 {
		t.Fatalf("unchanged file in skip mode must not emit CAPTURE_LOSS; got %d (false-reset flood)", got)
	}
}

// TestWatcherInodeReuseCoincidentalNewlineReReads covers finding #2: a stale cursor whose consumed
// offset lands where a DIFFERENT file (reused inode) coincidentally has a newline at consumed-1 must
// still be re-read from 0 — the multi-byte anchor fingerprint mismatches the different content, so
// the one-byte coincidence no longer causes a silent skip.
func TestWatcherInodeReuseCoincidentalNewlineReReads(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	recB0 := msgLine("bfirst") + "\n"
	recB1 := msgLine("bsecond") + "\n"
	writeFileString(t, p, recB0+recB1)
	info, _ := os.Stat(p)
	dev, ino, _ := fileIdentityOf(info)
	consumed := int64(len(recB0)) // a real newline boundary in B (byte at consumed-1 is '\n')

	// Seed a stale cursor at B's identity with an anchor fingerprint for DIFFERENT (file-A) content.
	// size/mtime are consistent so LoadCursor resumes and drain reaches the anchor comparison.
	fakeAnchor := []byte(strings.Repeat("A", anchorLen))
	seed := persistedCursor{
		Version: cursorStateVersion, Device: dev, Inode: ino,
		Consumed: consumed, Size: consumed, ModNanos: 1,
		AnchorHash: hashBytes(fakeAnchor), AnchorSize: anchorLen,
	}
	b, _ := json.Marshal(seed)
	if err := os.WriteFile(cursorStatePath(state, dev, ino), b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "bfirst" || got[1] != "bsecond" {
		t.Fatalf("coincidental-newline reused inode must re-read from 0 (both records), got %v", got)
	}
}

// TestWatcherSameLengthInPlaceRewriteReReads covers finding #3: an in-place O_TRUNC rewrite whose
// new leading record is the SAME byte length as the old (so consumed-1 lands on the new record's
// terminating newline) must still be re-read from 0 — the anchor fingerprint of the new content
// differs from the old, defeating the same-length coincidence that a single-byte check missed.
func TestWatcherSameLengthInPlaceRewriteReReads(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	old := msgLine("aa") + "\n"
	writeFileString(t, p, old)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	before := inodeOf(t, p)

	// Rewrite in place: new leading record "bb" is the SAME length as "aa", followed by "cc".
	writeFileString(t, p, msgLine("bb")+"\n"+msgLine("cc")+"\n")
	if inodeOf(t, p) != before {
		t.Skip("filesystem changed the inode on rewrite; same-length in-place rewrite not exercised")
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	got := sink.messages()
	// "bb" must appear (re-read from 0), not be skipped by the same-length coincidence.
	sawBB := false
	for _, m := range got {
		if m == "bb" {
			sawBB = true
		}
	}
	if !sawBB {
		t.Fatalf("same-length in-place rewrite must re-read 'bb' from 0, got %v", got)
	}
	if got := countDiagnosticsWithCode(sink.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS); got == 0 {
		t.Fatalf("same-length rewrite must emit a CAPTURE_LOSS diagnostic; got none")
	}
}

// TestWatcherUnreadableFileDoesNotStarveOthers covers finding #4: one tracked file whose read
// permission is revoked after discovery must be skipped (not crash Poll), so co-tracked transcripts
// are still drained.
func TestWatcherUnreadableFileDoesNotStarveOthers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 does not deny read")
	}
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	bad := filepath.Join(root, "asession.jsonl")
	good := filepath.Join(root, "zsession.jsonl")
	writeFileString(t, bad, msgLine("bad1")+"\n")
	writeFileString(t, good, msgLine("good1")+"\n")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	// Revoke read on the (lexicographically first) bad file and append to the good one.
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	appendString(t, good, msgLine("good2")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2 must not fail because one file is unreadable: %v", err)
	}
	if !containsMessage(sink.messages(), "good2") {
		t.Fatalf("an unreadable co-tracked file must not starve the good file's tail; got %v", sink.messages())
	}
}

func containsMessage(msgs []string, want string) bool {
	for _, m := range msgs {
		if m == want {
			return true
		}
	}
	return false
}

// TestWatcherRestartThenPartialAppendKeepsAnchorAgainstRewrite covers the post-restart anchor
// durability hole: after a restart, a poll that consumes only a partial (unterminated) line must
// NOT wipe the persisted fingerprint down to a shorter/empty window (which would downgrade to the
// vulnerable single-byte check). The in-memory anchor is re-seeded from the validated read, so a
// subsequent same-length in-place rewrite is still caught and re-read.
func TestWatcherRestartThenPartialAppendKeepsAnchorAgainstRewrite(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")

	// Run 1: consume one full record (persists a full anchor), then simulate a restart.
	writeFileString(t, p, msgLine("first")+"\n")
	w1 := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: &recordingSink{}})
	if err := w1.Poll(ctx); err != nil {
		t.Fatalf("poll w1: %v", err)
	}

	// Run 2 (restart): a partial (no-newline) append is consumed as 0 complete lines — the commit
	// must not degrade the persisted anchor.
	appendString(t, p, "{partial-no-newline")
	sink := &recordingSink{}
	w2 := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("poll w2: %v", err)
	}

	// Run 3 (restart): an in-place same-length rewrite whose leading record matches the old consumed
	// length (so consumed-1 is a newline). A degraded anchor would silently skip it; the intact
	// fingerprint must catch the content change and re-read.
	writeFileString(t, p, msgLine("SECON")+"\n"+msgLine("third")+"\n") // "SECON"→msgLine same length as "first"
	sink3 := &recordingSink{}
	w3 := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink3})
	if err := w3.Poll(ctx); err != nil {
		t.Fatalf("poll w3: %v", err)
	}
	if !containsMessage(sink3.messages(), "SECON") {
		t.Fatalf("post-restart-partial anchor must still catch the same-length rewrite and re-read 'SECON', got %v", sink3.messages())
	}
	if countDiagnosticsWithCode(sink3.all(), wire.CaptureDiagnosticPayloadCodeCAPTURELOSS) == 0 {
		t.Fatalf("the rewrite must emit a CAPTURE_LOSS diagnostic; got none (anchor was degraded)")
	}
}

func TestWatcherSinkFailureDoesNotAdvanceCursor(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{failNext: true, failErr: errors.New("boom")}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err == nil {
		t.Fatal("poll should surface the sink delivery failure")
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("failed delivery must not be recorded, got %v", got)
	}

	// The cursor was not advanced, so the next poll re-reads the same bytes (at-least-once).
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("retry poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("retry should re-deliver a exactly once, got %v", got)
	}
}
