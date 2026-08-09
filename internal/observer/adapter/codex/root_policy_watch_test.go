//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

func TestForwardOnlyBaselineUsesStatOnlyAndNeverObservesWholeContent(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("before-consent") + "\n"
	post := msgLine("after-consent") + "\n"
	writeFileString(t, p, pre)

	var reads [][2]int64
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: &recordingSink{}, ContentObserver: obs,
		ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
			reads = append(reads, [2]int64{off, n})
			return readRangeAt(f, off, n)
		},
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("baseline poll: %v", err)
	}
	if len(reads) != 0 || len(w.cfg.Sink.(*recordingSink).messages()) != 0 {
		t.Fatalf("baseline read/capture = %v/%v, want zero transcript reads and captures", reads, w.cfg.Sink.(*recordingSink).messages())
	}
	if _, ok := obs.last(); ok {
		t.Fatal("forward-only baseline reached content observer")
	}

	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only appended bytes", reads)
	}
	if got := w.cfg.Sink.(*recordingSink).messages(); len(got) != 1 || got[0] != "after-consent" {
		t.Fatalf("messages = %v, want post-consent record only", got)
	}
	if _, ok := obs.last(); ok {
		t.Fatal("baseline-origin file reached content observer after append")
	}
}

func TestForwardOnlyLostCursorResealsFromCommittedRootFloor(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("before") + "\n"
	post := msgLine("after") + "\n"
	writeFileString(t, p, pre)
	policy := []rootpolicy.Record{{Path: root, Generation: 3, Active: true, Mode: rootpolicy.ForwardOnly}}
	w1 := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: &recordingSink{}})
	if err := w1.Poll(ctx); err != nil {
		t.Fatalf("baseline poll: %v", err)
	}
	for _, p := range mustGlob(t, filepath.Join(state, "root-cursors", "*", "codex-cursor-*.json")) {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	appendString(t, p, post)
	var reads [][2]int64
	sink := &recordingSink{}
	w2 := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: sink, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads = append(reads, [2]int64{off, n})
		return readRangeAt(f, off, n)
	}})
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("restart poll: %v", err)
	}
	if len(reads) != 1 || reads[0][0] != int64(len(pre)) {
		t.Fatalf("restart reads = %v, want read from committed baseline EOF %d", reads, len(pre))
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after" {
		t.Fatalf("restart messages = %v, want only post-consent record", got)
	}
}

func TestForwardOnlyUncommittedActivationMarkerRestartsStatOnly(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("before-crash") + "\n"
	writeFileString(t, p, pre)
	record := rootpolicy.Record{Path: root, Generation: 5, Active: true, Mode: rootpolicy.ForwardOnly}
	// This is the crash window after the high-water record was made durable and before its atomic
	// generation marker: a prior process may have started, but cannot drain the root yet.
	if _, err := newRootPolicyState(state, record); err != nil {
		t.Fatalf("prepare uncommitted control: %v", err)
	}
	var reads int
	w := mustWatcher(t, WatchConfig{RootPolicies: []rootpolicy.Record{record}, StateDir: state, Sink: &recordingSink{}, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads++
		return readRangeAt(f, off, n)
	}})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("restarted activation poll: %v", err)
	}
	if reads != 0 {
		t.Fatalf("activation recovery read %d transcript ranges, want stat-only reseal", reads)
	}
	if !w.rootPolicies[root].control.Committed {
		t.Fatal("activation marker was not committed after all baseline state was durable")
	}
}

func TestForwardBaselineTruncateResealsAtEOFWithoutReadingPrefix(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("long-pre-consent-record") + "\n"
	writeFileString(t, p, pre)
	var reads [][2]int64
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}, StateDir: state, Sink: sink, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads = append(reads, [2]int64{off, n})
		return readRangeAt(f, off, n)
	}})
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	// A short rewrite triggers the forward-baseline recovery path. It must seal at the new raw
	// EOF; it must neither use the legacy anchor reader nor restart at byte zero.
	rewritten := msgLine("rewritten") + "\n"
	writeFileString(t, p, rewritten)
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(reads) != 0 {
		t.Fatalf("truncate/rewrite read %v, want no pre-consent range reads", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("truncate/rewrite captured %v, want no byte-zero fallback", got)
	}
	post := msgLine("after-reseal") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 || reads[0][0] != int64(len(rewritten)) {
		t.Fatalf("post-reseal reads = %v, want appended bytes from EOF %d", reads, len(rewritten))
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-reseal" {
		t.Fatalf("post-reseal messages = %v", got)
	}
}

func TestForwardOnlyDeletedBaselineDoesNotFenceLaterNewIdentity(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("old")+"\n")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("drop poll: %v", err)
	}
	writeFileString(t, p, msgLine("new-file")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-file poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "new-file" {
		t.Fatalf("new identity messages = %v, want post-activation new file", got)
	}
}

// TestForwardOnlyTransientUnreadableDirKeepsSealedPrefixFenced proves a store subdirectory that
// cannot be read for one poll does not release the generation-local floors of the transcripts under
// it. A failed readdir looks exactly like a deletion from the walk's point of view, and releasing
// the floor there would republish the whole pre-consent prefix — on the metadata channel and, once
// the identity stopped being a baseline, on the content channel too — as soon as the directory came
// back.
func TestForwardOnlyTransientUnreadableDirKeepsSealedPrefixFenced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits, so the unreadable poll cannot be staged")
	}
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	store := filepath.Join(root, "projects")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(store, "session.jsonl")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)

	var reads [][2]int64
	sink := &recordingSink{}
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink, ContentObserver: obs,
		ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
			reads = append(reads, [2]int64{off, n})
			return readRangeAt(f, off, n)
		},
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}

	if err := os.Chmod(store, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("unreadable poll: %v", err)
	}
	if err := os.Chmod(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("restored poll: %v", err)
	}
	if got := len(w.rootPolicies[root].control.Baselines); got != 1 {
		t.Fatalf("baseline floors after a transient walk error = %d, want the sealed floor retained", got)
	}
	if got := obs.forgotten(); len(got) != 0 {
		t.Fatalf("forgot %v, want no identity released on an uncorroborated absence", got)
	}

	post := msgLine("post-consent") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "post-consent" {
		t.Fatalf("messages = %v, want the sealed prefix to stay fenced", got)
	}
	if o, ok := obs.last(); ok {
		t.Fatalf("baseline-origin transcript reached the content channel: %+v", o)
	}
}

// TestForwardOnlyMissingRootDefersActivationCommit proves activation does not commit over a root the
// walk never enumerated. Committing with zero baselines would mark every file discovered later as
// post-consent and upload it in full.
func TestForwardOnlyMissingRootDefersActivationCommit(t *testing.T) {
	ctx := context.Background()
	parent, state := t.TempDir(), t.TempDir()
	root := filepath.Join(parent, "store")
	var reads [][2]int64
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
		ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
			reads = append(reads, [2]int64{off, n})
			return readRangeAt(f, off, n)
		},
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("missing-root poll: %v", err)
	}
	if w.rootPolicies[root].control.Committed {
		t.Fatal("activation committed over a root the walk never read")
	}

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("appeared-root poll: %v", err)
	}
	if !w.rootPolicies[root].control.Committed {
		t.Fatal("activation did not commit after the root was enumerated")
	}

	post := msgLine("post-consent") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want the pre-existing file sealed at its EOF", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "post-consent" {
		t.Fatalf("messages = %v, want no historical bytes", got)
	}
}

func TestRootPolicyRejectsStaleGenerationAndBackfillIsPerRoot(t *testing.T) {
	ctx := context.Background()
	rootA, rootB, state := t.TempDir(), t.TempDir(), t.TempDir()
	writeFileString(t, filepath.Join(rootA, "a.jsonl"), msgLine("a")+"\n")
	writeFileString(t, filepath.Join(rootB, "b.jsonl"), msgLine("b")+"\n")
	forward := []rootpolicy.Record{
		{Path: rootA, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
		{Path: rootB, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
	}
	if err := mustWatcher(t, WatchConfig{RootPolicies: forward, StateDir: state, Sink: &recordingSink{}}).Poll(ctx); err != nil {
		t.Fatal(err)
	}
	// Only A transitions to backfill. B retains generation 1 and must not be re-read.
	backfillA := []rootpolicy.Record{
		{Path: rootA, Generation: 2, Active: true, Mode: rootpolicy.Backfill},
		{Path: rootB, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
	}
	sink := &recordingSink{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfillA, StateDir: state, Sink: sink}).Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("named-root backfill messages = %v, want only root A", got)
	}
	stale := []rootpolicy.Record{{Path: rootA, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}
	if _, err := NewWatcher(WatchConfig{RootPolicies: stale, StateDir: state, Sink: &recordingSink{}}); err == nil {
		t.Fatal("stale generation succeeded")
	}
}

func TestForwardOnlyUnregisterReregisterFencesInactiveGap(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	first := msgLine("first") + "\n"
	inactive := msgLine("while-inactive") + "\n"
	last := msgLine("after-reregister") + "\n"
	writeFileString(t, p, first)

	active1 := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}
	if err := mustWatcher(t, WatchConfig{RootPolicies: active1, StateDir: state, Sink: &recordingSink{}}).Poll(ctx); err != nil {
		t.Fatal(err)
	}
	inactive2 := []rootpolicy.Record{{Path: root, Generation: 2, Active: false}}
	if err := mustWatcher(t, WatchConfig{RootPolicies: inactive2, StateDir: state, Sink: &recordingSink{}}).Poll(ctx); err != nil {
		t.Fatal(err)
	}
	appendString(t, p, inactive)

	active3 := []rootpolicy.Record{{Path: root, Generation: 3, Active: true, Mode: rootpolicy.ForwardOnly}}
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{RootPolicies: active3, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("re-register replayed inactive gap: %v", got)
	}
	appendString(t, p, last)
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-reregister" {
		t.Fatalf("re-register messages = %v, want only post-registration record", got)
	}
}

func TestRootPolicyWatcherCapturesClaudeAndCodexJSONLAfterForwardActivation(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	claude := filepath.Join(root, "48bc659f-6656-4f39-b424-864992f96c2c.jsonl")
	codex := filepath.Join(root, "rollout-2026-07-14T23-46-58-019f6306-cdf3-7813-ae8e-a90bb1799c99.jsonl")
	writeFileString(t, claude, msgLine("old-claude")+"\n")
	writeFileString(t, codex, msgLine("old-codex")+"\n")
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink, Match: func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	appendString(t, claude, msgLine("new-claude")+"\n")
	appendString(t, codex, msgLine("new-codex")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "new-claude" || got[1] != "new-codex" {
		t.Fatalf("provider-neutral messages = %v, want both appended provider transcripts", got)
	}
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no paths match %s", pattern)
	}
	return paths
}
