//go:build unix

package codex

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestForwardOnlyBaselinesNonmatchingIdentityBeforeItIsRenamedToJSONL(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	staged := filepath.Join(root, "session.tmp")
	transcript := filepath.Join(root, "session.jsonl")
	pre := msgLine("before-consent") + "\n"
	post := msgLine("after-consent") + "\n"
	writeFileString(t, staged, pre)

	var reads [][2]int64
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
		ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
			reads = append(reads, [2]int64{off, n})
			return readRangeAt(f, off, n)
		},
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if len(reads) != 0 || len(sink.messages()) != 0 {
		t.Fatalf("activation read/capture = %v/%v, want zero", reads, sink.messages())
	}

	if err := os.Rename(staged, transcript); err != nil {
		t.Fatalf("rename staged transcript: %v", err)
	}
	appendString(t, transcript, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("renamed transcript poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want post-consent bytes only", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-consent" {
		t.Fatalf("messages = %v, want post-consent record only", got)
	}
}

func TestForwardOnlyIncompleteActivationDoesNotCommitOrDrainEarlierBytes(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	transcript := filepath.Join(root, "session.jsonl")
	blocker := filepath.Join(root, "z-stat-failure.jsonl")
	pre := msgLine("before-incomplete-activation") + "\n"
	during := msgLine("while-activation-incomplete") + "\n"
	post := msgLine("after-complete-activation") + "\n"
	writeFileString(t, transcript, pre)
	if err := os.Symlink(filepath.Join(root, "missing-target"), blocker); err != nil {
		t.Fatalf("create dangling symlink: %v", err)
	}

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	// bd-main-4qv: a dangling symlink is gone by the time the walk stats it — a mid-walk vanish
	// (ENOENT), i.e. ordinary rotation churn, not a fault. The activation now DEFERS (returns nil) and
	// retries on a later poll rather than returning fatal and terminating Run. The guarantee this test
	// exists for is preserved by the checks below: the incomplete walk still does NOT commit its
	// durable baseline, and it still never drains the pre-consent prefix.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll over a mid-walk vanish should defer, not terminate Run: %v", err)
	}
	if w.rootPolicies[root].control.Committed {
		t.Fatal("activation marker committed despite incomplete traversal")
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("incomplete activation captured %v", got)
	}

	if err := os.Remove(blocker); err != nil {
		t.Fatalf("remove stat-failure symlink: %v", err)
	}
	appendString(t, transcript, during)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("completed activation poll: %v", err)
	}
	if !w.rootPolicies[root].control.Committed {
		t.Fatal("activation marker was not committed after complete traversal")
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("completed activation captured pre-consent bytes %v", got)
	}

	appendString(t, transcript, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-activation poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-complete-activation" {
		t.Fatalf("messages = %v, want only bytes appended after complete activation", got)
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
	// Two clean walks, because retiring the locator's fence is corroborated to the same N>=2 standard
	// as releasing the identity's cursor (A1-v2): one walk finding the path empty is what a rotation
	// caught in flight looks like too.
	for i := 0; i < absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("drop poll %d: %v", i, err)
		}
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

// TestForwardBaselineGrowingInPlaceRewriteResealsAtEOF is the D5 proof. A rewrite that replaces the
// sealed prefix and grows past it is invisible to a size comparison: the file is larger than the
// floor, so the old code read from the floor into unrelated content, delivering bytes that belong to
// a file the owner never consented to and parsing them mid-record. The floor fingerprint catches it,
// and the recovery reseals at the current EOF rather than replaying anything below it.
func TestForwardBaselineGrowingInPlaceRewriteResealsAtEOF(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret-that-must-never-be-delivered") + "\n"
	writeFileString(t, p, pre)

	var reads [][2]int64
	sink := &recordingSink{}
	policy := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}
	w := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: sink, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads = append(reads, [2]int64{off, n})
		return readRangeAt(f, off, n)
	}})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}

	// A GROWING in-place rewrite: same inode, different bytes under the floor, larger than the floor.
	rewritten := msgLine("rewritten-first-record-with-entirely-different-content") + "\n" + msgLine("rewritten-second") + "\n"
	if len(rewritten) <= len(pre) {
		t.Fatalf("rewrite is %d bytes, must grow past the %d-byte floor to exercise D5", len(rewritten), len(pre))
	}
	writeFileString(t, p, rewritten)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rewrite poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("rewrite poll read %v, want no bytes read below or above the diverged floor", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("rewrite poll delivered %v, want nothing from a file whose sealed prefix diverged", got)
	}
	diags := diagnostics(sink.all())
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one rewrite diagnostic", len(diags))
	}
	ctxText := diags[0].Diagnostic.Context
	if !strings.Contains(ctxText, "diverged") || !strings.Contains(ctxText, "resealing capture at the current end of file") || !strings.Contains(ctxText, "no bytes are re-delivered") {
		t.Fatalf("rewrite diagnostic = %q, want an honest reseal-at-EOF description", ctxText)
	}
	if strings.Contains(ctxText, "restarting capture at 0") {
		t.Fatalf("rewrite diagnostic = %q, want no claim of a byte-zero restart the code never performs", ctxText)
	}

	base := mustBaseline(t, readRootControl(t, state, root), p)
	if base.Floor != int64(len(rewritten)) {
		t.Fatalf("floor = %d, want the rewritten EOF %d", base.Floor, len(rewritten))
	}
	if base.FingerprintLen != floorFingerprintLen {
		t.Fatalf("refreshed fingerprint length = %d, want %d", base.FingerprintLen, floorFingerprintLen)
	}

	post := msgLine("after-rewrite") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rewrite append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(rewritten)), int64(len(post))} {
		t.Fatalf("post-rewrite reads = %v, want only the bytes appended above the new floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-rewrite" {
		t.Fatalf("post-rewrite messages = %v, want only the record appended after the reseal", got)
	}
}

// TestForwardBaselineUnchangedPrefixAppendRecordsFingerprintOnce proves the corroboration is inert
// on the ordinary path: the fingerprint is computed once, on the first drain after the seal, and
// every later drain only verifies it, so an append still delivers exactly its own bytes and the
// durable floor record never moves.
func TestForwardBaselineUnchangedPrefixAppendRecordsFingerprintOnce(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent") + "\n"
	writeFileString(t, p, pre)

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
		t.Fatalf("activation poll: %v", err)
	}
	sealed := mustBaseline(t, readRootControl(t, state, root), p)
	if sealed.Floor != int64(len(pre)) || sealed.FingerprintLen != floorFingerprintLen || sealed.FingerprintHash == 0 {
		t.Fatalf("sealed baseline = %+v, want floor %d with a full fingerprint recorded on the first drain", sealed, len(pre))
	}

	first := msgLine("first-append") + "\n"
	appendString(t, p, first)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first append poll: %v", err)
	}
	second := msgLine("second-append") + "\n"
	appendString(t, p, second)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("second append poll: %v", err)
	}
	want := [][2]int64{{int64(len(pre)), int64(len(first))}, {int64(len(pre) + len(first)), int64(len(second))}}
	if len(reads) != 2 || reads[0] != want[0] || reads[1] != want[1] {
		t.Fatalf("reads = %v, want only the two appended ranges %v", reads, want)
	}
	if got := sink.messages(); len(got) != 2 || got[0] != "first-append" || got[1] != "second-append" {
		t.Fatalf("messages = %v, want both appends and nothing from the sealed prefix", got)
	}
	if got := diagnostics(sink.all()); len(got) != 0 {
		t.Fatalf("diagnostics = %d, want none for an unchanged sealed prefix", len(got))
	}
	if got := mustBaseline(t, readRootControl(t, state, root), p); got != sealed {
		t.Fatalf("baseline after appends = %+v, want the once-recorded %+v", got, sealed)
	}
}

// TestForwardBaselineTruncateBelowFloorLowersFloorDurably is the A22 proof: a truncation below the
// floor lowers the durable floor (and drops the fingerprint window that described the removed
// bytes), and the lowered floor survives a restart that has lost every cursor file. Keeping the old
// floor would leave capture pointing past the end of the file forever; forgetting it entirely would
// republish the surviving prefix.
func TestForwardBaselineTruncateBelowFloorLowersFloorDurably(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-record-one") + "\n" + msgLine("pre-consent-record-two") + "\n"
	writeFileString(t, p, pre)
	policy := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	truncated := int64(len(pre) / 2)
	if err := os.Truncate(p, truncated); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("truncate poll: %v", err)
	}
	lowered := mustBaseline(t, readRootControl(t, state, root), p)
	if lowered.Floor != truncated {
		t.Fatalf("floor = %d, want it lowered to the truncated size %d", lowered.Floor, truncated)
	}
	if lowered.FingerprintLen != floorFingerprintLen || lowered.FingerprintHash == 0 {
		t.Fatalf("fingerprint after truncation = %+v, want a window refreshed at the new floor", lowered)
	}
	diags := diagnostics(sink.all())
	if len(diags) != 1 || !strings.Contains(diags[0].Diagnostic.Context, "resealing capture at the new end of file") {
		t.Fatalf("truncation diagnostics = %+v, want one honest reseal report", diags)
	}

	// Restart with every cursor lost: the durable floor is the only surviving fence.
	for _, cursor := range mustGlob(t, filepath.Join(state, "root-cursors", "*", "codex-cursor-*.json")) {
		if err := os.Remove(cursor); err != nil {
			t.Fatal(err)
		}
	}
	post := msgLine("after-truncate") + "\n"
	appendString(t, p, post)
	var reads [][2]int64
	restarted := &recordingSink{}
	w2 := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: restarted, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads = append(reads, [2]int64{off, n})
		return readRangeAt(f, off, n)
	}})
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("restart poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{truncated, int64(len(post))} {
		t.Fatalf("restart reads = %v, want only the bytes appended above the lowered floor %d", reads, truncated)
	}
	if got := restarted.messages(); len(got) != 1 || got[0] != "after-truncate" {
		t.Fatalf("restart messages = %v, want only the post-truncation record", got)
	}
}

// TestRootPolicyControlUpgradeKeepsV1Floors proves the schema bump is not a capture-loss event: a
// control file written by the previous build stores each baseline as a bare floor integer, and
// dropping those on upgrade would re-publish every sealed pre-consent prefix on the next poll.
func TestRootPolicyControlUpgradeKeepsV1Floors(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("sealed-before-the-upgrade") + "\n"
	writeFileString(t, p, pre)
	dev, ino := identityOf(t, p)

	v1, err := json.Marshal(map[string]any{
		"version": rootPolicyControlMinVersion, "root": root, "generation": 1,
		"active": true, "mode": rootpolicy.ForwardOnly, "committed": true,
		"baselines": map[string]int64{identityString(dev, ino): int64(len(pre))},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFileString(t, filepath.Join(state, "root-policy-"+rootPolicyID(root)+".json"), string(v1))

	post := msgLine("after-the-upgrade") + "\n"
	appendString(t, p, post)
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
		t.Fatalf("upgraded poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the inherited floor %d", reads, len(pre))
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-the-upgrade" {
		t.Fatalf("messages = %v, want the v1 floor to keep fencing the sealed prefix", got)
	}
	control := readRootControl(t, state, root)
	if control.Version != rootPolicyControlVersion {
		t.Fatalf("control version = %d, want it re-stamped to %d", control.Version, rootPolicyControlVersion)
	}
	base := mustBaseline(t, control, p)
	if base.Floor != int64(len(pre)) || base.FingerprintLen != floorFingerprintLen {
		t.Fatalf("upgraded baseline = %+v, want the v1 floor %d plus a lazily recorded fingerprint", base, len(pre))
	}
}

// TestSealedFloorSurvivesIdenticalRewriteViaRename is the A1 proof. sed -i, an editor save, and most
// sync tools do not write in place: they write a temp file and rename it over the original. The path
// the owner was told is sealed never changes, but the inode does, so every cursor and floor keyed on
// identity misses and the whole pre-consent history would drain - and, no longer looking like a
// baseline, upload whole-file too. The locator's seal lineage carries the floor across.
func TestSealedFloorSurvivesIdenticalRewriteViaRename(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret-that-must-never-be-delivered") + "\n"
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
	sealed := mustBaseline(t, readRootControl(t, state, root), p)
	if sealed.Floor != int64(len(pre)) || !sealed.hasFingerprint() {
		t.Fatalf("sealed baseline = %+v, want floor %d with the window recorded by the first drain", sealed, len(pre))
	}

	before := inodeOf(t, p)
	replaceViaRename(t, p, pre)
	if after := inodeOf(t, p); after == before {
		t.Fatalf("replacement kept inode %d, so the rewrite-via-rename path is not exercised", after)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("replacement poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("replacement poll read %v, want nothing below the inherited floor", reads)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("replacement poll delivered %d candidates, want none for a byte-identical rewrite", len(got))
	}
	if o, ok := obs.last(); ok {
		t.Fatalf("replaced transcript reached the content channel: %+v", o)
	}
	if got := mustBaseline(t, readRootControl(t, state, root), p); got != sealed {
		t.Fatalf("inherited baseline = %+v, want the floor and window sealed before the rename %+v", got, sealed)
	}

	post := msgLine("after-the-rename") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rename append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("post-rename reads = %v, want only the bytes appended above the inherited floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-the-rename" {
		t.Fatalf("post-rename messages = %v, want only the record appended after the rewrite", got)
	}
}

// TestSealedFloorReplacementWithDivergedPrefixResealsAtEOF covers the other half of A1: the
// replacement's prefix demonstrably is not the sealed one, so the floor describes no boundary in
// this file. It is the same situation an in-place rewrite of the same inode produces and takes the
// same recovery - reseal at the current EOF - rather than draining a rewritten history from zero.
func TestSealedFloorReplacementWithDivergedPrefixResealsAtEOF(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)

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
		t.Fatalf("activation poll: %v", err)
	}

	replacement := msgLine("a-completely-different-first-record-written-by-the-rewrite") + "\n" + msgLine("and-a-second") + "\n"
	if len(replacement) <= len(pre) {
		t.Fatalf("replacement is %d bytes, must grow past the %d-byte floor", len(replacement), len(pre))
	}
	replaceViaRename(t, p, replacement)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("replacement poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("diverged replacement read %v, want no bytes from a file whose sealed prefix is gone", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("diverged replacement delivered %v, want no pre-rename bytes", got)
	}
	diags := diagnostics(sink.all())
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one replacement report", len(diags))
	}
	ctxText := diags[0].Diagnostic.Context
	for _, want := range []string{"a new file replaced the transcript sealed at offset", "diverged", "resealing capture at the current end of file", "no bytes are re-delivered"} {
		if !strings.Contains(ctxText, want) {
			t.Fatalf("replacement diagnostic = %q, want it to state %q", ctxText, want)
		}
	}
	resealed := mustBaseline(t, readRootControl(t, state, root), p)
	if resealed.Floor != int64(len(replacement)) {
		t.Fatalf("floor = %d, want the replacement's EOF %d", resealed.Floor, len(replacement))
	}

	post := msgLine("after-the-diverged-replacement") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-replacement append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(replacement)), int64(len(post))} {
		t.Fatalf("post-replacement reads = %v, want only the bytes appended above the new floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-the-diverged-replacement" {
		t.Fatalf("post-replacement messages = %v, want only the record appended after the reseal", got)
	}
}

// TestSealedFloorReplacementWithoutFingerprintInheritsFloor stages the crash window between the
// stat-only activation seal and the first drain, where a floor exists but the window that would
// corroborate it was never recorded. Nothing can confirm or refute the replacement, and the two ways
// to be wrong are not symmetric: capture would publish a prefix the owner was told was sealed, while
// inheriting only defers history the owner can still backfill. It inherits, and says why.
func TestSealedFloorReplacementWithoutFingerprintInheritsFloor(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("sealed-before-any-drain-recorded-a-window") + "\n"
	writeFileString(t, p, pre)
	dev, ino := identityOf(t, p)
	writeRootControl(t, state, root, rootPolicyControl{
		Version: rootPolicyControlVersion, Root: root, Generation: 1, Active: true,
		Mode: rootpolicy.ForwardOnly, Committed: true,
		Baselines: map[string]baselineRecord{identityString(dev, ino): {Floor: int64(len(pre))}},
		Lineages: map[string]sealLineage{
			"session.jsonl": {Floor: int64(len(pre)), Generation: 1, Device: dev, Inode: ino},
		},
	})

	post := msgLine("appended-by-the-rewrite") + "\n"
	replaceViaRename(t, p, pre+post)

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
		t.Fatalf("replacement poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes above the inherited floor %d", reads, len(pre))
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-by-the-rewrite" {
		t.Fatalf("messages = %v, want nothing from below the inherited floor", got)
	}
	diags := diagnostics(sink.all())
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ambiguity report", len(diags))
	}
	ctxText := diags[0].Diagnostic.Context
	for _, want := range []string{"before that prefix was ever fingerprinted", "neither confirmed nor refuted", "inheriting the sealed floor"} {
		if !strings.Contains(ctxText, want) {
			t.Fatalf("ambiguity diagnostic = %q, want it to state %q", ctxText, want)
		}
	}
	if got := mustBaseline(t, readRootControl(t, state, root), p); got.Floor != int64(len(pre)) {
		t.Fatalf("floor = %d, want the inherited %d", got.Floor, len(pre))
	}
}

// TestNewTranscriptAtNeverSealedLocatorIsCapturedInFull keeps the inheritance narrow: a post-consent
// session at a path no sealed transcript has occupied is still captured from its first byte.
func TestNewTranscriptAtNeverSealedLocatorIsCapturedInFull(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	writeFileString(t, filepath.Join(root, "old.jsonl"), msgLine("pre-consent")+"\n")

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
		t.Fatalf("activation poll: %v", err)
	}
	fresh := msgLine("brand-new-session") + "\n"
	writeFileString(t, filepath.Join(root, "new.jsonl"), fresh)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-file poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{0, int64(len(fresh))} {
		t.Fatalf("reads = %v, want the new transcript read from byte zero", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "brand-new-session" {
		t.Fatalf("messages = %v, want the new transcript captured in full", got)
	}
	if got := diagnostics(sink.all()); len(got) != 0 {
		t.Fatalf("diagnostics = %d, want none for a locator no sealed file has held", len(got))
	}
}

// TestSealLineageDoesNotSurviveGenerationBump proves re-registration fences the inheritance: consent
// given again is consent to seal again, so a replacement is sealed at ITS own EOF by the new
// generation's activation rather than inheriting the retired generation's floor.
func TestSealLineageDoesNotSurviveGenerationBump(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("sealed-under-generation-one") + "\n"
	writeFileString(t, p, pre)
	if err := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: &recordingSink{},
	}).Poll(ctx); err != nil {
		t.Fatalf("generation-1 activation poll: %v", err)
	}

	// An identical prefix: under generation 1 this would inherit the smaller floor.
	extra := msgLine("written-between-the-registrations") + "\n"
	replaceViaRename(t, p, pre+extra)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 2, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("generation-2 activation poll: %v", err)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("generation-2 activation delivered %d candidates, want a silent re-seal", len(got))
	}
	control := readRootControl(t, state, root)
	if got := mustBaseline(t, control, p); got.Floor != int64(len(pre)+len(extra)) {
		t.Fatalf("floor = %d, want the whole file resealed at %d by the new generation", got.Floor, len(pre)+len(extra))
	}
	if got := control.Lineages["session.jsonl"]; got.Generation != 2 {
		t.Fatalf("lineage = %+v, want it re-stamped to the current generation", got)
	}
}

// TestSealLineageFromARetiredGenerationIsIgnored checks the fence directly rather than through the
// control record's rewrite: an entry stamped with a generation that is no longer current cannot
// fence anything, so the file at that locator is a new transcript and is captured in full.
func TestSealLineageFromARetiredGenerationIsIgnored(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	body := msgLine("captured-under-the-current-generation") + "\n"
	writeFileString(t, p, body)
	dev, ino := identityOf(t, p)
	writeRootControl(t, state, root, rootPolicyControl{
		Version: rootPolicyControlVersion, Root: root, Generation: 2, Active: true,
		Mode: rootpolicy.ForwardOnly, Committed: true,
		Lineages: map[string]sealLineage{
			"session.jsonl": {Floor: int64(len(body)), Generation: 1, Device: dev, Inode: ino + 1},
		},
	})
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 2, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("retired-lineage poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "captured-under-the-current-generation" {
		t.Fatalf("messages = %v, want a retired lineage to fence nothing", got)
	}
}

// TestSealLineageSurvivesATransientWalkError pairs the lineage with the fail-closed absence rule it
// rides on. A store subdirectory that cannot be read for one poll looks exactly like an emptied
// path, and retiring the lineage on that evidence would unseal the very next rewrite.
func TestSealLineageSurvivesATransientWalkError(t *testing.T) {
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
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
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
	replaceViaRename(t, p, pre)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("replacement poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("replacement after a transient walk error read %v, want the floor still inherited", reads)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("replacement after a transient walk error delivered %d candidates, want none", len(got))
	}
}

// replaceViaRename rewrites path the way sed -i, an editor save, and most sync tools do: write a
// temp file beside it and rename it over the original, leaving the path in place and the inode new.
func replaceViaRename(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".rewrite"
	writeFileString(t, tmp, content)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename %s over %s: %v", tmp, path, err)
	}
}

func writeRootControl(t *testing.T, stateDir, root string, control rootPolicyControl) {
	t.Helper()
	data, err := json.Marshal(control)
	if err != nil {
		t.Fatalf("encode root-policy control: %v", err)
	}
	writeFileString(t, filepath.Join(stateDir, "root-policy-"+rootPolicyID(root)+".json"), string(data))
}

func readRootControl(t *testing.T, stateDir, root string) rootPolicyControl {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "root-policy-"+rootPolicyID(root)+".json"))
	if err != nil {
		t.Fatalf("read root-policy control: %v", err)
	}
	var c rootPolicyControl
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("decode root-policy control: %v", err)
	}
	return c
}

func mustBaseline(t *testing.T, control rootPolicyControl, path string) baselineRecord {
	t.Helper()
	dev, ino := identityOf(t, path)
	base, ok := control.Baselines[identityString(dev, ino)]
	if !ok {
		t.Fatalf("no durable baseline for %s in %+v", path, control.Baselines)
	}
	return base
}

func identityOf(t *testing.T, path string) (dev, ino uint64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatalf("no filesystem identity for %s", path)
	}
	return dev, ino
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
