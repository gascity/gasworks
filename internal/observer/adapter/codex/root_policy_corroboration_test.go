//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// TestTrackedIdentityReappearingAtANewNameResumesInsteadOfDrainingFromZero is the bd-main-zsu proof.
// A tracked transcript that is missing from ONE clean walk and comes back under a different name -
// what a rename racing the walk produces, and what a file moved out of the root and back produces -
// is the same file, carrying the same identity. Releasing it on that single uncorroborated absence
// deletes its cursor and its generation-local floor, and the file is then re-tracked at a locator no
// lineage covers: the whole sealed, pre-consent prefix drains to the sink. One clean-walk miss is
// below the corroboration standard the watcher already applies to every other release.
func TestTrackedIdentityReappearingAtANewNameResumesInsteadOfDrainingFromZero(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
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
	dev, ino := identityOf(t, p)
	sealed := mustBaseline(t, readRootControl(t, state, root), p)

	// The walk misses the file exactly once: the rename is in flight, the directory listing still
	// holds the old name, and the stat of that name finds nothing.
	hidden := filepath.Join(away, "session.jsonl")
	if err := os.Rename(p, hidden); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("absent poll: %v", err)
	}
	renamed := filepath.Join(root, "session-renamed.jsonl")
	if err := os.Rename(hidden, renamed); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("reappearance poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reappearance read %v, want nothing below the floor the identity is still sealed at", reads)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("reappearance delivered %d candidates, want none for a file that never changed", len(got))
	}
	if got := obs.forgotten(); len(got) != 0 {
		t.Fatalf("forgot %v after a single absent poll, want the identity kept until absence is corroborated", got)
	}
	if got := mustBaseline(t, readRootControl(t, state, root), renamed); got != sealed {
		t.Fatalf("baseline after reappearance = %+v, want the floor sealed before the rename %+v", got, sealed)
	}
	if d, i := identityOf(t, renamed); d != dev || i != ino {
		t.Fatalf("renamed file identity = %d:%d, want the tracked %d:%d", d, i, dev, ino)
	}
	// The fence follows the file: the locator it now occupies carries the lineage, and the one it
	// left carries nothing.
	control := readRootControl(t, state, root)
	if _, ok := control.Lineages["session-renamed.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the seal lineage moved to the new locator", control.Lineages)
	}

	post := msgLine("after-the-rename") + "\n"
	appendString(t, renamed, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-reappearance append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("post-reappearance reads = %v, want only the bytes appended above the floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-the-rename" {
		t.Fatalf("messages = %v, want only the record appended after the reappearance", got)
	}
}

// TestSingleAbsentPollDoesNotReleaseATrackedIdentity is the same rule at the same name: a transcript
// that vanishes from one clean walk and is back at its own path on the next keeps its cursor, its
// floor, and its content-channel state. Releasing and re-admitting it would re-upload the whole file
// on the content channel even where the metadata floor happens to be recovered from the locator.
func TestSingleAbsentPollDoesNotReleaseATrackedIdentity(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
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
	dev, ino := identityOf(t, p)
	cursorPath := cursorStatePath(filepath.Join(state, "root-cursors", w.rootPolicies[root].scope), dev, ino)
	if _, err := os.Stat(cursorPath); err != nil {
		t.Fatalf("sealed cursor state should exist after activation: %v", err)
	}

	hidden := filepath.Join(away, "session.jsonl")
	if err := os.Rename(p, hidden); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("absent poll: %v", err)
	}
	if _, err := os.Stat(cursorPath); err != nil {
		t.Fatalf("cursor state released on a single absent poll: %v", err)
	}
	post := msgLine("written-while-out-of-the-root") + "\n"
	appendString(t, hidden, post)
	if err := os.Rename(hidden, p); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("reappearance poll: %v", err)
	}
	if got := obs.forgotten(); len(got) != 0 {
		t.Fatalf("forgot %v after a single absent poll, want corroboration first", got)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want the resumed cursor to read only the appended bytes", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "written-while-out-of-the-root" {
		t.Fatalf("messages = %v, want the sealed prefix to stay fenced across the absence", got)
	}
}

// TestSealLineageRetiresOnlyAfterCorroboratedEmptyWalks holds lineage retirement to the same standard
// as cursor-state GC (amendment A1-v2). Retirement is the one step that un-fences a locator, so the
// evidence for it - "nothing is there any more" - has to be corroborated: a single walk that finds a
// path empty is exactly what an in-flight rotation looks like from the outside.
func TestSealLineageRetiresOnlyAfterCorroboratedEmptyWalks(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first empty poll: %v", err)
	}
	if _, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence held after a single empty walk", w.rootPolicies[root].control.Lineages)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("second empty poll: %v", err)
	}
	if _, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; ok {
		t.Fatalf("lineages = %+v, want the fence retired once two clean walks agree the locator is empty", w.rootPolicies[root].control.Lineages)
	}

	fresh := msgLine("a-genuinely-new-session-created-after-the-retirement") + "\n"
	writeFileString(t, p, fresh)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-file poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "a-genuinely-new-session-created-after-the-retirement" {
		t.Fatalf("messages = %v, want a file created after retirement captured in full", got)
	}
	if got := diagnostics(sink.all()); len(got) != 0 {
		t.Fatalf("diagnostics = %d, want none for a locator whose fence was properly retired", len(got))
	}
}

// TestMidWalkVanishedEntryDefersLineageRetirement covers the other half of the retirement rule: a
// directory entry that is gone by the time the walk stats it (a rename in flight - here a dangling
// symlink, which is the same ENOENT) means the walk did not positively observe the tree, so it is not
// evidence any locator is empty.
func TestMidWalkVanishedEntryDefersLineageRetirement(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: &recordingSink{},
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	inflight := filepath.Join(root, "z-in-flight.jsonl")
	if err := os.Symlink(filepath.Join(root, "gone"), inflight); err != nil {
		t.Fatalf("stage an entry that vanishes between readdir and stat: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("incomplete poll %d: %v", i, err)
		}
	}
	if _, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence held while the walk keeps missing entries", w.rootPolicies[root].control.Lineages)
	}

	if err := os.Remove(inflight); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("complete poll %d: %v", i, err)
		}
	}
	if _, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; ok {
		t.Fatalf("lineages = %+v, want retirement once the walks are complete again", w.rootPolicies[root].control.Lineages)
	}
}
