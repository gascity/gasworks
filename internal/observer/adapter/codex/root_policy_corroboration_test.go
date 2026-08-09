//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
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

// TestSinkFailureDuringSealReplacementLeavesAbsenceEvidenceUntouched is the bd-main-t4o proof. A
// delivery error on the seal-replacement path escaped the reconcile unwrapped, so a bare ENOENT from
// the sink aborted the walk mid-root and then passed the walk's own os.IsNotExist tolerance: the
// partial walk was treated as complete and clean, and every file past the abort point was accounted
// missing - lineages retired over locators the walk never reached, absent-poll counters advanced for
// files that were sitting right there. An error that ends a walk is not evidence about what the walk
// never got to.
func TestSinkFailureDuringSealReplacementLeavesAbsenceEvidenceUntouched(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	first, last := filepath.Join(root, "a.jsonl"), filepath.Join(root, "z.jsonl")
	writeFileString(t, first, msgLine("pre-consent-first")+"\n")
	writeFileString(t, last, msgLine("pre-consent-last-and-never-reached")+"\n")

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	sealedLast := mustBaseline(t, readRootControl(t, state, root), last)
	dev, ino := identityOf(t, last)

	// The walk's first file is replaced by a diverged one, so reconciling it reports the replacement
	// to the sink - which fails with the error shape that used to be swallowed whole.
	replaceViaRename(t, first, msgLine("a-completely-different-record-written-by-the-rewrite")+"\n")
	sink.failNext = true
	sink.failErr = &os.PathError{Op: "deliver", Path: "sink", Err: syscall.ENOENT}
	if err := w.Poll(ctx); err == nil {
		t.Fatal("poll succeeded despite a sink failure that ended the walk before its last file")
	}

	control := w.rootPolicies[root].control
	if _, ok := control.Lineages["z.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence of a file the aborted walk never reached", control.Lineages)
	}
	if got, ok := control.Baselines[identityString(dev, ino)]; !ok || got != sealedLast {
		t.Fatalf("baseline for the unreached file = %+v/%v, want the sealed floor %+v", got, ok, sealedLast)
	}
	tf, ok := w.tracked[identityKey{dev: dev, ino: ino}]
	if !ok {
		t.Fatal("the file past the abort point was dropped from tracking")
	}
	if tf.absentPolls != 0 {
		t.Fatalf("absentPolls = %d for a present file the aborted walk never reached, want 0", tf.absentPolls)
	}

	// Nothing was committed on the failed path, so the next poll re-derives the same decision.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("recovery poll: %v", err)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want no pre-consent bytes from either file", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want the replacement reported exactly once after recovery", len(got))
	}
}

// TestRotationWhileTheDaemonIsDownResealsTheNewSessionWithADiagnostic is the bd-main-i4i shape with
// the bd-main-x6u semantics. Seal a session, stop the daemon, rotate the sealed file out of the way,
// let a NEW session be created at the path it left, and start the daemon again. The fence still
// follows the sealed bytes to the locator they moved to - the identity is alive there, which is
// positive evidence - but that says nothing about what the vacated locator now holds. No walk of this
// process ever observed that locator empty, so the file sitting there is resealed at its current EOF
// with an ingestion-loss diagnostic rather than published from byte zero; only its later appends are
// captured.
//
// This is a ratified semantics change from a617d3e (bd-main-x6u, design-v2.1 amendment A1-v2): the
// same displacement that used to license a byte-zero ingest here is what `sed -i.bak` produces, where
// the file at the vacated locator is the owner's own pre-consent history with an edit applied.
func TestRotationWhileTheDaemonIsDownResealsTheNewSessionWithADiagnostic(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	rotated := filepath.Join(root, "session.jsonl.rotated")
	pre := msgLine("pre-consent-secret") + "\n"
	writeFileString(t, p, pre)
	policy := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}}

	if err := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: &recordingSink{}}).Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	sealedDev, sealedIno := identityOf(t, p)

	if err := os.Rename(p, rotated); err != nil {
		t.Fatal(err)
	}
	fresh := msgLine("a-new-post-consent-session-started-after-the-rotation") + "\n"
	writeFileString(t, p, fresh)

	var reads [][2]int64
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{RootPolicies: policy, StateDir: state, Sink: sink, ReadRange: func(f *os.File, off, n int64) ([]byte, error) {
		reads = append(reads, [2]int64{off, n})
		return readRangeAt(f, off, n)
	}})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("restart poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want nothing read from either file", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want the unwitnessed replacement fenced, not published", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic for the resealed locator", len(got))
	}
	control := readRootControl(t, state, root)
	if _, ok := control.Lineages["session.jsonl.rotated"]; !ok {
		t.Fatalf("lineages = %+v, want the fence to have followed the sealed bytes to their new locator", control.Lineages)
	}
	if got, ok := control.Baselines[identityString(sealedDev, sealedIno)]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("rotated file baseline = %+v/%v, want its floor %d intact", got, ok, len(pre))
	}
	freshDev, freshIno := identityOf(t, p)
	if got, ok := control.Baselines[identityString(freshDev, freshIno)]; !ok || got.Floor != int64(len(fresh)) {
		t.Fatalf("vacated-locator baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(fresh))
	}

	// The reseal is a fence, not a stop: everything appended after it is captured.
	post := msgLine("appended-after-the-reseal") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(fresh)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the reseal", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-after-the-reseal" {
		t.Fatalf("messages = %v, want capture to resume above the reseal", got)
	}
}

// TestLiveRotationResealsWithinTheRetirementWindow is the same rotation with the daemon running,
// which is where the walk order used to decide the outcome: "session.jsonl" sorts before
// "session.jsonl.rotated", so the new file was reconciled against a lineage the rename had not yet
// moved. Enumerating the whole root before reconciling any of it takes the ordering out of the
// answer.
//
// A single corroborated empty walk between the rename and the creation used to be enough to publish
// the new session from byte zero - the rename VACATED the fence at the name it left, deleting the
// fingerprint with it (bd-main-37y). A rename copies the fence now, so one empty walk leaves the
// locator inside its retirement window and whatever appears there answers to the fence still
// standing: the window ending at the floor does not corroborate, so it reseals at its own EOF with an
// ingestion-loss diagnostic. Its appends are captured; nothing that already existed is.
// TestRotationRetirementWindowElapsesThenTheNewSessionIsCapturedInFull is the other side.
func TestLiveRotationResealsWithinTheRetirementWindow(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	rotated := filepath.Join(root, "session.jsonl.rotated")
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
	if err := os.Rename(p, rotated); err != nil {
		t.Fatal(err)
	}
	// The poll the live daemon actually gets between the two filesystem operations: it sees the
	// rotated file where it now lives and the locator it left standing empty - once, which is one
	// short of what retiring that locator's fence takes.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rename poll: %v", err)
	}
	if got := w.rootPolicies[root].absentLineagePolls["session.jsonl"]; got != 1 {
		t.Fatalf("empty-walk streak = %d, want the vacated locator positively observed empty exactly once", got)
	}
	fresh := msgLine("a-new-post-consent-session-started-after-the-rotation") + "\n"
	writeFileString(t, p, fresh)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rotation poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want nothing read at a locator still inside its retirement window", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want the session resealed rather than published from byte zero", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic for the resealed locator", len(got))
	}
	if got, ok := readRootControl(t, state, root).Baselines[identityString(identityOf(t, p))]; !ok || got.Floor != int64(len(fresh)) {
		t.Fatalf("new-session baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(fresh))
	}

	// The reseal is a fence, not a stop.
	after := msgLine("appended-after-the-reseal") + "\n"
	appendString(t, p, after)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-reseal append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(fresh)), int64(len(after))} {
		t.Fatalf("reads = %v, want only the bytes appended above the reseal", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-after-the-reseal" {
		t.Fatalf("messages = %v, want capture to resume above the reseal", got)
	}

	// The rotated file keeps its floor at its new path: its own appends are captured, its sealed
	// prefix is not.
	post := msgLine("appended-to-the-rotated-file") + "\n"
	appendString(t, rotated, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rotated-file append poll: %v", err)
	}
	if len(reads) != 2 || reads[1] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the rotated file's floor", reads)
	}
	if got := sink.messages(); len(got) != 2 || got[1] != "appended-to-the-rotated-file" {
		t.Fatalf("messages = %v, want the rotated file's sealed prefix still fenced", got)
	}
}

// TestRotationRetirementWindowElapsesThenTheNewSessionIsCapturedInFull is the positive companion to
// the test above, and the reason a rename copying its fence costs capture rather than correctness
// (bd-main-37y). Carry the same rotation past the retirement window - absenceEvictionPolls
// consecutive corroborated walks that find the locator empty - and the fence there is retired by the
// one mechanism that retires anything. The session created afterwards is genuinely new by the
// standard that un-fences every other locator, and is captured in full, with no diagnostic.
func TestRotationRetirementWindowElapsesThenTheNewSessionIsCapturedInFull(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	rotated := filepath.Join(root, "session.jsonl.rotated")
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
	if err := os.Rename(p, rotated); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("empty-locator poll %d: %v", i, err)
		}
		_, fenced := w.rootPolicies[root].control.Lineages["session.jsonl"]
		if want := i < absenceEvictionPolls-1; fenced != want {
			t.Fatalf("fenced = %v after %d empty walks, want %v - retirement takes %d", fenced, i+1, want, absenceEvictionPolls)
		}
	}

	fresh := msgLine("a-new-post-consent-session-started-after-the-rotation") + "\n"
	writeFileString(t, p, fresh)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-session poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{0, int64(len(fresh))} {
		t.Fatalf("reads = %v, want the new session read from byte zero", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "a-new-post-consent-session-started-after-the-rotation" {
		t.Fatalf("messages = %v, want the new post-consent session captured in full", got)
	}
	if got := diagnostics(sink.all()); len(got) != 0 {
		t.Fatalf("diagnostics = %d, want none for a locator whose fence was properly retired", len(got))
	}
	// The rotated file's own fence never depended on any of that: it is still standing where the file
	// went, and nothing below its floor was read.
	if got, ok := readRootControl(t, state, root).Lineages["session.jsonl.rotated"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("lineage at session.jsonl.rotated = %+v/%v, want the sealed floor %d held where the file went", got, ok, len(pre))
	}
}
