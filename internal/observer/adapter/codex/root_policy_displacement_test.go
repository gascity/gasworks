//go:build unix

package codex

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// TestSedInPlaceBackupNeverPublishesTheEditedPreConsentHistory is the bd-main-x6u probe. `sed -i.bak`
// leaves the untouched ORIGINAL inode at a.jsonl.bak and writes the EDITED text into a brand-new inode
// at a.jsonl. Displacement sees the lineage's identity alive at the .bak locator and used to read that
// as "whatever is at a.jsonl now must be new" - so the file it captured from byte zero was the owner's
// own pre-consent history with an edit applied, which is exactly the redaction case A1-v2 was written
// to prevent. An identity being alive elsewhere says where the sealed bytes went; it says nothing
// about what is standing at the locator they left.
func TestSedInPlaceBackupNeverPublishesTheEditedPreConsentHistory(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "a.jsonl")
	bak := filepath.Join(root, "a.jsonl.bak")
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
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
	sealedDev, sealedIno := identityOf(t, p)

	if err := os.Rename(p, bak); err != nil {
		t.Fatal(err)
	}
	edited := msgLine("pre-consent-secret-one") + "\n" + msgLine("redacted-and-longer-than-the-line-it-replaced") + "\n"
	writeFileString(t, p, edited)

	if err := w.Poll(ctx); err != nil {
		t.Fatalf("sed -i.bak poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want nothing read below either file's floor", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want no pre-consent record delivered from an edited copy", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic for the resealed locator", len(got))
	}
	control := readRootControl(t, state, root)
	if _, ok := control.Lineages["a.jsonl.bak"]; !ok {
		t.Fatalf("lineages = %+v, want the fence to have followed the untouched original to .bak", control.Lineages)
	}
	if got, ok := control.Baselines[identityString(sealedDev, sealedIno)]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("original baseline = %+v/%v, want its floor %d intact at .bak", got, ok, len(pre))
	}
	editedDev, editedIno := identityOf(t, p)
	if got, ok := control.Baselines[identityString(editedDev, editedIno)]; !ok || got.Floor != int64(len(edited)) {
		t.Fatalf("edited-file baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(edited))
	}

	post := msgLine("written-after-the-edit") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-edit append poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "written-after-the-edit" {
		t.Fatalf("messages = %v, want only what was written after the reseal", got)
	}
}

// TestSedInPlaceBackupThatLeavesTheSealedWindowIntactInheritsTheFloor is the same displacement with an
// edit that does not shift the window ending at the floor. The replacement's own bytes then
// demonstrably ARE the sealed prefix, so the corroborated-window fence decides it: the floor is
// inherited at the vacated locator and nothing beneath it is delivered - the displacement check never
// gets to weigh in.
func TestSedInPlaceBackupThatLeavesTheSealedWindowIntactInheritsTheFloor(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "a.jsonl")
	bak := filepath.Join(root, "a.jsonl.bak")
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
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

	if err := os.Rename(p, bak); err != nil {
		t.Fatal(err)
	}
	// Same length, and the edit lands far enough from the end that the fingerprinted window is
	// byte-identical.
	edited := msgLine("pre-consent-REDACTED-1") + "\n" + msgLine("pre-consent-secret-two") + "\n"
	if len(edited) != len(pre) {
		t.Fatalf("staging error: edited length %d != sealed length %d", len(edited), len(pre))
	}
	writeFileString(t, p, edited)

	if err := w.Poll(ctx); err != nil {
		t.Fatalf("window-preserving edit poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want nothing read below the inherited floor", reads)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("delivered %d candidates, want none for a replacement that corroborates as the sealed prefix", len(got))
	}
	editedDev, editedIno := identityOf(t, p)
	control := readRootControl(t, state, root)
	if got, ok := control.Baselines[identityString(editedDev, editedIno)]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("edited-file baseline = %+v/%v, want the sealed floor %d inherited", got, ok, len(pre))
	}
}

// TestHardLinkedTranscriptRewriteIsNeverCapturedFromByteZero is the bd-main-x6u F2 probe. `ln a.jsonl
// b.jsonl` gives ONE identity two locators, and a scan that records only one path per identity has to
// throw one of them away: the fence at the discarded locator went with it, so an atomic rewrite of
// that link found no lineage at all and was captured from byte zero. A hard link is not a rename - the
// identity did not leave anything behind - so both locators stay fenced and the rewritten one reseals.
func TestHardLinkedTranscriptRewriteIsNeverCapturedFromByteZero(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "a.jsonl"), filepath.Join(root, "b.jsonl")
	pre := msgLine("pre-consent-secret-behind-two-links") + "\n"
	writeFileString(t, a, pre)
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unavailable on this filesystem: %v", err)
	}

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
	control := readRootControl(t, state, root)
	for _, link := range []string{"a.jsonl", "b.jsonl"} {
		if _, ok := control.Lineages[link]; !ok {
			t.Fatalf("lineages = %+v, want every link of a sealed identity fenced", control.Lineages)
		}
	}

	// The owner rewrites one link in place the way every editor does. b.jsonl still holds the original
	// identity and the original pre-consent bytes.
	replaceViaRename(t, a, msgLine("the-rewrite-that-must-not-be-published")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rewrite poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want the rewritten link resealed, not read from byte zero", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want nothing published from a rewritten link of a sealed file", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic", len(got))
	}
}

// TestDisplacementWithAnAmbiguousIdentityFailsClosed covers the other half of F2. With three links,
// unlinking one and creating a file in its place gives the watcher everything a byte-zero ingest asks
// for - a corroborated walk that saw the locator EMPTY, and the sealed identity alive elsewhere - but
// "elsewhere" is two places at once. An identity at several locators names nowhere in particular, so
// it is not usable as evidence that anything moved, and the new file takes the fail-closed reseal
// instead of being published.
func TestDisplacementWithAnAmbiguousIdentityFailsClosed(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	a := filepath.Join(root, "a.jsonl")
	pre := msgLine("pre-consent-secret-behind-three-links") + "\n"
	writeFileString(t, a, pre)
	for _, link := range []string{"b.jsonl", "c.jsonl"} {
		if err := os.Link(a, filepath.Join(root, link)); err != nil {
			t.Skipf("hard links unavailable on this filesystem: %v", err)
		}
	}

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("empty-locator poll: %v", err)
	}
	if got := w.rootPolicies[root].absentLineagePolls["a.jsonl"]; got != 1 {
		t.Fatalf("empty-walk streak = %d, want the locator positively observed empty once", got)
	}

	writeFileString(t, a, msgLine("a-file-created-where-a-multiply-linked-identity-was")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-file poll: %v", err)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want an ambiguous displacement to fence rather than publish", got)
	}
	control := readRootControl(t, state, root)
	for _, link := range []string{"b.jsonl", "c.jsonl"} {
		if _, ok := control.Lineages[link]; !ok {
			t.Fatalf("lineages = %+v, want the surviving links still fenced", control.Lineages)
		}
	}
}

// TestTwoTranscriptsExchangingPathsKeepBothFences is the second half of F2. When two sealed files swap
// names the walk reports two renames whose sources and destinations are each other's, and applying
// them one at a time let the second overwrite what the first had just written - so the identity guard
// rejected it and one fence was dropped on the floor. Both files are sealed; both fences have to land
// where their file did.
func TestTwoTranscriptsExchangingPathsKeepBothFences(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "a.jsonl"), filepath.Join(root, "b.jsonl")
	preA := msgLine("pre-consent-secret-in-a") + "\n"
	preB := msgLine("pre-consent-secret-in-b-which-is-a-different-length") + "\n"
	writeFileString(t, a, preA)
	writeFileString(t, b, preB)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	devA, inoA := identityOf(t, a)
	devB, inoB := identityOf(t, b)

	swap := filepath.Join(root, "swap.tmp")
	for _, mv := range [][2]string{{a, swap}, {b, a}, {swap, b}} {
		if err := os.Rename(mv[0], mv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("exchange poll: %v", err)
	}
	control := readRootControl(t, state, root)
	if got, ok := control.Lineages["a.jsonl"]; !ok || got.Device != devB || got.Inode != inoB || got.Floor != int64(len(preB)) {
		t.Fatalf("lineage at a.jsonl = %+v/%v, want b's fence to have followed it there", got, ok)
	}
	if got, ok := control.Lineages["b.jsonl"]; !ok || got.Device != devA || got.Inode != inoA || got.Floor != int64(len(preA)) {
		t.Fatalf("lineage at b.jsonl = %+v/%v, want a's fence to have followed it there", got, ok)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("exchange delivered %d candidates, want none - neither file changed", len(got))
	}

	// Each fence is still standing where its file is: an atomic rewrite of either locator inherits the
	// floor rather than publishing the pre-consent bytes it kept.
	replaceViaRename(t, a, preB+msgLine("appended-by-the-rewrite")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-exchange rewrite poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-by-the-rewrite" {
		t.Fatalf("messages = %v, want only the record appended above b's inherited floor", got)
	}
}

// TestRotationToAnEarlierNameInOnePollWindowResealsTheVacatedLocator holds the F1 semantics under the
// walk order that hides the evidence. When the sealed file is renamed to a name that sorts BEFORE the
// one it left, the walk reconciles the rename first - and a fence relocated on the spot is gone by the
// time the file standing at the vacated locator is looked at, which reads as a locator no fence ever
// covered and captures it from byte zero. Staging the relocation until the whole walk is reconciled is
// what keeps that file answerable to the fence it displaced.
func TestRotationToAnEarlierNameInOnePollWindowResealsTheVacatedLocator(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	rotated := filepath.Join(root, "a-rotated.jsonl")
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

	// Both filesystem operations land inside one poll window, so no walk ever sees session.jsonl empty.
	if err := os.Rename(p, rotated); err != nil {
		t.Fatal(err)
	}
	writeFileString(t, p, msgLine("whatever-is-standing-here-now")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rotation poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want the unwitnessed replacement resealed", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want nothing published from a locator that was never observed empty", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic", len(got))
	}
	control := readRootControl(t, state, root)
	if got, ok := control.Lineages["a-rotated.jsonl"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("lineage at a-rotated.jsonl = %+v/%v, want the sealed floor %d to have followed it", got, ok, len(pre))
	}
}

// TestSuccessiveRenameRacingWalksDoNotReleaseATrackedIdentity is the bd-main-x6u F3 probe. A walk that
// lost an entry between readdir and stat is not evidence about anything, which the lineage-retirement
// side already knows - but the identity-absence counter took the same walk as proof the file was gone.
// Two of them in a row (a rename racing each poll) reached the eviction threshold, released the durable
// floor, and the identity was then re-tracked from byte zero.
func TestSuccessiveRenameRacingWalksDoNotReleaseATrackedIdentity(t *testing.T) {
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

	// The tracked file is out of the root, and every walk while it is away loses an entry between
	// readdir and stat - a rename in flight, staged here as the same ENOENT a dangling symlink gives.
	hidden := filepath.Join(away, "session.jsonl")
	if err := os.Rename(p, hidden); err != nil {
		t.Fatal(err)
	}
	inflight := filepath.Join(root, "z-in-flight.jsonl")
	if err := os.Symlink(filepath.Join(root, "gone"), inflight); err != nil {
		t.Skipf("cannot stage an entry that vanishes between readdir and stat: %v", err)
	}
	for i := 0; i < absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("rename-racing poll %d: %v", i, err)
		}
	}
	tf, ok := w.tracked[identityKey{dev: dev, ino: ino}]
	if !ok {
		t.Fatal("the tracked identity was released on walks that lost an entry to a rename in flight")
	}
	if tf.absentPolls != 0 {
		t.Fatalf("absentPolls = %d after uncorroborated walks, want absence counted only on the evidence retirement runs on", tf.absentPolls)
	}
	if got := obs.forgotten(); len(got) != 0 {
		t.Fatalf("forgot %v on uncorroborated absence, want the identity kept", got)
	}

	if err := os.Remove(inflight); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hidden, p); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("reappearance poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want the identity to resume from its floor", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want the sealed prefix still fenced after the reappearance", got)
	}
	if got := mustBaseline(t, readRootControl(t, state, root), p); got != sealed {
		t.Fatalf("baseline after reappearance = %+v, want the floor sealed before the races %+v", got, sealed)
	}
}

// TestReconcileErrorRestartsTheRetirementStreak is the bd-main-x6u F4 defect. A reconcile that fails
// part way returns before the poll's streak bookkeeping, so the run of consecutive corroborated
// observations a retirement rests on was neither advanced nor broken - it simply carried across a poll
// that established nothing. An errored poll is not evidence, and it is not consecutive with anything.
func TestReconcileErrorRestartsTheRetirementStreak(t *testing.T) {
	ctx := context.Background()
	root, state, scratch := t.TempDir(), t.TempDir(), t.TempDir()
	replaced, gone := filepath.Join(root, "a.jsonl"), filepath.Join(root, "gone.jsonl")
	writeFileString(t, replaced, msgLine("pre-consent-in-the-replaced-file")+"\n")
	writeFileString(t, gone, msgLine("pre-consent-in-the-deleted-file")+"\n")

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}

	// The replacement inode is minted BEFORE anything is unlinked, so it cannot land on the inode the
	// deletion below frees - which would make it a rename of the deleted file rather than a
	// replacement of this one, and would stage a different bug than the one under test.
	staged := filepath.Join(scratch, "staged.jsonl")
	writeFileString(t, staged, msgLine("a-completely-different-record")+"\n")
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first empty poll: %v", err)
	}
	if got := w.rootPolicies[root].absentLineagePolls["gone.jsonl"]; got != 1 {
		t.Fatalf("retirement streak = %d after one corroborated empty walk, want 1", got)
	}

	// A reseal diagnostic the sink refuses ends this reconcile early. Nothing it did or did not see is
	// usable, including about the locator whose streak is standing at one.
	if err := os.Rename(staged, replaced); err != nil {
		t.Fatal(err)
	}
	sink.failNext = true
	sink.failErr = errors.New("sink unavailable")
	if err := w.Poll(ctx); err == nil {
		t.Fatal("poll succeeded despite a sink failure that ended the reconcile")
	}
	if got := w.rootPolicies[root].absentLineagePolls["gone.jsonl"]; got != 0 {
		t.Fatalf("retirement streak = %d after an errored poll, want the run broken", got)
	}

	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first recovered poll: %v", err)
	}
	if _, ok := w.rootPolicies[root].control.Lineages["gone.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence held until two corroborated walks agree", w.rootPolicies[root].control.Lineages)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("second recovered poll: %v", err)
	}
	if _, ok := w.rootPolicies[root].control.Lineages["gone.jsonl"]; ok {
		t.Fatalf("lineages = %+v, want the fence retired once two corroborated walks agree", w.rootPolicies[root].control.Lineages)
	}
}

// TestRedactAndRestoreAfterOneEmptyWalkNeverPublishesTheEditedHistory is the bd-main-ikh probe for the
// newness threshold. Displacement licensed a byte-zero ingest at a vacated locator on ONE corroborated
// empty walk, which is the same one-walk standard retirement itself refuses - and one walk is all a
// redact-and-restore takes: move the sealed transcript out of the root (a single walk sees the locator
// empty, one short of retirement, so the fence is still standing), write an EDITED copy back at the
// sealed name, and bring the original back beside it. The identity is then alive at exactly one other
// locator with the window diverged, which used to read as "whatever is here now must be new" and
// published the owner's own pre-consent history, redacted line and all.
func TestRedactAndRestoreAfterOneEmptyWalkNeverPublishesTheEditedHistory(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	keep := filepath.Join(root, "session.keep.jsonl")
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
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
	sealedDev, sealedIno := identityOf(t, p)
	if got := w.rootPolicies[root].control.Lineages["session.jsonl"]; got.FingerprintLen == 0 {
		t.Fatalf("staging error: lineage %+v carries no fingerprint for the edit to diverge from", got)
	}

	// The sealed transcript leaves the root. Exactly one corroborated walk finds the locator empty,
	// which is one short of what retiring its fence takes.
	hidden := filepath.Join(away, "session.jsonl")
	if err := os.Rename(p, hidden); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("empty-locator poll: %v", err)
	}
	if got := w.rootPolicies[root].absentLineagePolls["session.jsonl"]; got != 1 {
		t.Fatalf("empty-walk streak = %d, want the locator positively observed empty exactly once", got)
	}
	if _, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence held after a single empty walk", w.rootPolicies[root].control.Lineages)
	}

	// The redaction: an EDITED copy of the history takes the sealed name, and the untouched original
	// comes back under the root beside it.
	edited := msgLine("pre-consent-secret-one") + "\n" + msgLine("REDACTED") + "\n"
	writeFileString(t, p, edited)
	if err := os.Rename(hidden, keep); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("redact-and-restore poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want nothing read from an edited copy of the sealed history", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want no pre-consent-derived record published from byte zero", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic for the resealed locator", len(got))
	}
	control := readRootControl(t, state, root)
	if got, ok := control.Lineages["session.keep.jsonl"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("lineage at session.keep.jsonl = %+v/%v, want the sealed floor %d to have followed the original", got, ok, len(pre))
	}
	if got, ok := control.Baselines[identityString(sealedDev, sealedIno)]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("original baseline = %+v/%v, want its floor %d intact where it now lives", got, ok, len(pre))
	}
	editedDev, editedIno := identityOf(t, p)
	if got, ok := control.Baselines[identityString(editedDev, editedIno)]; !ok || got.Floor != int64(len(edited)) {
		t.Fatalf("edited-copy baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(edited))
	}

	// The reseal is a fence, not a stop.
	post := msgLine("written-after-the-redaction") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-redaction append poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "written-after-the-redaction" {
		t.Fatalf("messages = %v, want only what was written after the reseal", got)
	}
}

// TestRotationOutOfTheRootIngestsFromZeroOnlyAfterCorroboratedEmptyWalks is the other side of the
// bd-main-ikh threshold, and the reason raising it costs capture rather than correctness. The same
// staging carried far enough to be evidence - absenceEvictionPolls consecutive corroborated walks that
// find the locator empty - retires the fence, and the session created there afterwards is captured in
// full. Newness is established by the standard that un-fences every other locator, not by a lower one
// reserved for displacement.
func TestRotationOutOfTheRootIngestsFromZeroOnlyAfterCorroboratedEmptyWalks(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
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
	if err := os.Rename(p, filepath.Join(away, "session.jsonl")); err != nil {
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
}

// TestErroredReconcileKeepsEveryStagedVacate is the bd-main-ikh probe for half-staged relocations. The
// staged shifts were applied unconditionally on the way out of reconcileScan, including from a scan
// that ended early - so two sealed files exchanging paths staged the first half of the exchange, hit an
// unrelated error before reaching the second, and released the fence over the locator the counterpart
// had just moved INTO. A vacate is only ever justified by what the rest of the walk found; a walk that
// did not finish has not found it. Holds still land: adding a fence needs no evidence.
//
// bd-main-37y removed the vacate entirely - a rename copies its fence to the destination and leaves
// the source lineage to retirement - so what this now holds is the property that made vacates
// unstageable in the first place: an errored reconcile leaves every fence standing, and the next
// complete walk still converges each one onto the locator its file occupies. Kept unmodified.
func TestErroredReconcileKeepsEveryStagedVacate(t *testing.T) {
	ctx := context.Background()
	root, state, scratch := t.TempDir(), t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "a.jsonl"), filepath.Join(root, "b.jsonl")
	preA := msgLine("pre-consent-secret-in-a") + "\n"
	preB := msgLine("pre-consent-secret-in-b-which-is-a-different-length") + "\n"
	writeFileString(t, a, preA)
	writeFileString(t, b, preB)
	// A third sealed file whose replacement trips the sink AFTER a.jsonl has been reconciled and
	// BEFORE b.jsonl, in the walk's own lexical order: a.jsonl < aa.jsonl < b.jsonl.
	c := filepath.Join(root, "aa.jsonl")
	writeFileString(t, c, msgLine("pre-consent-in-aa")+"\n")

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	devA, inoA := identityOf(t, a)
	devB, inoB := identityOf(t, b)
	fencedBefore := make(map[string]struct{}, len(w.rootPolicies[root].control.Lineages))
	for locator := range w.rootPolicies[root].control.Lineages {
		fencedBefore[locator] = struct{}{}
	}

	// Every replacement inode is minted while all three sealed inodes are still alive, so no
	// replacement can land on a freed inode number and rebind to a stale identity - which would stage a
	// divergence reseal rather than the half-applied exchange under test.
	diverged := filepath.Join(scratch, "aa-new.jsonl")
	writeFileString(t, diverged, msgLine("a-completely-different-record")+"\n")

	swap := filepath.Join(root, "swap.tmp")
	for _, mv := range [][2]string{{a, swap}, {b, a}, {swap, b}} {
		if err := os.Rename(mv[0], mv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(diverged, c); err != nil {
		t.Fatal(err)
	}
	sink.failNext = true
	sink.failErr = errors.New("sink unavailable")
	if err := w.Poll(ctx); err == nil {
		t.Fatal("poll succeeded despite a sink failure that ended the reconcile mid-exchange")
	}
	for locator := range fencedBefore {
		if _, ok := w.rootPolicies[root].control.Lineages[locator]; !ok {
			t.Fatalf("lineages = %+v, want every fence still standing after an errored reconcile - %q was released", w.rootPolicies[root].control.Lineages, locator)
		}
	}

	// The next complete walk converges: each fence ends up where its file did.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("recovery poll: %v", err)
	}
	control := readRootControl(t, state, root)
	if got, ok := control.Lineages["a.jsonl"]; !ok || got.Device != devB || got.Inode != inoB || got.Floor != int64(len(preB)) {
		t.Fatalf("lineage at a.jsonl = %+v/%v, want b's fence to have followed it there", got, ok)
	}
	if got, ok := control.Lineages["b.jsonl"]; !ok || got.Device != devA || got.Inode != inoA || got.Floor != int64(len(preA)) {
		t.Fatalf("lineage at b.jsonl = %+v/%v, want a's fence to have followed it there", got, ok)
	}

	// The fence at b.jsonl is real: an atomic rewrite there inherits a's floor instead of publishing
	// the pre-consent history the errored poll left sitting unfenced.
	replaceViaRename(t, b, preA+msgLine("appended-by-the-rewrite")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-recovery rewrite poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-by-the-rewrite" {
		t.Fatalf("messages = %v, want only the record appended above a's inherited floor", got)
	}
}

// TestRenameThenEditedCopyBackNeverPublishesTheEditedHistory is the bd-main-37y probe. Renaming a
// sealed transcript inside the root used to VACATE the fence at the name it left after a SINGLE
// corroborated poll - the last un-fencing that did not take retirement-grade evidence - and the
// lineage's fingerprint was deleted with it. An owner who then wrote an edited copy of the
// pre-consent history back at the sealed name met a locator no lineage covered, and the whole edited
// history was published from byte zero: the one record that could have refuted it was gone. A rename
// COPIES the fence now - the destination is fenced, the source keeps everything it had until
// retirement clears it - so the copy-back faces the ordinary fingerprint fence and reseals.
func TestRenameThenEditedCopyBackNeverPublishesTheEditedHistory(t *testing.T) {
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
	edited := msgLine("pre-consent-secret-one") + "\n" + msgLine("redacted-and-longer-than-the-line-it-replaced") + "\n"

	// Both orders a live daemon can observe the sequence in. The one-poll vacate made the second one
	// publish; the first was saved only by the relocation being staged until the end of the walk.
	for _, tc := range []struct {
		name            string
		pollAfterRename bool
	}{
		{name: "copy back inside the same poll window", pollAfterRename: false},
		{name: "copy back a poll after the rename is observed", pollAfterRename: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root, state := t.TempDir(), t.TempDir()
			p := filepath.Join(root, "session.jsonl")
			// The new name sorts AFTER the sealed one, so the walk reaches the copy-back before it has
			// seen where the sealed identity went.
			renamed := filepath.Join(root, "zz-renamed.jsonl")
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
			sealedDev, sealedIno := identityOf(t, p)
			if got := w.rootPolicies[root].control.Lineages["session.jsonl"]; got.FingerprintLen == 0 {
				t.Fatalf("staging error: lineage %+v carries no fingerprint for the copy-back to diverge from", got)
			}

			if err := os.Rename(p, renamed); err != nil {
				t.Fatal(err)
			}
			if tc.pollAfterRename {
				if err := w.Poll(ctx); err != nil {
					t.Fatalf("post-rename poll: %v", err)
				}
			}
			writeFileString(t, p, edited)
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("copy-back poll: %v", err)
			}
			if len(reads) != 0 {
				t.Fatalf("reads = %v, want nothing read from an edited copy of the sealed history", reads)
			}
			if got := sink.messages(); len(got) != 0 {
				t.Fatalf("messages = %v, want no pre-consent-derived record published from byte zero", got)
			}
			if got := diagnostics(sink.all()); len(got) != 1 {
				t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic for the resealed locator", len(got))
			}
			control := readRootControl(t, state, root)
			if got, ok := control.Lineages["zz-renamed.jsonl"]; !ok || got.Floor != int64(len(pre)) {
				t.Fatalf("lineage at zz-renamed.jsonl = %+v/%v, want the sealed floor %d held where the file went", got, ok, len(pre))
			}
			if got, ok := control.Baselines[identityString(sealedDev, sealedIno)]; !ok || got.Floor != int64(len(pre)) {
				t.Fatalf("renamed baseline = %+v/%v, want its floor %d intact", got, ok, len(pre))
			}
			editedDev, editedIno := identityOf(t, p)
			if got, ok := control.Baselines[identityString(editedDev, editedIno)]; !ok || got.Floor != int64(len(edited)) {
				t.Fatalf("copy-back baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(edited))
			}

			// The reseal is a fence, not a stop.
			appendString(t, p, msgLine("written-after-the-copy-back")+"\n")
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("post-copy-back append poll: %v", err)
			}
			if got := sink.messages(); len(got) != 1 || got[0] != "written-after-the-copy-back" {
				t.Fatalf("messages = %v, want only what was written after the reseal", got)
			}
		})
	}
}

// TestRenamedTranscriptKeepsItsFenceAtItsNewLocator is the other half of bd-main-37y: copying the
// fence to the destination must fence the destination as completely as a move did. The renamed file
// delivers everything appended above its floor and nothing beneath it, an atomic rewrite at its new
// name inherits that floor rather than republishing the sealed prefix, and the name it left keeps its
// own lineage until the ordinary retirement streak - not the rename - clears it.
func TestRenamedTranscriptKeepsItsFenceAtItsNewLocator(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	renamed := filepath.Join(root, "zz-renamed.jsonl")
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
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
	if err := os.Rename(p, renamed); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rename poll: %v", err)
	}
	policy := w.rootPolicies[root]
	if got, ok := policy.control.Lineages["zz-renamed.jsonl"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("lineage at zz-renamed.jsonl = %+v/%v, want the sealed floor %d held where the file went", got, ok, len(pre))
	}
	if _, ok := policy.control.Lineages["session.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the name the file left still fenced one walk into its retirement", policy.control.Lineages)
	}
	if got := policy.absentLineagePolls["session.jsonl"]; got != 1 {
		t.Fatalf("empty-walk streak = %d for the vacated name, want the rename to leave it to ordinary retirement", got)
	}

	post := msgLine("appended-after-the-rename") + "\n"
	appendString(t, renamed, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rename append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{int64(len(pre)), int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the renamed file's floor", reads)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "appended-after-the-rename" {
		t.Fatalf("messages = %v, want the renamed file's sealed prefix still fenced", got)
	}
	if _, ok := policy.control.Lineages["session.jsonl"]; ok {
		t.Fatalf("lineages = %+v, want the name the file left retired once two corroborated walks agree", policy.control.Lineages)
	}

	// The fence at the new name is real: an atomic rewrite there inherits the floor.
	rewritten := pre + msgLine("appended-by-the-rewrite") + "\n"
	replaceViaRename(t, renamed, rewritten)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rewrite poll: %v", err)
	}
	if len(reads) != 2 || reads[1] != [2]int64{int64(len(pre)), int64(len(rewritten) - len(pre))} {
		t.Fatalf("reads = %v, want the rewrite read only above the inherited floor", reads)
	}
	if got := sink.messages(); len(got) != 2 || got[1] != "appended-by-the-rewrite" {
		t.Fatalf("messages = %v, want only the record the rewrite appended above the inherited floor", got)
	}
	for _, r := range reads {
		if r[0] < int64(len(pre)) {
			t.Fatalf("reads = %v, want no read to start below the floor %d", reads, len(pre))
		}
	}
}

// TestUncorroboratedWalkNeverVacatesAHardLinkFence is the bd-main-ikh probe for uncorroborated
// relocations. A walk that lost an entry between readdir and stat found one of a hard link's two names
// and missed the other, which reads exactly like a rename - so the fence at the name it missed was
// vacated while that name still held the sealed bytes, and an atomic rewrite there before the next walk
// re-fenced it was captured from byte zero. Positive evidence (the identity IS here) survives a tainted
// walk; negative evidence (it is no longer THERE) does not.
func TestUncorroboratedWalkNeverVacatesAHardLinkFence(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "a.jsonl"), filepath.Join(root, "b.jsonl")
	pre := msgLine("pre-consent-secret-behind-two-links") + "\n"
	writeFileString(t, a, pre)
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unavailable on this filesystem: %v", err)
	}

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

	// The tainted walk: one link is momentarily out of the root, and the walk demonstrably lost an
	// entry (a dangling symlink is the same ENOENT a rename in flight gives). It positively sees the
	// identity at a.jsonl and nowhere else.
	hidden := filepath.Join(away, "b.jsonl")
	if err := os.Rename(b, hidden); err != nil {
		t.Fatal(err)
	}
	inflight := filepath.Join(root, "z-in-flight.jsonl")
	if err := os.Symlink(filepath.Join(root, "gone"), inflight); err != nil {
		t.Skipf("cannot stage an entry that vanishes between readdir and stat: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rename-racing poll: %v", err)
	}
	if _, ok := readRootControl(t, state, root).Lineages["b.jsonl"]; !ok {
		t.Fatal("the fence at b.jsonl was vacated on a walk that lost an entry between readdir and stat")
	}

	// The link comes back and is rewritten the way every editor saves, before any walk has re-fenced it.
	if err := os.Remove(inflight); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hidden, b); err != nil {
		t.Fatal(err)
	}
	rewritten := msgLine("the-rewrite-that-must-not-be-published") + "\n"
	replaceViaRename(t, b, rewritten)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("rewrite poll: %v", err)
	}
	if len(reads) != 0 {
		t.Fatalf("reads = %v, want the rewritten link resealed, not read from byte zero", reads)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want nothing published from a rewritten link of a sealed file", got)
	}
	if got := diagnostics(sink.all()); len(got) != 1 {
		t.Fatalf("diagnostics = %d, want exactly one ingestion-loss diagnostic", len(got))
	}
	// The corroborated walk that follows converges: the surviving link keeps the original floor, and
	// the rewritten one is fenced at its own EOF.
	control := readRootControl(t, state, root)
	if got, ok := control.Lineages["a.jsonl"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("lineage at a.jsonl = %+v/%v, want the sealed floor %d still fencing the surviving link", got, ok, len(pre))
	}
	rewrittenDev, rewrittenIno := identityOf(t, b)
	if got, ok := control.Baselines[identityString(rewrittenDev, rewrittenIno)]; !ok || got.Floor != int64(len(rewritten)) {
		t.Fatalf("rewritten-link baseline = %+v/%v, want a reseal at its EOF %d", got, ok, len(rewritten))
	}
}
