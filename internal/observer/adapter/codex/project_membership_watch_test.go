//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// codexMemberLocator is one date-sharded codex store path. That layout carries no directory witness,
// so membership turns purely on the cwd the transcript records — the simplest fixture for routing a
// store transcript to a project root by its content alone.
func codexMemberLocator(name string) string {
	return filepath.Join("2026", "08", "09", "rollout-"+name+".jsonl")
}

func projectRecord(path string, mode rootpolicy.Mode) rootpolicy.Record {
	return rootpolicy.Record{Path: path, Generation: 1, Active: true, Mode: mode, Kind: rootpolicy.Project}
}

func statSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

func hasBaseline(t *testing.T, control rootPolicyControl, path string) bool {
	t.Helper()
	dev, ino := identityOf(t, path)
	_, ok := control.Baselines[identityString(dev, ino)]
	return ok
}

// The seal pass covers the store transcripts that classify into the project root and leaves every
// other session in the shared store untouched: a member is sealed at a durable floor, a non-member is
// neither sealed nor tracked.
func TestProjectSealCoversMembersAndSkipsNonMembers(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	memberPath := writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project), msgLine("pre-consent"))
	nonMemberPath := writeTranscript(t, store, codexMemberLocator("stranger"), codexMetaLine(t.TempDir()), msgLine("not-ours"))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("seal poll: %v", err)
	}

	control := readRootControl(t, state, project)
	if !control.Committed {
		t.Fatal("project root did not commit its seal over a clean store sweep")
	}
	memSize := statSize(t, memberPath)
	if base := mustBaseline(t, control, memberPath); base.Floor != memSize {
		t.Fatalf("member floor = %d, want the sealed size %d", base.Floor, memSize)
	}
	if hasBaseline(t, control, nonMemberPath) {
		t.Fatal("a non-member transcript was sealed under the project root")
	}
	nd, ni := identityOf(t, nonMemberPath)
	if _, tracked := w.tracked[identityKey{dev: nd, ino: ni}]; tracked {
		t.Fatal("a non-member transcript was tracked")
	}
	if msgs := sink.messages(); len(msgs) != 0 {
		t.Fatalf("pre-consent bytes were published: %v", msgs)
	}
}

// An undetermined transcript — one still opening with cwd-less bookkeeping — never blocks the seal
// commit: the sweep stays clean, the member seals, the root commits, and the undetermined file is
// neither sealed nor tracked until a later poll classifies it.
func TestUndeterminedFileDoesNotBlockProjectSealCommit(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	memberPath := writeTranscript(t, store, codexMemberLocator("member"), codexMetaLine(project))
	undeterminedPath := writeTranscript(t, store, codexMemberLocator("opening"), queueLine, msgLine("still-typing"))

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("seal poll: %v", err)
	}

	control := readRootControl(t, state, project)
	if !control.Committed {
		t.Fatal("an undetermined transcript blocked the project seal commit")
	}
	if !hasBaseline(t, control, memberPath) {
		t.Fatal("the member was not sealed alongside the undetermined file")
	}
	if hasBaseline(t, control, undeterminedPath) {
		t.Fatal("an undetermined transcript was sealed before it was classified")
	}
	ud, ui := identityOf(t, undeterminedPath)
	if _, tracked := w.tracked[identityKey{dev: ud, ino: ui}]; tracked {
		t.Fatal("an undetermined transcript was tracked before classification")
	}
}

// A file first classified a member AFTER the seal committed seals at its size at classification time,
// so everything it wrote while it was still undetermined is fenced as pre-consent and only what it
// appends afterward is captured.
func TestLateMemberSealsAtClassificationTimeSize(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	// An anchor member present at activation commits the root on the first poll.
	writeTranscript(t, store, codexMemberLocator("anchor"), codexMetaLine(project))
	// The late file opens as pure bookkeeping — undetermined, so activation does not seal it.
	latePath := writeTranscript(t, store, codexMemberLocator("late"), queueLine, msgLine("pre-consent"))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         sink,
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if control := readRootControl(t, state, project); !control.Committed {
		t.Fatal("root did not commit on the first clean sweep")
	} else if hasBaseline(t, control, latePath) {
		t.Fatal("the late file was sealed while still undetermined")
	}

	// It records its cwd only now, after the seal committed: classified a member on this poll, it must
	// seal at its current size rather than take a byte-zero cursor over its pre-consent bytes.
	appendString(t, latePath, codexMetaLine(project)+"\n")
	classSize := statSize(t, latePath)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("late-member poll: %v", err)
	}
	if base := mustBaseline(t, readRootControl(t, state, project), latePath); base.Floor != classSize {
		t.Fatalf("late-member floor = %d, want the classification-time size %d", base.Floor, classSize)
	}
	if msgs := sink.messages(); containsMessage(msgs, "pre-consent") {
		t.Fatalf("late-member published a pre-consent record: %v", msgs)
	}

	// Only what it appends after classification is captured.
	appendString(t, latePath, msgLine("post-consent")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-consent poll: %v", err)
	}
	msgs := sink.messages()
	if !containsMessage(msgs, "post-consent") {
		t.Fatalf("late-member post-consent record was not captured: %v", msgs)
	}
	if containsMessage(msgs, "pre-consent") {
		t.Fatalf("late-member published a pre-consent record: %v", msgs)
	}
}

// The content side channel's gate for a project member composes to member AND root sealed AND
// (floor==0 OR backfilled), while a non-member keeps the legacy forward-baseline suppression.
func TestProjectContentGateComposesMemberSealedFloorOrBackfill(t *testing.T) {
	ctx := context.Background()
	store := t.TempDir()
	fwdProject, fwdState := t.TempDir(), t.TempDir()
	bfProject, bfState := t.TempDir(), t.TempDir()

	fwd := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(fwdProject, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     fwdState,
		Sink:         &recordingSink{},
	})
	fwdPolicy := fwd.rootPolicies[fwdProject]
	member := func(policy *rootPolicyState, forwardBaseline bool, dev, ino uint64) *trackedFile {
		return &trackedFile{policy: policy, member: true, forwardBaseline: forwardBaseline, dev: dev, ino: ino}
	}

	// Root not sealed yet: a member is fenced whatever else is true.
	if fwd.contentGateOpen(member(fwdPolicy, true, 1, 1)) {
		t.Fatal("member content gate opened before the root sealed")
	}
	fwdPolicy.control.Committed = true
	// A nonzero floor: the pre-consent prefix beneath the fence forbids a whole-file snapshot.
	fwdPolicy.setBaseline("a", 1, 2, baselineRecord{Floor: 128})
	if fwd.contentGateOpen(member(fwdPolicy, true, 1, 2)) {
		t.Fatal("member content gate opened over a nonzero floor without backfill")
	}
	// Sealed with nothing beneath it (floor zero): observable.
	fwdPolicy.setBaseline("b", 1, 3, baselineRecord{Floor: 0})
	if !fwd.contentGateOpen(member(fwdPolicy, true, 1, 3)) {
		t.Fatal("member content gate stayed closed at floor zero")
	}
	// The non-member gate is exactly the legacy forward-baseline suppression, unchanged.
	if fwd.contentGateOpen(&trackedFile{policy: fwdPolicy, forwardBaseline: true, dev: 1, ino: 4}) {
		t.Fatal("non-member forward-baseline gate opened")
	}
	if !fwd.contentGateOpen(&trackedFile{policy: fwdPolicy, forwardBaseline: false, dev: 1, ino: 5}) {
		t.Fatal("non-member non-baseline gate closed")
	}

	// A backfill root delivers the whole file, history included, so a committed member is observable
	// whatever its floor.
	bf := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(bfProject, rootpolicy.Backfill)},
		Stores:       []string{store},
		StateDir:     bfState,
		Sink:         &recordingSink{},
	})
	bfPolicy := bf.rootPolicies[bfProject]
	bfPolicy.control.Committed = true
	if !bf.contentGateOpen(member(bfPolicy, false, 1, 6)) {
		t.Fatal("backfill member content gate stayed closed")
	}

	// The observe path routes through the same gate: a floor-zero committed member reaches the observer.
	obs := &recordingContentObserver{}
	fwd.cfg.ContentObserver = obs
	memPath := writeTranscript(t, store, codexMemberLocator("gate"), codexMetaLine(fwdProject))
	dev, ino := identityOf(t, memPath)
	fwdPolicy.setBaseline(codexMemberLocator("gate"), dev, ino, baselineRecord{Floor: 0})
	tf := &trackedFile{policy: fwdPolicy, member: true, forwardBaseline: true, root: store, locator: codexMemberLocator("gate"), path: memPath, dev: dev, ino: ino}
	fwd.observeContent(ctx, tf, statSize(t, memPath), 0)
	if _, ok := obs.last(); !ok {
		t.Fatal("observeContent suppressed a floor-zero member: the gate is not wired into the observe path")
	}
}

// Two projects drawing from the same store each seal and drain under their own root: each member's
// floor lands in its own root's control and under no other, and neither root's drain ever crosses the
// other's fence.
func TestProjectDrainGatedPerRootAcrossTwoProjects(t *testing.T) {
	ctx := context.Background()
	projectA, projectB := t.TempDir(), t.TempDir()
	store, state := t.TempDir(), t.TempDir()

	aPath := writeTranscript(t, store, codexMemberLocator("a"), codexMetaLine(projectA), msgLine("before-A"))
	bPath := writeTranscript(t, store, codexMemberLocator("b"), codexMetaLine(projectB), msgLine("before-B"))

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{
			projectRecord(projectA, rootpolicy.ForwardOnly),
			projectRecord(projectB, rootpolicy.ForwardOnly),
		},
		Stores:   []string{store},
		StateDir: state,
		Sink:     sink,
		Match:    func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("seal poll: %v", err)
	}

	controlA := readRootControl(t, state, projectA)
	controlB := readRootControl(t, state, projectB)
	if !hasBaseline(t, controlA, aPath) || hasBaseline(t, controlA, bPath) {
		t.Fatal("project A's control does not hold exactly its own member")
	}
	if !hasBaseline(t, controlB, bPath) || hasBaseline(t, controlB, aPath) {
		t.Fatal("project B's control does not hold exactly its own member")
	}
	if msgs := sink.messages(); len(msgs) != 0 {
		t.Fatalf("pre-consent records published before any append: %v", msgs)
	}

	appendString(t, aPath, msgLine("after-A")+"\n")
	appendString(t, bPath, msgLine("after-B")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("append poll: %v", err)
	}
	msgs := sink.messages()
	if !containsMessage(msgs, "after-A") || !containsMessage(msgs, "after-B") {
		t.Fatalf("post-consent records were not both captured: %v", msgs)
	}
	if containsMessage(msgs, "before-A") || containsMessage(msgs, "before-B") {
		t.Fatalf("a pre-consent record crossed the fence: %v", msgs)
	}
}

// A6: the member seal floor falls after the last COMPLETE newline-terminated line at or before the
// observed size, so a partial tail line still being written at seal time counts as post-seal and no
// record is split across the fence.
func TestProjectSealFloorIsLineAligned(t *testing.T) {
	ctx := context.Background()
	project, store, state := t.TempDir(), t.TempDir(), t.TempDir()

	loc := codexMemberLocator("partial")
	writeTranscript(t, store, loc) // create the store subdirectories
	complete := codexMetaLine(project) + "\n"
	partialPath := filepath.Join(store, loc)
	writeFileString(t, partialPath, complete+`{"type":"message","role":"user","text":"unterminated`)

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{projectRecord(project, rootpolicy.ForwardOnly)},
		Stores:       []string{store},
		StateDir:     state,
		Sink:         &recordingSink{},
		Match:        func(name string) bool { return filepath.Ext(name) == ".jsonl" },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("seal poll: %v", err)
	}

	base := mustBaseline(t, readRootControl(t, state, project), partialPath)
	if base.Floor != int64(len(complete)) {
		t.Fatalf("seal floor = %d, want the boundary after the last complete line %d (the partial tail is post-seal)",
			base.Floor, len(complete))
	}
}
