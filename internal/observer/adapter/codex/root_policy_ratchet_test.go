//go:build unix

package codex

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// TestEmptyInterpositionNeverUnfencesARotatedOutSealedLocator is the bd-main-9xl F1 probe. The sealed
// transcript rotates OUT of the root - renamed to a .bak, moved aside, archived - so its bytes are
// alive and untouched somewhere no walk of the root will find them, and the name it left is inside
// its retirement window. An EMPTY file appearing at that name used to reseal the locator at its own
// end of file, which is byte zero, and a floor of zero deleted the fence outright. The owner's edited
// copy of the pre-consent history put back there afterwards then met a locator no fence covered and
// was published from byte zero.
func TestEmptyInterpositionNeverUnfencesARotatedOutSealedLocator(t *testing.T) {
	runInterposedFenceProbe(t, "")
}

// TestShortInterpositionNeverLowersARotatedOutSealedFence is the bd-main-9xl F2 probe: the same
// rotation, with one byte standing at the vacated name instead of none. The reseal wrote that byte
// count over the sealed floor, so the fence survived as a fence over nothing, and the edited copy put
// back at the name inherited it - corroborated against a one-byte window it trivially matched - and
// published every byte above offset one.
func TestShortInterpositionNeverLowersARotatedOutSealedFence(t *testing.T) {
	runInterposedFenceProbe(t, "{")
}

// runInterposedFenceProbe stages one interposed replacement at the name a sealed transcript rotated
// away from, in both orders a live daemon can observe the sequence in, and holds the whole invariant:
// the fence stands exactly where it stood, in memory and on disk, and nothing beneath it is ever
// delivered. The sealed bytes were never destroyed - they are alive in the file that rotated away -
// so no file that is not that one may cut the fence down to its own size.
func runInterposedFenceProbe(t *testing.T, interposed string) {
	t.Helper()
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
	edited := msgLine("pre-consent-secret-one") + "\n" + msgLine("redacted-and-longer-than-the-line-it-replaced") + "\n"

	for _, tc := range []struct {
		name              string
		pollAfterRotation bool
	}{
		{name: "interposed after a corroborated walk observed the name empty", pollAfterRotation: true},
		{name: "interposed before any walk observed the name empty", pollAfterRotation: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
			p := filepath.Join(root, "session.jsonl")
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
			fence := w.rootPolicies[root].control.Lineages["session.jsonl"]
			if fence.Floor != int64(len(pre)) || fence.FingerprintLen == 0 {
				t.Fatalf("staging error: fence %+v, want the sealed floor %d carrying a fingerprint", fence, len(pre))
			}

			// The sealed transcript leaves the root entirely. Its bytes are untouched at a path the
			// walk cannot see, which is exactly the state a rotation, an archive or a `mv` aside
			// produces - and the reason nothing at the name it left may lower that name's fence.
			if err := os.Rename(p, filepath.Join(away, "session.jsonl")); err != nil {
				t.Fatal(err)
			}
			if tc.pollAfterRotation {
				if err := w.Poll(ctx); err != nil {
					t.Fatalf("post-rotation poll: %v", err)
				}
				if got := w.rootPolicies[root].absentLineagePolls["session.jsonl"]; got != 1 {
					t.Fatalf("empty-walk streak = %d, want one corroborated empty observation, short of the %d retirement takes", got, absenceEvictionPolls)
				}
			}

			writeFileString(t, p, interposed)
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("interposition poll: %v", err)
			}
			// Reported rather than fatal, so a build that cuts the fence here goes on to show what
			// that costs: the copy-back below is the step that reaches the owner's own history.
			if got, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]; !ok || got != fence {
				t.Errorf("fence after a %d-byte interposition = %+v/%v, want the sealed %+v held", len(interposed), got, ok, fence)
			}
			if got := readRootControl(t, state, root).Lineages["session.jsonl"]; got != fence {
				t.Errorf("persisted fence = %+v, want the sealed %+v held on disk as well as in memory", got, fence)
			}

			// The copy-back: an edited copy of the owner's own pre-consent history put back at the
			// sealed name, as a new inode, the way an editor save or a restore from backup writes it.
			replaceViaRename(t, p, edited)
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("copy-back poll: %v", err)
			}
			if got := sink.messages(); len(got) != 0 {
				t.Errorf("messages = %v, want no pre-consent-derived record delivered", got)
			}
			if len(reads) != 0 {
				t.Fatalf("reads = %v, want nothing read from an edited copy of the sealed history", reads)
			}
			if got := diagnostics(sink.all()); len(got) != 2 {
				t.Fatalf("diagnostics = %d, want one ingestion-loss report for the interposition and one for the copy-back", len(got))
			}
			control := readRootControl(t, state, root)
			editedDev, editedIno := identityOf(t, p)
			if got, ok := control.Baselines[identityString(editedDev, editedIno)]; !ok || got.Floor != int64(len(edited)) {
				t.Fatalf("copy-back baseline = %+v/%v, want a reseal at its own end of file %d", got, ok, len(edited))
			}

			// The held fence is a fence, not a stop: what the owner writes after it still flows.
			post := msgLine("written-after-the-copy-back") + "\n"
			appendString(t, p, post)
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("post-copy-back append poll: %v", err)
			}
			if got := sink.messages(); len(got) != 1 || got[0] != "written-after-the-copy-back" {
				t.Fatalf("messages = %v, want only what was written after the reseal", got)
			}
			if len(reads) != 1 || reads[0] != [2]int64{int64(len(edited)), int64(len(post))} {
				t.Fatalf("reads = %v, want only the bytes appended above the resealed floor %d", reads, len(edited))
			}
		})
	}
}

// TestInterposedFenceStillRetiresOnCorroboratedAbsence closes the loop on holding the fence: holding
// is not keeping it forever. A name whose sealed transcript rotated away and which then held an
// interposed file keeps its fence while anything stands there, and clears it through the one step
// that un-fences a locator at all - absenceEvictionPolls consecutive corroborated walks finding the
// name empty. After that the name is genuinely new again and the next transcript created there is
// captured in full.
func TestInterposedFenceStillRetiresOnCorroboratedAbsence(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-secret-one") + "\n" + msgLine("pre-consent-secret-two") + "\n"
	writeFileString(t, p, pre)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if err := os.Rename(p, filepath.Join(away, "session.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rotation poll: %v", err)
	}
	writeFileString(t, p, "{")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("interposition poll: %v", err)
	}
	policy := w.rootPolicies[root]
	if got, ok := policy.control.Lineages["session.jsonl"]; !ok || got.Floor != int64(len(pre)) {
		t.Fatalf("fence after the interposition = %+v/%v, want the sealed floor %d held", got, ok, len(pre))
	}
	if got := policy.absentLineagePolls["session.jsonl"]; got != 0 {
		t.Fatalf("empty-walk streak = %d, want an occupied name to have restarted it", got)
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("first empty poll: %v", err)
	}
	if _, ok := policy.control.Lineages["session.jsonl"]; !ok {
		t.Fatalf("lineages = %+v, want the fence held after a single empty walk", policy.control.Lineages)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("second empty poll: %v", err)
	}
	if _, ok := policy.control.Lineages["session.jsonl"]; ok {
		t.Fatalf("lineages = %+v, want the fence retired once two corroborated walks agree", policy.control.Lineages)
	}

	fresh := msgLine("a-genuinely-new-session") + "\n"
	writeFileString(t, p, fresh)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("new-transcript poll: %v", err)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "a-genuinely-new-session" {
		t.Fatalf("messages = %v, want a retired name to capture its next transcript in full", got)
	}
}

// TestSameIdentityTruncationStillLowersItsOwnFence is the other side of the ratchet, and the reason
// it is keyed on identity rather than on the floor alone. A file that truncates ITSELF really did
// destroy the bytes above the new end of file: nothing is left anywhere for the fence to protect,
// keeping it would leave capture pointing past the end of the file forever, and the reseal is
// reported. That lowering must keep working at the locator as well as at the identity (A22).
func TestSameIdentityTruncationStillLowersItsOwnFence(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-record-one") + "\n" + msgLine("pre-consent-record-two") + "\n"
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
	dev, ino := identityOf(t, p)
	truncated := int64(len(pre) / 2)
	if err := os.Truncate(p, truncated); err != nil {
		t.Fatal(err)
	}
	if gotDev, gotIno := identityOf(t, p); gotDev != dev || gotIno != ino {
		t.Skip("filesystem changed the identity on truncate; in-place truncation not exercised")
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("truncate poll: %v", err)
	}
	lowered, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]
	if !ok || lowered.Floor != truncated {
		t.Fatalf("fence after an in-place truncation = %+v/%v, want it lowered to the new end of file %d", lowered, ok, truncated)
	}
	if lowered.Device != dev || lowered.Inode != ino {
		t.Fatalf("fence identity = %d:%d, want the truncated file's own identity %d:%d", lowered.Device, lowered.Inode, dev, ino)
	}
	diags := diagnostics(sink.all())
	if len(diags) != 1 || !strings.Contains(diags[0].Diagnostic.Context, "resealing capture at the new end of file") {
		t.Fatalf("truncation diagnostics = %+v, want one honest reseal report", diags)
	}

	post := msgLine("after-truncate") + "\n"
	appendString(t, p, post)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-truncate append poll: %v", err)
	}
	if len(reads) != 1 || reads[0] != [2]int64{truncated, int64(len(post))} {
		t.Fatalf("reads = %v, want only the bytes appended above the lowered floor %d", reads, truncated)
	}
	if got := sink.messages(); len(got) != 1 || got[0] != "after-truncate" {
		t.Fatalf("messages = %v, want only the post-truncation record", got)
	}
}

// TestEveryLineageWriteFlowsThroughTheRatchetOrRetirement keeps the invariant a property of the
// package rather than of the three call sites that happen to hold it today. Rebinding, lowering or
// deleting a locator's fence is the whole of the exposure, so the map may be written in exactly two
// primitives that route through reconcileLineage, plus retirement - the one sanctioned un-fencing -
// and a fourth writer added later fails here rather than in a customer's transcript.
func TestEveryLineageWriteFlowsThroughTheRatchetOrRetirement(t *testing.T) {
	writers := map[string]bool{"setLineage": true, "holdLineage": true, "retireAbsentLineages": true}
	mustGuard := map[string]bool{"setLineage": true, "holdLineage": true}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package sources: %v", err)
	}
	guards := map[string]bool{}
	found := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							idx, isIndex := lhs.(*ast.IndexExpr)
							if !isIndex || !isLineageMap(idx.X) {
								continue
							}
							found++
							if !writers[fn.Name.Name] {
								t.Errorf("%s writes a locator's fence directly in %s; every write goes through setLineage or holdLineage", fset.Position(lhs.Pos()), fn.Name.Name)
							}
						}
					case *ast.CallExpr:
						if id, isIdent := x.Fun.(*ast.Ident); isIdent && id.Name == "delete" && len(x.Args) > 0 && isLineageMap(x.Args[0]) {
							found++
							if !writers[fn.Name.Name] {
								t.Errorf("%s deletes a locator's fence in %s; un-fencing is retireAbsentLineages' alone", fset.Position(x.Pos()), fn.Name.Name)
							}
						}
						if sel, isSel := x.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "reconcileLineage" {
							guards[fn.Name.Name] = true
						}
					}
					return true
				})
			}
		}
	}
	if found == 0 {
		t.Fatal("found no fence write at all; this probe has stopped watching the map it names")
	}
	for name := range mustGuard {
		if !guards[name] {
			t.Errorf("%s writes a locator's fence without routing through reconcileLineage; a live fence's identity must only be rebound or lowered by the identity it names", name)
		}
	}
}

// isLineageMap reports an expression naming the control record's per-locator fence map.
func isLineageMap(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Lineages"
}

// TestForeignReplacementAtOrAboveFloorNeverRebindsTheFenceIdentity is the bd-main-dyc regression, and
// the door bd-main-9xl left open. The floor-only ratchet refused a foreign write only when it would
// LOWER the floor, so a replacement standing at or ABOVE the floor slipped through and rebound the
// fence to its own identity. Once the fence named the replacement, the same-identity exemption applied
// to it: it could truncate the floor to zero and delete the fence outright, and the owner's edited
// pre-consent history copied back afterwards then met a locator no fence covered and was published
// from byte zero. No inode reuse is required anywhere - a fresh inode at or above the floor captures
// the identity directly, which is why the ratchet cannot lean on inode uniqueness.
func TestForeignReplacementAtOrAboveFloorNeverRebindsTheFenceIdentity(t *testing.T) {
	ctx := context.Background()
	root, state, away := t.TempDir(), t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
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
	floor := int64(len(pre))
	dev, ino0 := identityOf(t, p)
	fence := w.rootPolicies[root].control.Lineages["session.jsonl"]
	if fence.Floor != floor || fence.FingerprintLen == 0 || fence.Device != dev || fence.Inode != ino0 {
		t.Fatalf("staging error: fence %+v, want the sealed floor %d fingerprinted and named by (%d,%d)", fence, floor, dev, ino0)
	}

	// The sealed transcript rotates entirely off the root. Its bytes are alive and untouched at a name
	// no walk of the root reaches, the locator it left stays fenced through its retirement window, and
	// its inode stays allocated there so nothing at the locator can reuse it.
	if err := os.Rename(p, filepath.Join(away, "session.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("post-rotation poll: %v", err)
	}

	// A foreign file - a fresh inode - is written at the vacated locator at a size ABOVE the floor with
	// a diverged prefix: exactly the write the floor-only guard let through. Its own bytes say nothing
	// about the sealed prefix (alive elsewhere), so it must reseal WITHOUT taking the fence's identity.
	replacement := msgLine("a-different-first-record-from-the-replacement") + "\n" +
		msgLine("and-a-second-record") + "\n" + msgLine("and-a-third-record") + "\n" + msgLine("and-a-fourth-record") + "\n"
	if int64(len(replacement)) <= floor {
		t.Fatalf("replacement is %d bytes, must exceed the %d-byte floor to exercise the ratchet door", len(replacement), floor)
	}
	writeFileString(t, p, replacement)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("foreign-replacement poll: %v", err)
	}
	_, ino1 := identityOf(t, p)
	if ino1 == ino0 {
		t.Fatalf("replacement reused the sealed inode %d; this probe requires a fresh identity", ino0)
	}
	afterReplace, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]
	if !ok {
		t.Fatalf("fence vanished on a foreign write at or above the floor")
	}
	if afterReplace.Device != dev || afterReplace.Inode != ino0 {
		t.Fatalf("fence identity after a foreign replacement = (%d,%d), want the incumbent (%d,%d) held; a rebind at or above the floor is the defect",
			afterReplace.Device, afterReplace.Inode, dev, ino0)
	}
	if afterReplace.Floor < floor {
		t.Fatalf("fence floor = %d, want it held at or ratcheted above %d", afterReplace.Floor, floor)
	}

	// The captured identity's next move: truncate to zero. Under the defect the fence now NAMES this
	// writer, so its same-identity exemption lets a zero floor delete the fence. A foreign writer never
	// lowers, and a zero from one clears nothing - only retirement un-fences a locator.
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("foreign-truncation poll: %v", err)
	}
	afterTrunc, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]
	if !ok {
		t.Fatalf("fence deleted by a foreign truncation to zero; retirement is the only un-fencing")
	}
	if afterTrunc.Device != dev || afterTrunc.Inode != ino0 {
		t.Fatalf("fence identity after a foreign truncation = (%d,%d), want the incumbent (%d,%d) held",
			afterTrunc.Device, afterTrunc.Inode, dev, ino0)
	}

	// The copy-back: an edited copy of the owner's own pre-consent history, a new inode, put back at
	// the sealed name the way an editor save or a restore from backup writes it. With the fence held it
	// inherits the floor and nothing beneath it is delivered; with the fence captured-then-deleted it
	// would be ingested from byte zero.
	edited := msgLine("redacted-pre-consent-history") + "\n"
	replaceViaRename(t, p, edited)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("copy-back poll: %v", err)
	}
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("messages = %v, want no pre-consent-derived record ever delivered", got)
	}
	for _, r := range reads {
		if r[0] < floor {
			t.Fatalf("read %v dips below the sealed floor %d; the pre-consent prefix was published", r, floor)
		}
	}
	final, ok := w.rootPolicies[root].control.Lineages["session.jsonl"]
	if !ok || final.Device != dev || final.Inode != ino0 {
		t.Fatalf("fence after the copy-back = %+v/%v, want the incumbent identity (%d,%d) never rebound", final, ok, dev, ino0)
	}
}

// TestForeignWriteAtRootPolicyNeverRebindsOrClearsALiveFence forces the divergent state directly on
// rootPolicyState, with no filesystem, so the invariant is pinned at the primitive rather than only at
// the poll that happens to reach it. A live fence names (dev,ino0); a foreign identity writes at or
// above the floor and then at zero, and neither the rebind nor the delete may happen - through either
// door onto the map, setLineage or holdLineage.
func TestForeignWriteAtRootPolicyNeverRebindsOrClearsALiveFence(t *testing.T) {
	const (
		dev     = uint64(2304)
		ino0    = uint64(1001)
		ino1    = uint64(2002)
		ino2    = uint64(3003)
		floor   = int64(186)
		raised  = int64(512)
		locator = "session.jsonl"
	)
	s := &rootPolicyState{
		record: rootpolicy.Record{Path: "/root", Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
		control: rootPolicyControl{
			Version: rootPolicyControlVersion, Root: "/root", Generation: 1, Active: true,
			Mode: rootpolicy.ForwardOnly, Committed: true,
			Lineages: map[string]sealLineage{
				locator: {Floor: floor, Generation: 1, Device: dev, Inode: ino0},
			},
		},
	}

	// A foreign identity writes at a floor above the fence's: it ratchets the floor up but keeps the
	// incumbent identity, never rebinding to the writer.
	s.setLineage(locator, dev, ino1, baselineRecord{Floor: raised})
	got := s.control.Lineages[locator]
	if got.Device != dev || got.Inode != ino0 {
		t.Fatalf("fence identity after a foreign write at %d = (%d,%d), want the incumbent (%d,%d)", raised, got.Device, got.Inode, dev, ino0)
	}
	if got.Floor != raised {
		t.Fatalf("fence floor after a foreign write at %d = %d, want it ratcheted to max(%d,%d)", raised, got.Floor, floor, raised)
	}

	// The same foreign identity now writes a zero floor - the move that, once it had captured the
	// fence under the defect, deleted it. It names a foreign identity, so it clears nothing.
	s.setLineage(locator, dev, ino1, baselineRecord{Floor: 0})
	got, ok := s.control.Lineages[locator]
	if !ok {
		t.Fatal("fence deleted by a foreign zero-floor write; only the identity it names may clear it")
	}
	if got.Device != dev || got.Inode != ino0 || got.Floor != raised {
		t.Fatalf("fence after a foreign zero-floor write = %+v, want it unchanged at {Floor:%d Device:%d Inode:%d}", got, raised, dev, ino0)
	}

	// holdLineage is the other door onto the same map, and had the identical defect: a foreign baseline
	// at or above the floor rebound the fence to the arriving identity. It must hold instead.
	s.control.Baselines = map[string]baselineRecord{identityString(dev, ino2): {Floor: raised}}
	s.holdLineage(locator, dev, ino2)
	got = s.control.Lineages[locator]
	if got.Device != dev || got.Inode != ino0 {
		t.Fatalf("fence identity after holdLineage by a foreign identity = (%d,%d), want the incumbent (%d,%d) not rebound", got.Device, got.Inode, dev, ino0)
	}
	if got.Floor != raised {
		t.Fatalf("fence floor after holdLineage by a foreign identity = %d, want it held at %d", got.Floor, raised)
	}
}
