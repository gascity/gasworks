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
// package rather than of the three call sites that happen to hold it today. Lowering or deleting a
// locator's fence is the whole of the exposure, so the map may be written in exactly two guarded
// primitives plus retirement - the one sanctioned un-fencing - and a fourth writer added later fails
// here rather than in a customer's transcript.
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
						if sel, isSel := x.Fun.(*ast.SelectorExpr); isSel && sel.Sel.Name == "fenceHolds" {
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
			t.Errorf("%s writes a locator's fence without consulting fenceHolds; a live fence must only be lowered by the identity it names", name)
		}
	}
}

// isLineageMap reports an expression naming the control record's per-locator fence map.
func isLineageMap(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Lineages"
}
