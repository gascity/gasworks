//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// containsRoot reports whether a tailed-roots slice holds an exact path.
func containsRoot(roots []string, want string) bool {
	for _, r := range roots {
		if r == want {
			return true
		}
	}
	return false
}

// sinkDeliveredLossFor reports whether the sink received a CAPTURE_LOSS / PARTIAL diagnostic in a
// batch whose ref names locator. The ref is what puts the locator on the record; the wire codes are
// the ones drain uses for a capture-loss report.
func sinkDeliveredLossFor(sink *recordingSink, locator string) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, b := range sink.batches {
		if b.ref.Locator != locator {
			continue
		}
		for _, c := range diagnostics(b.cands) {
			if c.Diagnostic.Code == wire.CaptureDiagnosticPayloadCodeCAPTURELOSS &&
				c.Diagnostic.CompletenessEffect == wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL {
				return true
			}
		}
	}
	return false
}

// TestCursorForLoweredRecoveredFloorEmitsLossDiagnostic is bd-main-4qv item 1. cursorFor's A22
// recovered-floor branch lowers a durable floor to the current size when a same-identity file has
// shrunk below it (a truncation) and drops the fingerprint that described the removed bytes. That
// lowering used to be SILENT; the loss/ambiguity must be on the record. The floor math is unchanged
// (it still ratchets down to the surviving size); the branch only ALSO emits one honest diagnostic.
func TestCursorForLoweredRecoveredFloorEmitsLossDiagnostic(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	member := filepath.Join(root, "session.jsonl")
	pre := msgLine("pre-consent-record-one") + "\n" + msgLine("pre-consent-record-two") + "\n"
	writeFileString(t, member, pre)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state,
		Sink:         sink,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	floor := mustBaseline(t, readRootControl(t, state, root), member).Floor
	if floor <= 0 {
		t.Fatalf("activation sealed at floor %d, want a floor above zero", floor)
	}
	dev, ino := identityOf(t, member)

	// The crash the recovered-floor branch exists for: the durable baseline survives the control write
	// but the individual cursor is lost, so re-discovery has to recover the floor from the committed
	// baseline rather than reopen at byte zero.
	scoped := filepath.Join(state, "root-cursors", w.rootPolicies[root].scope)
	if err := os.Remove(cursorStatePath(scoped, dev, ino)); err != nil {
		t.Fatalf("remove the scoped cursor to force floor recovery: %v", err)
	}

	// Present the SAME identity at a size below its recorded floor (an in-place shrink). The floor
	// ratchets down to the surviving size AND that lowering is reported instead of silent.
	shrunk := floor / 2
	d := discovered{
		root: root, path: member, locator: "session.jsonl",
		dev: dev, ino: ino, size: shrunk, mod: time.Now().UnixNano(),
	}
	cur, forwardBaseline, err := w.cursorFor(ctx, w.rootPolicies[root], d, &rootScan{byIdentity: map[identityKey][]string{}})
	if err != nil {
		t.Fatalf("cursorFor over a shrunk recovered floor: %v", err)
	}

	// The floor math is unchanged: it still lowers to the surviving size, and the recovered cursor is
	// sealed there.
	if !forwardBaseline {
		t.Fatalf("cursorFor returned forwardBaseline=false, want the recovered baseline honored")
	}
	if !cur.IsSealed() || cur.Consumed() != shrunk {
		t.Fatalf("recovered cursor sealed=%v consumed=%d, want it lowered to the shrunk size %d", cur.IsSealed(), cur.Consumed(), shrunk)
	}
	if got, ok := w.rootPolicies[root].baseline(dev, ino); !ok || got.Floor != shrunk {
		t.Fatalf("recovered baseline floor = %+v/%v, want it lowered to %d", got, ok, shrunk)
	}

	// The added honesty: one CAPTURE_LOSS / PARTIAL diagnostic naming the locator whose floor dropped.
	if !sinkDeliveredLossFor(sink, "session.jsonl") {
		t.Fatalf("no CAPTURE_LOSS/PARTIAL diagnostic delivered for the lowered floor; batches=%+v", sink.batches)
	}
}

// TestNewWatcherNeverTailsAProjectRoot is bd-main-4qv item 2: a test-only lock-in of an existing
// structural refusal. NewWatcher promotes an Active policy to the tailed roots only when it is NOT a
// kind=project root, so the owner's project folder is never walked, sealed, or tailed — its sessions
// are drawn from the recorded stores by membership instead. A transcripts-kind root IS promoted.
func TestNewWatcherNeverTailsAProjectRoot(t *testing.T) {
	project, transcripts, store, state := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{
			projectRecord(project, rootpolicy.ForwardOnly),
			{Path: transcripts, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
		},
		Stores:   []string{store},
		StateDir: state,
		Sink:     &recordingSink{},
	})
	if containsRoot(w.cfg.ApprovedRoots, project) {
		t.Fatalf("the kind=project root %q was promoted to the tailed roots %v; walking it would seal and "+
			"capture the owner's own project folder", project, w.cfg.ApprovedRoots)
	}
	if !containsRoot(w.cfg.ApprovedRoots, transcripts) {
		t.Fatalf("the transcripts-kind root %q was NOT promoted to the tailed roots %v", transcripts, w.cfg.ApprovedRoots)
	}
	// The project root still has policy state: it is reconciled via membership over the stores, just
	// never added to the directory the walk tails.
	if _, ok := w.rootPolicies[project]; !ok {
		t.Fatal("the project root has no policy state; it must still be reconciled by membership, only never tailed")
	}
}

// TestForwardActivationDefersOnMidWalkChurn is bd-main-4qv item 3. A transcript that rotates away
// between readdir and stat during a forward activation is ordinary churn, not a fault: the walk used
// to return that ENOENT as FATAL, which propagated all the way to Run and took the daemon down until
// restart. It must instead DEFER — mark the scan so the activation cannot commit this poll and retry
// on the next — exactly as the not-yet-existent-root carve-out already does. The commit gate stays
// fail-closed throughout: a churned walk that did not see the whole root never commits its baseline.
func TestForwardActivationDefersOnMidWalkChurn(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	keep := filepath.Join(root, "session.jsonl")
	writeFileString(t, keep, msgLine("pre-consent")+"\n")

	// A dangling symlink is gone by the time the walk stats it: the same ENOENT a transcript rotating
	// away mid-walk produces, staged deterministically. It sorts after the real file, so the walk seals
	// the real file first and then meets the churn.
	inflight := filepath.Join(root, "z-in-flight.jsonl")
	if err := os.Symlink(filepath.Join(root, "gone"), inflight); err != nil {
		t.Skipf("cannot stage an entry that vanishes between readdir and stat: %v", err)
	}

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: &recordingSink{},
	})

	// Before bd-main-4qv this poll returned the fatal `stat <inflight>: no such file or directory` and
	// Run terminated; now the activation defers on the churn.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll over a mid-walk vanish returned an error (Run would have terminated): %v", err)
	}
	// Fail-closed: a walk that did not enumerate the whole root must NOT commit its durable baseline.
	if readRootControl(t, state, root).Committed {
		t.Fatal("the activation committed over a churned walk that did not see the whole root")
	}

	// The churn clears: a clean walk lets the deferred activation commit on the retry.
	if err := os.Remove(inflight); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("clean retry poll: %v", err)
	}
	if !readRootControl(t, state, root).Committed {
		t.Fatal("the activation did not commit once the churn cleared and the walk saw the whole root")
	}
}

// TestForwardActivationStillFailsClosedOnGenuineStatFault guards the other side of bd-main-4qv item
// 3: only the ENOENT churn case defers. A genuine, non-ENOENT stat fault (here EACCES from a root
// whose search bit was removed) is a real I/O/permission fault, not rotation, and must still fail the
// activation closed rather than silently defer.
func TestForwardActivationStillFailsClosedOnGenuineStatFault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits, so a non-ENOENT stat fault cannot be staged")
	}
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	writeFileString(t, filepath.Join(root, "session.jsonl"), msgLine("pre-consent")+"\n")

	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state, Sink: &recordingSink{},
	})

	// Remove the root's search (x) bit: readdir still lists the entry (r is intact), but statting it
	// faults with EACCES — a genuine fault, not ENOENT churn.
	if err := os.Chmod(root, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(root, 0o700) }()

	if err := w.Poll(ctx); err == nil {
		t.Fatal("activation poll swallowed a genuine (non-ENOENT) stat fault; a real fault must fail closed, not defer")
	}
}
