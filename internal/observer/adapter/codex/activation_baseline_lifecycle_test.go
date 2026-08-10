//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// bd-main-1qh facet A. A forward-only activation seals EVERY regular file standing under the root
// before the Match gate, so a non-transcript sidecar gets a durable identity floor it is never tracked
// through. The per-identity release sweep only GCs TRACKED identities, so that floor used to linger
// forever; once the sidecar's inode NUMBER was handed to a genuinely new transcript, the dead floor
// fenced the new file's leading bytes with no divergence ever detected — an ingestion loss. The floor
// and its durable cursor must instead be evicted on the same N>=2 corroborated-absence discipline
// retirement uses, and a genuinely live fence must be left untouched throughout.
func TestReusedInodeNumberIsNotFencedByADeadActivationBaseline(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()

	// A genuine transcript that seals with pre-consent history. Its live floor must survive every sweep.
	member := filepath.Join(root, "session.jsonl")
	writeFileString(t, member, msgLine("pre-consent")+"\n")
	// A non-transcript sidecar the activation seal fences at its own floor but never tracks (Match
	// admits only .jsonl). This is the untracked activation baseline the bug stranded.
	sidecar := filepath.Join(root, "tool-output.txt")
	writeFileString(t, sidecar, "opaque\n")

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{
		RootPolicies: []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly}},
		StateDir:     state,
		Sink:         sink,
		Match:        jsonlMatch,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("activation poll: %v", err)
	}
	if !readRootControl(t, state, root).Committed {
		t.Fatal("the forward-only root did not commit over a clean walk")
	}

	sidecarDev, sidecarIno := identityOf(t, sidecar)
	sidecarID := identityString(sidecarDev, sidecarIno)
	if _, sealed := readRootControl(t, state, root).Baselines[sidecarID]; !sealed {
		t.Fatal("the forward-activation seal did not fence the non-transcript sidecar")
	}
	memberFloor := mustBaseline(t, readRootControl(t, state, root), member).Floor
	if memberFloor <= 0 {
		t.Fatalf("the genuine transcript sealed at floor %d, want a live floor above zero", memberFloor)
	}
	scopedDir := filepath.Join(state, "root-cursors", w.rootPolicies[root].scope)
	sidecarCursor := cursorStatePath(scopedDir, sidecarDev, sidecarIno)
	if _, err := os.Stat(sidecarCursor); err != nil {
		t.Fatalf("the activation seal left no durable cursor for the sidecar: %v", err)
	}

	// While the sidecar still STANDS, corroborated walks must never evict its floor: a present but
	// untracked file is occupied, not absent. Over-fencing here is the safe direction; the eviction may
	// only ever fire for an identity no walk found.
	for i := 0; i <= absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("present-sidecar poll %d: %v", i, err)
		}
	}
	if _, sealed := readRootControl(t, state, root).Baselines[sidecarID]; !sealed {
		t.Fatal("the sidecar's floor was evicted while its file still stood under the root; a present " +
			"untracked file is not an absent one")
	}

	// The sidecar is deleted, freeing its inode NUMBER for the allocator to hand to a new file.
	if err := os.Remove(sidecar); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}
	for i := 0; i <= absenceEvictionPolls; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("post-delete poll %d: %v", i, err)
		}
	}

	// The dead activation floor and its durable cursor are GC'd on the corroborated-absence gate.
	if _, sealed := readRootControl(t, state, root).Baselines[sidecarID]; sealed {
		t.Fatalf("the dead activation baseline for the deleted sidecar was never evicted; a file reusing " +
			"its inode NUMBER would be fenced by a floor whose own file is gone")
	}
	if _, err := os.Stat(sidecarCursor); !os.IsNotExist(err) {
		t.Fatalf("the deleted sidecar's durable cursor survived its eviction (stat err=%v); a reused inode "+
			"number would resume the stranger's sealed position", err)
	}

	// A genuinely new post-consent transcript reuses the freed inode NUMBER. With the dead floor and its
	// cursor gone, cursorFor captures it from its own byte zero rather than fencing it at the stranger's
	// floor. inheritSealLineage returns before any read for a locator that carries no lineage, so this
	// direct drive needs no file on disk at the reused number.
	fresh := discovered{
		root: root, path: filepath.Join(root, "reused.jsonl"), locator: "reused.jsonl",
		dev: sidecarDev, ino: sidecarIno, size: 4096, mod: time.Now().UnixNano(),
	}
	cur, forwardBaseline, err := w.cursorFor(ctx, w.rootPolicies[root], fresh, &rootScan{byIdentity: map[identityKey][]string{}})
	if err != nil {
		t.Fatalf("cursorFor for the reused inode number: %v", err)
	}
	if forwardBaseline || cur.IsSealed() || cur.Consumed() != 0 {
		t.Fatalf("the reused inode number was fenced by the dead activation floor: forwardBaseline=%v sealed=%v consumed=%d, "+
			"want an unfenced capture from byte zero", forwardBaseline, cur.IsSealed(), cur.Consumed())
	}

	// The genuine transcript's live fence is untouched: its floor still stands and its pre-consent
	// prefix was never published while the stranger's baseline was evicted.
	if got := mustBaseline(t, readRootControl(t, state, root), member).Floor; got != memberFloor {
		t.Fatalf("the genuine transcript's floor moved from %d to %d during the eviction sweep", memberFloor, got)
	}
	if containsMessage(sink.messages(), "pre-consent") {
		t.Fatalf("a pre-consent byte beneath a live floor was published: %v", sink.messages())
	}
}
