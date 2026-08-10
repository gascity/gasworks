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

// These tests pin the cross-generation backfill re-delivery idempotency contract documented on the
// rootpolicy.Backfill / rootpolicy.ForwardOnly modes. The watcher's contribution to an observation's
// identity is generation-stable: a byte-identical re-read (a restart that lost its durable cursor, or
// a re-registration that mints a new generation and a fresh scoped cursor) re-presents the same
// content under the same content-derived fields — provenance.source_locator (TranscriptRef.Locator),
// the provider event time (Candidate.OccurredAt), the observation kind, and the kind's typed payload
// metadata (a MESSAGE's role and byte_count). None of those change across a generation bump or a
// restart, so an endpoint that keys dedup on them collapses the re-delivery. The values that DO change
// — the daemon-minted sequence and observation id, and the delivery-time captured_at — are minted
// downstream in internal/observer/daemon/sink.go and never appear at this seam; keying dedup on them
// would fail to collapse a backfill re-delivery, which is exactly what the RED of each test proves.

// stableObsKey is the generation-stable identity an endpoint dedups a re-delivered candidate on. It
// deliberately excludes anything minted per-delivery downstream (the daemon sequence/observation id,
// the delivery-time captured_at); it carries only fields the watcher re-presents byte-identically.
type stableObsKey struct {
	locator   string
	kind      CandidateKind
	occurred  string
	role      wire.MessagePayloadRole
	byteCount int64
}

func stableKeyOf(ref TranscriptRef, c *Candidate) stableObsKey {
	k := stableObsKey{
		locator:  ref.Locator,
		kind:     c.Kind,
		occurred: c.OccurredAt.UTC().Format(time.RFC3339Nano),
	}
	if c.Message != nil {
		k.role = c.Message.Role
		if c.Message.ByteCount != nil {
			k.byteCount = *c.Message.ByteCount
		}
	}
	return k
}

// deliveredStableKeys flattens every delivered candidate, in delivery order, to its generation-stable
// dedup key.
func deliveredStableKeys(s *recordingSink) []stableObsKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stableObsKey
	for _, b := range s.batches {
		for _, c := range b.cands {
			out = append(out, stableKeyOf(b.ref, c))
		}
	}
	return out
}

func equalStableKeys(a, b []stableObsKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBackfillReDeliveryIsIdempotentAcrossRestart proves that a backfill member re-read after a
// simulated daemon restart re-delivers byte-identical content under the SAME generation-stable
// identifying fields, so a content-keyed endpoint collapses it. A restart that kept its durable cursor
// resumes and re-delivers nothing; a restart that lost the cursor (the cursor advance was not durable
// before the crash) re-reads the whole backfill file from its floor and re-delivers it — under a
// stable key identical to the first delivery's.
func TestBackfillReDeliveryIsIdempotentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("one")+"\n"+msgLine("two")+"\n")
	backfill := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.Backfill}}

	// First run: the whole backfill file is delivered.
	sink1 := &recordingSink{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: sink1}).Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	keys1 := deliveredStableKeys(sink1)
	if len(keys1) != 2 {
		t.Fatalf("first backfill delivery = %d candidates, want 2 (%v)", len(keys1), sink1.messages())
	}

	// Restart with the durable cursor intact: a fresh watcher over the same state resumes at the
	// persisted floor and re-delivers nothing.
	sink2 := &recordingSink{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: sink2}).Poll(ctx); err != nil {
		t.Fatalf("poll 2 (resume): %v", err)
	}
	if got := deliveredStableKeys(sink2); len(got) != 0 {
		t.Fatalf("restart with intact cursor re-delivered %d candidates, want 0 (resume): %v", len(got), sink2.messages())
	}

	// Restart that lost the durable cursor: the whole backfill file is re-read and re-delivered.
	lost := mustGlob(t, filepath.Join(state, "root-cursors", "*", "codex-cursor-*.json"))
	if len(lost) == 0 {
		t.Fatalf("expected a persisted cursor file to remove")
	}
	for _, c := range lost {
		if err := os.Remove(c); err != nil {
			t.Fatalf("remove cursor %s: %v", c, err)
		}
	}
	sink3 := &recordingSink{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: sink3}).Poll(ctx); err != nil {
		t.Fatalf("poll 3 (restart, cursor lost): %v", err)
	}
	keys3 := deliveredStableKeys(sink3)

	if !equalStableKeys(keys3, keys1) {
		t.Fatalf("backfill re-delivery is not idempotent under generation-stable fields:\n first  = %#v\n reread = %#v", keys1, keys3)
	}
}

// TestBackfillToForwardFlipReseals proves that a root re-registered from Backfill to ForwardOnly (a
// new generation) reseals: the new generation's fresh scoped cursor seals at the current line-aligned
// EOF floor, so the flip poll republishes NOTHING beneath the floor, and it never emits an
// un-dedupable duplicate of the pre-flip content. Only content appended after the flip is delivered.
func TestBackfillToForwardFlipReseals(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("one")+"\n"+msgLine("two")+"\n")

	// Generation 1, backfill: the whole file is delivered.
	sink1 := &recordingSink{}
	backfill := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.Backfill}}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: sink1}).Poll(ctx); err != nil {
		t.Fatalf("poll gen1 backfill: %v", err)
	}
	preFlip := deliveredStableKeys(sink1)
	if len(preFlip) != 2 {
		t.Fatalf("gen1 backfill delivered %d candidates, want 2 (%v)", len(preFlip), sink1.messages())
	}

	// Generation 2, forward-only: the flip reseals. The fresh scoped cursor seals at EOF, so the
	// flip poll delivers nothing beneath the new floor.
	sink2 := &recordingSink{}
	flip := []rootpolicy.Record{{Path: root, Generation: 2, Active: true, Mode: rootpolicy.ForwardOnly}}
	w2 := mustWatcher(t, WatchConfig{RootPolicies: flip, StateDir: state, Sink: sink2})
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("poll gen2 flip: %v", err)
	}
	if got := deliveredStableKeys(sink2); len(got) != 0 {
		t.Fatalf("backfill->forward flip republished %d candidates beneath the new floor, want 0: %v", len(got), sink2.messages())
	}

	// After the flip only newly-appended content is delivered, and it never re-presents the pre-flip
	// content (no un-dedupable duplicate).
	appendString(t, p, msgLine("three")+"\n")
	if err := w2.Poll(ctx); err != nil {
		t.Fatalf("poll gen2 after append: %v", err)
	}
	postFlip := deliveredStableKeys(sink2)
	if got := messageBodies(sink2.all()); len(got) != 1 || got[0] != "three" {
		t.Fatalf("after flip delivered %v, want exactly [three]", got)
	}
	preSet := make(map[stableObsKey]struct{}, len(preFlip))
	for _, k := range preFlip {
		preSet[k] = struct{}{}
	}
	for _, k := range postFlip {
		if _, dup := preSet[k]; dup {
			t.Fatalf("post-flip delivery re-presented pre-flip content under key %#v (un-dedupable duplicate beneath the reseal)", k)
		}
	}
}

// contentKey is the generation-stable identity the whole-file content side channel presents for a
// snapshot. The content endpoint dedups snapshots by hash plus this identity (Locator, Device, Inode,
// GCSessionID) and lets a later, larger snapshot supersede; a byte-identical re-delivery re-presents
// the same identity and size, so it collapses rather than double-ingesting.
type contentKey struct {
	locator string
	device  uint64
	inode   uint64
	size    int64
}

func contentKeyOf(o ContentObservation) contentKey {
	return contentKey{locator: o.Locator, device: o.Device, inode: o.Inode, size: o.Size}
}

// TestContentChannelUnderBackfillReDelivery proves the whole-file content side channel behaves per the
// documented contract across a backfill re-delivery: the content gate is open under Backfill, so the
// observer fires once per poll with the file's identity/stat, and a byte-identical re-read after a
// restart that lost the cursor re-presents the SAME generation-stable identity (Locator, Device,
// Inode) and the SAME size — so a content-keyed endpoint collapses the re-presented snapshot rather
// than ingesting the transcript's content twice.
func TestContentChannelUnderBackfillReDelivery(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("one")+"\n"+msgLine("two")+"\n")
	backfill := []rootpolicy.Record{{Path: root, Generation: 1, Active: true, Mode: rootpolicy.Backfill}}

	obs1 := &recordingContentObserver{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: &recordingSink{}, ContentObserver: obs1}).Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	first, ok := obs1.last()
	if !ok {
		t.Fatalf("content observer did not fire under backfill (gate should be open)")
	}
	if first.Size <= 0 {
		t.Fatalf("content observation reported non-positive size %d", first.Size)
	}

	// Restart that lost the durable cursor: the file is re-read, and the content channel fires again
	// for the byte-identical whole file.
	lost := mustGlob(t, filepath.Join(state, "root-cursors", "*", "codex-cursor-*.json"))
	for _, c := range lost {
		if err := os.Remove(c); err != nil {
			t.Fatalf("remove cursor %s: %v", c, err)
		}
	}
	obs2 := &recordingContentObserver{}
	if err := mustWatcher(t, WatchConfig{RootPolicies: backfill, StateDir: state, Sink: &recordingSink{}, ContentObserver: obs2}).Poll(ctx); err != nil {
		t.Fatalf("poll 2 (restart, cursor lost): %v", err)
	}
	second, ok := obs2.last()
	if !ok {
		t.Fatalf("content observer did not fire on the backfill re-read")
	}

	if contentKeyOf(second) != contentKeyOf(first) {
		t.Fatalf("content re-delivery is not idempotent under generation-stable identity:\n first  = %#v\n reread = %#v", contentKeyOf(first), contentKeyOf(second))
	}
}
