//go:build unix

package codex

import "testing"

func memberVerdict(id string) Membership {
	return Membership{State: MembershipMember, ProjectRootID: id}
}

func nonMemberVerdict(reason NonMemberReason) Membership {
	return Membership{State: MembershipNonMember, Reason: reason}
}

func mustLookup(t *testing.T, ix *MembershipIndex, dev, ino uint64, path string, st TranscriptStat) Membership {
	t.Helper()
	m, ok := ix.Lookup(dev, ino, path, st)
	if !ok {
		t.Fatalf("lookup(%d,%d,%q) missed, want a cached verdict", dev, ino, path)
	}
	return m
}

func wantMiss(t *testing.T, ix *MembershipIndex, dev, ino uint64, path string, st TranscriptStat) {
	t.Helper()
	if m, ok := ix.Lookup(dev, ino, path, st); ok {
		t.Fatalf("lookup(%d,%d,%q) = %s, want a miss forcing a re-peek", dev, ino, path, m.State)
	}
}

func TestMembershipIndexCachesDecidedVerdicts(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", st, memberVerdict("root-a"))
	ix.Record(1, 11, "/store/b.jsonl", st, nonMemberVerdict(ReasonOutsideProjectRoots))

	if got := mustLookup(t, ix, 1, 10, "/store/a.jsonl", st); got != memberVerdict("root-a") {
		t.Fatalf("member entry = %+v", got)
	}
	if got := mustLookup(t, ix, 1, 11, "/store/b.jsonl", st); got != nonMemberVerdict(ReasonOutsideProjectRoots) {
		t.Fatalf("non-member entry = %+v", got)
	}
	wantMiss(t, ix, 1, 12, "/store/c.jsonl", st)
}

func TestMembershipIndexNeverCachesUndetermined(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 10, CtimeNanos: 1, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", st, Membership{State: MembershipUndetermined})
	wantMiss(t, ix, 1, 10, "/store/a.jsonl", st)
}

// A negative verdict is only as good as the file it was reached on: either half of {size, ctime}
// moving means the bytes changed under the inode, so the verdict is re-derived.
func TestMembershipIndexInvalidatesNegativeOnStatChange(t *testing.T) {
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	for _, tc := range []struct {
		name string
		live TranscriptStat
	}{
		{"size changed", TranscriptStat{Size: 101, CtimeNanos: 7, UID: 1000}},
		{"size shrank", TranscriptStat{Size: 0, CtimeNanos: 7, UID: 1000}},
		{"ctime changed", TranscriptStat{Size: 100, CtimeNanos: 8, UID: 1000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := NewMembershipIndex()
			ix.Record(1, 10, "/store/a.jsonl", st, nonMemberVerdict(ReasonPeekCapExhausted))
			wantMiss(t, ix, 1, 10, "/store/a.jsonl", tc.live)
			// The invalidated entry is gone, not merely skipped for one poll.
			wantMiss(t, ix, 1, 10, "/store/a.jsonl", st)
		})
	}
}

// A member transcript grows on every append, so its verdict must survive the stat moving; that is
// the whole point of caching it.
func TestMembershipIndexKeepsMemberVerdictAcrossAppends(t *testing.T) {
	ix := NewMembershipIndex()
	ix.Record(1, 10, "/store/a.jsonl", TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}, memberVerdict("root-a"))
	got := mustLookup(t, ix, 1, 10, "/store/a.jsonl", TranscriptStat{Size: 4096, CtimeNanos: 99, UID: 1000})
	if got != memberVerdict("root-a") {
		t.Fatalf("member entry after append = %+v, want the cached member verdict", got)
	}
}

// A file whose clock has not ticked between two observations still grew by appending; the corroboration
// must not read that as a rewrite, because coarse ctime granularity would then evict busy transcripts.
func TestMembershipIndexKeepsMemberWhenGrowthSharesACtime(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", st, memberVerdict("root-a"))
	if got := mustLookup(t, ix, 1, 10, "/store/a.jsonl", TranscriptStat{Size: 180, CtimeNanos: 7, UID: 1000}); got != memberVerdict("root-a") {
		t.Fatalf("member entry after a same-ctime append = %+v", got)
	}
}

// A positive verdict is only as good as the bytes it was read from. An in-place rewrite keeps both
// the inode and the path, so the path check alone would hand back "member" forever; what refuses it
// is that a file which is only appended to may sit still or grow and nothing else. Every other shape
// of movement is rewrite evidence and costs the entry its place in the index.
func TestMembershipIndexEvictsMemberOnRewriteEvidence(t *testing.T) {
	snap := TranscriptStat{Size: 4096, CtimeNanos: 100, UID: 1000}
	for _, tc := range []struct {
		name string
		live TranscriptStat
	}{
		{"truncated and rewritten shorter", TranscriptStat{Size: 512, CtimeNanos: 200, UID: 1000}},
		{"truncated to nothing", TranscriptStat{Size: 0, CtimeNanos: 200, UID: 1000}},
		{"overwritten at the same length", TranscriptStat{Size: 4096, CtimeNanos: 200, UID: 1000}},
		{"ctime went backwards", TranscriptStat{Size: 8192, CtimeNanos: 99, UID: 1000}},
		{"owner changed", TranscriptStat{Size: 8192, CtimeNanos: 200, UID: 1001}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := NewMembershipIndex()
			ix.Record(1, 10, "/store/a.jsonl", snap, memberVerdict("root-a"))
			wantMiss(t, ix, 1, 10, "/store/a.jsonl", tc.live)
			// The entry is gone, not merely skipped for one poll: the original stat does not
			// resurrect it either.
			wantMiss(t, ix, 1, 10, "/store/a.jsonl", snap)
		})
	}
}

// A surviving entry re-anchors to the stat that corroborated it, so growth is judged against the
// file's last observed length rather than against the (much smaller) length it was peeked at.
func TestMembershipIndexReanchorsMemberOnEveryCorroboration(t *testing.T) {
	ix := NewMembershipIndex()
	ix.Record(1, 10, "/store/a.jsonl", TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}, memberVerdict("root-a"))
	if got := mustLookup(t, ix, 1, 10, "/store/a.jsonl", TranscriptStat{Size: 4096, CtimeNanos: 99, UID: 1000}); got != memberVerdict("root-a") {
		t.Fatalf("member entry after append = %+v", got)
	}
	// 200 bytes is more than the 100 the verdict was peeked at but far less than the 4096 last seen:
	// the file was rewritten, not appended to.
	wantMiss(t, ix, 1, 10, "/store/a.jsonl", TranscriptStat{Size: 200, CtimeNanos: 120, UID: 1000})
}

// A4: an identity seen at a NEW path is a reused inode, never the same file.
func TestMembershipIndexInvalidatesOnNewPath(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store/-p-one/a.jsonl", st, memberVerdict("root-a"))

	wantMiss(t, ix, 1, 10, "/store/-p-two/a.jsonl", st)
	// The old entry is dropped outright, so the original path does not resurrect it either.
	wantMiss(t, ix, 1, 10, "/store/-p-one/a.jsonl", st)
}

func TestMembershipIndexEvictPathDropsTheEntry(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", st, nonMemberVerdict(ReasonOutsideProjectRoots))
	ix.Record(1, 11, "/store/b.jsonl", st, memberVerdict("root-a"))

	ix.EvictPath("/store/a.jsonl")
	wantMiss(t, ix, 1, 10, "/store/a.jsonl", st)
	if got := mustLookup(t, ix, 1, 11, "/store/b.jsonl", st); got != memberVerdict("root-a") {
		t.Fatalf("sibling entry = %+v, want it untouched by the eviction", got)
	}
	ix.EvictPath("/store/never-recorded.jsonl") // must not panic
}

// Rewrite-via-rename puts a new inode at a path an old identity owned; the old entry can never be
// corroborated again, so recording the new one retires it.
func TestMembershipIndexRecordAtAnOwnedPathRetiresTheOldIdentity(t *testing.T) {
	ix := NewMembershipIndex()
	old := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	fresh := TranscriptStat{Size: 20, CtimeNanos: 9, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", old, nonMemberVerdict(ReasonOutsideProjectRoots))
	ix.Record(1, 11, "/store/a.jsonl", fresh, memberVerdict("root-a"))

	wantMiss(t, ix, 1, 10, "/store/a.jsonl", old)
	if got := mustLookup(t, ix, 1, 11, "/store/a.jsonl", fresh); got != memberVerdict("root-a") {
		t.Fatalf("replacement entry = %+v", got)
	}
	// Evicting the path clears the live entry, leaving nothing behind for either identity.
	ix.EvictPath("/store/a.jsonl")
	wantMiss(t, ix, 1, 11, "/store/a.jsonl", fresh)
	if len(ix.entries) != 0 || len(ix.byPath) != 0 {
		t.Fatalf("index = %d entries / %d paths, want empty", len(ix.entries), len(ix.byPath))
	}
}

// A file that moved keeps exactly one path index entry, so a later eviction of the stale path can
// never take the live verdict with it.
func TestMembershipIndexRerecordAtANewPathReleasesTheOldPath(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store/a.jsonl", st, memberVerdict("root-a"))
	ix.Record(1, 10, "/store/b.jsonl", st, memberVerdict("root-a"))

	ix.EvictPath("/store/a.jsonl")
	if got := mustLookup(t, ix, 1, 10, "/store/b.jsonl", st); got != memberVerdict("root-a") {
		t.Fatalf("moved entry = %+v, want it to survive eviction of its old path", got)
	}
	if len(ix.entries) != 1 || len(ix.byPath) != 1 {
		t.Fatalf("index = %d entries / %d paths, want exactly one of each", len(ix.entries), len(ix.byPath))
	}
}

// Distinct devices with the same inode number are distinct files.
func TestMembershipIndexKeysOnDeviceAndInode(t *testing.T) {
	ix := NewMembershipIndex()
	st := TranscriptStat{Size: 100, CtimeNanos: 7, UID: 1000}
	ix.Record(1, 10, "/store-a/x.jsonl", st, memberVerdict("root-a"))
	ix.Record(2, 10, "/store-b/x.jsonl", st, nonMemberVerdict(ReasonOutsideProjectRoots))

	if got := mustLookup(t, ix, 1, 10, "/store-a/x.jsonl", st); got != memberVerdict("root-a") {
		t.Fatalf("dev 1 entry = %+v", got)
	}
	if got := mustLookup(t, ix, 2, 10, "/store-b/x.jsonl", st); got != nonMemberVerdict(ReasonOutsideProjectRoots) {
		t.Fatalf("dev 2 entry = %+v", got)
	}
}
