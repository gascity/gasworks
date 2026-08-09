//go:build unix

package codex

import "sync"

// MembershipIndex caches decided membership verdicts so a store of thousands of transcripts costs
// one peek per file rather than one peek per poll. It is IN-MEMORY ONLY and deliberately so (A3):
// a roots-file change always restarts the daemon, so there is no cross-process staleness to reason
// about, and a rebuilt-per-process cache cannot outlive the consent it was computed under.
//
// Entries are keyed by filesystem identity (device, inode) — the same key the cursors use — and are
// corroborated on every lookup, because inode numbers are reused.
type MembershipIndex struct {
	// mu guards both maps: the poll loop records verdicts while the content side channel consults
	// them from its own goroutine.
	mu      sync.Mutex
	entries map[transcriptIdentity]membershipEntry
	byPath  map[string]transcriptIdentity
}

type transcriptIdentity struct {
	dev uint64
	ino uint64
}

type membershipEntry struct {
	verdict Membership
	// path is where the identity was standing when the verdict was reached. A4: the same inode seen
	// at a different path is a different file (inode reuse across projects), so the verdict dies.
	path string
	// stat is the {size, ctime} a negative verdict is anchored to.
	stat TranscriptStat
}

// NewMembershipIndex returns an empty index.
func NewMembershipIndex() *MembershipIndex {
	return &MembershipIndex{
		entries: make(map[transcriptIdentity]membershipEntry),
		byPath:  make(map[string]transcriptIdentity),
	}
}

// Lookup returns the cached verdict for the identity (dev, ino) as currently seen at path with stat
// st, reporting false when there is nothing usable and the caller must peek.
//
// A cached entry is discarded when the identity has moved to a different path (A4), and — for a
// NEGATIVE verdict — when its size or ctime has changed since the verdict, which is what makes an
// inode reused by a new file at the same path re-peek instead of inheriting a stale "not yours".
// A POSITIVE verdict is deliberately not stat-corroborated: a member transcript's size and ctime
// change on every append, so anchoring it to a stat would defeat the cache entirely. Its protection
// is the path check plus EvictPath, and the failure it forgives — an inode reused at the identical
// path inside the same consented project directory — resolves to the same project anyway.
func (ix *MembershipIndex) Lookup(dev, ino uint64, path string, st TranscriptStat) (Membership, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	id := transcriptIdentity{dev: dev, ino: ino}
	e, ok := ix.entries[id]
	if !ok {
		return Membership{}, false
	}
	if e.path != path {
		ix.dropLocked(id, e)
		return Membership{}, false
	}
	if e.verdict.State == MembershipNonMember && (e.stat.Size != st.Size || e.stat.CtimeNanos != st.CtimeNanos) {
		ix.dropLocked(id, e)
		return Membership{}, false
	}
	return e.verdict, true
}

// Record caches a decided verdict for the identity (dev, ino) seen at path, anchored to the stat
// the peek reached the verdict under. An undetermined verdict is never cached: it is not a decision,
// and the re-peek that resolves it reads only the bounded head again.
func (ix *MembershipIndex) Record(dev, ino uint64, path string, st TranscriptStat, m Membership) {
	if m.State == MembershipUndetermined {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	id := transcriptIdentity{dev: dev, ino: ino}
	// A new inode standing at a path a previous identity owned is a rewrite-via-rename: the old
	// entry can never be corroborated again, so it goes now rather than leaking until eviction.
	if prev, ok := ix.byPath[path]; ok && prev != id {
		delete(ix.entries, prev)
	}
	if old, ok := ix.entries[id]; ok && old.path != path {
		if owner, ok := ix.byPath[old.path]; ok && owner == id {
			delete(ix.byPath, old.path)
		}
	}
	ix.entries[id] = membershipEntry{verdict: m, path: path, stat: st}
	ix.byPath[path] = id
}

// EvictPath drops whatever verdict was recorded at path. The walk calls it for a path that has
// vanished, which is the only signal that a negative verdict's file is gone for good: without it a
// deleted transcript's entry would sit in the index until its inode was reused somewhere visible.
func (ix *MembershipIndex) EvictPath(path string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	id, ok := ix.byPath[path]
	if !ok {
		return
	}
	delete(ix.byPath, path)
	delete(ix.entries, id)
}

func (ix *MembershipIndex) dropLocked(id transcriptIdentity, e membershipEntry) {
	delete(ix.entries, id)
	if owner, ok := ix.byPath[e.path]; ok && owner == id {
		delete(ix.byPath, e.path)
	}
}
