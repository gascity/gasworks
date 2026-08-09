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
	// stat is the corroboration snapshot the verdict currently stands on. It starts as the stat the
	// peek reached the verdict under and is re-anchored by every lookup that keeps the entry, so a
	// member's growth is judged against the length last observed rather than an ever-staler one.
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
// A cached entry is discarded when the identity has moved to a different path (A4), and whenever the
// live stat no longer corroborates the verdict. Dropping an entry never substitutes a verdict: it
// only costs the caller a fresh bounded peek, which re-decides the file the identity is now.
func (ix *MembershipIndex) Lookup(dev, ino uint64, path string, st TranscriptStat) (Membership, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	id := transcriptIdentity{dev: dev, ino: ino}
	e, ok := ix.entries[id]
	if !ok {
		return Membership{}, false
	}
	if e.path != path || !corroborates(e.verdict.State, e.stat, st) {
		ix.dropLocked(id, e)
		return Membership{}, false
	}
	if e.stat != st {
		e.stat = st
		ix.entries[id] = e
	}
	return e.verdict, true
}

// corroborates reports whether the live stat st still supports a verdict reached under snap.
//
// A NEGATIVE verdict is anchored rigidly: the file was shown not to be ours at exactly this
// {size, ctime}, so either half moving means the bytes changed under the inode and the verdict is
// re-derived. Nothing legitimate rewrites a non-member in place and expects to stay one.
//
// A POSITIVE verdict cannot be anchored that way — a member transcript's size and ctime move on
// every append, which is the case the cache exists for — so it is anchored to the SHAPE of the
// movement instead. A file that is only appended to either sat still or grew, and growth carries the
// change time forward with it. Everything else is rewrite evidence: a shrink (a truncate, or a
// shorter session copied over the inode), a change at unchanged length (an in-place overwrite), a
// ctime that ran backwards (a restore over the same inode), or a change of owner (which also retires
// the peek's uid corroboration). A rewritten file's recorded cwd is no longer the one the verdict
// was read from, so the entry goes and the next peek decides it again.
//
// Growth at an unchanged ctime is treated as an append: ctime granularity is coarse enough that two
// observations of a busy transcript can share one, and refusing it would evict exactly the files the
// cache is for while catching no rewrite the size test does not already see.
func corroborates(state MembershipState, snap, st TranscriptStat) bool {
	if state == MembershipNonMember {
		return snap.Size == st.Size && snap.CtimeNanos == st.CtimeNanos
	}
	if snap.UID != st.UID {
		return false
	}
	if st.Size == snap.Size {
		return st.CtimeNanos == snap.CtimeNanos
	}
	return st.Size > snap.Size && st.CtimeNanos >= snap.CtimeNanos
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
