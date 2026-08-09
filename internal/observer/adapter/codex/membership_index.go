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
// live stat no longer corroborates the verdict. A positive verdict on a file that has GROWN is
// consistent with either an append or a foreign session copied over the inode that ended up larger;
// head — invoked only in that one case — re-reads the bounded leading window the verdict was
// fingerprinted over so the two can be told apart. An append leaves that window unchanged and the
// verdict is kept; a foreign replacement changes it and the entry is dropped. Every other corroborated
// verdict, of either sign, is decided on {size, ctime} alone with no content read. Dropping an entry
// never substitutes a verdict: it only costs the caller a fresh bounded peek, which re-decides the
// file the identity now is.
//
// head may be nil; then a grown positive verdict is neither confirmed nor refused but simply re-peeked,
// so a caller that supplies no head reader never trusts growth it cannot corroborate. A non-nil error
// is transient (the head read raced a vanish or rotation): the entry is left in place and the caller
// skips the file this poll, exactly as it treats a failed peek.
func (ix *MembershipIndex) Lookup(dev, ino uint64, path string, st TranscriptStat, head HeadHasher) (Membership, bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	id := transcriptIdentity{dev: dev, ino: ino}
	e, ok := ix.entries[id]
	if !ok {
		return Membership{}, false, nil
	}
	if e.path != path {
		ix.dropLocked(id, e)
		return Membership{}, false, nil
	}
	switch corroborate(e.verdict.State, e.stat, st, e.verdict.Head.present()) {
	case corrEvict:
		ix.dropLocked(id, e)
		return Membership{}, false, nil
	case corrCheckHead:
		if head == nil {
			// No head reader this poll: do not trust the growth, but do not destroy a verdict that may
			// still be valid — a bounded re-peek re-decides it.
			return Membership{}, false, nil
		}
		liveHash, err := head(e.verdict.Head.Len)
		if err != nil {
			// Transient: the head read raced a vanish or rotation. Keep the entry; the caller skips the
			// file and re-decides on the next poll.
			return Membership{}, false, err
		}
		if liveHash != e.verdict.Head.Hash {
			// The leading bytes are a different session's: a foreign replacement, not an append.
			ix.dropLocked(id, e)
			return Membership{}, false, nil
		}
	}
	if e.stat != st {
		e.stat = st
		ix.entries[id] = e
	}
	return e.verdict, true, nil
}

// corroboration is what the live stat says about a cached verdict on the next poll.
type corroboration int

const (
	// corrEvict: the stat is rewrite evidence; the entry is dropped and the file re-peeked.
	corrEvict corroboration = iota
	// corrHold: the stat corroborates the verdict with no content read needed.
	corrHold
	// corrCheckHead: a positive verdict on a file that grew — consistent with an append, but a foreign
	// session copied over the inode that ended up larger looks the same to {size, ctime}. The head
	// fingerprint is what decides it, so the caller must re-read the leading window.
	corrCheckHead
)

// corroborate reports what the live stat st says about a verdict reached under snap. hasHead is
// whether the verdict carries a head fingerprint to fall back on when the file has grown.
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
// Growth alone, though, cannot tell an append from a foreign session copied over the inode that
// happens to end up larger: both only grow the file and only move ctime forward. That is the one case
// {size, ctime} leaves open, and it is closed by re-checking the head fingerprint (corrCheckHead). A
// verdict that carries no head fingerprint (hasHead false) falls back to accepting the growth, the
// same way the seal side inherits a floor it never fingerprinted — an anchor never taken can neither
// confirm nor refute the growth.
//
// Growth at an unchanged ctime is treated as growth, not a rewrite: ctime granularity is coarse
// enough that two observations of a busy transcript can share one, and the head check (or its
// fallback) governs it either way.
func corroborate(state MembershipState, snap, st TranscriptStat, hasHead bool) corroboration {
	if state == MembershipNonMember {
		if snap.Size == st.Size && snap.CtimeNanos == st.CtimeNanos {
			return corrHold
		}
		return corrEvict
	}
	if snap.UID != st.UID {
		return corrEvict
	}
	if st.Size == snap.Size {
		if st.CtimeNanos == snap.CtimeNanos {
			return corrHold
		}
		return corrEvict
	}
	if st.Size < snap.Size || st.CtimeNanos < snap.CtimeNanos {
		return corrEvict
	}
	if !hasHead {
		return corrHold
	}
	return corrCheckHead
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
