//go:build unix

package codex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// Project-folder membership (design v2.1 section B) decides which transcripts in a provider STORE
// (the Claude projects dir, the Codex sessions dir) belong to a consented kind=project root. The
// store holds every session on the machine, so consent to capture one project must not be consent
// to capture the rest: each transcript is admitted only after its own recorded session cwd is shown
// to lie inside an active project root, and only after that self-declaration is corroborated by
// evidence the transcript itself cannot forge.
//
// This is unrelated to the run-attachment "membership evidence" the hook stamps on a RunContext;
// that answers "which run does this session belong to", this answers "may we read this file at all".

// MembershipState is the three-state verdict of A3. The third state is what makes the peek safe on
// a live file: a session that has not yet written a cwd-bearing record is not evidence of
// non-membership, it is evidence of nothing yet.
type MembershipState int

const (
	// MembershipUndetermined means no cwd record has been seen and the peek cap is not exhausted:
	// the transcript is still being written and the caller re-peeks on a later poll. It is never
	// cached — a re-peek reads at most the bounded head again.
	MembershipUndetermined MembershipState = iota
	// MembershipMember means the recorded cwd lies inside exactly one active project root and every
	// corroboration passed.
	MembershipMember
	// MembershipNonMember means the transcript is provably not this consent's to capture: the peek
	// cap was genuinely exhausted without a cwd, the cwd fell outside every active project root, or
	// a corroboration failed. Reason names which.
	MembershipNonMember
)

func (s MembershipState) String() string {
	switch s {
	case MembershipMember:
		return "member"
	case MembershipNonMember:
		return "non-member"
	default:
		return "undetermined"
	}
}

// NonMemberReason is the machine-readable cause of a negative verdict. Every corroboration failure
// gets its own value so status/doctor output can tell a foreign-uid file (a shared-machine
// misconfiguration) from a cwd that disagrees with its own store directory (a forged or rewritten
// transcript) from the ordinary case of a session belonging to some other project.
type NonMemberReason string

const (
	// ReasonNone is the zero value, carried by every non-negative verdict.
	ReasonNone NonMemberReason = ""
	// ReasonForeignUID: the peeked file's fstat uid is not the daemon's euid (A9a).
	ReasonForeignUID NonMemberReason = "foreign-uid"
	// ReasonPeekCapExhausted: the bounded head peek ran out of budget with no cwd record.
	ReasonPeekCapExhausted NonMemberReason = "peek-cap-exhausted"
	// ReasonCWDNotAbsolute: the transcript recorded a cwd that is not an absolute path.
	ReasonCWDNotAbsolute NonMemberReason = "cwd-not-absolute"
	// ReasonStoreDirMismatch: the munged store subdirectory does not encode the recorded cwd (A9b).
	ReasonStoreDirMismatch NonMemberReason = "store-dir-mismatch"
	// ReasonOutsideProjectRoots: the cwd is well-formed and corroborated but lies inside no active
	// project root. This is the common, expected negative — most sessions in a store are other work.
	ReasonOutsideProjectRoots NonMemberReason = "cwd-outside-project-roots"
)

// Membership is one transcript's verdict.
type Membership struct {
	State MembershipState
	// ProjectRootID is the matched active project root's stable id (the same sha256-derived id the
	// per-root state layout is keyed by). Set only when State is MembershipMember.
	ProjectRootID string
	// Reason is the machine-readable cause of a negative verdict. Set only when State is
	// MembershipNonMember.
	Reason NonMemberReason
	// Head is the content anchor a positive verdict carries: a bounded fingerprint of the transcript's
	// leading bytes, taken at verdict time. {size, ctime} alone cannot tell an append from a foreign
	// session copied over the inode that merely ends up larger — both only grow the file and move
	// ctime forward — so the corroboration path re-reads this leading window when a cached member has
	// grown and refuses the verdict if the bytes are a different session's. Set only when State is
	// MembershipMember; a negative verdict is anchored rigidly to its {size, ctime} and needs no
	// content anchor. This parallels the seal-side floor fingerprint (root_policy.go), which
	// corroborates a forward-only floor by the bytes ending at it; here the anchored boundary is the
	// file's head rather than a floor.
	Head HeadFingerprint
}

// HeadFingerprint is a bounded hash of a transcript's leading bytes together with how many bytes it
// covers. A zero Len means no head anchor was recorded, in which case a grown member falls back to
// the stat-only append acceptance (an anchor never taken can neither confirm nor refute the growth,
// the same stance the seal side takes for a floor it never fingerprinted).
type HeadFingerprint struct {
	// Hash is the FNV-1a hash of the first Len bytes — hashBytes, the same function the seal-floor
	// fingerprint and the cursor anchor use.
	Hash uint64
	// Len is how many leading bytes Hash covers: min(bytes read at verdict time, membershipHeadLen).
	// It is what the corroboration path re-reads, so a short member fingerprinted over fewer than
	// membershipHeadLen bytes is compared over exactly those bytes.
	Len int
}

func (h HeadFingerprint) present() bool { return h.Len > 0 }

// TranscriptStat is the cheap stat evidence a cached verdict is anchored to: the owner uid the uid
// corroboration compares, and the {size, ctime} pair the index re-corroborates every verdict — of
// either sign — against. ctime rather than mtime because ctime cannot be back-dated by utimes, so a
// rewritten file cannot keep a stale verdict alive.
type TranscriptStat struct {
	Size       int64
	CtimeNanos int64
	UID        uint32
}

const (
	// maxPeekParseFailures is how many CONSECUTIVE unparseable records the peek tolerates before it
	// calls the budget exhausted. It exists only to stop a file that is not JSONL at all — a binary
	// blob, a log, a half-written garbage file — from being scanned to the full byte budget on the
	// chance a cwd record turns up in it. It deliberately does not count parsed cwd-less records:
	// bookkeeping records such as {"type":"queue-operation"} are how real transcripts open, and a
	// count over them would hand a permanent cached non-member to exactly the long-preamble sessions
	// the byte budget below was raised to admit. A run broken by one parseable record starts over.
	maxPeekParseFailures = 32
	// maxPeekBytes bounds the head read of a single peek, and with it the peek's memory: the buffer
	// is min(file size, this), and a head that is one pathologically long unterminated line can
	// never buffer more. It is deliberately the watcher's own DefaultMaxReadChunk, so deciding a
	// file costs no more in one pass than tailing it does.
	//
	// The original 256KB was set from short transcripts and refused real sessions: measurement over
	// a 574-transcript store found first cwd records at byte offsets up to ~850KB, 1.7% of sessions
	// past 256KB — a long pasted opening prompt or a burst of cwd-less bookkeeping precedes them.
	maxPeekBytes int64 = DefaultMaxReadChunk
	// membershipHeadLen bounds the leading-byte window a positive verdict is fingerprinted over, and
	// with it the single bounded pread the corroboration path spends to confirm a grown member is an
	// append rather than a foreign replacement. It is larger than the 64-byte seal-floor / cursor-
	// anchor windows on purpose: those sit at a distinctive mid-file offset, whereas a transcript's
	// first bytes are often shared opening bookkeeping, so the head window must span enough leading
	// records to reach the session-identifying content (the first cwd / session_meta record) that
	// tells one session from another. It stays far below maxPeekBytes, so an append never re-reads
	// more than this to corroborate.
	membershipHeadLen = 512
)

// MembershipPeeker answers the membership question for transcripts discovered beneath the recorded
// provider stores. It is built once per policy load and holds no per-file state; the caller caches
// decided verdicts in a MembershipIndex.
type MembershipPeeker struct {
	projects []projectRoot
	stores   []string
	// euid is the identity every peeked file must be owned by (A9a). It is a field rather than a
	// call to os.Geteuid per peek so the corroboration is fixed for the daemon's lifetime.
	euid uint32
	// maxParseFailures / maxBytes are the peek caps, fields so tests can exercise exhaustion cheaply.
	maxParseFailures int
	maxBytes         int64
}

// projectRoot is one active kind=project consent root. Path arrives canonical from
// rootpolicy.LoadPolicy (absolute, lexically clean, symlinks already resolved).
type projectRoot struct {
	id   string
	path string
}

// NewMembershipPeeker builds the peek engine from a parsed policy, keeping the active kind=project
// roots and the recorded stores. Tombstones and kind=transcripts roots are excluded: a transcript
// root is tailed directly and never selected by membership.
func NewMembershipPeeker(policy rootpolicy.Policy) *MembershipPeeker {
	p := &MembershipPeeker{
		stores:           append([]string(nil), policy.Stores...),
		euid:             uint32(os.Geteuid()),
		maxParseFailures: maxPeekParseFailures,
		maxBytes:         maxPeekBytes,
	}
	for _, r := range policy.Roots {
		if r.Active && r.IsProject() {
			p.projects = append(p.projects, projectRoot{id: rootPolicyID(r.Path), path: r.Path})
		}
	}
	return p
}

// Peek reads the bounded head of one store transcript and returns its verdict together with the
// stat the verdict was reached under. store must be one of the recorded stores and locator is the
// file's path relative to it; the file is opened through the same anchored, no-symlink, identity-
// validated open the tail reader uses, so nothing between discovery and read can redirect it.
//
// An error means "could not decide right now" — the file vanished, rotated to a new inode, went
// non-regular, or the read failed — never a verdict. Callers treat it exactly like the watcher's
// other mid-poll races: skip the file and re-peek on the next poll.
func (p *MembershipPeeker) Peek(store, locator string, dev, ino uint64) (Membership, TranscriptStat, error) {
	if !p.recordedStore(store) {
		return Membership{}, TranscriptStat{}, fmt.Errorf("codex membership: %q is not a recorded store", store)
	}
	f, _, _, err := openValidatedTranscript(store, locator, dev, ino)
	if err != nil {
		return Membership{}, TranscriptStat{}, err
	}
	defer f.Close()
	st, err := transcriptStatOf(f)
	if err != nil {
		return Membership{}, TranscriptStat{}, err
	}
	// The uid corroboration runs before a single content byte is read: a file this daemon does not
	// own is refused on its ownership alone, whatever it claims about itself.
	if st.UID != p.euid {
		return Membership{State: MembershipNonMember, Reason: ReasonForeignUID}, st, nil
	}

	budget := p.maxBytes
	if st.Size < budget {
		budget = st.Size
	}
	head := make([]byte, budget)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return Membership{}, TranscriptStat{}, err
	}
	// The head fingerprint is taken once, over the bytes just read, and attached to a positive verdict
	// so a later poll can tell an append from a foreign session copied over this inode. It costs
	// nothing here — the bytes are already in hand.
	hf := headFingerprintOf(head[:n])

	// How far the scan reaches is the byte budget's business: a record that parsed but carried no
	// cwd is ordinary transcript bookkeeping, and however many of them precede the cwd record they
	// are not evidence of anything. Only a run of records that do not parse at all suggests this is
	// not a transcript, and that run is what the failure cap bounds.
	failures := 0
	for _, line := range splitJSONLines(head[:n]) {
		cwd, found, parsed := peekCWD(line)
		if found {
			return withHead(p.classify(cwd, locator), hf), st, nil
		}
		if parsed {
			failures = 0
			continue
		}
		// A torn write or a record shape this peek does not know spends budget but never aborts the
		// peek; only an unbroken run of them does.
		failures++
		if failures >= p.maxParseFailures {
			return Membership{State: MembershipNonMember, Reason: ReasonPeekCapExhausted}, st, nil
		}
	}
	// splitJSONLines drops a trailing unterminated line, so a cwd record still being written is
	// simply not seen yet. Only a genuinely spent budget is negative evidence.
	if int64(n) >= p.maxBytes {
		return Membership{State: MembershipNonMember, Reason: ReasonPeekCapExhausted}, st, nil
	}
	// A small file that never records a cwd at all — a stub opened and abandoned before the first
	// envelope — stays undetermined for good: it is under both caps, so no later peek can turn it
	// negative, and an undetermined verdict is deliberately never cached. It is therefore re-read
	// (at most its own small length) on every poll. That is intentional: silence is not evidence of
	// non-membership, and the re-peek cadence is what the store-scale tiering of A11 bounds — old
	// files drop to the slow stat-only tier and stop being re-peeked every poll.
	return Membership{State: MembershipUndetermined}, st, nil
}

// classify turns a recorded cwd into a verdict: it corroborates the claim against the store
// directory that encodes it, then matches it against the active project roots.
//
// SYMLINK STANCE — the recorded cwd is only lexically cleaned, never EvalSymlinks'd. It is a string
// a past process wrote; the directory may since have been deleted or replaced (a torn-down worktree
// is the normal case), so a resolve would fail on exactly the transcripts that most need a verdict,
// and resolving a path whose components are writable by the session under audit would be a TOCTOU.
// Project roots are canonical (resolved) at policy load, so the comparison is canonical-to-lexical:
// a session whose cwd reached the project through a symlink is not a member. That is the
// conservative direction — it under-captures, never over-captures.
func (p *MembershipPeeker) classify(cwd, locator string) Membership {
	clean := filepath.Clean(cwd)
	if !filepath.IsAbs(clean) {
		return Membership{State: MembershipNonMember, Reason: ReasonCWDNotAbsolute}
	}
	// A9b: in the claude-projects layout the store itself encodes a cwd in the directory name, so
	// the transcript's self-declaration has an independent witness. The munge is taken over the cwd
	// exactly as recorded, because that is the string Claude Code encoded.
	if dir, ok := claudeStoreSubdir(locator); ok && !dirWitnessesCWD(dir, cwd) {
		return Membership{State: MembershipNonMember, Reason: ReasonStoreDirMismatch}
	}
	// A19 keeps active roots mutually non-overlapping, so at most one can match.
	for _, root := range p.projects {
		if pathContains(root.path, clean) {
			return Membership{State: MembershipMember, ProjectRootID: root.id}
		}
	}
	return Membership{State: MembershipNonMember, Reason: ReasonOutsideProjectRoots}
}

// peekCWD returns the session cwd of one transcript record, for either dialect, together with
// whether the line was a JSON record at all. Claude writes the cwd as a top-level "cwd" on its
// per-message envelopes; Codex writes it once, on the session_meta record, at payload.cwd. cwd is
// read as a raw message so a record whose cwd is not a string is a cwd-less record rather than an
// unparseable line — parsed is what separates ordinary bookkeeping from garbage, and only garbage
// is rationed.
func peekCWD(line []byte) (cwd string, found, parsed bool) {
	var probe struct {
		Type    string          `json:"type"`
		CWD     json.RawMessage `json:"cwd"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(line, &probe) != nil {
		return "", false, false
	}
	if top, ok := decodeCWD(probe.CWD); ok {
		return top, true, true
	}
	if probe.Type == rolloutSessionMeta && len(probe.Payload) > 0 {
		var meta struct {
			CWD json.RawMessage `json:"cwd"`
		}
		if json.Unmarshal(probe.Payload, &meta) == nil {
			nested, ok := decodeCWD(meta.CWD)
			return nested, ok, true
		}
	}
	return "", false, true
}

func decodeCWD(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var cwd string
	if json.Unmarshal(raw, &cwd) != nil || cwd == "" {
		return "", false
	}
	return cwd, true
}

// dirWitnessesCWD reports whether a claude-projects store subdirectory name corroborates the cwd a
// transcript recorded. Claude names that directory from the session LAUNCH directory, while the
// first recorded cwd is whatever directory the session was working in — for an in-repo worktree
// (<proj>/.claude/worktrees/x) that is a strictly deeper path. Requiring equality therefore refused
// genuine members (5.7% of a real 574-transcript store), so a munged ANCESTOR is accepted too: the
// name must equal the munged cwd or be a '-'-separated prefix of it.
//
// The comparison is on munged strings and so is lossy — a directory named for a sibling
// (<proj>-other) also clears the prefix test. That slack is deliberate. The witness only has to
// refuse a transcript claiming a cwd unrelated to the directory it was filed under; which root a
// member actually belongs to is decided by classify's component-wise containment check on the
// recorded path itself, which no amount of munging can loosen.
func dirWitnessesCWD(dirname, cwd string) bool {
	munged := mungeClaudeProjectDir(cwd)
	return munged == dirname || strings.HasPrefix(munged, dirname+"-")
}

// mungeClaudeProjectDir encodes a session cwd the way Claude Code names the per-project directory
// it stores that session's transcript in: every byte outside [a-zA-Z0-9-] becomes '-'. The rule is
// length-preserving and operates on BYTES, so a non-ASCII path component expands to one '-' per
// byte, exactly as Claude's encoder does.
//
//	/data/projects/infra/.claude/worktrees/docs -> -data-projects-infra--claude-worktrees-docs
func mungeClaudeProjectDir(cwd string) string {
	b := []byte(cwd)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			b[i] = '-'
		}
	}
	return string(b)
}

// claudeStoreSubdir returns the store subdirectory a transcript sits DIRECTLY under, and whether
// the munged-dir corroboration applies at all. Exactly two locator components
// (<munged-cwd>/<session>.jsonl) is the claude-projects layout. The Codex sessions store shards by
// date (YYYY/MM/DD/rollout-*.jsonl) and so is three levels deep — it never carries a cwd-derived
// directory name and is corroborated by content plus uid alone. A file directly in the store root,
// or nested deeper than one subdirectory, likewise gets no directory witness.
func claudeStoreSubdir(locator string) (string, bool) {
	dir, _ := filepath.Split(filepath.Clean(locator))
	dir = filepath.Clean(dir)
	if dir == "." || dir == string(filepath.Separator) || strings.ContainsRune(dir, filepath.Separator) {
		return "", false
	}
	return dir, true
}

func (p *MembershipPeeker) recordedStore(store string) bool {
	for _, s := range p.stores {
		if s == store {
			return true
		}
	}
	return false
}

// transcriptStatOf reads the corroboration fields from the already-open descriptor the peek reads
// content from, so the uid checked and the {size, ctime} recorded are the ones the bytes came from
// and not a second, re-resolvable path lookup.
func transcriptStatOf(f *os.File) (TranscriptStat, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return TranscriptStat{}, err
	}
	return TranscriptStat{Size: st.Size, CtimeNanos: st.Ctim.Nano(), UID: st.Uid}, nil
}

// StatTranscript reads the same corroboration fields for a path the caller has not opened, for the
// walk-side MembershipIndex lookup that decides whether a cached verdict still holds. It does not
// follow a symlink; discovery has already refused symlinked transcripts. It stays a bare lstat — no
// content read — so the common case (an idle or absent file) never touches a byte; the head anchor is
// re-read lazily, only when a cached member has actually grown (see MembershipIndex.Lookup).
func StatTranscript(path string) (TranscriptStat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return TranscriptStat{}, err
	}
	return TranscriptStat{Size: st.Size, CtimeNanos: st.Ctim.Nano(), UID: st.Uid}, nil
}

// headFingerprintOf fingerprints up to membershipHeadLen leading bytes of a head already read into
// memory, for the peek that has the bytes in hand. A short transcript is fingerprinted whole; the
// recorded Len is exactly what the corroboration path later re-reads and re-hashes.
func headFingerprintOf(head []byte) HeadFingerprint {
	n := len(head)
	if n > membershipHeadLen {
		n = membershipHeadLen
	}
	if n <= 0 {
		return HeadFingerprint{}
	}
	return HeadFingerprint{Hash: hashBytes(head[:n]), Len: n}
}

// withHead attaches the head fingerprint to a positive verdict. A negative verdict is anchored to its
// {size, ctime} alone — nothing legitimate rewrites a non-member in place and expects to stay one —
// so it carries no content fingerprint.
func withHead(m Membership, hf HeadFingerprint) Membership {
	if m.State == MembershipMember {
		m.Head = hf
	}
	return m
}

// HeadHasher re-reads the leading n bytes of the file behind a positive verdict and returns their
// FNV-1a hash, so a grown member can be confirmed as an append (head unchanged) rather than refused
// as a foreign replacement. n is the byte length the verdict's HeadFingerprint was recorded over. The
// MembershipIndex invokes it only when a cached member's file has grown past its last observed length,
// so an append pays exactly this one bounded read and never a full re-peek.
type HeadHasher func(n int) (uint64, error)

// OpenTranscriptHeadHasher builds a HeadHasher over the identity-validated transcript at
// store/locator, opened through the same anchored, no-symlink, identity-checked path the peek uses,
// so the live head hash is computed over exactly the bytes the peek fingerprinted. An error (the file
// vanished, rotated to a new inode, or shrank below the recorded window) is returned to the index,
// which treats it as a transient miss the same way it treats a failed peek: skip the file and
// re-decide on the next poll.
func OpenTranscriptHeadHasher(store, locator string, dev, ino uint64) HeadHasher {
	return func(n int) (uint64, error) {
		f, _, _, err := openValidatedTranscript(store, locator, dev, ino)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return readHeadHash(f, n)
	}
}

// readHeadHash reads exactly n leading bytes from an open transcript and hashes them with the same
// FNV-1a the fingerprint was taken with. It reports io.ErrUnexpectedEOF when the file no longer holds
// that many bytes (a shrink or rotation caught mid-poll), which the caller treats as a window it
// cannot corroborate against rather than as a match.
func readHeadHash(f *os.File, n int) (uint64, error) {
	if n <= 0 {
		return 0, nil
	}
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if got < n {
		return 0, io.ErrUnexpectedEOF
	}
	return hashBytes(buf), nil
}
