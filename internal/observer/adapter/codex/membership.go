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
}

// TranscriptStat is the cheap stat evidence a verdict is anchored to: the owner uid the uid
// corroboration compares, and the {size, ctime} pair a negative entry is invalidated by. ctime
// rather than mtime because ctime cannot be back-dated by utimes, so a rewritten file cannot keep
// a stale negative verdict alive.
type TranscriptStat struct {
	Size       int64
	CtimeNanos int64
	UID        uint32
}

const (
	// maxPeekCWDLines is how many parsed cwd-less records the peek tolerates before it calls the
	// budget exhausted. A real transcript of either dialect records its cwd within the first few
	// lines (Claude opens with cwd-less bookkeeping records such as {"type":"queue-operation"});
	// 32 is generous headroom over every transcript observed in the wild.
	maxPeekCWDLines = 32
	// maxPeekBytes bounds the head read of a single peek, and with it the peek's memory: the buffer
	// is min(file size, this), and a head that is one pathologically long unterminated line can
	// never buffer more. It is deliberately the watcher's own DefaultMaxReadChunk, so deciding a
	// file costs no more in one pass than tailing it does.
	//
	// The original 256KB was set from short transcripts and refused real sessions: measurement over
	// a 574-transcript store found first cwd records at byte offsets up to ~850KB, 1.7% of sessions
	// past 256KB — a long pasted opening prompt or a burst of cwd-less bookkeeping precedes them.
	maxPeekBytes int64 = DefaultMaxReadChunk
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
	// maxLines / maxBytes are the peek caps, fields so tests can exercise exhaustion cheaply.
	maxLines int
	maxBytes int64
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
		stores:   append([]string(nil), policy.Stores...),
		euid:     uint32(os.Geteuid()),
		maxLines: maxPeekCWDLines,
		maxBytes: maxPeekBytes,
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

	lines := 0
	for _, line := range splitJSONLines(head[:n]) {
		if lines >= p.maxLines {
			break
		}
		if cwd, ok := peekCWD(line); ok {
			return p.classify(cwd, locator), st, nil
		}
		// An unparseable line is a cwd-less line: a torn write or a record shape this peek does not
		// know spends budget, but it never aborts the peek.
		lines++
	}
	// splitJSONLines drops a trailing unterminated line, so a cwd record still being written is
	// simply not seen yet. Only a genuinely spent budget is negative evidence.
	if lines >= p.maxLines || int64(n) >= p.maxBytes {
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

// peekCWD returns the session cwd of one transcript record, for either dialect. Claude writes it as
// a top-level "cwd" on its per-message envelopes; Codex writes it once, on the session_meta record,
// at payload.cwd. cwd is read as a raw message so a record whose cwd is not a string is a cwd-less
// record rather than an unparseable line.
func peekCWD(line []byte) (string, bool) {
	var probe struct {
		Type    string          `json:"type"`
		CWD     json.RawMessage `json:"cwd"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(line, &probe) != nil {
		return "", false
	}
	if cwd, ok := decodeCWD(probe.CWD); ok {
		return cwd, true
	}
	if probe.Type == rolloutSessionMeta && len(probe.Payload) > 0 {
		var meta struct {
			CWD json.RawMessage `json:"cwd"`
		}
		if json.Unmarshal(probe.Payload, &meta) == nil {
			return decodeCWD(meta.CWD)
		}
	}
	return "", false
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
// follow a symlink; discovery has already refused symlinked transcripts.
func StatTranscript(path string) (TranscriptStat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return TranscriptStat{}, err
	}
	return TranscriptStat{Size: st.Size, CtimeNanos: st.Ctim.Nano(), UID: st.Uid}, nil
}
