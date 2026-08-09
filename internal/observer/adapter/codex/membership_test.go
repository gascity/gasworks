//go:build unix

package codex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

const (
	queueLine  = `{"type":"queue-operation","operation":"add"}`
	brokenLine = `{"type":"user","cwd":`
)

func claudeCWDLine(cwd string) string {
	return `{"type":"user","sessionId":"s-1","cwd":"` + cwd + `"}`
}

func codexMetaLine(cwd string) string {
	return `{"type":"session_meta","payload":{"id":"019c-0001","cwd":"` + cwd + `"}}`
}

// fillerLine is one cwd-less record of roughly n bytes, for pushing a cwd record out to a byte
// offset without spending the peek's much smaller line budget.
func fillerLine(n int) string {
	return `{"type":"queue-operation","pad":"` + strings.Repeat("a", n) + `"}`
}

// writeStraddlingTranscript writes a byte-cap fixture and returns its size, having checked that the
// fixture leaves the garbage cap slack — otherwise a peek-cap-exhausted verdict would prove nothing
// about the byte budget under test.
func writeStraddlingTranscript(t *testing.T, store, locator string, lines []string) int64 {
	t.Helper()
	if run := longestParseFailureRun(lines); run >= maxPeekParseFailures {
		t.Fatalf("fixture has a %d-record unparseable run, at or over the %d-failure cap", run, maxPeekParseFailures)
	}
	info, err := os.Stat(writeTranscript(t, store, locator, lines...))
	if err != nil {
		t.Fatalf("stat %s: %v", locator, err)
	}
	return info.Size()
}

// longestParseFailureRun is the longest run of consecutive unparseable records in a fixture, which
// is the only thing the peek still caps by record count.
func longestParseFailureRun(lines []string) int {
	worst, run := 0, 0
	for _, l := range lines {
		if _, _, parsed := peekCWD([]byte(l)); parsed {
			run = 0
			continue
		}
		run++
		if run > worst {
			worst = run
		}
	}
	return worst
}

func mustStat(t *testing.T, path string) TranscriptStat {
	t.Helper()
	st, err := StatTranscript(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st
}

func peekerFor(t *testing.T, store string, projects ...string) *MembershipPeeker {
	t.Helper()
	policy := rootpolicy.Policy{Stores: []string{store}}
	for _, p := range projects {
		policy.Roots = append(policy.Roots, rootpolicy.Record{
			Path: p, Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly, Kind: rootpolicy.Project,
		})
	}
	return NewMembershipPeeker(policy)
}

// writeTranscript writes lines (one per line, newline-terminated) at store/locator, creating the
// intermediate store subdirectories.
func writeTranscript(t *testing.T, store, locator string, lines ...string) string {
	t.Helper()
	path := filepath.Join(store, locator)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	writeFileString(t, path, body)
	return path
}

func mustPeek(t *testing.T, p *MembershipPeeker, store, locator string) (Membership, TranscriptStat) {
	t.Helper()
	dev, ino := identityOf(t, filepath.Join(store, locator))
	m, st, err := p.Peek(store, locator, dev, ino)
	if err != nil {
		t.Fatalf("peek %s: %v", locator, err)
	}
	return m, st
}

func wantVerdict(t *testing.T, got Membership, state MembershipState, id string, reason NonMemberReason) {
	t.Helper()
	if got.State != state || got.ProjectRootID != id || got.Reason != reason {
		t.Fatalf("verdict = {%s %q %q}, want {%s %q %q}", got.State, got.ProjectRootID, got.Reason, state, id, reason)
	}
}

func TestMungeClaudeProjectDirMatchesRealStoreNames(t *testing.T) {
	cases := []struct{ cwd, want string }{
		{"/data/projects/infra/.claude/worktrees/docs", "-data-projects-infra--claude-worktrees-docs"},
		{"/var/tmp/s17-review-pr.Lhoohy/worktree", "-var-tmp-s17-review-pr-Lhoohy-worktree"},
		{"/home/u/my_project", "-home-u-my-project"},
		{"/", "-"},
	}
	for _, tc := range cases {
		got := mungeClaudeProjectDir(tc.cwd)
		if got != tc.want {
			t.Fatalf("munge(%q) = %q, want %q", tc.cwd, got, tc.want)
		}
		if len(got) != len(tc.cwd) {
			t.Fatalf("munge(%q) length = %d, want %d (the encoding is length-preserving)", tc.cwd, len(got), len(tc.cwd))
		}
	}
}

// The peek races the writer: Claude opens a transcript with cwd-less bookkeeping records, so an
// empty verdict at that moment must be undetermined (re-peeked later), never negative.
func TestPeekIsUndeterminedUntilACWDRecordIsWritten(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	path := writeTranscript(t, store, locator, queueLine, queueLine)
	p := peekerFor(t, store, project)

	m, _ := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipUndetermined, "", ReasonNone)

	appendString(t, path, claudeCWDLine(project)+"\n")
	m, _ = mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

// A cwd record still being written has no trailing newline, so it is not a record yet.
func TestPeekIgnoresAnUnterminatedTrailingLine(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	writeTranscript(t, store, locator, queueLine)
	appendString(t, filepath.Join(store, locator), claudeCWDLine(project)[:20])

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipUndetermined, "", ReasonNone)
}

// The head scan is governed by the byte budget alone, never by a count of parsed cwd-less records:
// a genuine member session that opens with a long run of bookkeeping records is precisely the
// session the 4MiB budget was raised for, so a record count that pre-empted it would cache a
// permanent misclassification of the sessions the amendment was written to admit.
func TestPeekByteBudgetGovernsRunsOfCWDLessRecords(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")

	const cwdLess = 40
	if cwdLess <= maxPeekParseFailures {
		t.Fatalf("fixture spends %d cwd-less records, want more than the %d-failure garbage cap",
			cwdLess, maxPeekParseFailures)
	}
	lines := make([]string, 0, cwdLess+1)
	for i := 0; i < cwdLess; i++ {
		lines = append(lines, queueLine)
	}
	lines = append(lines, claudeCWDLine(project))
	writeTranscript(t, store, locator, lines...)

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

// What stays bounded by a record count is unparseable garbage: a file that is not JSONL at all must
// not be scanned to the full byte budget on the chance a cwd record appears in it. The bound counts
// CONSECUTIVE failures, so a run broken by a real (if cwd-less) record starts over.
func TestPeekParseFailureCapExhaustionIsNonMember(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	dir := mungeClaudeProjectDir(project)
	p := peekerFor(t, store, project)

	atCap := make([]string, maxPeekParseFailures)
	for i := range atCap {
		atCap[i] = "not json at all"
	}

	underCap := append(append([]string(nil), atCap[:maxPeekParseFailures-1]...), claudeCWDLine(project))
	writeTranscript(t, store, filepath.Join(dir, "under.jsonl"), underCap...)
	m, _ := mustPeek(t, p, store, filepath.Join(dir, "under.jsonl"))
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	overCap := append(append([]string(nil), atCap...), claudeCWDLine(project))
	writeTranscript(t, store, filepath.Join(dir, "over.jsonl"), overCap...)
	m, _ = mustPeek(t, p, store, filepath.Join(dir, "over.jsonl"))
	wantVerdict(t, m, MembershipNonMember, "", ReasonPeekCapExhausted)

	split := append(append([]string(nil), atCap[:maxPeekParseFailures-1]...), queueLine)
	split = append(split, atCap[:maxPeekParseFailures-1]...)
	split = append(split, claudeCWDLine(project))
	writeTranscript(t, store, filepath.Join(dir, "split.jsonl"), split...)
	m, _ = mustPeek(t, p, store, filepath.Join(dir, "split.jsonl"))
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

func TestPeekByteCapExhaustionIsNonMember(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	writeTranscript(t, store, locator, queueLine, queueLine, queueLine, claudeCWDLine(project))

	p := peekerFor(t, store, project)
	m, _ := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	// Same file, budget cut below the cwd record's offset: the peek is out of bytes, not out of file.
	p.maxBytes = int64(len(queueLine))
	m, _ = mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipNonMember, "", ReasonPeekCapExhausted)
}

// The peek's byte budget is the watcher's own read chunk, not the original 256KB: measurement over
// a real 574-transcript store found 1.7% of sessions writing their first cwd record past 256KB, at
// offsets up to ~850KB. These fixtures straddle the real bound with the record count held well
// under maxPeekCWDLines, so the byte budget is the only cap in play.
func TestPeekByteCapCoversRecordsFarPastTheOldBound(t *testing.T) {
	if maxPeekBytes != DefaultMaxReadChunk {
		t.Fatalf("maxPeekBytes = %d, want the watcher's DefaultMaxReadChunk %d", maxPeekBytes, DefaultMaxReadChunk)
	}
	store, project := t.TempDir(), t.TempDir()
	dir := mungeClaudeProjectDir(project)
	p := peekerFor(t, store, project)

	const filler = 800 << 10
	// Four fillers put the cwd record past 3MB — far beyond the old cap, inside the new one.
	deep := []string{fillerLine(filler), fillerLine(filler), fillerLine(filler), fillerLine(filler), claudeCWDLine(project)}
	size := writeStraddlingTranscript(t, store, filepath.Join(dir, "deep.jsonl"), deep)
	if size <= 256<<10 || size >= maxPeekBytes {
		t.Fatalf("fixture is %d bytes, want it past the old 256KB cap and inside the %d-byte budget", size, maxPeekBytes)
	}
	m, _ := mustPeek(t, p, store, filepath.Join(dir, "deep.jsonl"))
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	// Two more fillers push it past 4MiB: the budget is spent on complete records, which is the one
	// honest way to run out of bytes rather than out of lines.
	beyond := append(append([]string(nil), deep[:4]...), fillerLine(filler), fillerLine(filler), claudeCWDLine(project))
	size = writeStraddlingTranscript(t, store, filepath.Join(dir, "beyond.jsonl"), beyond)
	if size <= maxPeekBytes {
		t.Fatalf("fixture is %d bytes, want more than the %d-byte budget", size, maxPeekBytes)
	}
	m, _ = mustPeek(t, p, store, filepath.Join(dir, "beyond.jsonl"))
	wantVerdict(t, m, MembershipNonMember, "", ReasonPeekCapExhausted)
}

func TestPeekTreatsUnparseableLinesAsCWDLessWithoutAborting(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	writeTranscript(t, store, locator, "not json at all", brokenLine, `["array","not","object"]`,
		`{"type":"user","cwd":17}`, claudeCWDLine(project))

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

// The Codex sessions store shards by date, so its transcripts get no directory witness: content
// plus uid decide them.
func TestPeekCodexSessionMetaInDateShardedStore(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join("2026", "08", "09", "rollout-019c-0001.jsonl")
	writeTranscript(t, store, locator, codexMetaLine(project), `{"type":"turn_context","payload":{"model":"gpt-x"}}`)

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

func TestPeekCodexSessionMetaOutsideProjectsIsNonMember(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join("2026", "08", "09", "rollout-019c-0002.jsonl")
	writeTranscript(t, store, locator, codexMetaLine("/somewhere/else"))

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipNonMember, "", ReasonOutsideProjectRoots)
}

func TestPeekMungedDirMismatchIsNonMember(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project)+"-tampered", "session.jsonl")
	writeTranscript(t, store, locator, claudeCWDLine(project))

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipNonMember, "", ReasonStoreDirMismatch)
}

// Claude names the store subdirectory from the session LAUNCH directory while the first recorded
// cwd can be a deeper path (an in-repo worktree is the ordinary case), so the directory witness
// accepts a munged ancestor of the recorded cwd — A9b as amended by the 574-transcript field
// measurement, where strict equality refused 5.7% of genuine members. Unrelated directories, and
// prefixes that are not ancestors, still refuse.
func TestDirWitnessAcceptsAMungedAncestorOfTheRecordedCWD(t *testing.T) {
	const launch = "/data/projects/gascity"
	const worktree = launch + "/.claude/worktrees/docs"
	p := peekerFor(t, t.TempDir(), launch)

	cases := []struct {
		name    string
		dirname string
		cwd     string
		state   MembershipState
		id      string
		reason  NonMemberReason
	}{
		{"launch dir is a munged ancestor of the worktree cwd",
			"-data-projects-gascity", worktree, MembershipMember, rootPolicyID(launch), ReasonNone},
		{"exact equality still passes",
			"-data-projects-gascity", launch, MembershipMember, rootPolicyID(launch), ReasonNone},
		{"a worktree filed under its own munged name is exact too",
			mungeClaudeProjectDir(worktree), worktree, MembershipMember, rootPolicyID(launch), ReasonNone},
		{"an unrelated project's directory refuses",
			"-data-projects-other", worktree, MembershipNonMember, "", ReasonStoreDirMismatch},
		{"a prefix that is not a path boundary is not an ancestor",
			"-data-projects-gas", launch, MembershipNonMember, "", ReasonStoreDirMismatch},
		{"a descendant directory does not witness a shallower cwd",
			mungeClaudeProjectDir(worktree), launch, MembershipNonMember, "", ReasonStoreDirMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.classify(tc.cwd, filepath.Join(tc.dirname, "session.jsonl"))
			wantVerdict(t, got, tc.state, tc.id, tc.reason)
		})
	}
}

// The same amendment through the real peek: a transcript filed under its launch directory's munged
// name, recording the worktree the session actually ran in.
func TestPeekWorktreeSessionFiledUnderItsLaunchDir(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	worktree := filepath.Join(project, ".claude", "worktrees", "docs")
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	writeTranscript(t, store, locator, queueLine, claudeCWDLine(worktree))

	m, _ := mustPeek(t, peekerFor(t, store, project), store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	// That same recorded cwd, filed under some other project's directory, is still refused.
	foreign := filepath.Join(mungeClaudeProjectDir(t.TempDir()), "session.jsonl")
	writeTranscript(t, store, foreign, claudeCWDLine(worktree))
	m, _ = mustPeek(t, peekerFor(t, store, project), store, foreign)
	wantVerdict(t, m, MembershipNonMember, "", ReasonStoreDirMismatch)
}

// The munged-dir witness only exists for a file sitting DIRECTLY under a store subdirectory; a file
// nested deeper is corroborated by content plus uid alone.
func TestPeekNestedStoreSubdirSkipsDirCorroboration(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	nested := filepath.Join("not-a-munged-name", "deeper", "session.jsonl")
	writeTranscript(t, store, nested, claudeCWDLine(project))
	m, _ := mustPeek(t, peekerFor(t, store, project), store, nested)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	flat := "session.jsonl"
	writeTranscript(t, store, flat, claudeCWDLine(project))
	m, _ = mustPeek(t, peekerFor(t, store, project), store, flat)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
}

func TestPeekForeignUIDIsNonMemberBeforeAnyContentIsTrusted(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	writeTranscript(t, store, locator, claudeCWDLine(project))

	p := peekerFor(t, store, project)
	p.euid = ^uint32(0) // (uid_t)-1 owns no file
	m, st := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipNonMember, "", ReasonForeignUID)
	if st.UID != uint32(os.Geteuid()) {
		t.Fatalf("peeked uid = %d, want the test process euid %d", st.UID, os.Geteuid())
	}
}

func TestPeekRefusesAStoreThePolicyDidNotRecord(t *testing.T) {
	store, other, project := t.TempDir(), t.TempDir(), t.TempDir()
	locator := "session.jsonl"
	path := writeTranscript(t, other, locator, claudeCWDLine(project))
	dev, ino := identityOf(t, path)

	_, _, err := peekerFor(t, store, project).Peek(other, locator, dev, ino)
	if err == nil || !strings.Contains(err.Error(), "not a recorded store") {
		t.Fatalf("peek of an unrecorded store: err = %v, want a recorded-store refusal", err)
	}
}

func TestPeekReportsTheStatTheVerdictWasReachedUnder(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join(mungeClaudeProjectDir(project), "session.jsonl")
	line := claudeCWDLine(project) + "\n"
	writeTranscript(t, store, locator, strings.TrimSuffix(line, "\n"))

	_, st := mustPeek(t, peekerFor(t, store, project), store, locator)
	if st.Size != int64(len(line)) {
		t.Fatalf("stat size = %d, want %d", st.Size, len(line))
	}
	if st.CtimeNanos == 0 {
		t.Fatal("stat ctime = 0, want the file's change time")
	}
	walked, err := StatTranscript(filepath.Join(store, locator))
	if err != nil {
		t.Fatalf("StatTranscript: %v", err)
	}
	if walked != st {
		t.Fatalf("StatTranscript = %+v, want the peek's %+v", walked, st)
	}
}

// The peek and the index together, over a file that is rewritten in place. Copying another session
// over a transcript — or truncating and rewriting it — preserves both the inode and the path, so the
// cached member verdict has nothing left to stand on but the stat corroboration. Without it the
// index would keep answering "member" for content whose recorded cwd lies outside every registered
// root, and no re-peek would ever run.
func TestIndexedMemberIsRePeekedAfterAnInPlaceRewrite(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	// The date-sharded codex layout carries no directory witness, so the verdict turns purely on the
	// cwd the content records — exactly the evidence a rewrite replaces.
	locator := filepath.Join("2026", "08", "09", "rollout-019c-0003.jsonl")
	lines := []string{codexMetaLine(project)}
	for i := 0; i < 8; i++ {
		lines = append(lines, fillerLine(256))
	}
	path := writeTranscript(t, store, locator, lines...)
	p := peekerFor(t, store, project)
	ix := NewMembershipIndex()

	dev, ino := identityOf(t, path)
	m, st := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
	ix.Record(dev, ino, path, st, m)

	// Appending is the normal case: the cache must answer it without a re-peek.
	appendString(t, path, fillerLine(256)+"\n")
	if got := mustLookup(t, ix, dev, ino, path, mustStat(t, path)); got != m {
		t.Fatalf("verdict after an append = %+v, want the cached %+v", got, m)
	}

	// cp another session over the file: same inode, same path, a cwd in no registered root.
	foreign := t.TempDir()
	writeFileString(t, path, codexMetaLine(foreign)+"\n")
	if dev2, ino2 := identityOf(t, path); dev2 != dev || ino2 != ino {
		t.Fatalf("the rewrite moved the identity to (%d,%d), want the original (%d,%d) — "+
			"the fixture must exercise an in-place rewrite, not a replacement", dev2, ino2, dev, ino)
	}
	wantMiss(t, ix, dev, ino, path, mustStat(t, path))

	// The forced re-peek decides the file it is now, not the one it was.
	m2, st2 := mustPeek(t, p, store, locator)
	wantVerdict(t, m2, MembershipNonMember, "", ReasonOutsideProjectRoots)
	ix.Record(dev, ino, path, st2, m2)
	if got := mustLookup(t, ix, dev, ino, path, mustStat(t, path)); got != m2 {
		t.Fatalf("verdict after the re-peek = %+v, want the fresh non-member %+v", got, m2)
	}
}

// The residual the stat corroboration cannot close on its own: a foreign session copied over a
// member's inode that ends up STRICTLY LARGER with a forward change time is, to {size, ctime} alone,
// indistinguishable from an ordinary append — both only grow the file and only move ctime forward.
// Anchoring the positive verdict to a bounded head fingerprint is what refuses it: the replacement's
// leading bytes are a different session's, so the cached member verdict must be dropped and the file
// re-peeked rather than treated as an append onto the member.
func TestIndexedMemberIsRePeekedAfterALargerForeignReplacement(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	// The date-sharded codex layout carries no directory witness, so the verdict turns purely on the
	// cwd the content records — exactly the evidence a foreign replacement rewrites.
	locator := filepath.Join("2026", "08", "09", "rollout-019c-0004.jsonl")
	lines := []string{codexMetaLine(project)}
	for i := 0; i < 8; i++ {
		lines = append(lines, fillerLine(256))
	}
	path := writeTranscript(t, store, locator, lines...)
	p := peekerFor(t, store, project)
	ix := NewMembershipIndex()

	dev, ino := identityOf(t, path)
	m, st := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
	ix.Record(dev, ino, path, st, m)

	// Copy a different, strictly larger session over the file: same inode, same path, a cwd in no
	// registered root. Unlike a truncate or a shorter overwrite, the size only grows and the change
	// time only moves forward, so the stat evidence alone reads exactly like an append.
	foreign := t.TempDir()
	body := codexMetaLine(foreign) + "\n"
	for i := 0; i < 40; i++ {
		body += fillerLine(256) + "\n"
	}
	writeFileString(t, path, body)
	if dev2, ino2 := identityOf(t, path); dev2 != dev || ino2 != ino {
		t.Fatalf("the replacement moved the identity to (%d,%d), want the original (%d,%d) — "+
			"the fixture must exercise an in-place replacement, not a rename", dev2, ino2, dev, ino)
	}
	live := mustStat(t, path)
	if live.Size <= st.Size || live.CtimeNanos < st.CtimeNanos {
		t.Fatalf("fixture must grow the file with a forward ctime: live %+v, recorded %+v", live, st)
	}

	// The cached member verdict must NOT survive a growth-to-larger foreign replacement.
	wantMiss(t, ix, dev, ino, path, live)

	// The forced re-peek decides the file it is now, not the member it was.
	m2, _ := mustPeek(t, p, store, locator)
	wantVerdict(t, m2, MembershipNonMember, "", ReasonOutsideProjectRoots)
}

// An ordinary append must still corroborate against the head fingerprint without a full re-peek: the
// leading bytes the fingerprint covers are untouched by an append, so the bounded anchor read matches
// and the cached member verdict is kept.
func TestIndexedMemberSurvivesAnAppendViaTheHeadFingerprint(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := filepath.Join("2026", "08", "09", "rollout-019c-0005.jsonl")
	lines := []string{codexMetaLine(project)}
	for i := 0; i < 8; i++ {
		lines = append(lines, fillerLine(256))
	}
	path := writeTranscript(t, store, locator, lines...)
	p := peekerFor(t, store, project)
	ix := NewMembershipIndex()

	dev, ino := identityOf(t, path)
	m, st := mustPeek(t, p, store, locator)
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)
	ix.Record(dev, ino, path, st, m)

	// Grow the file the way a live session does: append records, leaving the head untouched.
	appendString(t, path, fillerLine(256)+"\n")
	grown := mustStat(t, path)
	if grown.Size <= st.Size {
		t.Fatalf("append did not grow the file: grown %+v, recorded %+v", grown, st)
	}
	if got := mustLookup(t, ix, dev, ino, path, grown); got != m {
		t.Fatalf("verdict after an append = %+v, want the cached member %+v", got, m)
	}
}

func TestPeekVanishedFileIsAnErrorNotAVerdict(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	locator := "session.jsonl"
	path := writeTranscript(t, store, locator, claudeCWDLine(project))
	dev, ino := identityOf(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	m, _, err := peekerFor(t, store, project).Peek(store, locator, dev, ino)
	if !os.IsNotExist(err) {
		t.Fatalf("peek of a vanished file: err = %v, want not-exist", err)
	}
	if m.State != MembershipUndetermined {
		t.Fatalf("verdict = %s, want the zero verdict on error", m.State)
	}
}

// Containment is component-wise, so a project's name may never be matched by a sibling that merely
// shares its prefix.
func TestProjectMatchIsPathBoundaryAware(t *testing.T) {
	const project = "/p/project"
	p := peekerFor(t, t.TempDir(), project, "/other/root")
	cases := []struct {
		cwd    string
		state  MembershipState
		id     string
		reason NonMemberReason
	}{
		{"/p/project", MembershipMember, rootPolicyID(project), ReasonNone},
		{"/p/project/", MembershipMember, rootPolicyID(project), ReasonNone},
		{"/p/project/sub/dir", MembershipMember, rootPolicyID(project), ReasonNone},
		{"/other/root/x", MembershipMember, rootPolicyID("/other/root"), ReasonNone},
		{"/p/proj", MembershipNonMember, "", ReasonOutsideProjectRoots},
		{"/p/projectile", MembershipNonMember, "", ReasonOutsideProjectRoots},
		{"/p/project/../projectile", MembershipNonMember, "", ReasonOutsideProjectRoots},
		{"/p", MembershipNonMember, "", ReasonOutsideProjectRoots},
		{"/", MembershipNonMember, "", ReasonOutsideProjectRoots},
		{"p/project", MembershipNonMember, "", ReasonCWDNotAbsolute},
		{"../p/project", MembershipNonMember, "", ReasonCWDNotAbsolute},
	}
	for _, tc := range cases {
		// A one-component locator carries no directory witness, so this exercises matching alone.
		got := p.classify(tc.cwd, "rollout.jsonl")
		if got.State != tc.state || got.ProjectRootID != tc.id || got.Reason != tc.reason {
			t.Fatalf("classify(%q) = {%s %q %q}, want {%s %q %q}",
				tc.cwd, got.State, got.ProjectRootID, got.Reason, tc.state, tc.id, tc.reason)
		}
	}
}

func TestClaudeStoreSubdirOnlyMatchesTheOneLevelLayout(t *testing.T) {
	cases := []struct {
		locator string
		dir     string
		ok      bool
	}{
		{"-home-u-proj/session.jsonl", "-home-u-proj", true},
		{"session.jsonl", "", false},
		{"2026/08/09/rollout.jsonl", "", false},
		{"a/b/session.jsonl", "", false},
	}
	for _, tc := range cases {
		dir, ok := claudeStoreSubdir(tc.locator)
		if dir != tc.dir || ok != tc.ok {
			t.Fatalf("claudeStoreSubdir(%q) = (%q, %v), want (%q, %v)", tc.locator, dir, ok, tc.dir, tc.ok)
		}
	}
}

func TestNewMembershipPeekerKeepsOnlyActiveProjectRoots(t *testing.T) {
	store := t.TempDir()
	policy := rootpolicy.Policy{
		Stores: []string{store},
		Roots: []rootpolicy.Record{
			{Path: "/p/live", Generation: 2, Active: true, Mode: rootpolicy.ForwardOnly, Kind: rootpolicy.Project},
			{Path: "/p/revoked", Generation: 3, Active: false, Kind: rootpolicy.Project},
			{Path: "/p/transcripts", Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly, Kind: rootpolicy.Transcripts},
			{Path: "/p/v1", Generation: 1, Active: true, Mode: rootpolicy.ForwardOnly},
		},
	}
	p := NewMembershipPeeker(policy)
	if len(p.projects) != 1 || p.projects[0].path != "/p/live" || p.projects[0].id != rootPolicyID("/p/live") {
		t.Fatalf("projects = %+v, want only the active project root", p.projects)
	}
}
