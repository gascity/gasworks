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

func identityOf(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatalf("no filesystem identity for %s", path)
	}
	return dev, ino
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

func TestPeekLineCapExhaustionIsNonMember(t *testing.T) {
	store, project := t.TempDir(), t.TempDir()
	dir := mungeClaudeProjectDir(project)
	p := peekerFor(t, store, project)

	atCap := make([]string, 0, maxPeekCWDLines+1)
	for i := 0; i < maxPeekCWDLines; i++ {
		atCap = append(atCap, queueLine)
	}
	underCap := append(append([]string(nil), atCap[:maxPeekCWDLines-1]...), claudeCWDLine(project))
	writeTranscript(t, store, filepath.Join(dir, "under.jsonl"), underCap...)
	m, _ := mustPeek(t, p, store, filepath.Join(dir, "under.jsonl"))
	wantVerdict(t, m, MembershipMember, rootPolicyID(project), ReasonNone)

	overCap := append(append([]string(nil), atCap...), claudeCWDLine(project))
	writeTranscript(t, store, filepath.Join(dir, "over.jsonl"), overCap...)
	m, _ = mustPeek(t, p, store, filepath.Join(dir, "over.jsonl"))
	wantVerdict(t, m, MembershipNonMember, "", ReasonPeekCapExhausted)
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
