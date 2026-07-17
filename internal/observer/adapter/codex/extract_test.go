package codex

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

func commitRefs(cands []*Candidate) map[string]string {
	m := map[string]string{}
	for _, c := range cands {
		if c.Kind == KindCommitReference {
			m[c.Commit.Identifier] = c.Commit.Extraction.PatternId
		}
	}
	return m
}

func prRefs(cands []*Candidate) map[string]string {
	m := map[string]string{}
	for _, c := range cands {
		if c.Kind == KindPullRequestReference {
			m[c.PullRequest.Identifier] = c.PullRequest.Extraction.PatternId
		}
	}
	return m
}

func beadRefs(cands []*Candidate) map[string]bool {
	m := map[string]bool{}
	for _, c := range cands {
		if c.Kind == KindWorkReference {
			m[c.Work.BeadID] = true
		}
	}
	return m
}

func TestExtractCommitsTruePositives(t *testing.T) {
	const (
		c40    = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
		cMerge = "356a192b7913b04c54574d18c28d46e6395428ab"
		c64    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)
	res := Parse(readFixture(t, "commits_truepos.jsonl"), defaultRefConfig())
	got := commitRefs(res.Candidates)
	want := map[string]string{
		c40:    "git-commit-header-v1",
		cMerge: "git-merge-line-v1",
		c64:    "git-cli-object-arg-v1",
	}
	if len(got) != len(want) {
		t.Fatalf("commit refs = %v, want %v", got, want)
	}
	for id, pat := range want {
		if got[id] != pat {
			t.Errorf("commit %s pattern = %q, want %q", id, got[id], pat)
		}
	}
	// Every commit reference seals cleanly through the committed policy (proves each identifier
	// satisfies the constructor's strict 40/64-hex pattern).
	for _, c := range res.Candidates {
		if c.Kind == KindCommitReference {
			canonicalBytes(t, c)
		}
	}
}

func TestExtractPullRequestsTruePositives(t *testing.T) {
	res := Parse(readFixture(t, "pull_requests_truepos.jsonl"), defaultRefConfig())
	got := prRefs(res.Candidates)
	want := map[string]string{
		"https://github.com/gascity/gasworks/pull/4188": "gh-pr-url-v1",
		"#4147": "pr-anchored-hash-v1",
		"#4111": "gh-pr-command-v1",
	}
	if len(got) != len(want) {
		t.Fatalf("pr refs = %v, want %v", got, want)
	}
	for id, pat := range want {
		if got[id] != pat {
			t.Errorf("pr %s pattern = %q, want %q", id, got[id], pat)
		}
	}
	// The URL-anchored PR also captured its repo_slug.
	for _, c := range res.Candidates {
		if c.Kind == KindPullRequestReference && strings.HasPrefix(c.PullRequest.Identifier, "https://") {
			if c.PullRequest.RepoSlug != "gascity/gasworks" {
				t.Errorf("url PR repo_slug = %q, want gascity/gasworks", c.PullRequest.RepoSlug)
			}
		}
		if c.Kind == KindPullRequestReference {
			canonicalBytes(t, c)
		}
	}
}

func TestExtractBeadsTruePositives(t *testing.T) {
	res := Parse(readFixture(t, "beads_truepos.jsonl"), defaultRefConfig())
	got := beadRefs(res.Candidates)
	for _, want := range []string{"ga-1tzraj-repair-merge", "ga-5g3her"} {
		if !got[want] {
			t.Errorf("expected bead ref %q, got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("bead refs = %v, want exactly 2", got)
	}
	// A resolvable project (configured default) means the extracted reference seals rather than
	// being dropped.
	for _, c := range res.Candidates {
		if c.Kind == KindWorkReference {
			canonicalBytes(t, c)
		}
	}
}

func TestHexSecretsAreNeverExtracted(t *testing.T) {
	res := Parse(readFixture(t, "secrets_falsepos.jsonl"), defaultRefConfig())
	got := commitRefs(res.Candidates)

	// The only extractable commit is the real git-log header sha in the second record.
	const realCommit = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	if len(got) != 1 || got[realCommit] != "git-commit-header-v1" {
		t.Fatalf("want exactly the real header commit extracted, got %v", got)
	}

	// None of the planted secrets — 40-hex, 64-hex, or 32-hex — are ever captured, whether on a
	// non-git shell surface or as diff-body lines on a git surface.
	forbidden := []string{
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",                         // 40-hex secret
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // 64-hex secret
		"5f4dcc3b5aa765d61d8327deb882cf99",                                 // 32-hex md5
	}
	for _, secret := range forbidden {
		if _, extracted := got[secret]; extracted {
			t.Errorf("hex secret %q was extracted as a commit reference", secret)
		}
	}
	// And nothing PR/work shaped came out of the secrets fixture either.
	if n := len(prRefs(res.Candidates)) + len(beadRefs(res.Candidates)); n != 0 {
		t.Errorf("secrets fixture produced %d pr/work refs, want 0", n)
	}
}

func TestBeadIdInMessageProseIsNeverExtracted(t *testing.T) {
	res := Parse(readFixture(t, "bead_prose_falsepos.jsonl"), defaultRefConfig())
	if n := len(beadRefs(res.Candidates)); n != 0 {
		t.Fatalf("bead ids in MESSAGE prose must not be extracted, got %d", n)
	}
	// The message itself still parses (with its body slated for policy stripping).
	if got := kindCounts(res.Candidates); got[KindMessage] != 1 || len(res.Candidates) != 1 {
		t.Fatalf("want exactly one message candidate, got %v", got)
	}
}

func TestAbbreviatedShaIsNeverExtracted(t *testing.T) {
	res := Parse(readFixture(t, "abbrev_sha_falsepos.jsonl"), defaultRefConfig())
	// Even with a `commit ` anchor, a 7-hex abbreviated sha is below the full-hex requirement.
	if n := len(commitRefs(res.Candidates)); n != 0 {
		t.Fatalf("abbreviated shas must not be extracted, got %d commit refs", n)
	}
}

func TestReferenceOverflowYieldsDiagnostic(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "commit %040x\n", i)
	}
	output, err := json.Marshal(b.String())
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	line := fmt.Sprintf(`{"type":"tool_result","tool":"git","category":"SHELL","status":"OK","output":%s,"ts":"2026-07-17T10:11:00Z"}`+"\n", output)

	res := Parse([]byte(line), defaultRefConfig())
	got := kindCounts(res.Candidates)
	if got[KindCommitReference] != evidence.MaxReferencesPerObservation {
		t.Fatalf("want %d commit refs after the per-observation cap, got %d", evidence.MaxReferencesPerObservation, got[KindCommitReference])
	}
	overflowSeen := false
	for _, c := range res.Diagnostics() {
		if c.Diagnostic.Code == wire.CaptureDiagnosticPayloadCodeREFERENCEOVERFLOW {
			overflowSeen = true
			canonicalBytes(t, c)
		}
	}
	if !overflowSeen {
		t.Fatalf("overflow past 32 references must emit a REFERENCE_OVERFLOW diagnostic; kinds=%v", got)
	}
}

// countingAdmitter is a test double for the caller-owned per-run/per-source distinct-ref cap
// hook. It admits distinct references up to limit, then rejects, and is idempotent for an
// identifier it already admitted.
type countingAdmitter struct {
	limit int
	seen  map[string]bool
}

func (c *countingAdmitter) Admit(kind RefKind, id string) bool {
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	key := string(kind) + "\x00" + id
	if c.seen[key] {
		return true
	}
	if len(c.seen) >= c.limit {
		return false
	}
	c.seen[key] = true
	return true
}

func TestDistinctRefCapHookDropsAndDiagnoses(t *testing.T) {
	text := "commit da39a3ee5e6b4b0d3255bfef95601890afd80709\n" +
		"parent 356a192b7913b04c54574d18c28d46e6395428ab\n" +
		"git show e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"

	cfg := defaultRefConfig()
	cfg.DistinctRefs = &countingAdmitter{limit: 2}

	refs, diags := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLRESULT, SurfaceText{Tool: "git", Text: text}, cfg)
	if len(refs) != 2 {
		t.Fatalf("distinct-ref cap of 2 should admit 2 refs, got %d", len(refs))
	}
	if len(diags) == 0 {
		t.Fatalf("rejecting a reference at the distinct-ref cap must emit a diagnostic")
	}
	if diags[0].Code != wire.CaptureDiagnosticPayloadCodeREFERENCEOVERFLOW {
		t.Errorf("distinct-cap diagnostic code = %q, want REFERENCE_OVERFLOW", diags[0].Code)
	}
}

func TestExtractionSkippedOnNonGitSurfaceForCommits(t *testing.T) {
	// A full-hex, git-anchored-looking string on a non-git tool surface is not a git/gh surface,
	// so commit/PR extraction does not run.
	text := "commit da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
	refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLRESULT, SurfaceText{Tool: "cat", Text: text}, defaultRefConfig())
	if len(refs) != 0 {
		t.Fatalf("commit extraction must not run on a non-git surface, got %d refs", len(refs))
	}
}

// TestGitCliAnchorDoesNotLeakSecrets is the finding-1 (BLOCKER) regression: a full 40/64-hex
// secret that merely shares a line with a git subcommand — but is NOT the command's immediate
// object argument — must never be captured as a COMMIT, on any surface. It also pins finding 4:
// a non-git tool whose OUTPUT begins with "git "/"gh " must not enable commit/PR extraction.
func TestGitCliAnchorDoesNotLeakSecrets(t *testing.T) {
	res := Parse(readFixture(t, "git_anchor_falsepos.jsonl"), defaultRefConfig())
	if n := len(commitRefs(res.Candidates)); n != 0 {
		t.Fatalf("git-CLI non-adjacency / output-prefix spoof leaked %d commit refs, want 0: %v", n, commitRefs(res.Candidates))
	}
	if n := len(prRefs(res.Candidates)); n != 0 {
		t.Fatalf("output-prefix spoof leaked %d pr refs, want 0", n)
	}
	// None of the planted secrets survive anywhere as an extracted identifier.
	forbidden := []string{
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	}
	all := commitRefs(res.Candidates)
	for _, secret := range forbidden {
		if _, ok := all[secret]; ok {
			t.Errorf("secret %q was extracted as a commit", secret)
		}
	}

	// The committed true positive — a hex that IS the immediate object argument of a git
	// subcommand — must still extract, proving the fix is a precise narrowing, not a blanket off.
	tp, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
		SurfaceText{Tool: "git", Text: "git show da39a3ee5e6b4b0d3255bfef95601890afd80709"}, defaultRefConfig())
	if len(tp) != 1 || tp[0].Kind != RefKindCommit || tp[0].Commit.Extraction.PatternId != "git-cli-object-arg-v1" {
		t.Fatalf("git show <sha> true positive regressed: %+v", tp)
	}
}

// TestBeadExtractionGatedToRecognizedSurfaces is the finding-3 (MAJOR) regression: bead-ID
// extraction must run only on recognized bd/git/gh surfaces, never on arbitrary tool output
// where bead-shaped tokens are incidental substrings of URLs/paths/filenames.
func TestBeadExtractionGatedToRecognizedSurfaces(t *testing.T) {
	res := Parse(readFixture(t, "bead_surface_falsepos.jsonl"), defaultRefConfig())
	if n := len(beadRefs(res.Candidates)); n != 0 {
		t.Fatalf("bead extraction on a non-recognized (curl) surface minted %d work refs, want 0: %v", n, beadRefs(res.Candidates))
	}

	// A real bead id on a recognized bd surface still extracts.
	tp, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLRESULT,
		SurfaceText{Tool: "bd", Text: "ga-5g3her is ready"}, defaultRefConfig())
	if len(tp) != 1 || tp[0].Kind != RefKindBead || tp[0].Work.BeadID != "ga-5g3her" {
		t.Fatalf("bead extraction on a bd surface regressed: %+v", tp)
	}
}
