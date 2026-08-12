package codex

import (
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestParseRealClaudeExtractsToolCallReferences is the BLOCKER-1 regression: a REAL Claude Code
// transcript runs bd/git inside Bash tool_use blocks, and those must project onto the reference
// extractors — the prior parser read only message.usage, so bd/git/gh calls in a live Claude
// session produced ZERO reference candidates and the whole run→bead linkage was dead.
func TestParseRealClaudeExtractsToolCallReferences(t *testing.T) {
	res := Parse(readFixture(t, "claude_toolcall_real.jsonl"), defaultRefConfig())

	if got := kindCounts(res.Candidates)[KindDiagnostic]; got != 0 {
		t.Fatalf("real claude transcript produced %d diagnostics, want 0", got)
	}
	if got := kindCounts(res.Candidates)[KindSessionLifecycle]; got != 1 {
		t.Fatalf("SESSION_LIFECYCLE count = %d, want 1", got)
	}

	beads := beadRefs(res.Candidates)
	if !beads["ga-5g3her"] {
		t.Fatalf("bead ga-5g3her from the `bd close` tool_use was not extracted; got %v", beads)
	}
	// A bead id that appears only in an assistant text block (prose), or only inside a non-shell
	// tool's structured input (a Read file_path), is never a recognized surface.
	if beads["ga-proseonly"] {
		t.Errorf("bead id in assistant prose must not be extracted")
	}
	if beads["ga-notreal"] {
		t.Errorf("bead id inside a Read tool file_path must not be extracted")
	}
	// The `git show <sha>` tool_use and its `commit <sha>` output both surface as git, so the
	// commit extractor runs — proving the tool_use→TOOL_CALL and tool_result→TOOL_RESULT
	// correlation (the result carries no tool name of its own).
	const sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	if commitRefs(res.Candidates)[sha] == "" {
		t.Fatalf("commit %s from the git tool_use/tool_result was not extracted", sha)
	}
}

// TestParseRealCodexRolloutExtractsToolCallReferences is the BLOCKER-1 regression for the Codex
// side: a live `codex exec` rollout records shell activity as response_item function/tool calls,
// which returned nil before. A bd invocation inside one must now extract its bead id.
func TestParseRealCodexRolloutExtractsToolCallReferences(t *testing.T) {
	res := Parse(readFixture(t, "rollout_toolcall_real.jsonl"), defaultRefConfig())

	if got := kindCounts(res.Candidates)[KindDiagnostic]; got != 0 {
		t.Fatalf("real rollout produced %d diagnostics, want 0", got)
	}
	if got := kindCounts(res.Candidates)[KindSessionLifecycle]; got != 1 {
		t.Fatalf("SESSION_LIFECYCLE count = %d, want 1", got)
	}
	if got := firstSession(t, res.Candidates).Model; got != "gpt-5.4" {
		t.Fatalf("model = %q, want gpt-5.4 (threaded from turn_context)", got)
	}
	if beads := beadRefs(res.Candidates); !beads["ga-1tzraj-repair-merge"] {
		t.Fatalf("bead ga-1tzraj-repair-merge from the shell function_call was not extracted; got %v", beads)
	}
}

// TestBeadSurfaceRecognizesToolAfterShellSeparator is the finding-4 false-negative fix: Claude Code
// routinely runs `cd <repo> && bd …`, and the surface gate must see the bd invocation at the head
// of the second pipeline segment, not only at the very start of the command.
func TestBeadSurfaceRecognizesToolAfterShellSeparator(t *testing.T) {
	cases := []string{
		"cd /data/projects/lego && bd close ga-5g3her --reason done",
		"cd repo; bd update ga-5g3her --status closed",
		"true && (bd show ga-5g3her)",
	}
	for _, cmd := range cases {
		refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
			SurfaceText{Tool: "Bash", Text: cmd}, defaultRefConfig())
		if len(refs) != 1 || refs[0].Kind != RefKindBead || refs[0].Work.BeadID != "ga-5g3her" {
			t.Errorf("cmd %q: want one bead ga-5g3her, got %+v", cmd, refs)
		}
	}
}

// TestToolResultNeverEnabledByContent guards the security boundary the finding-4 gate change must
// preserve: a TOOL_RESULT surface is recognized only by an exact bd/git/gh tool name, never because
// its untrusted output bytes contain a `bd …` segment.
func TestToolResultNeverEnabledByContent(t *testing.T) {
	refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLRESULT,
		SurfaceText{Tool: "cat", Text: "cd x && bd close ga-5g3her"}, defaultRefConfig())
	if len(refs) != 0 {
		t.Fatalf("tool output must not enable extraction by content, got %+v", refs)
	}
}

// TestGitBranchNameDoesNotOvercapture is the finding-4 false-positive fix: a branch-create operand
// is a caller-chosen <bead>-<slug> name; capturing it whole would mint a phantom bead and bury the
// real id, so the branch-name position extracts nothing.
func TestGitBranchNameDoesNotOvercapture(t *testing.T) {
	cases := []string{
		"git checkout -b ga-x-add-docs",
		"git switch -c ga-y-fix-bug",
		"git checkout -B ga-w-hotfix",
		"git branch ga-z-newthing",
	}
	for _, cmd := range cases {
		refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
			SurfaceText{Tool: "git", Text: cmd}, defaultRefConfig())
		if n := len(refs); n != 0 {
			t.Errorf("cmd %q: branch name must not mint a bead, got %+v", cmd, refs)
		}
	}
}

// TestRepoPathSlugDoesNotMintPhantomBead is the finding-4 false-positive fix: a repo/path slug that
// merely starts with a bead prefix (ga-pilot.git, a clone URL) is a whole token that continues past
// the id, so whole-token anchoring rejects it rather than minting a phantom ga-pilot.
func TestRepoPathSlugDoesNotMintPhantomBead(t *testing.T) {
	cases := []struct {
		tool, text string
	}{
		{"git", "git clone https://github.com/gascity/ga-pilot.git"},
		{"bd", "bd export --out ga-pilot.git"},
		{"git", "git remote add origin git@github.com:gascity/ga-pilot.git"},
	}
	for _, c := range cases {
		refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
			SurfaceText{Tool: c.tool, Text: c.text}, defaultRefConfig())
		for _, r := range refs {
			if r.Kind == RefKindBead {
				t.Errorf("cmd %q: path/repo slug minted phantom bead %q", c.text, r.Work.BeadID)
			}
		}
	}
	// Precision check: a real bead as a whole argv token is still captured after the anchoring.
	refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
		SurfaceText{Tool: "bd", Text: "bd show ga-5g3her"}, defaultRefConfig())
	if len(refs) != 1 || refs[0].Work.BeadID != "ga-5g3her" {
		t.Fatalf("real bead token regressed: %+v", refs)
	}
}
