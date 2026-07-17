package codex

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// ExtractorVersion is the versioned identity of the deterministic reference extractors. Each
// captured reference records this alongside the fixture-proven pattern_id that matched, so a
// later extractor revision is distinguishable on the wire. Bump it whenever a pattern changes.
const ExtractorVersion = "codex-refextract-v1"

// RefKind is the closed set of reference kinds this extractor can capture. COMMIT and
// PULL_REQUEST are VCS references; BEAD is an extracted work reference. BRANCH is deliberately
// excluded from v1 (branch names are human-chosen text with no defined pattern).
type RefKind string

// The closed reference-kind set.
const (
	RefKindCommit      RefKind = "COMMIT"
	RefKindPullRequest RefKind = "PULL_REQUEST"
	RefKindBead        RefKind = "BEAD"
)

// DistinctRefAdmitter is the per-run/per-source distinct-reference cap hook. The counter is
// owned by the caller (wired in E1.8b/E1.10); the extractor consults it once per candidate
// reference and drops any it rejects, emitting a bounded diagnostic. A nil admitter imposes no
// cross-observation cap — only the fixed per-observation cap still applies.
type DistinctRefAdmitter interface {
	// Admit reports whether one more distinct (kind, identifier) reference may be captured. It
	// is the caller's responsibility to make the decision idempotent for an identifier already
	// admitted so a replayed observation does not double-count.
	Admit(kind RefKind, identifier string) bool
}

// ReferenceConfig is the declared extraction configuration for one parse. BeadPrefixes is the
// project-prefix set that selects which bead identifiers to capture (declared configuration, not
// policy parsed out of the identifier — the captured value stays opaque downstream). Resolver
// supplies the team_server_project_id for every extracted bead reference. DistinctRefs is the
// optional caller-owned cross-observation cap hook.
type ReferenceConfig struct {
	BeadPrefixes []string
	Resolver     evidence.ProjectResolver
	DistinctRefs DistinctRefAdmitter
}

// SurfaceText is the input to the extractors: the producing tool name and the recognized
// git/gh output (a command on a TOOL_CALL surface, tool output on a TOOL_RESULT surface).
type SurfaceText struct {
	Tool string
	Text string
}

// ExtractedReference is a tagged union of one captured reference. Exactly one pointer is set,
// selected by Kind.
type ExtractedReference struct {
	Kind        RefKind
	Commit      *evidence.CommitReferenceCandidate
	PullRequest *evidence.PullRequestReferenceCandidate
	Work        *evidence.ExtractedWorkReferenceCandidate
}

func (r ExtractedReference) identifier() string {
	switch r.Kind {
	case RefKindCommit:
		return r.Commit.Identifier
	case RefKindPullRequest:
		return r.PullRequest.Identifier
	default:
		return r.Work.BeadID
	}
}

// fullHexPattern matches a standalone lowercase full 40- or 64-hex token. The word boundaries
// make it reject a 40-hex substring of a 64-hex token (and vice versa), so a longer hex secret
// never yields a spurious short "commit". A 7-hex abbreviated SHA is never matched.
var fullHexPattern = regexp.MustCompile(`\b(?:[0-9a-f]{64}|[0-9a-f]{40})\b`)

// The git-syntax anchors that must immediately precede a full-hex token for it to be a COMMIT.
// Each is matched against the text between the token's line start and the token itself, so the
// anchor must be adjacent (only intervening whitespace / earlier shas on a Merge line). A bare
// hex token with none of these anchors is never captured.
var (
	commitHeaderAnchor = regexp.MustCompile(`(?:^|[\s(])commit\s+$`)
	commitParentAnchor = regexp.MustCompile(`(?:^|\s)parent\s+$`)
	commitFromAnchor   = regexp.MustCompile(`(?:^|\s)From\s+$`)
	commitMergeAnchor  = regexp.MustCompile(`(?:^|\s)Merge:\s+(?:[0-9a-f]{40}\s+|[0-9a-f]{64}\s+)*$`)
	// End-anchored like its siblings: the hex must be the git subcommand's immediate object
	// argument, tolerating only intervening option flags and whitespace. Without the trailing
	// `\s+$` the git verb could appear anywhere earlier on the line and a later hex secret
	// (`git log ... <secret>`, `git log --grep=<secret>`, `git log -p | grep <secret>`) would be
	// mis-captured as a COMMIT.
	commitGitCLIAnchor = regexp.MustCompile(`\bgit\s+(?:show|checkout|switch|cherry-pick|revert|reset|diff|log|branch|tag|merge|rebase|cat-file|rev-parse|rev-list|clone|fetch|pull|push|stash|bisect|describe)(?:\s+-{1,2}[A-Za-z0-9][\w=-]*)*\s+$`)
)

// Pull-request patterns. The URL form captures repo_slug (URL-anchored) and the PR number; the
// #N forms require an explicit PR / gh-pr anchor so a bare "#123" (issue, array index) is never
// captured.
var (
	prURLPattern     = regexp.MustCompile(`\bhttps://github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/pull/([0-9]{1,20})\b`)
	prAnchoredHashRe = regexp.MustCompile(`(?i)\b(?:pull[ -]request|pr)\s+#([0-9]{1,20})\b`)
	prGhCommandRe    = regexp.MustCompile(`\bgh\s+pr\s+[a-z-]+\s+#?([0-9]{1,20})\b`)
)

// ExtractReferences runs the deterministic reference extractors over one recognized tool surface
// and returns the captured references plus any cap diagnostics. COMMIT and PULL_REQUEST capture
// run only on a git/gh surface and require adjacent git/gh syntax; bead-ID capture runs only on a
// recognized bd/git/gh surface (spec §317). None run on MESSAGE prose — the parser only calls
// this for tool records. Within one observation, duplicate (kind, identifier) references are
// collapsed; the result is then subjected to the caller-owned distinct-ref cap (if any) and the
// fixed per-observation cap of MaxReferencesPerObservation, each overflow producing a bounded
// diagnostic.
func ExtractReferences(surface wire.ExtractionProvenanceSurface, in SurfaceText, cfg ReferenceConfig) ([]ExtractedReference, []evidence.DiagnosticCandidate) {
	var refs []ExtractedReference
	if isGitGhSurface(surface, in.Tool, in.Text) {
		refs = append(refs, extractCommits(surface, in.Text)...)
		refs = append(refs, extractPullRequests(surface, in.Text)...)
	}
	if isBeadSurface(surface, in.Tool, in.Text) {
		refs = append(refs, extractBeads(surface, in.Text, cfg)...)
	}
	refs = dedupReferences(refs)

	var diags []evidence.DiagnosticCandidate

	if cfg.DistinctRefs != nil {
		kept := refs[:0]
		rejected := 0
		for _, r := range refs {
			if cfg.DistinctRefs.Admit(r.Kind, r.identifier()) {
				kept = append(kept, r)
			} else {
				rejected++
			}
		}
		refs = kept
		if rejected > 0 {
			diags = append(diags, refCapDiagnostic(fmt.Sprintf(
				"distinct-reference cap reached: dropped %d extracted reference(s)", rejected)))
		}
	}

	if len(refs) > evidence.MaxReferencesPerObservation {
		dropped := len(refs) - evidence.MaxReferencesPerObservation
		refs = refs[:evidence.MaxReferencesPerObservation]
		diags = append(diags, refCapDiagnostic(fmt.Sprintf(
			"reference overflow: dropped %d extracted reference(s) beyond the per-observation cap of %d",
			dropped, evidence.MaxReferencesPerObservation)))
	}

	return refs, diags
}

func extractCommits(surface wire.ExtractionProvenanceSurface, text string) []ExtractedReference {
	var out []ExtractedReference
	for _, loc := range fullHexPattern.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		lineStart := strings.LastIndexByte(text[:start], '\n') + 1
		prefix := text[lineStart:start]
		patternID, ok := commitAnchor(prefix)
		if !ok {
			continue
		}
		out = append(out, ExtractedReference{
			Kind: RefKindCommit,
			Commit: &evidence.CommitReferenceCandidate{
				Identifier: text[start:end],
				Extraction: extractionProvenance(surface, patternID),
			},
		})
	}
	return out
}

// commitAnchor reports which git-syntax anchor immediately precedes a full-hex token (given the
// text between the token's line start and the token), and thus the fixture-proven pattern_id.
func commitAnchor(prefix string) (string, bool) {
	switch {
	case commitHeaderAnchor.MatchString(prefix):
		return "git-commit-header-v1", true
	case commitParentAnchor.MatchString(prefix):
		return "git-commit-parent-v1", true
	case commitFromAnchor.MatchString(prefix):
		return "git-format-patch-from-v1", true
	case commitMergeAnchor.MatchString(prefix):
		return "git-merge-line-v1", true
	case commitGitCLIAnchor.MatchString(prefix):
		return "git-cli-object-arg-v1", true
	default:
		return "", false
	}
}

func extractPullRequests(surface wire.ExtractionProvenanceSurface, text string) []ExtractedReference {
	var out []ExtractedReference
	for _, m := range prURLPattern.FindAllStringSubmatch(text, -1) {
		out = append(out, ExtractedReference{
			Kind: RefKindPullRequest,
			PullRequest: &evidence.PullRequestReferenceCandidate{
				Identifier: strings.TrimRight(m[0], "/"),
				RepoSlug:   m[1],
				Extraction: extractionProvenance(surface, "gh-pr-url-v1"),
			},
		})
	}
	for _, m := range prAnchoredHashRe.FindAllStringSubmatch(text, -1) {
		out = append(out, ExtractedReference{
			Kind: RefKindPullRequest,
			PullRequest: &evidence.PullRequestReferenceCandidate{
				Identifier: "#" + m[1],
				Extraction: extractionProvenance(surface, "pr-anchored-hash-v1"),
			},
		})
	}
	for _, m := range prGhCommandRe.FindAllStringSubmatch(text, -1) {
		out = append(out, ExtractedReference{
			Kind: RefKindPullRequest,
			PullRequest: &evidence.PullRequestReferenceCandidate{
				Identifier: "#" + m[1],
				Extraction: extractionProvenance(surface, "gh-pr-command-v1"),
			},
		})
	}
	return out
}

func extractBeads(surface wire.ExtractionProvenanceSurface, text string, cfg ReferenceConfig) []ExtractedReference {
	re := beadPattern(cfg.BeadPrefixes)
	if re == nil {
		return nil
	}
	var out []ExtractedReference
	for _, m := range re.FindAllString(text, -1) {
		out = append(out, ExtractedReference{
			Kind: RefKindBead,
			Work: &evidence.ExtractedWorkReferenceCandidate{BeadID: m, Resolver: cfg.Resolver},
		})
	}
	return out
}

// beadPattern compiles the declared prefix set into an anchored bead-ID matcher, or nil when no
// prefixes are declared. A bead ID is a declared prefix followed by one or more alphanumerics
// and any number of dash-joined alphanumeric segments (e.g. ga-1tzraj, ga-1tzraj-repair-merge).
func beadPattern(prefixes []string) *regexp.Regexp {
	if len(prefixes) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		quoted = append(quoted, regexp.QuoteMeta(p))
	}
	if len(quoted) == 0 {
		return nil
	}
	return regexp.MustCompile(`\b(?:` + strings.Join(quoted, "|") + `)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b`)
}

// isGitGhSurface reports whether a tool surface is a recognized git/gh surface, gating COMMIT
// and PULL_REQUEST capture. Classification keys on the producing tool NAME; the command-prefix
// fallback is honored only for a TOOL_CALL surface (where the text is the command line). It is
// never keyed off TOOL_RESULT output bytes, so an untrusted output that merely begins with
// "git "/"gh " cannot spoof the surface into enabling extraction.
func isGitGhSurface(surface wire.ExtractionProvenanceSurface, tool, text string) bool {
	return recognizedSurface(surface, tool, text, "git", "gh")
}

// isBeadSurface reports whether a tool surface is a recognized bead-ID extraction surface. Per
// spec §317 the recognized set is bd/git/gh — bead identifiers legitimately surface from those
// tools, not from arbitrary curl/cat/tar output where bead-shaped tokens are incidental
// substrings of URLs, paths, and filenames.
func isBeadSurface(surface wire.ExtractionProvenanceSurface, tool, text string) bool {
	return recognizedSurface(surface, tool, text, "bd", "git", "gh")
}

// recognizedSurface classifies a surface against an allowed tool-name set: an exact tool-name
// match on any surface, or a "<name> " command prefix on a TOOL_CALL surface only.
func recognizedSurface(surface wire.ExtractionProvenanceSurface, tool, text string, names ...string) bool {
	name := strings.ToLower(strings.TrimSpace(tool))
	for _, n := range names {
		if name == n {
			return true
		}
	}
	if surface == wire.ExtractionProvenanceSurfaceTOOLCALL {
		trimmed := strings.TrimSpace(text)
		for _, n := range names {
			if strings.HasPrefix(trimmed, n+" ") {
				return true
			}
		}
	}
	return false
}

func extractionProvenance(surface wire.ExtractionProvenanceSurface, patternID string) wire.ExtractionProvenance {
	return wire.ExtractionProvenance{
		Surface:          surface,
		PatternId:        patternID,
		ExtractorVersion: ExtractorVersion,
	}
}

// dedupReferences collapses duplicate (kind, identifier) references within one observation,
// preserving first-seen order so distinct-ref and overflow caps count distinct references.
func dedupReferences(refs []ExtractedReference) []ExtractedReference {
	if len(refs) < 2 {
		return refs
	}
	seen := make(map[string]struct{}, len(refs))
	out := refs[:0]
	for _, r := range refs {
		key := string(r.Kind) + "\x00" + r.identifier()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func refCapDiagnostic(context string) evidence.DiagnosticCandidate {
	return evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeREFERENCEOVERFLOW,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            context,
	}
}
