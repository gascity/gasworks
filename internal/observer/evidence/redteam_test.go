package evidence

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func validExtraction() wire.ExtractionProvenance {
	return wire.ExtractionProvenance{
		Surface: wire.ExtractionProvenanceSurfaceTOOLRESULT, PatternId: "git-log-oneline-v1", ExtractorVersion: "1",
	}
}

func mustBuildErr(t *testing.T, err error, what string) {
	t.Helper()
	var be *BuildError
	if !errors.As(err, &be) {
		t.Fatalf("%s: want a *BuildError, got %T (%v)", what, err, err)
	}
}

// TestCommitIdentifierPatternEnforced proves NewCommitReference rejects everything that is
// not a lowercase full 40/64-hex identifier (branch names, abbreviated hashes, non-hex,
// uppercase, token-shaped values) and accepts the two valid hex lengths.
func TestCommitIdentifierPatternEnforced(t *testing.T) {
	reject := []string{
		"deadbeef",                      // abbreviated
		"feature/my-branch-name",        // branch name
		"ghp_SENTINELtokenSHAPEDvalue1", // token-shaped
		strings.Repeat("A", 40),         // uppercase non-hex
		strings.Repeat("0", 39),         // 39-hex (too short)
		strings.Repeat("0", 41),         // 41-hex (not 40/64)
		"HEAD~3",
		"not hex at all!",
		hex32, // 32-hex is abbreviated, excluded
	}
	for _, id := range reject {
		_, err := NewCommitReference(testCommon(), CommitReferenceInput{Identifier: id, Extraction: validExtraction()})
		mustBuildErr(t, err, "commit identifier "+id)
	}
	for _, id := range []string{strings.Repeat("a", 40), strings.Repeat("f", 64), hex40, hex64} {
		if _, err := NewCommitReference(testCommon(), CommitReferenceInput{Identifier: id, Extraction: validExtraction()}); err != nil {
			t.Fatalf("valid commit identifier %q rejected: %v", id, err)
		}
	}
}

// TestPullRequestIdentifierPatternEnforced proves the anchored #N / https:// PR-URL rule.
func TestPullRequestIdentifierPatternEnforced(t *testing.T) {
	reject := []string{
		"fix the login bug",
		"PR 42",
		"42",
		"4178",
		"http://github.com/org/repo/pull/1", // non-https scheme
		"#",                                 // #N requires at least one digit
		"#abc",
	}
	for _, id := range reject {
		_, err := NewPullRequestReference(testCommon(), PullRequestReferenceInput{Identifier: id, Extraction: validExtraction()})
		mustBuildErr(t, err, "pr identifier "+id)
	}
	for _, id := range []string{"#42", "#1", "https://github.com/org/repo/pull/4178"} {
		if _, err := NewPullRequestReference(testCommon(), PullRequestReferenceInput{Identifier: id, Extraction: validExtraction()}); err != nil {
			t.Fatalf("valid pr identifier %q rejected: %v", id, err)
		}
	}
}

// TestRepoSlugPatternEnforced proves repo_slug charset enforcement on both VCS constructors.
func TestRepoSlugPatternEnforced(t *testing.T) {
	reject := []string{
		"my repo with spaces",
		"https://evil.example/x?token=SENTINELslugSECRET&u=z",
		"git@github.com:org/repo.git",
		"user:tok3n@host/org/repo",
		"org/repoé", // unicode
		strings.Repeat("a", 141),
	}
	for _, slug := range reject {
		_, cerr := NewCommitReference(testCommon(), CommitReferenceInput{Identifier: hex40, RepoSlug: slug, Extraction: validExtraction()})
		mustBuildErr(t, cerr, "commit repo_slug "+slug)
		_, perr := NewPullRequestReference(testCommon(), PullRequestReferenceInput{Identifier: "#1", RepoSlug: slug, Extraction: validExtraction()})
		mustBuildErr(t, perr, "pr repo_slug "+slug)
	}
	for _, slug := range []string{"org/repo", "org.name/repo-1", "a_b/c.d/e-f"} {
		if _, err := NewCommitReference(testCommon(), CommitReferenceInput{Identifier: hex40, RepoSlug: slug, Extraction: validExtraction()}); err != nil {
			t.Fatalf("valid repo_slug %q rejected: %v", slug, err)
		}
	}
}

// TestVcsTransformFailsClosedOnBadIdentifier proves the policy transform substitutes a
// content-free diagnostic (never the raw identifier) when the pattern guard rejects.
func TestVcsTransformFailsClosedOnBadIdentifier(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	r := p.TransformCommitReference(env, CommitReferenceCandidate{
		Identifier: "feature/SENTINELbranchNAME",
		RepoSlug:   "SENTINELslug with spaces",
		Extraction: validExtraction(),
	})
	if !r.Diagnostic || r.Observation.Kind() != "CAPTURE_DIAGNOSTIC" {
		t.Fatalf("bad commit identifier must fail closed to a diagnostic, got kind=%q diag=%v", r.Observation.Kind(), r.Diagnostic)
	}
	b := sealForScan(t, r, 1)
	for _, s := range []string{"SENTINELbranchNAME", "feature/", "SENTINELslug"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("fail-closed diagnostic leaked %q:\n%s", s, b)
		}
	}
}

// TestContextEmbeddedPathDropped proves sanitizeContext (now inside NewCaptureDiagnostic)
// drops a diagnostic context that carries an absolute/home/traversal path ANYWHERE, not
// only at a whitespace-delimited prefix.
func TestContextEmbeddedPathDropped(t *testing.T) {
	leaky := []string{
		"read failed for file=/home/alice/SECRET/id_rsa",
		"open(/home/alice/SECRET/id_rsa): permission denied",
		"err=/etc/shadow",
		`parse "/home/alice/x": unexpected record`, // %q double-quote boundary
		"cfg=~/secretproj/observer.toml",           // ~/ home form
		"/var/run/SENTINELleadingpath",             // leading absolute
		"~alice/.ssh/id_rsa",                       // leading ~
		"error(path:/root/.kube/config)",           // colon boundary
	}
	for _, ctx := range leaky {
		// Direct constructor path (E1.4/E1.6-E1.8 use this, not only the transform).
		p, err := NewCaptureDiagnostic(testCommon(), CaptureDiagnosticInput{
			Code:               wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE,
			Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
			CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
			Context:            ctx,
		})
		if err != nil {
			t.Fatalf("diagnostic must still build with the context dropped, ctx=%q err=%v", ctx, err)
		}
		o := sealOne(t, p, 1, "obs_1")
		b := canonicalOf(t, o)
		for _, banned := range []string{"/home/", "/etc/", "/var/", "/root/", "~/", "~alice", "SECRET", "shadow", "SENTINELleadingpath", "secretproj"} {
			if bytes.Contains(b, []byte(banned)) {
				t.Fatalf("context %q leaked %q into canonical bytes:\n%s", ctx, banned, b)
			}
		}
		// The context key itself must be absent (dropped to nil, not empty).
		if bytes.Contains(b, []byte(`"context"`)) {
			t.Fatalf("path-bearing context must be dropped to absent, ctx=%q:\n%s", ctx, b)
		}
	}
}

// TestContextRelativeSurvives proves the sanitizer is a projection, not a blanket wipe: an
// ordinary relative-path-free or in-token-slash context survives.
func TestContextRelativeSurvives(t *testing.T) {
	for _, ctx := range []string{"parse failed at codex/2026/rollout record 12", "either/or ambiguous shape", "50/50 unknown"} {
		p, err := NewCaptureDiagnostic(testCommon(), CaptureDiagnosticInput{
			Code:               wire.CaptureDiagnosticPayloadCodeUNSUPPORTEDFORMAT,
			Severity:           wire.CaptureDiagnosticPayloadSeverityINFO,
			CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectNONE,
			Context:            ctx,
		})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if !bytes.Contains(canonicalOf(t, sealOne(t, p, 1, "obs_1")), []byte(ctx)) {
			t.Fatalf("a path-free relative context must survive: %q", ctx)
		}
	}
}

// TestLocatorTraversalDropped proves keepRelativeLocator rejects a "../"-escaping locator on
// both the provenance source_locator and the RUN_ENDED watermark sinks.
func TestLocatorTraversalDropped(t *testing.T) {
	p := testPolicy()
	occ := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
	env := PolicyEnvelope{
		OccurredAt: occ, CapturedAt: occ,
		Provenance: RawProvenance{RootRelativeLocator: "../../../../home/alice/.ssh/SENTINELid_rsa"},
	}
	b := sealForScan(t, p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRoleUSER}), 1)
	if bytes.Contains(b, []byte("SENTINELid_rsa")) || bytes.Contains(b, []byte("source_locator")) {
		t.Fatalf("traversal locator leaked into provenance:\n%s", b)
	}
	// Watermark sink via keepRelativeLocatorPtr.
	wm := p.TransformRunEndedDrain(env, RunEndedDrainCandidate{
		RunID:          "gwr_1",
		BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		DrainStatus:    wire.RunEndedBoundaryDrainStatusPARTIALTIMEOUT,
		CoveredWatermark: wire.Watermark{
			ByteOffset:    1024,
			SourceLocator: strptr("../../etc/SENTINELpasswd"),
		},
	})
	bw := sealForScan(t, wm, 1)
	if bytes.Contains(bw, []byte("SENTINELpasswd")) || bytes.Contains(bw, []byte("source_locator")) {
		t.Fatalf("traversal watermark locator leaked:\n%s", bw)
	}
}

// TestNumericBoundsRejected proves every schema minimum:0 field is enforced at construction,
// and that price_table_version/provider_source honor the maxLength:64 bound.
func TestNumericBoundsRejected(t *testing.T) {
	neg := int64(-5)
	t.Run("message_byte_count_negative", func(t *testing.T) {
		_, err := NewMessage(testCommon(), MessageInput{Role: wire.MessagePayloadRoleUSER, ByteCount: &neg})
		mustBuildErr(t, err, "byte_count")
	})
	t.Run("usage_token_negative", func(t *testing.T) {
		_, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityPROVIDERREPORTED, InputTokens: &neg})
		mustBuildErr(t, err, "input_tokens")
	})
	t.Run("tool_call_arg_negative", func(t *testing.T) {
		_, err := NewToolCall(testCommon(), ToolCallInput{Category: wire.ToolCallPayloadCategorySHELL, ArgumentByteCount: &neg})
		mustBuildErr(t, err, "argument_byte_count")
	})
	t.Run("watermark_byte_offset_negative", func(t *testing.T) {
		_, err := NewRunEndedDrain(testCommon(), RunEndedDrainInput{
			RunID:            "gwr_1",
			BoundarySource:   wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
			DrainStatus:      wire.RunEndedBoundaryDrainStatusCOMPLETE,
			CoveredWatermark: wire.Watermark{ByteOffset: -4096},
		})
		mustBuildErr(t, err, "byte_offset")
	})
	t.Run("pid_negative", func(t *testing.T) {
		_, err := NewProcessLifecycle(testCommon(), ProcessLifecycleInput{
			Transition: wire.ProcessLifecyclePayloadTransitionREGISTERED,
			Identity:   wire.ProcessIdentity{BootId: "boot-1", Pid: -1, ProcessStartTime: 5},
		})
		mustBuildErr(t, err, "pid")
	})
	t.Run("process_start_time_negative", func(t *testing.T) {
		_, err := NewProcessLifecycle(testCommon(), ProcessLifecycleInput{
			Transition: wire.ProcessLifecyclePayloadTransitionREGISTERED,
			Identity:   wire.ProcessIdentity{BootId: "boot-1", Pid: 1, ProcessStartTime: -7},
		})
		mustBuildErr(t, err, "process_start_time")
	})
	t.Run("price_table_version_overlong", func(t *testing.T) {
		_, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityESTIMATED, PriceTableVersion: strings.Repeat("p", 65)})
		mustBuildErr(t, err, "price_table_version")
	})
	t.Run("provider_source_overlong", func(t *testing.T) {
		_, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityPROVIDERREPORTED, ProviderSource: strings.Repeat("s", 65)})
		mustBuildErr(t, err, "provider_source")
	})
}

// TestByteRangeValidated proves ByteRange start>=0 and end>=start are enforced through
// validateProvenance (both the direct-constructor and the policy projection paths).
func TestByteRangeValidated(t *testing.T) {
	t.Run("negative_start", func(t *testing.T) {
		c := testCommon()
		c.Provenance.ByteRange = &wire.ByteRange{Start: -10, End: 20}
		_, err := NewMessage(c, MessageInput{Role: wire.MessagePayloadRoleUSER})
		mustBuildErr(t, err, "byte_range.start")
	})
	t.Run("end_before_start", func(t *testing.T) {
		c := testCommon()
		c.Provenance.ByteRange = &wire.ByteRange{Start: 30, End: 20}
		_, err := NewMessage(c, MessageInput{Role: wire.MessagePayloadRoleUSER})
		mustBuildErr(t, err, "byte_range.end")
	})
	t.Run("policy_path_drops_bad_range", func(t *testing.T) {
		// The projection drops an out-of-bounds optional byte range (consistent with how it
		// drops invalid enums/paths), so the observation is still emitted — clean, and
		// without a byte_range — rather than poisoning the shared provenance into a dead result.
		p := testPolicy()
		occ := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
		env := PolicyEnvelope{OccurredAt: occ, CapturedAt: occ, Provenance: RawProvenance{ByteRange: &wire.ByteRange{Start: -1, End: 5}}}
		r := p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRoleUSER})
		if !r.HasObservation() || r.Diagnostic {
			t.Fatalf("a bad optional byte range must be dropped, not fail closed (diag=%v cause=%v)", r.Diagnostic, r.Cause)
		}
		if bytes.Contains(sealForScan(t, r, 1), []byte("byte_range")) {
			t.Fatalf("an out-of-bounds byte range must be dropped from the projection")
		}
	})
}

// TestRunContextDeepCopied proves a sealed observation is immune to post-construction
// mutation of caller-held run-context memory — including an out-of-enum membership_evidence
// that would otherwise reach canonical bytes unvalidated.
func TestRunContextDeepCopied(t *testing.T) {
	refs := []wire.WorkReference{{TeamServerProjectId: "btsproj_1", BeadId: "bd-clean", Origin: wire.WorkReferenceOriginDECLARED}}
	rc := &wire.RunContext{RunId: "gwr_clean", MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY, WorkItemRefs: &refs}
	c := testCommon()
	c.RunContext = rc

	p, err := NewMessage(c, MessageInput{Role: wire.MessagePayloadRoleASSISTANT})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	// Mutate the caller-held memory AFTER construction.
	rc.RunId = "SENTINELmutatedRUNID"
	rc.MembershipEvidence = wire.RunContextMembershipEvidence("BOGUS_NOT_A_MEMBER")
	refs[0].BeadId = "SENTINELmutatedBEAD"

	b := canonicalOf(t, sealOne(t, p, 1, "obs_1"))
	for _, s := range []string{"SENTINELmutatedRUNID", "BOGUS_NOT_A_MEMBER", "SENTINELmutatedBEAD"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("post-construction mutation reached canonical bytes (%q):\n%s", s, b)
		}
	}
	// The clean values are what sealed.
	for _, s := range []string{"gwr_clean", "bd-clean", "DECLARED_BOUNDARY"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatalf("expected clean value %q in canonical bytes:\n%s", s, b)
		}
	}
}

// TestHasObservationDeadState proves HasObservation() is false for the dead fail-closed
// result, both for an invalid Policy identity and for a valid Policy with absent timestamps.
func TestHasObservationDeadState(t *testing.T) {
	t.Run("invalid_policy_identity", func(t *testing.T) {
		var badPolicy Policy // empty adapter/version/policy
		r := badPolicy.TransformMessage(hostileEnvelope(), MessageCandidate{Role: wire.MessagePayloadRoleUSER})
		if r.HasObservation() {
			t.Fatalf("dead result must report HasObservation()==false")
		}
		if r.Dropped {
			t.Fatalf("a dead result is not a drop")
		}
		if r.Cause == nil {
			t.Fatalf("a dead result must carry a Cause")
		}
	})
	t.Run("valid_policy_absent_timestamps", func(t *testing.T) {
		p := testPolicy()
		// Valid policy, but the candidate has no timestamps — the diagnostic rebuild also
		// rejects the zero timestamps, so failClosed cannot produce an observation.
		env := PolicyEnvelope{} // zero OccurredAt/CapturedAt
		r := p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRole("NOPE")})
		if r.HasObservation() {
			t.Fatalf("dead result under valid policy must report HasObservation()==false")
		}
	})
}

// TestValidEnumErrorHasNoCandidateContent proves an adapter-cast oversized enum string does
// not ride the error/log channel (BuildError.Detail / TransformResult.Cause).
func TestValidEnumErrorHasNoCandidateContent(t *testing.T) {
	sentinel := "SENTINEL" + strings.Repeat("x", 4096)
	p := testPolicy()
	r := p.TransformMessage(hostileEnvelope(), MessageCandidate{Role: wire.MessagePayloadRole(sentinel)})
	if r.Cause == nil {
		t.Fatalf("expected a fail-closed cause")
	}
	if strings.Contains(r.Cause.Error(), sentinel) || strings.Contains(r.Cause.Error(), "SENTINEL") {
		t.Fatalf("candidate enum string leaked into the error channel: %v", r.Cause)
	}
}

// fakeTokenBody returns a deterministic pseudo-random body of n characters drawn from alphabet.
// Fixture credentials are assembled at runtime from a split scheme and this body so no literal
// token-shaped string lives in the repository (secret scanners) while the shapes stay realistic.
func fakeTokenBody(n int, alphabet string, seed uint32) string {
	var b strings.Builder
	x := seed<<1 | 1 // xorshift32 state: odd so never 0, and distinct for distinct seeds
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(alphabet[int(x%uint32(len(alphabet)))])
	}
	return b.String()
}

const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	digits     = "0123456789"
	lowerHex   = "0123456789abcdef"
)

// fakeUUID returns a deterministic UUID-shaped string (8-4-4-4-12 lowercase hex).
func fakeUUID(seed uint32) string {
	return fakeTokenBody(8, lowerHex, seed) + "-" + fakeTokenBody(4, lowerHex, seed+1) + "-" +
		fakeTokenBody(4, lowerHex, seed+2) + "-" + fakeTokenBody(4, lowerHex, seed+3) + "-" +
		fakeTokenBody(12, lowerHex, seed+4)
}

// secretFixture is a credential and the declared project prefix it would be captured under.
type secretFixture struct{ tok, prefix string }

// secretShapedFixtures are dash-joined credential shapes that the alphanumeric/dash bead tail
// grammar can match whole once a user-chosen project prefix collides with the credential scheme
// (bts-xpw.13.3.6). Each is under maxBeadID, so the length bound alone does not stop it.
func secretShapedFixtures() map[string]secretFixture {
	sk, xoxb, xoxp, xapp := "s"+"k-", "xox"+"b-", "xox"+"p-", "xap"+"p-"
	glpat, xai, pypi := "glp"+"at-", "xa"+"i-", "py"+"pi-"
	return map[string]secretFixture{
		"anthropic":       {sk + "ant-api03-" + fakeTokenBody(93, alnum, 1), sk},
		"anthropic-short": {sk + "ant-" + fakeTokenBody(12, lowerAlnum, 2), sk},
		"openai-proj":     {sk + "proj-" + fakeTokenBody(48, alnum, 3), sk},
		"slack-bot":       {xoxb + fakeTokenBody(13, digits, 4) + "-" + fakeTokenBody(13, digits, 5) + "-" + fakeTokenBody(24, alnum, 6), xoxb},
		"slack-user":      {xoxp + fakeTokenBody(12, digits, 7) + "-" + fakeTokenBody(12, digits, 8) + "-" + fakeTokenBody(13, digits, 9) + "-" + fakeTokenBody(32, lowerAlnum, 10), xoxp},
		"slack-app":       {xapp + "1-" + fakeTokenBody(11, alnum, 11) + "-" + fakeTokenBody(13, digits, 12) + "-" + fakeTokenBody(64, lowerAlnum, 13), xapp},
		"gitlab-pat":      {glpat + fakeTokenBody(20, alnum, 14), glpat},
		"gitlab-pat-lc":   {glpat + fakeTokenBody(20, lowerAlnum, 15), glpat},
		"xai":             {xai + fakeTokenBody(80, alnum, 16), xai},
		"pypi":            {pypi + fakeTokenBody(100, alnum, 17), pypi},
		// A credential under a scheme not on the list is still caught by its high-entropy body.
		"unknown-scheme": {"acme-" + fakeTokenBody(40, alnum, 18), "acme-"},
		"mixed-segment":  {"acme-" + fakeTokenBody(16, alnum, 19) + "x9Z", "acme-"},
		// UUID-bodied keys under a generic project prefix: every segment is short, so only the
		// UUID run gives them away (LaunchDarkly api-/sdk-<uuid>, Plaid access-<env>-<uuid>).
		"launchdarkly-api": {"ap" + "i-" + fakeUUID(20), "api-"},
		"launchdarkly-sdk": {"sd" + "k-" + fakeUUID(30), "sdk-"},
		"plaid-access":     {"acc" + "ess-sandbox-" + fakeUUID(40), "access-"},
	}
}

// TestSecretShapedBeadIDRejectsCredentials is the redteam fixture set for bts-xpw.13.3.6: every
// credential shape is screened by SecretShapedBeadID, both under the declared prefix it would be
// captured with and with no prefix, and NewExtractedWorkReference fails closed on it with a
// BuildError that never carries the value, even though the resolver maps its prefix.
func TestSecretShapedBeadIDRejectsCredentials(t *testing.T) {
	fixtures := secretShapedFixtures()
	var mappings []BeadPrefixMapping
	for _, f := range fixtures {
		mappings = append(mappings, BeadPrefixMapping{Prefix: f.prefix, ProjectID: "proj_" + strings.TrimSuffix(f.prefix, "-")})
	}
	pm := mustPrefixMap(t, mappings...)
	for name, f := range fixtures {
		if len(f.tok) > maxBeadID {
			t.Fatalf("%s: fixture is %d bytes; it must be under maxBeadID to exercise the screen", name, len(f.tok))
		}
		if got := pm.LongestPrefix(f.tok); got != f.prefix {
			t.Fatalf("%s: longest declared prefix is %q, want %q", name, got, f.prefix)
		}
		for _, prefix := range []string{f.prefix, ""} {
			if !SecretShapedBeadID(f.tok, prefix) {
				t.Errorf("%s: not screened as secret-shaped (declared prefix %q)", name, prefix)
			}
		}
		_, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: f.tok, DeclaredPrefix: f.prefix},
			ProjectResolver{Prefixes: pm, DefaultProjectID: "proj_default"})
		mustBuildErr(t, err, name)
		if strings.Contains(err.Error(), f.tok) || strings.Contains(err.Error(), f.tok[len(f.tok)-8:]) {
			t.Errorf("%s: build error leaks the credential: %v", name, err)
		}
	}
	// A declared prefix that swallows most of a UUID cannot hide it: the UUID check spans the
	// whole id, prefix included.
	ld := fixtures["launchdarkly-api"].tok
	if !SecretShapedBeadID(ld, ld[:strings.LastIndexByte(ld, '-')+1]) {
		t.Error("a declared prefix covering part of a UUID hid it from the screen")
	}
}

// TestSecretShapedBeadIDKeepsRealBeads: real bead ids, including ones under a prefix that
// collides with a credential scheme, are not screened even with no declared prefix to exempt.
func TestSecretShapedBeadIDKeepsRealBeads(t *testing.T) {
	for _, id := range []string{
		"ga-1tzraj", "ga-1tzraj-repair-merge", "bts-xpw.13.3.6", "ga-a1b2.1", "lego-pilot-7",
		"gas-city-9", "acme-ops-3", "ABC-123", "proj-internationalization", "bd-0a1b2c3d4e5f",
		"s" + "k-a1b2c3", "s" + "k-a1b2c3.4.12", "xox" + "b-9z", "glp" + "at-abc", "py" + "pi-3.1",
		"api-k3x", "sdk-a1b2-retry-backoff", "bd-cafe-bead-face-feed",
	} {
		if SecretShapedBeadID(id, "") {
			t.Errorf("%q: real bead id screened as secret-shaped", id)
		}
	}
	// Under a credential-colliding prefix only the strict bead shape survives.
	for _, id := range []string{
		"s" + "k-ant-a1b2", "s" + "k-a1b2-slug", "s" + "k-A1b2", "s" + "k-a1b2.", "s" + "k-a1b2.x",
		"s" + "k-" + strings.Repeat("a", maxStrictBeadHash+1),
	} {
		for _, prefix := range []string{"", "s" + "k-"} {
			if !SecretShapedBeadID(id, prefix) {
				t.Errorf("%q (declared prefix %q): credential-prefixed id outside the strict bead shape was not screened", id, prefix)
			}
		}
	}
}

// TestSecretShapedBeadIDExemptsTheDeclaredPrefix: BTS project prefixes are user-chosen, up to 32
// characters, in mixed case, and may begin with a credential scheme. Such a prefix is
// configuration, not token material, so with the declared prefix known only the rest of the id is
// screened and the project's real beads are kept. With the prefix unknown the same ids are
// screened, which is why the extractor always passes the prefix it matched.
func TestSecretShapedBeadIDExemptsTheDeclaredPrefix(t *testing.T) {
	for _, c := range []struct{ id, prefix string }{
		{"PlatformServices-a1b2", "PlatformServices-"},
		{"CustomerPortalV2-a1b2.3", "CustomerPortalV2-"},
		{"projectphoenix2026-q7x", "projectphoenix2026-"},
		{"ops-ReleaseTrain2026-x9z-cut-branch", "ops-ReleaseTrain2026-"},
		{"s" + "k-team-a1b2", "s" + "k-team-"},
		{"xa" + "i-research-a1b2.1", "xa" + "i-research-"},
		{"py" + "pi-mirror-k3", "py" + "pi-mirror-"},
	} {
		if SecretShapedBeadID(c.id, c.prefix) {
			t.Errorf("%q under declared prefix %q: real bead id screened as secret-shaped", c.id, c.prefix)
		}
		if !SecretShapedBeadID(c.id, "") {
			t.Errorf("%q: the whole-id screen (no declared prefix) did not reject it", c.id)
		}
	}
	// The exemption covers only the prefix: a credential-shaped remainder is still screened.
	for _, c := range []struct{ id, prefix string }{
		{"PlatformServices-" + fakeTokenBody(24, alnum, 50), "PlatformServices-"},
		{"s" + "k-team-a1b2-slug", "s" + "k-team-"},
		{"s" + "k-team-" + fakeTokenBody(20, lowerAlnum, 51), "s" + "k-team-"},
	} {
		if !SecretShapedBeadID(c.id, c.prefix) {
			t.Errorf("declared prefix %q: credential-shaped remainder not screened", c.prefix)
		}
	}
	// Only a dash-terminated proper prefix of the id, at most maxBeadPrefix bytes, is honored;
	// anything else falls back to screening the whole id.
	id := "PlatformServices-a1b2"
	for _, bogus := range []string{"Other-", "PlatformServices", "platformservices-", id, id + "-"} {
		if !SecretShapedBeadID(id, bogus) {
			t.Errorf("malformed declared prefix %q was honored", bogus)
		}
	}
	long := strings.Repeat("Ab1", 22) + "-"
	if !SecretShapedBeadID(long+"a1b2", long) {
		t.Errorf("a %d-byte declared prefix (max %d) was honored", len(long), maxBeadPrefix)
	}
}

// TestExtractedWorkReferenceKeepsBeadsUnderDeclaredPrefix: the constructor's fail-closed screen
// sees the declared prefix the extractor matched, so a real bead of a project with a long,
// mixed-case or credential-colliding prefix resolves to its project instead of failing closed.
func TestExtractedWorkReferenceKeepsBeadsUnderDeclaredPrefix(t *testing.T) {
	pm := mustPrefixMap(t,
		BeadPrefixMapping{Prefix: "PlatformServices-", ProjectID: "btsproj_ps"},
		BeadPrefixMapping{Prefix: "s" + "k-team-", ProjectID: "btsproj_skteam"},
	)
	for bead, want := range map[string]string{"PlatformServices-a1b2": "btsproj_ps", "s" + "k-team-a1b2.1": "btsproj_skteam"} {
		in := ExtractedWorkRefInput{BeadID: bead, DeclaredPrefix: pm.LongestPrefix(bead)}
		res, err := NewExtractedWorkReference(testCommon(), in, ProjectResolver{Prefixes: pm})
		if err != nil {
			t.Fatalf("%s: %v", bead, err)
		}
		if res.Dropped() {
			t.Fatalf("%s: dropped (%s)", bead, res.DropReason)
		}
		wr, err := sealOne(t, *res.Resolved, 1, "obs_1").AsWorkReferenceObservation()
		if err != nil || wr.WorkReference.TeamServerProjectId != want || wr.WorkReference.BeadId != bead {
			t.Errorf("%s -> %+v (%v), want project %s", bead, wr.WorkReference, err, want)
		}
		// Without its declared prefix the constructor screens the whole id and fails closed.
		_, err = NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: bead}, ProjectResolver{Prefixes: pm})
		mustBuildErr(t, err, bead+" without its declared prefix")
	}
}
