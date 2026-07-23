package evidence

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// The load-bearing acceptance for deliverable 2: adversarial adapter candidates carrying
// every forbidden content class are transformed, sealed, and canonically encoded, and the
// exact wire bytes are scanned for the planted sentinels. None may survive. Outcome payloads
// are rejected at the wire boundary, and absent-not-empty is proven over the canonical bytes.

const (
	sentMessageBody   = "SENTINELmessageBODYtext"
	sentCommand       = "SENTINELrmDASHrfCOMMAND"
	sentArgv          = "SENTINELargvSECRET"
	sentEnvKey        = "SENTINELenvKEY"
	sentEnvVal        = "SENTINELenvVALUE"
	sentURL           = "https://sentinel.example/SECRETpath"
	sentMCPName       = "SENTINELcustomMCPname"
	sentResultBody    = "SENTINELtoolRESULTbody"
	sentAbsPath       = "/home/alice/SENTINELsecretPATH/rollout.jsonl"
	sentPrompt        = "SENTINELignorePREVIOUSinstructions"
	sentExecPath      = "/usr/local/bin/SENTINELexecPATH"
	sentDiagAbsPath   = "/var/run/SENTINELdiagPATH"
	hex32             = "0123456789abcdef0123456789abcdef"
	hex40             = "0123456789abcdef0123456789abcdef01234567"
	hex64             = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	relativeLocator   = "codex/2026/07/16/rollout.jsonl"
	stampedProject    = "btsproj_stamped01"
	extractedBeadSent = "SENTINELextractedBEAD"
)

// allSentinels are the planted content strings that must NEVER appear in any output.
var allSentinels = []string{
	sentMessageBody, sentCommand, sentArgv, sentEnvKey, sentEnvVal, sentURL,
	sentMCPName, sentResultBody, sentAbsPath, sentPrompt, sentExecPath,
	sentDiagAbsPath, hex32, hex40, hex64,
	"outcome", // no observation kind carries a run outcome; it must not appear either
}

func testPolicy() Policy {
	return Policy{
		Adapter:        "codex-hook",
		AdapterVersion: "1.0.0",
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     DefaultExtractionConfig(),
	}
}

// hostileEnvelope plants absolute-path and raw-hash sentinels in the provenance candidate,
// alongside a legitimate root-relative locator.
func hostileEnvelope() PolicyEnvelope {
	occ := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
	return PolicyEnvelope{
		OccurredAt: occ,
		CapturedAt: occ.Add(80 * time.Millisecond),
		Provenance: RawProvenance{
			Provider:            "codex",
			NativeSessionID:     "019f6979-1a2b-7c3d-8e4f-5a6b7c8d9e0f",
			RootRelativeLocator: relativeLocator,
			AbsolutePath:        sentAbsPath,
			SourceHash:          hex64,
		},
	}
}

func sealForScan(t *testing.T, r TransformResult, seq int64) []byte {
	t.Helper()
	if !r.HasObservation() {
		t.Fatalf("transform produced no observation (dropped=%v cause=%v)", r.Dropped, r.Cause)
	}
	o, err := r.Observation.Seal(seq, "obs_scan")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := wire.CanonicalBytes(o)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	return b
}

// TestMetadataPolicyStripsAllForbiddenContent is the sentinel-scan proof. It runs one
// adversarial candidate per content-bearing kind through the METADATA_ONLY transform and
// asserts no planted sentinel survives into any observation's canonical bytes.
func TestMetadataPolicyStripsAllForbiddenContent(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	bc := int64(len(hex64))

	results := map[string]TransformResult{
		"message": p.TransformMessage(env, MessageCandidate{
			Role:      wire.MessagePayloadRoleUSER,
			ByteCount: &bc,
			Body:      sentMessageBody + hex64,
		}),
		"tool_call": p.TransformToolCall(env, ToolCallCandidate{
			Category:    wire.ToolCallPayloadCategorySHELL,
			Command:     sentCommand + hex40,
			Argv:        []string{sentArgv, hex40},
			Environment: map[string]string{sentEnvKey: sentEnvVal},
			URL:         sentURL,
			MCPName:     sentMCPName,
		}),
		"tool_result": p.TransformToolResult(env, ToolResultCandidate{
			Category:   wire.ToolResultPayloadCategoryFILE,
			Status:     wire.ToolResultPayloadStatusOK,
			ResultBody: sentResultBody + hex32,
		}),
		"run_started": p.TransformRunStarted(env, RunStartedCandidate{
			RunID:          "gwr_1",
			BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
			Argv:           []string{"--prompt", sentPrompt},
			Environment:    map[string]string{sentEnvKey: sentEnvVal},
		}),
		"run_ended_drain": p.TransformRunEndedDrain(env, RunEndedDrainCandidate{
			RunID:          "gwr_1",
			BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
			DrainStatus:    wire.RunEndedBoundaryDrainStatusCOMPLETE,
			CoveredWatermark: wire.Watermark{
				ByteOffset:    4096,
				SourceLocator: strptr(sentAbsPath), // absolute -> dropped
			},
		}),
		"process": p.TransformProcessLifecycle(env, ProcessLifecycleCandidate{
			Transition:     wire.ProcessLifecyclePayloadTransitionPROCESSEXITED,
			Identity:       wire.ProcessIdentity{BootId: "boot-1", Pid: 4242, ProcessStartTime: 999},
			ExitCode:       i32ptr(0),
			Argv:           []string{sentArgv, sentPrompt},
			Environment:    map[string]string{sentEnvKey: sentEnvVal},
			ExecutablePath: sentExecPath,
		}),
		"diagnostic": p.TransformCaptureDiagnostic(env, DiagnosticCandidate{
			Code:               wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE,
			Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
			CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
			Context:            "dropped near " + sentDiagAbsPath, // absolute path -> whole context dropped
		}),
		// The four non-content kinds share the same provenance projection; route the hostile
		// envelope through them too so provenance stripping is pinned for every constructor.
		"usage": p.TransformUsage(env, UsageCandidate{Quality: wire.UsagePayloadQualityPROVIDERREPORTED}),
		"session_lifecycle": p.TransformSessionLifecycle(env, SessionLifecycleCandidate{
			NativeSessionID: "019f-native",
			Provider:        "codex",
			StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
			Transition:      wire.SessionLifecyclePayloadTransitionSTARTED,
		}),
		"declared_work_reference": p.TransformDeclaredWorkReference(env, DeclaredWorkReferenceCandidate{
			TeamServerProjectID: "btsproj_01",
			BeadID:              "bd-1",
		}),
		"run_ended_launch_failure": p.TransformRunEndedLaunchFailure(env, RunEndedLaunchFailureCandidate{
			RunID:          "gwr_1",
			BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		}),
	}

	var seq int64
	for name, r := range results {
		seq++
		b := sealForScan(t, r, seq)
		if r.Diagnostic {
			t.Fatalf("%s: expected a clean observation, got a fail-closed diagnostic (cause=%v)", name, r.Cause)
		}
		for _, s := range allSentinels {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("%s: forbidden content %q survived into canonical bytes:\n%s", name, s, b)
			}
		}
	}
}

// TestPolicyKeepsAllowedMetadata proves the transform is a projection, not a blanket wipe:
// the allowed bounded metadata (role, category, counts, native session id, relative locator)
// survives so the observation is still useful.
func TestPolicyKeepsAllowedMetadata(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	bc := int64(128)
	b := sealForScan(t, p.TransformMessage(env, MessageCandidate{
		Role:      wire.MessagePayloadRoleASSISTANT,
		ByteCount: &bc,
		Body:      sentMessageBody,
	}), 1)
	for _, want := range []string{`"role":"ASSISTANT"`, `"byte_count":128`, relativeLocator, `"content_policy":"METADATA_ONLY"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("expected allowed metadata %q in canonical bytes:\n%s", want, b)
		}
	}
	// The absolute path and raw hash from the same envelope are gone.
	if bytes.Contains(b, []byte(sentAbsPath)) || bytes.Contains(b, []byte("source_hash")) {
		t.Fatalf("provenance leaked an absolute path or source_hash:\n%s", b)
	}
}

// TestPolicyAbsentNotEmpty proves optional fields left empty in the candidate become absent
// in the output — never an empty-string value — across every content policy path.
func TestPolicyAbsentNotEmpty(t *testing.T) {
	p := testPolicy()
	occ := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
	// A minimal envelope: no provider, no locator, no optional provenance at all.
	env := PolicyEnvelope{OccurredAt: occ, CapturedAt: occ}

	cases := map[string][]byte{
		"message_no_counts": sealForScan(t, p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRoleUSER}), 1),
		"session_no_model": sealForScan(t, p.TransformSessionLifecycle(env, SessionLifecycleCandidate{
			NativeSessionID: "n1", Provider: "codex",
			StartSource: wire.SessionLifecyclePayloadStartSourceSTARTUP,
			Transition:  wire.SessionLifecyclePayloadTransitionSTARTED,
			Model:       "",
		}), 1),
		"usage_no_optionals": sealForScan(t, p.TransformUsage(env, UsageCandidate{Quality: wire.UsagePayloadQualityPROVIDERREPORTED}), 1),
	}
	// The keys for empty optionals must be wholly absent, and no empty-string value may
	// appear anywhere in the canonical bytes.
	absentKeys := map[string][]string{
		"message_no_counts":  {`"byte_count"`, `"token_count"`, `"content"`},
		"session_no_model":   {`"model"`},
		"usage_no_optionals": {`"input_tokens"`, `"price_table_version"`, `"provider_source"`},
	}
	for name, b := range cases {
		if bytes.Contains(b, []byte(`:""`)) {
			t.Fatalf("%s: canonical bytes carry an empty-string value:\n%s", name, b)
		}
		for _, k := range absentKeys[name] {
			if bytes.Contains(b, []byte(k)) {
				t.Fatalf("%s: absent optional %q must not appear:\n%s", name, k, b)
			}
		}
	}
	// An empty provider on provenance is also absent (not "provider":"").
	if bytes.Contains(cases["message_no_counts"], []byte(`"provider"`)) {
		t.Fatalf("empty provider must be absent:\n%s", cases["message_no_counts"])
	}
}

// TestPolicyFailsClosed proves that a transform error yields a content-free
// CAPTURE_DIAGNOSTIC substitute — never raw content and never a malformed observation.
func TestPolicyFailsClosed(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	// An out-of-enum role cannot build a MESSAGE; the transform must fail closed.
	r := p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRole("NOTAROLE"), Body: sentMessageBody})
	if !r.Diagnostic {
		t.Fatalf("expected a fail-closed diagnostic, got clean observation")
	}
	if r.Observation.Kind() != "CAPTURE_DIAGNOSTIC" {
		t.Fatalf("fail-closed substitute must be a CAPTURE_DIAGNOSTIC, got %q", r.Observation.Kind())
	}
	if r.Cause == nil {
		t.Fatal("fail-closed result should carry the underlying cause for logging")
	}
	b := sealForScan(t, r, 1)
	for _, s := range allSentinels {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("fail-closed diagnostic leaked %q:\n%s", s, b)
		}
	}
}

// TestPolicyFailsClosedOnBadStampedContext proves a malformed daemon-stamped run context
// fails closed to a diagnostic that carries no run context at all.
func TestPolicyFailsClosedOnBadStampedContext(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	env.RunContext = &wire.RunContext{RunId: "gwr_1", MembershipEvidence: wire.RunContextMembershipEvidence("BOGUS")}
	r := p.TransformMessage(env, MessageCandidate{Role: wire.MessagePayloadRoleUSER})
	if !r.Diagnostic || r.Observation.Kind() != "CAPTURE_DIAGNOSTIC" {
		t.Fatalf("expected fail-closed diagnostic for a bad stamped context")
	}
	b := sealForScan(t, r, 1)
	if bytes.Contains(b, []byte(`"run_context"`)) {
		t.Fatalf("fail-closed diagnostic must not carry a run context:\n%s", b)
	}
}

// TestExtractionTogglesGateReferences proves the per-ref-kind toggles gate which reference
// observations pass policy: off drops entirely (no observation), on produces one.
func TestExtractionTogglesGateReferences(t *testing.T) {
	env := hostileEnvelope()
	extraction := wire.ExtractionProvenance{
		Surface: wire.ExtractionProvenanceSurfaceTOOLRESULT, PatternId: "git-log-oneline", ExtractorVersion: "1",
	}

	t.Run("commit_off_drops", func(t *testing.T) {
		p := testPolicy()
		p.Extraction.Commit = false
		r := p.TransformCommitReference(env, CommitReferenceCandidate{Identifier: hex40, Extraction: extraction})
		if !r.Dropped || r.HasObservation() {
			t.Fatalf("commit toggle off must drop the reference (dropped=%v)", r.Dropped)
		}
	})
	t.Run("commit_on_passes", func(t *testing.T) {
		p := testPolicy()
		r := p.TransformCommitReference(env, CommitReferenceCandidate{Identifier: hex40, Extraction: extraction})
		if r.Dropped || !r.HasObservation() {
			t.Fatalf("commit toggle on must pass the reference")
		}
		if r.Observation.Kind() != "VCS_REFERENCE" {
			t.Fatalf("expected VCS_REFERENCE, got %q", r.Observation.Kind())
		}
	})
	t.Run("pull_request_off_drops", func(t *testing.T) {
		p := testPolicy()
		p.Extraction.PullRequest = false
		r := p.TransformPullRequestReference(env, PullRequestReferenceCandidate{Identifier: "#42", Extraction: extraction})
		if !r.Dropped {
			t.Fatal("pull-request toggle off must drop the reference")
		}
	})
	t.Run("bead_id_off_drops", func(t *testing.T) {
		p := testPolicy()
		p.Extraction.BeadID = false
		r := p.TransformExtractedWorkReference(env, ExtractedWorkReferenceCandidate{
			BeadID:   "bd-9",
			Resolver: ProjectResolver{StampedProjectID: stampedProject},
		})
		if !r.Dropped {
			t.Fatal("bead-id toggle off must drop the reference")
		}
	})
}

// TestExtractedWorkReferencePolicyDrop proves the project-resolution drop path through the
// policy transform emits a content-free diagnostic (no bead id) rather than a partial ref.
func TestExtractedWorkReferencePolicyDrop(t *testing.T) {
	p := testPolicy()
	env := hostileEnvelope()
	r := p.TransformExtractedWorkReference(env, ExtractedWorkReferenceCandidate{
		BeadID:   extractedBeadSent,
		Resolver: ProjectResolver{}, // unresolvable
	})
	if !r.Diagnostic {
		t.Fatalf("unresolvable extracted reference must emit a drop diagnostic")
	}
	b := sealForScan(t, r, 1)
	if bytes.Contains(b, []byte(extractedBeadSent)) {
		t.Fatalf("drop diagnostic leaked the bead id:\n%s", b)
	}
	// And a resolvable one becomes a real EXTRACTED reference carrying the stamped project.
	r2 := p.TransformExtractedWorkReference(env, ExtractedWorkReferenceCandidate{
		BeadID:   "bd-ok",
		Resolver: ProjectResolver{StampedProjectID: stampedProject},
	})
	if r2.Diagnostic || r2.Dropped {
		t.Fatalf("resolvable extracted reference must pass")
	}
	b2 := sealForScan(t, r2, 1)
	if !bytes.Contains(b2, []byte(stampedProject)) {
		t.Fatalf("extracted reference must carry the stamped project:\n%s", b2)
	}
}

// TestOutcomePayloadsRejected proves the wire boundary rejects any attempt to smuggle a run
// outcome: an unknown RUN_OUTCOME kind and an extra outcome field on a RUN_ENDED boundary
// are both rejected by the strict decoder the endpoint runs before any WAL append.
func TestOutcomePayloadsRejected(t *testing.T) {
	t.Run("run_outcome_kind_unknown", func(t *testing.T) {
		batch := []byte(`{"schema_version":1,"source_id":"src_x","first_sequence":1,"last_sequence":1,
			"observations":[{"sequence":1,"observation_id":"obs_1","kind":"RUN_OUTCOME",
			"occurred_at":"2026-07-16T10:01:00Z","captured_at":"2026-07-16T10:01:00Z",
			"provenance":{"adapter":"codex-hook","adapter_version":"1.0.0","content_policy":"METADATA_ONLY"},
			"run_outcome":{"outcome":"SUCCEEDED"}}]}`)
		if _, err := wire.DecodeObservationBatch(batch); err == nil {
			t.Fatal("a RUN_OUTCOME observation kind must be rejected")
		} else if !errors.Is(err, wire.ErrUnknownDiscriminator) {
			t.Fatalf("want ErrUnknownDiscriminator, got %v", err)
		}
	})
	t.Run("outcome_field_on_run_ended_unknown_field", func(t *testing.T) {
		batch := []byte(`{"schema_version":1,"source_id":"src_x","first_sequence":1,"last_sequence":1,
			"observations":[{"sequence":1,"observation_id":"obs_1","kind":"RUN_BOUNDARY",
			"occurred_at":"2026-07-16T10:01:00Z","captured_at":"2026-07-16T10:01:00Z",
			"provenance":{"adapter":"codex-hook","adapter_version":"1.0.0","content_policy":"METADATA_ONLY"},
			"run_boundary":{"transition":"RUN_ENDED","boundary_source":"EXPLICIT_WRAPPER","run_id":"gwr_1","outcome":"SUCCEEDED"}}]}`)
		if _, err := wire.DecodeObservationBatch(batch); err == nil {
			t.Fatal("an outcome field on a RUN_ENDED boundary must be rejected")
		} else if !errors.Is(err, wire.ErrUnknownField) {
			t.Fatalf("want ErrUnknownField, got %v", err)
		}
	})
}

func strptr(s string) *string { return &s }
func i32ptr(v int32) *int32   { return &v }
