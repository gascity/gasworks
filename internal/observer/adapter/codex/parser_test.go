package codex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

var testOccurred = time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)

func testPolicy() evidence.Policy {
	return evidence.Policy{
		Adapter:        AdapterName,
		AdapterVersion: AdapterVersion,
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
}

func testEnvelope() evidence.PolicyEnvelope {
	return evidence.PolicyEnvelope{
		OccurredAt: testOccurred,
		CapturedAt: testOccurred,
		Provenance: evidence.RawProvenance{Provider: "codex", ParserVersion: ParserVersion},
	}
}

func defaultRefConfig() ReferenceConfig {
	return ReferenceConfig{
		BeadPrefixes: []string{"ga-"},
		Resolver:     evidence.ProjectResolver{DefaultProjectID: "proj_test"},
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func kindCounts(cands []*Candidate) map[CandidateKind]int {
	m := map[CandidateKind]int{}
	for _, c := range cands {
		m[c.Kind]++
	}
	return m
}

// canonicalBytes runs a candidate through the committed METADATA_ONLY policy, seals it with
// placeholder identity, and returns the canonical wire bytes. It fails the test if the
// transform does not yield a sealable observation.
func canonicalBytes(t *testing.T, c *Candidate) []byte {
	t.Helper()
	res := c.Transform(testPolicy(), testEnvelope())
	if !res.HasObservation() {
		t.Fatalf("transform of %s produced no observation (cause: %v)", c.Kind, res.Cause)
	}
	obs, err := res.Observation.Seal(wire.SequenceMin, "obs_test")
	if err != nil {
		t.Fatalf("seal %s: %v", c.Kind, err)
	}
	b, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatalf("canonical bytes %s: %v", c.Kind, err)
	}
	return b
}

func TestParseMessages(t *testing.T) {
	res := Parse(readFixture(t, "messages.jsonl"), defaultRefConfig())
	if got := kindCounts(res.Candidates); got[KindMessage] != 4 || len(res.Candidates) != 4 {
		t.Fatalf("want 4 message candidates and nothing else, got %v", got)
	}
	wantRoles := []wire.MessagePayloadRole{
		wire.MessagePayloadRoleUSER,
		wire.MessagePayloadRoleASSISTANT,
		wire.MessagePayloadRoleSYSTEM,
		wire.MessagePayloadRoleTOOL,
	}
	for i, c := range res.Candidates {
		if c.Message.Role != wantRoles[i] {
			t.Errorf("candidate %d: role = %q, want %q", i, c.Message.Role, wantRoles[i])
		}
		// The parser derives a bounded byte count from the body when the record omits one.
		if c.Message.ByteCount == nil {
			t.Errorf("candidate %d: expected a derived byte count", i)
		}
	}
	// Every message seals cleanly through policy.
	for _, c := range res.Candidates {
		canonicalBytes(t, c)
	}
}

func TestParseToolCalls(t *testing.T) {
	res := Parse(readFixture(t, "tool_calls.jsonl"), defaultRefConfig())
	// Two tool calls; the git-log command carries a full-hex-free command so no references.
	if got := kindCounts(res.Candidates); got[KindToolCall] != 2 || got[KindCommitReference] != 0 {
		t.Fatalf("want 2 tool_call candidates and 0 references, got %v", got)
	}
	if cat := res.Candidates[0].ToolCall.Category; cat != wire.ToolCallPayloadCategorySHELL {
		t.Errorf("first tool_call category = %q, want SHELL", cat)
	}
	for _, c := range res.Candidates {
		canonicalBytes(t, c)
	}
}

func TestParseToolResults(t *testing.T) {
	res := Parse(readFixture(t, "tool_results.jsonl"), defaultRefConfig())
	got := kindCounts(res.Candidates)
	if got[KindToolResult] != 2 {
		t.Fatalf("want 2 tool_result candidates, got %v", got)
	}
	// Abbreviated 7-hex shas in the git output are not extractable.
	if got[KindCommitReference] != 0 {
		t.Fatalf("abbreviated shas must not be extracted, got %d commit refs", got[KindCommitReference])
	}
	if st := res.Candidates[0].ToolResult.Status; st != wire.ToolResultPayloadStatusOK {
		t.Errorf("first tool_result status = %q, want OK", st)
	}
	for _, c := range res.Candidates {
		canonicalBytes(t, c)
	}
}

func TestParseUsage(t *testing.T) {
	res := Parse(readFixture(t, "usage.jsonl"), defaultRefConfig())
	if got := kindCounts(res.Candidates); got[KindUsage] != 2 {
		t.Fatalf("want 2 usage candidates, got %v", got)
	}
	if q := res.Candidates[1].Usage.Quality; q != wire.UsagePayloadQualityESTIMATED {
		t.Errorf("second usage quality = %q, want ESTIMATED", q)
	}
	for _, c := range res.Candidates {
		canonicalBytes(t, c)
	}
}

func TestParseLifecycleTransitions(t *testing.T) {
	res := Parse(readFixture(t, "lifecycle.jsonl"), defaultRefConfig())
	if got := kindCounts(res.Candidates); got[KindSessionLifecycle] != 4 {
		t.Fatalf("want 4 lifecycle candidates, got %v", got)
	}
	wantTransitions := []wire.SessionLifecyclePayloadTransition{
		wire.SessionLifecyclePayloadTransitionSTARTED,
		wire.SessionLifecyclePayloadTransitionRESUMED,
		wire.SessionLifecyclePayloadTransitionCLEARED,
		wire.SessionLifecyclePayloadTransitionCOMPACTED,
	}
	wantSources := []wire.SessionLifecyclePayloadStartSource{
		wire.SessionLifecyclePayloadStartSourceSTARTUP,
		wire.SessionLifecyclePayloadStartSourceRESUME,
		wire.SessionLifecyclePayloadStartSourceCLEAR,
		wire.SessionLifecyclePayloadStartSourceCOMPACT,
	}
	for i, c := range res.Candidates {
		if c.SessionLifecycle.Transition != wantTransitions[i] {
			t.Errorf("candidate %d transition = %q, want %q", i, c.SessionLifecycle.Transition, wantTransitions[i])
		}
		if c.SessionLifecycle.StartSource != wantSources[i] {
			t.Errorf("candidate %d start_source = %q, want %q", i, c.SessionLifecycle.StartSource, wantSources[i])
		}
		canonicalBytes(t, c)
	}
}

func TestParseMalformedLineIsIsolatedDiagnostic(t *testing.T) {
	res := Parse(readFixture(t, "malformed_line.jsonl"), defaultRefConfig())
	got := kindCounts(res.Candidates)
	// The valid records on either side of the malformed line are still parsed.
	if got[KindMessage] != 1 || got[KindUsage] != 1 {
		t.Fatalf("valid records must survive a malformed line, got %v", got)
	}
	if got[KindDiagnostic] != 1 {
		t.Fatalf("malformed line must yield exactly one diagnostic, got %v", got)
	}
	for _, c := range res.Candidates {
		if c.Kind != KindDiagnostic {
			continue
		}
		if c.Diagnostic.Code != wire.CaptureDiagnosticPayloadCodeUNSUPPORTEDFORMAT {
			t.Errorf("malformed diagnostic code = %q, want UNSUPPORTED_FORMAT", c.Diagnostic.Code)
		}
		// The diagnostic seals cleanly even though its record had no usable timestamp.
		canonicalBytes(t, c)
	}
}

func TestParseUnknownRecordIsUnsupportedFormat(t *testing.T) {
	res := Parse(readFixture(t, "unknown_record.jsonl"), defaultRefConfig())
	got := kindCounts(res.Candidates)
	if got[KindMessage] != 1 || got[KindUsage] != 1 {
		t.Fatalf("recognized records must still parse, got %v", got)
	}
	if got[KindDiagnostic] != 1 {
		t.Fatalf("unknown record must yield one diagnostic, got %v", got)
	}
	// No fabricated known-kind evidence for the unknown record.
	if got[KindMessage]+got[KindUsage]+got[KindDiagnostic] != len(res.Candidates) {
		t.Fatalf("unexpected candidate kinds: %v", got)
	}
	for _, c := range res.Diagnostics() {
		if c.Diagnostic.Code != wire.CaptureDiagnosticPayloadCodeUNSUPPORTEDFORMAT {
			t.Errorf("unknown-record diagnostic code = %q, want UNSUPPORTED_FORMAT", c.Diagnostic.Code)
		}
		// The diagnostic context must be content-free: it must NOT echo the raw provider field
		// value (here the unknown `type`), which could carry a secret onto the wire.
		if strings.Contains(c.Diagnostic.Context, "reasoning") {
			t.Errorf("diagnostic context leaked the raw type value: %q", c.Diagnostic.Context)
		}
		canonicalBytes(t, c)
	}
}

func TestParsePartialTrailingLineNotConsumed(t *testing.T) {
	data := readFixture(t, "partial_trailing_line.jsonl")
	res := Parse(data, defaultRefConfig())
	// Only the first, newline-terminated record is parsed.
	if len(res.Candidates) != 1 || res.Candidates[0].Kind != KindMessage {
		t.Fatalf("want exactly the first message candidate, got %v", kindCounts(res.Candidates))
	}
	// Consumed stops immediately after the first newline; the durable cursor (E1.8b) resumes
	// there and re-presents the unconsumed partial line prepended to the next read.
	firstNL := -1
	for i, b := range data {
		if b == '\n' {
			firstNL = i
			break
		}
	}
	wantConsumed := firstNL + 1
	if res.Consumed != wantConsumed {
		t.Fatalf("Consumed = %d, want %d (offset just past the first newline)", res.Consumed, wantConsumed)
	}
	if res.Consumed >= len(data) {
		t.Fatalf("Consumed must be strictly less than the buffer length when a partial line trails")
	}
}

func TestParseResumeAfterPartialLine(t *testing.T) {
	// Simulate the E1.8b cursor contract: parse a buffer whose last line is partial, then feed
	// the unconsumed remainder plus the completing bytes and confirm the record parses once.
	data := readFixture(t, "partial_trailing_line.jsonl")
	first := Parse(data, defaultRefConfig())

	remainder := data[first.Consumed:]
	completion := append(append([]byte{}, remainder...), []byte("\",\"ts\":\"2026-07-17T10:00:01Z\"}\n")...)
	second := Parse(completion, defaultRefConfig())
	if len(second.Candidates) != 1 || second.Candidates[0].Kind != KindToolCall {
		t.Fatalf("completed partial line should parse as one tool_call, got %v", kindCounts(second.Candidates))
	}
	if second.Consumed != len(completion) {
		t.Fatalf("Consumed = %d, want full completion length %d", second.Consumed, len(completion))
	}
}

func TestMetadataOnlyPolicyStripsEveryChannel(t *testing.T) {
	// Sentinels planted in every content channel the parser touches: message/tool bodies AND the
	// rejected discriminator fields that feed a CAPTURE_DIAGNOSTIC context (finding-2 hex-secret
	// channel). The two discriminator sentinels are real 40/64-hex so they survive the
	// path-only context sanitizer if echoed — proving the fix, not the sanitizer, closes it.
	const (
		msgSentinel  = "SENTINEL_MESSAGE_BODY_9f1"
		cmdSentinel  = "SENTINEL_COMMAND_TEXT_2a7"
		outSentinel  = "SENTINEL_TOOL_OUTPUT_5c3"
		typeSecret   = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"                         // 40-hex in a rejected type
		roleSecret   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // 64-hex in a rejected role
		statusSecret = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe" // 64-hex in a rejected status
	)
	transcript := strings.Join([]string{
		`{"type":"message","role":"assistant","text":"` + msgSentinel + ` do not leak","ts":"2026-07-17T10:00:00Z"}`,
		`{"type":"tool_call","tool":"git","category":"SHELL","command":"git commit -m ` + cmdSentinel + `","ts":"2026-07-17T10:00:01Z"}`,
		`{"type":"tool_result","tool":"git","category":"SHELL","status":"OK","output":"` + outSentinel + ` body text","ts":"2026-07-17T10:00:02Z"}`,
		`{"type":"usage","quality":"PROVIDER_REPORTED","input_tokens":5,"provider_source":"codex","ts":"2026-07-17T10:00:03Z"}`,
		`{"type":"session","transition":"STARTED","start_source":"STARTUP","session_id":"s","provider":"codex","model":"m","ts":"2026-07-17T10:00:04Z"}`,
		`{"type":"` + typeSecret + `","ts":"2026-07-17T10:00:05Z"}`,
		`{"type":"message","role":"` + roleSecret + `","text":"x","ts":"2026-07-17T10:00:06Z"}`,
		`{"type":"tool_result","tool":"git","category":"SHELL","status":"` + statusSecret + `","output":"y","ts":"2026-07-17T10:00:07Z"}`,
		"",
	}, "\n")

	res := Parse([]byte(transcript), defaultRefConfig())
	// Expect: message, tool_call, tool_result, usage, session, plus three diagnostics (unknown
	// type, bad role, bad status). Every emitted candidate is sealed and scanned.
	if got := kindCounts(res.Candidates); got[KindDiagnostic] != 3 {
		t.Fatalf("want 3 diagnostics from the rejected-discriminator records, got %v", got)
	}
	sentinels := []string{msgSentinel, cmdSentinel, outSentinel, typeSecret, roleSecret, statusSecret}
	for _, c := range res.Candidates {
		got := string(canonicalBytes(t, c))
		for _, sentinel := range sentinels {
			if strings.Contains(got, sentinel) {
				t.Fatalf("sentinel %q leaked into canonical bytes of %s: %s", sentinel, c.Kind, got)
			}
		}
	}
}
