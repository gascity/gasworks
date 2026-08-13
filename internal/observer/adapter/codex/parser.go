package codex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// ParserVersion is the versioned transcript-parser identity, stamped into provenance as the
// parser_version. Codex warns that its transcript format is not a stable hook interface, so
// parsing is adapter-versioned and fixture-pinned: a record shape this version does not
// recognize degrades to an UNSUPPORTED_FORMAT diagnostic rather than being coerced into a known
// kind. It is distinct from the adapter contract version (AdapterVersion) and the reference
// extractor version (ExtractorVersion); bump it whenever the recognized record grammar changes.
const ParserVersion = "codex-transcript-v1"

// The recognized transcript record grammar (adapter version codex-transcript-v1). Each JSONL
// line is one record object discriminated by "type". Fields not listed are ignored (the format
// is allowed to grow additively without forcing an UNSUPPORTED_FORMAT), but an unknown "type",
// an empty "type", or a line that is not valid JSON is an unrecognized record.
//
//	{"type":"message","role":"user|assistant|system|tool","text":"...","token_count":N,"ts":"RFC3339"}
//	{"type":"tool_call","tool":"git","category":"SHELL","command":"git show <sha>","argument_bytes":N,"ts":...}
//	{"type":"tool_result","tool":"git","category":"SHELL","status":"OK","output":"...","result_bytes":N,"ts":...}
//	{"type":"usage","quality":"PROVIDER_REPORTED","input_tokens":N,"output_tokens":N,"provider_source":"...","ts":...}
//	{"type":"session","transition":"STARTED","start_source":"STARTUP","session_id":"...","provider":"codex","model":"...","ts":...}
const (
	recMessage    = "message"
	recToolCall   = "tool_call"
	recToolResult = "tool_result"
	recUsage      = "usage"
	recSession    = "session"
)

// CandidateKind names which evidence candidate a parsed record carries. It mirrors the wire
// observation kinds the record projects to; a KindDiagnostic candidate is an in-band record of
// an unrecognized or over-capacity input, never fabricated evidence.
type CandidateKind string

// The closed set of candidate kinds this adapter emits.
const (
	KindMessage              CandidateKind = "MESSAGE"
	KindToolCall             CandidateKind = "TOOL_CALL"
	KindToolResult           CandidateKind = "TOOL_RESULT"
	KindUsage                CandidateKind = "USAGE"
	KindSessionLifecycle     CandidateKind = "SESSION_LIFECYCLE"
	KindCommitReference      CandidateKind = "COMMIT_REFERENCE"
	KindPullRequestReference CandidateKind = "PULL_REQUEST_REFERENCE"
	KindWorkReference        CandidateKind = "WORK_REFERENCE"
	KindDiagnostic           CandidateKind = "CAPTURE_DIAGNOSTIC"
)

// Candidate is a single parsed transcript record, ready to run through the committed evidence
// Policy transform. Exactly one of the typed pointers is non-nil, selected by Kind. The struct
// still carries the raw forbidden content (a message body, a command, a tool output) inside its
// embedded evidence candidate; the Policy transform is the choke point that strips it — the
// parser never itself decides what leaves the endpoint.
type Candidate struct {
	Kind CandidateKind
	// OccurredAt is the provider event time parsed from the record ("ts"); it is the zero time
	// when the record omits a timestamp, in which case Transform falls back to the envelope's
	// caller-owned CapturedAt so a diagnostic is never dropped for want of a timestamp.
	OccurredAt time.Time
	// LineNumber is the 1-based source line the record was parsed from, for endpoint-side
	// debugging only; it never reaches the wire.
	LineNumber int

	Message          *evidence.MessageCandidate
	ToolCall         *evidence.ToolCallCandidate
	ToolResult       *evidence.ToolResultCandidate
	Usage            *evidence.UsageCandidate
	SessionLifecycle *evidence.SessionLifecycleCandidate
	Commit           *evidence.CommitReferenceCandidate
	PullRequest      *evidence.PullRequestReferenceCandidate
	Work             *evidence.ExtractedWorkReferenceCandidate
	Diagnostic       *evidence.DiagnosticCandidate
}

// Transform routes the candidate through the matching committed Policy transform, returning the
// policy-clean observation (or a fail-closed / gated result). The candidate's OccurredAt wins
// over the envelope's when set; an unstamped candidate falls back to the envelope's
// caller-owned CapturedAt for both timestamps so the transform always has a valid Common.
func (c *Candidate) Transform(p evidence.Policy, env evidence.PolicyEnvelope) evidence.TransformResult {
	if !c.OccurredAt.IsZero() {
		env.OccurredAt = c.OccurredAt
	}
	if env.OccurredAt.IsZero() {
		env.OccurredAt = env.CapturedAt
	}
	if env.CapturedAt.IsZero() {
		env.CapturedAt = env.OccurredAt
	}
	switch c.Kind {
	case KindMessage:
		return p.TransformMessage(env, *c.Message)
	case KindToolCall:
		return p.TransformToolCall(env, *c.ToolCall)
	case KindToolResult:
		return p.TransformToolResult(env, *c.ToolResult)
	case KindUsage:
		return p.TransformUsage(env, *c.Usage)
	case KindSessionLifecycle:
		return p.TransformSessionLifecycle(env, *c.SessionLifecycle)
	case KindCommitReference:
		return p.TransformCommitReference(env, *c.Commit)
	case KindPullRequestReference:
		return p.TransformPullRequestReference(env, *c.PullRequest)
	case KindWorkReference:
		return p.TransformExtractedWorkReference(env, *c.Work)
	case KindDiagnostic:
		return p.TransformCaptureDiagnostic(env, *c.Diagnostic)
	default:
		return p.TransformCaptureDiagnostic(env, unsupportedDiagnostic("candidate has unknown kind"))
	}
}

// ParseResult is the outcome of parsing a transcript byte slice: the ordered candidates (with
// any in-band diagnostics) and the consumed byte count.
type ParseResult struct {
	// Candidates are the parsed records in transcript order, including KindDiagnostic entries
	// for unrecognized records and reference-cap overflows.
	Candidates []*Candidate
	// Consumed is the number of leading bytes fully parsed: the offset just past the last
	// newline. A partial trailing line (bytes after the last newline, with no newline of its
	// own) is deliberately NOT parsed, and Consumed stops before it. The durable cursor
	// (E1.8b) advances by exactly this many bytes and re-presents the unconsumed remainder
	// prepended to the next read, so a record split across two reads is parsed exactly once.
	Consumed int
}

// Diagnostics returns just the diagnostic candidates, in order — a convenience for callers that
// want to count or surface unrecognized-record/overflow events without walking every candidate.
func (r ParseResult) Diagnostics() []*Candidate {
	var out []*Candidate
	for _, c := range r.Candidates {
		if c.Kind == KindDiagnostic {
			out = append(out, c)
		}
	}
	return out
}

// Parse consumes a transcript byte slice and emits the ordered candidates plus the consumed
// byte offset. It parses complete newline-terminated lines only; the final line is parsed only
// if it ends in a newline. The scan is single-pass and O(len(data)), so a caller that feeds
// only the bytes appended since the last cursor does O(new bytes) of work. Blank lines are
// consumed but produce no candidate; every non-blank complete line produces at least one
// candidate (a real record, or a diagnostic when the record is unrecognized).
func Parse(data []byte, cfg ReferenceConfig) ParseResult {
	st := newParseState(data)
	var cands []*Candidate
	consumed := 0
	lineNo := 0
	for {
		nl := bytes.IndexByte(data[consumed:], '\n')
		if nl < 0 {
			// No further newline: the remaining bytes are an incomplete trailing line. Do not
			// parse them; Consumed stops here so the cursor resumes at exactly this offset.
			break
		}
		line := data[consumed : consumed+nl]
		consumed += nl + 1
		lineNo++
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		cands = append(cands, st.parseLine(trimmed, lineNo, cfg)...)
	}
	return ParseResult{Candidates: cands, Consumed: consumed}
}

// ParseReader is the io.Reader convenience wrapper over Parse. It reads the reader to EOF and
// then parses the whole buffer; callers that need incremental cursor resumption should feed
// Parse the appended-bytes slice directly rather than re-reading from the start.
func ParseReader(r io.Reader, cfg ReferenceConfig) (ParseResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return ParseResult{}, fmt.Errorf("reading codex transcript: %w", err)
	}
	return Parse(data, cfg), nil
}

// rawRecord is the union of every recognized transcript record shape. All fields are optional at
// the JSON layer; which are meaningful is decided by Type. Unknown JSON fields are ignored so
// the format can grow additively without tripping UNSUPPORTED_FORMAT.
type rawRecord struct {
	Type      string     `json:"type"`
	Timestamp *time.Time `json:"ts"`

	// message
	Role       string `json:"role"`
	Text       string `json:"text"`
	ByteCount  *int64 `json:"byte_count"`
	TokenCount *int64 `json:"token_count"`

	// tool_call / tool_result
	Tool          string `json:"tool"`
	Category      string `json:"category"`
	Command       string `json:"command"`
	Output        string `json:"output"`
	Status        string `json:"status"`
	ArgumentBytes *int64 `json:"argument_bytes"`
	ResultBytes   *int64 `json:"result_bytes"`

	// usage
	Quality             string `json:"quality"`
	InputTokens         *int64 `json:"input_tokens"`
	OutputTokens        *int64 `json:"output_tokens"`
	CacheCreationTokens *int64 `json:"cache_creation_tokens"`
	CacheReadTokens     *int64 `json:"cache_read_tokens"`
	ProviderSource      string `json:"provider_source"`
	PriceTableVersion   string `json:"price_table_version"`

	// session
	SessionID   string `json:"session_id"`
	Provider    string `json:"provider"`
	Transition  string `json:"transition"`
	StartSource string `json:"start_source"`
	Model       string `json:"model"`
}

// formatProbe reads only the discriminating fields shared across the three real transcript
// dialects this adapter now recognizes natively, so one Unmarshal can route a line without
// coercing it into the wrong grammar:
//
//   - normalized codex-transcript-v1 (Type in the recognized normalized set; parsed by rawRecord);
//   - raw Codex rollout-*.jsonl (every record carries a "payload"; SESSION_LIFECYCLE + USAGE are
//     projected from session_meta / event_msg{token_count} natively — no external translate step);
//   - Claude Code transcripts (per-message envelopes carrying "sessionId" and a "message" block
//     with the provider "usage" and "model").
//
// The three are structurally disjoint — normalized uses a closed "type" set, rollout uniquely
// carries "payload", and Claude uniquely carries the camelCase "sessionId"/"message" — so the
// route is unambiguous and a line that matches none degrades to an UNSUPPORTED_FORMAT diagnostic.
type formatProbe struct {
	Type           string          `json:"type"`
	Payload        json.RawMessage `json:"payload"`   // rollout
	SessionIDCamel string          `json:"sessionId"` // Claude envelope
	Message        json.RawMessage `json:"message"`   // Claude message block
	TS             *time.Time      `json:"ts"`        // normalized / Claude-absent
	Timestamp      *time.Time      `json:"timestamp"` // rollout / Claude
}

// probeTime resolves the record's provider event time from whichever timestamp key the dialect
// uses ("ts" for normalized, "timestamp" for rollout and Claude), zero when absent.
func (p formatProbe) probeTime() time.Time {
	if p.TS != nil {
		return *p.TS
	}
	if p.Timestamp != nil {
		return *p.Timestamp
	}
	return time.Time{}
}

// isNormalizedType reports whether a top-level type names a normalized codex-transcript-v1 record.
func isNormalizedType(t string) bool {
	switch t {
	case recMessage, recToolCall, recToolResult, recUsage, recSession:
		return true
	default:
		return false
	}
}

// parseLine routes one transcript line to the dialect-specific parser. It is a method on
// parseState because the rollout and Claude dialects thread a one-per-buffer SESSION_LIFECYCLE
// (the session id and model live on different records than the usage that must inherit them).
func (st *parseState) parseLine(line []byte, lineNo int, cfg ReferenceConfig) []*Candidate {
	var probe formatProbe
	if err := json.Unmarshal(line, &probe); err != nil {
		return []*Candidate{diagnosticCandidate(time.Time{}, lineNo, "malformed transcript line: not valid JSON")}
	}
	switch {
	case isNormalizedType(probe.Type):
		return parseNormalizedLine(line, lineNo, cfg)
	case len(probe.Payload) > 0:
		return st.parseRolloutLine(probe, lineNo, cfg)
	case probe.SessionIDCamel != "" || len(probe.Message) > 0:
		return st.parseClaudeLine(probe, lineNo, cfg)
	default:
		return []*Candidate{diagnosticCandidate(probe.probeTime(), lineNo, "unsupported transcript record type")}
	}
}

// parseNormalizedLine parses one normalized codex-transcript-v1 record (the schema this adapter
// was born reading). It is unchanged from the original single-grammar parser.
func parseNormalizedLine(line []byte, lineNo int, cfg ReferenceConfig) []*Candidate {
	var rec rawRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return []*Candidate{diagnosticCandidate(time.Time{}, lineNo, "malformed transcript line: not valid JSON")}
	}
	var ts time.Time
	if rec.Timestamp != nil {
		ts = *rec.Timestamp
	}
	switch rec.Type {
	case recMessage:
		return parseMessage(rec, ts, lineNo)
	case recToolCall:
		return parseToolCall(rec, ts, lineNo, cfg)
	case recToolResult:
		return parseToolResult(rec, ts, lineNo, cfg)
	case recUsage:
		return parseUsage(rec, ts, lineNo)
	case recSession:
		return parseSession(rec, ts, lineNo)
	default:
		return []*Candidate{diagnosticCandidate(ts, lineNo, "unsupported transcript record type")}
	}
}

func parseMessage(rec rawRecord, ts time.Time, lineNo int) []*Candidate {
	role, ok := messageRole(rec.Role)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "message record with unrecognized role")}
	}
	byteCount := rec.ByteCount
	if byteCount == nil && rec.Text != "" {
		n := int64(len(rec.Text))
		byteCount = &n
	}
	// Body is carried through so the Policy transform (METADATA_ONLY) is the single point that
	// strips it. Reference extraction never runs over MESSAGE prose.
	return []*Candidate{{
		Kind:       KindMessage,
		OccurredAt: ts,
		LineNumber: lineNo,
		Message:    &evidence.MessageCandidate{Role: role, ByteCount: byteCount, TokenCount: rec.TokenCount, Body: rec.Text},
	}}
}

func parseToolCall(rec rawRecord, ts time.Time, lineNo int, cfg ReferenceConfig) []*Candidate {
	category, ok := toolCallCategory(rec.Category)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "tool_call record with unrecognized category")}
	}
	argBytes := rec.ArgumentBytes
	if argBytes == nil && rec.Command != "" {
		n := int64(len(rec.Command))
		argBytes = &n
	}
	out := []*Candidate{{
		Kind:       KindToolCall,
		OccurredAt: ts,
		LineNumber: lineNo,
		ToolCall:   &evidence.ToolCallCandidate{Category: category, ArgumentByteCount: argBytes, Command: rec.Command},
	}}
	out = append(out, extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLCALL, SurfaceText{Tool: rec.Tool, Text: rec.Command}, cfg, ts, lineNo)...)
	return out
}

func parseToolResult(rec rawRecord, ts time.Time, lineNo int, cfg ReferenceConfig) []*Candidate {
	category, ok := toolResultCategory(rec.Category)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "tool_result record with unrecognized category")}
	}
	status, ok := toolResultStatus(rec.Status)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "tool_result record with unrecognized status")}
	}
	resultBytes := rec.ResultBytes
	if resultBytes == nil && rec.Output != "" {
		n := int64(len(rec.Output))
		resultBytes = &n
	}
	out := []*Candidate{{
		Kind:       KindToolResult,
		OccurredAt: ts,
		LineNumber: lineNo,
		ToolResult: &evidence.ToolResultCandidate{Category: category, Status: status, ResultByteCount: resultBytes, ResultBody: rec.Output},
	}}
	out = append(out, extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLRESULT, SurfaceText{Tool: rec.Tool, Text: rec.Output}, cfg, ts, lineNo)...)
	return out
}

func parseUsage(rec rawRecord, ts time.Time, lineNo int) []*Candidate {
	quality, ok := usageQuality(rec.Quality)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "usage record with unrecognized quality")}
	}
	return []*Candidate{{
		Kind:       KindUsage,
		OccurredAt: ts,
		LineNumber: lineNo,
		Usage: &evidence.UsageCandidate{
			Quality:             quality,
			InputTokens:         rec.InputTokens,
			OutputTokens:        rec.OutputTokens,
			CacheCreationTokens: rec.CacheCreationTokens,
			CacheReadTokens:     rec.CacheReadTokens,
			ProviderSource:      rec.ProviderSource,
			PriceTableVersion:   rec.PriceTableVersion,
		},
	}}
}

func parseSession(rec rawRecord, ts time.Time, lineNo int) []*Candidate {
	transition, ok := sessionTransition(rec.Transition)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "session record with unrecognized transition")}
	}
	startSource, ok := sessionStartSource(rec.StartSource)
	if !ok {
		return []*Candidate{diagnosticCandidate(ts, lineNo, "session record with unrecognized start_source")}
	}
	return []*Candidate{{
		Kind:       KindSessionLifecycle,
		OccurredAt: ts,
		LineNumber: lineNo,
		SessionLifecycle: &evidence.SessionLifecycleCandidate{
			NativeSessionID: rec.SessionID,
			Provider:        rec.Provider,
			StartSource:     startSource,
			Transition:      transition,
			Model:           rec.Model,
		},
	}}
}

// extractedCandidates runs the deterministic reference extractors over one tool surface and
// wraps their output (references plus any cap diagnostics) as candidates.
func extractedCandidates(surface wire.ExtractionProvenanceSurface, in SurfaceText, cfg ReferenceConfig, ts time.Time, lineNo int) []*Candidate {
	refs, diags := ExtractReferences(surface, in, cfg)
	out := make([]*Candidate, 0, len(refs)+len(diags))
	for i := range refs {
		out = append(out, refCandidate(refs[i], ts, lineNo))
	}
	for i := range diags {
		d := diags[i]
		out = append(out, &Candidate{Kind: KindDiagnostic, OccurredAt: ts, LineNumber: lineNo, Diagnostic: &d})
	}
	return out
}

func refCandidate(r ExtractedReference, ts time.Time, lineNo int) *Candidate {
	switch r.Kind {
	case RefKindCommit:
		return &Candidate{Kind: KindCommitReference, OccurredAt: ts, LineNumber: lineNo, Commit: r.Commit}
	case RefKindPullRequest:
		return &Candidate{Kind: KindPullRequestReference, OccurredAt: ts, LineNumber: lineNo, PullRequest: r.PullRequest}
	default:
		return &Candidate{Kind: KindWorkReference, OccurredAt: ts, LineNumber: lineNo, Work: r.Work}
	}
}

// diagnosticCandidate builds an UNSUPPORTED_FORMAT diagnostic candidate for an unrecognized or
// malformed record. It never fabricates a known-kind candidate from the bad input.
func diagnosticCandidate(ts time.Time, lineNo int, context string) *Candidate {
	d := unsupportedDiagnostic(context)
	return &Candidate{Kind: KindDiagnostic, OccurredAt: ts, LineNumber: lineNo, Diagnostic: &d}
}

func unsupportedDiagnostic(context string) evidence.DiagnosticCandidate {
	return evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeUNSUPPORTEDFORMAT,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            context,
	}
}

// ---- enum decoders (unknown value -> not ok, never coerced) ----

func messageRole(s string) (wire.MessagePayloadRole, bool) {
	switch s {
	case "user", "USER":
		return wire.MessagePayloadRoleUSER, true
	case "assistant", "ASSISTANT":
		return wire.MessagePayloadRoleASSISTANT, true
	case "system", "SYSTEM":
		return wire.MessagePayloadRoleSYSTEM, true
	case "tool", "TOOL":
		return wire.MessagePayloadRoleTOOL, true
	default:
		return "", false
	}
}

func toolCallCategory(s string) (wire.ToolCallPayloadCategory, bool) {
	v := wire.ToolCallPayloadCategory(s)
	return v, v.Valid()
}

func toolResultCategory(s string) (wire.ToolResultPayloadCategory, bool) {
	v := wire.ToolResultPayloadCategory(s)
	return v, v.Valid()
}

func toolResultStatus(s string) (wire.ToolResultPayloadStatus, bool) {
	v := wire.ToolResultPayloadStatus(s)
	return v, v.Valid()
}

func usageQuality(s string) (wire.UsagePayloadQuality, bool) {
	v := wire.UsagePayloadQuality(s)
	return v, v.Valid()
}

func sessionTransition(s string) (wire.SessionLifecyclePayloadTransition, bool) {
	v := wire.SessionLifecyclePayloadTransition(s)
	return v, v.Valid()
}

func sessionStartSource(s string) (wire.SessionLifecyclePayloadStartSource, bool) {
	v := wire.SessionLifecyclePayloadStartSource(s)
	return v, v.Valid()
}
