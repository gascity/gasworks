package evidence

import (
	"fmt"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// The METADATA_ONLY content policy transform. Adapters (E1.7/E1.8) and the run daemon
// (E1.6) produce raw candidate records that still hold forbidden content — message and tool
// bodies, commands/argv/environment, URLs, custom MCP names, absolute paths, raw content
// hashes, and prompt text. Every candidate passes through a Transform* here before Observer
// creates its durable egress copy. The transform is total: it produces either a policy-clean
// PendingObservation (built through the types.go constructors, whose inputs have nowhere to
// put content) or a content-free CAPTURE_DIAGNOSTIC. A transform error fails closed to a
// diagnostic; it NEVER falls back to raw bytes (spec "Field-level content policy").
//
// The clean output cannot carry forbidden content by construction: the constructor input
// types model only bounded metadata, so the raw Body/Command/Argv/Environment/URL fields
// below are simply never read into a wire value. This file is where the projection happens.

// ExtractionConfig is the per-ref-kind extraction toggle map recorded in the consent record
// (spec "Reference extraction"). It gates which reference candidates pass policy. The v1
// defaults are all on; each kind captures bounded identifiers only.
type ExtractionConfig struct {
	Commit      bool
	PullRequest bool
	BeadID      bool
}

// DefaultExtractionConfig is the v1 default: COMMIT, PULL_REQUEST, and bead-ID capture all
// enabled.
func DefaultExtractionConfig() ExtractionConfig {
	return ExtractionConfig{Commit: true, PullRequest: true, BeadID: true}
}

// Policy is the daemon-constant capture policy consumed by every transform: the capturing
// adapter identity, the active content policy (METADATA_ONLY in v1), and the extraction
// toggles. Validate it once at daemon start; the transforms assume a valid Policy and treat
// the provenance projection as total.
type Policy struct {
	Adapter        string
	AdapterVersion string
	ContentPolicy  wire.ProvenanceContentPolicy
	Extraction     ExtractionConfig
}

// Validate reports whether the daemon-owned policy identity is well-formed. A transform can
// only guarantee a content-free fail-closed diagnostic when this holds.
func (p Policy) Validate() error {
	if err := boundedNonEmpty("policy.adapter", p.Adapter, maxAdapter); err != nil {
		return err
	}
	if err := boundedNonEmpty("policy.adapter_version", p.AdapterVersion, maxAdapterVersion); err != nil {
		return err
	}
	return validEnum("policy.content_policy", p.ContentPolicy)
}

// PolicyEnvelope is the per-observation envelope candidate: the two timestamps, the raw
// provenance candidate (carrying forbidden fields the transform strips), and the
// daemon-stamped run context — nil for passive-session evidence.
type PolicyEnvelope struct {
	OccurredAt time.Time
	CapturedAt time.Time
	Provenance RawProvenance
	// RunContext is stamped only for declared/inherited/lineage-proven attachments.
	RunContext *wire.RunContext
}

// RawProvenance is the messy per-observation provenance candidate. Only the allowed metadata
// survives; the forbidden candidates are never emitted.
type RawProvenance struct {
	Provider         string
	NativeSessionID  string // typed pseudonymous id (allowed)
	ParserVersion    string
	TransformVersion string
	// RootRelativeLocator is emitted only when it is genuinely root-relative; an absolute
	// path is dropped.
	RootRelativeLocator string
	ByteRange           *wire.ByteRange
	Completeness        *wire.ProvenanceCompleteness
	CaptureQuality      *wire.ProvenanceCaptureQuality

	// Forbidden candidates — never emitted under METADATA_ONLY:
	AbsolutePath string // e.g. /home/alice/project/...; never leaves the endpoint
	SourceHash   string // raw content hash; omitted under METADATA_ONLY
}

// TransformResult is the outcome of a policy transform. It has exactly three shapes:
//
//   - a live observation (HasObservation true, Dropped false): Observation carries a
//     content-clean intended observation, or a content-free CAPTURE_DIAGNOSTIC substitute
//     when Diagnostic is true (a fail-closed transform error or a spec-mandated reference
//     drop — never raw content);
//   - a drop (Dropped true): a per-ref-kind extraction toggle gated a reference out
//     entirely; no observation is produced (a consent-recorded policy choice, not a
//     failure);
//   - a dead result (HasObservation false, Dropped false): failClosed could not even build
//     its diagnostic — the Policy identity is invalid or the candidate timestamps are
//     absent — so Observation has a nil seal and Cause explains why. Consumers must gate on
//     HasObservation, never on !Dropped alone.
type TransformResult struct {
	Observation PendingObservation
	// Diagnostic is true when Observation is a content-free CAPTURE_DIAGNOSTIC substituted
	// for the intended observation. The substitute is never raw content.
	Diagnostic bool
	// Dropped is true when a per-ref-kind extraction toggle gated a reference out entirely.
	Dropped bool
	// Cause is the underlying error behind a Diagnostic or a dead result, for endpoint
	// logging only; it never reaches the wire.
	Cause error
}

// HasObservation reports whether the result carries a sealable observation to spool. It is
// false both for a gated drop and for the dead fail-closed state (a nil seal closure), so a
// consumer following "if r.HasObservation() { spool it }" never enqueues a dead result.
func (r TransformResult) HasObservation() bool {
	return !r.Dropped && r.Observation.seal != nil
}

// ---- provenance projection (total under a valid Policy) ----

func (p Policy) provenance(raw RawProvenance) (wire.Provenance, error) {
	if err := p.Validate(); err != nil {
		return wire.Provenance{}, err
	}
	prov := wire.Provenance{
		Adapter:          p.Adapter,
		AdapterVersion:   p.AdapterVersion,
		ContentPolicy:    p.ContentPolicy,
		Provider:         keepBounded(raw.Provider, maxProvider),
		NativeSessionId:  keepBounded(raw.NativeSessionID, maxNativeSessionID),
		ParserVersion:    keepBounded(raw.ParserVersion, maxParserVersion),
		TransformVersion: keepBounded(raw.TransformVersion, maxTransformVersion),
		SourceLocator:    keepRelativeLocator(raw.RootRelativeLocator, maxSourceLocator),
		ByteRange:        keepByteRange(raw.ByteRange),
		Completeness:     keepEnumPtr(raw.Completeness),
		CaptureQuality:   keepEnumPtr(raw.CaptureQuality),
	}
	// A raw content hash and absolute path never leave under METADATA_ONLY. Even under a
	// future FULL policy the hash must be a well-formed 64-hex value; anything else is
	// dropped rather than emitted.
	if p.ContentPolicy == wire.ProvenanceContentPolicyFULL {
		prov.SourceHash = keepHash(raw.SourceHash)
	}
	return prov, nil
}

func (p Policy) common(env PolicyEnvelope) (Common, error) {
	prov, err := p.provenance(env.Provenance)
	if err != nil {
		return Common{}, err
	}
	rc := env.RunContext
	if rc != nil {
		if err := validateRunContext(*rc); err != nil {
			return Common{}, err
		}
	}
	return Common{OccurredAt: env.OccurredAt, CapturedAt: env.CapturedAt, Provenance: prov, RunContext: rc}, nil
}

// failClosed builds a content-free CAPTURE_DIAGNOSTIC in place of an observation that could
// not be produced cleanly. It never carries the run context or the raw cause detail. It
// returns a dead result (nil-seal Observation, HasObservation false) only when even the
// diagnostic cannot be built — an invalid Policy identity (daemon misconfiguration) or
// candidate timestamps that are entirely absent — in which case Cause explains why and no
// observation reaches the spool.
func (p Policy) failClosed(env PolicyEnvelope, kind string, cause error) TransformResult {
	prov, perr := p.provenance(env.Provenance)
	if perr != nil {
		return TransformResult{Cause: fmt.Errorf("policy misconfigured, cannot emit diagnostic: %w", perr)}
	}
	occ, capt := env.OccurredAt, env.CapturedAt
	if capt.IsZero() {
		capt = occ
	}
	if occ.IsZero() {
		occ = capt
	}
	diagCommon := Common{OccurredAt: occ, CapturedAt: capt, Provenance: prov}
	diag, derr := NewCaptureDiagnostic(diagCommon, CaptureDiagnosticInput{
		Code:               wire.CaptureDiagnosticPayloadCodeUNSUPPORTEDFORMAT,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            "policy transform dropped a " + kind + " record; capture incomplete",
	})
	if derr != nil {
		return TransformResult{Cause: fmt.Errorf("failed to build fail-closed diagnostic: %w", derr)}
	}
	return TransformResult{Observation: diag, Diagnostic: true, Cause: cause}
}

// ---- content-bearing candidates ----

// MessageCandidate is a raw MESSAGE record. Body is forbidden and never emitted.
type MessageCandidate struct {
	Role       wire.MessagePayloadRole
	ByteCount  *int64
	TokenCount *int64

	Body string // forbidden
}

// TransformMessage projects a MESSAGE candidate to a policy-clean observation. The body is
// dropped; only role/timing/bounded counts survive.
func (p Policy) TransformMessage(env PolicyEnvelope, raw MessageCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "MESSAGE", err)
	}
	obs, err := NewMessage(common, MessageInput{Role: raw.Role, ByteCount: raw.ByteCount, TokenCount: raw.TokenCount})
	if err != nil {
		return p.failClosed(env, "MESSAGE", err)
	}
	return TransformResult{Observation: obs}
}

// ToolCallCandidate is a raw TOOL_CALL record. Command, argv, environment, url, and MCP name
// are forbidden and never emitted.
type ToolCallCandidate struct {
	Category          wire.ToolCallPayloadCategory
	ArgumentByteCount *int64

	Command     string            // forbidden
	Argv        []string          // forbidden
	Environment map[string]string // forbidden
	URL         string            // forbidden
	MCPName     string            // forbidden
}

// TransformToolCall projects a TOOL_CALL candidate to a policy-clean observation.
func (p Policy) TransformToolCall(env PolicyEnvelope, raw ToolCallCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "TOOL_CALL", err)
	}
	obs, err := NewToolCall(common, ToolCallInput{Category: raw.Category, ArgumentByteCount: raw.ArgumentByteCount})
	if err != nil {
		return p.failClosed(env, "TOOL_CALL", err)
	}
	return TransformResult{Observation: obs}
}

// ToolResultCandidate is a raw TOOL_RESULT record. The result body is forbidden.
type ToolResultCandidate struct {
	Category        wire.ToolResultPayloadCategory
	Status          wire.ToolResultPayloadStatus
	ResultByteCount *int64

	ResultBody string // forbidden
}

// TransformToolResult projects a TOOL_RESULT candidate to a policy-clean observation.
func (p Policy) TransformToolResult(env PolicyEnvelope, raw ToolResultCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "TOOL_RESULT", err)
	}
	obs, err := NewToolResult(common, ToolResultInput{Category: raw.Category, Status: raw.Status, ResultByteCount: raw.ResultByteCount})
	if err != nil {
		return p.failClosed(env, "TOOL_RESULT", err)
	}
	return TransformResult{Observation: obs}
}

// ---- metadata candidates ----

// SessionLifecycleCandidate is a raw SESSION_LIFECYCLE record.
type SessionLifecycleCandidate struct {
	NativeSessionID string
	Provider        string
	StartSource     wire.SessionLifecyclePayloadStartSource
	Transition      wire.SessionLifecyclePayloadTransition
	Model           string // optional; empty becomes absent
}

// TransformSessionLifecycle projects a SESSION_LIFECYCLE candidate to a clean observation.
func (p Policy) TransformSessionLifecycle(env PolicyEnvelope, raw SessionLifecycleCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "SESSION_LIFECYCLE", err)
	}
	obs, err := NewSessionLifecycle(common, SessionLifecycleInput{
		NativeSessionID: raw.NativeSessionID,
		Provider:        raw.Provider,
		StartSource:     raw.StartSource,
		Transition:      raw.Transition,
		Model:           raw.Model,
	})
	if err != nil {
		return p.failClosed(env, "SESSION_LIFECYCLE", err)
	}
	return TransformResult{Observation: obs}
}

// UsageCandidate is a raw USAGE record.
type UsageCandidate struct {
	Quality             wire.UsagePayloadQuality
	InputTokens         *int64
	OutputTokens        *int64
	CacheCreationTokens *int64
	CacheReadTokens     *int64
	ProviderSource      string
	PriceTableVersion   string
}

// TransformUsage projects a USAGE candidate to a clean observation.
func (p Policy) TransformUsage(env PolicyEnvelope, raw UsageCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "USAGE", err)
	}
	obs, err := NewUsage(common, UsageInput{
		Quality:             raw.Quality,
		InputTokens:         raw.InputTokens,
		OutputTokens:        raw.OutputTokens,
		CacheCreationTokens: raw.CacheCreationTokens,
		CacheReadTokens:     raw.CacheReadTokens,
		ProviderSource:      raw.ProviderSource,
		PriceTableVersion:   raw.PriceTableVersion,
	})
	if err != nil {
		return p.failClosed(env, "USAGE", err)
	}
	return TransformResult{Observation: obs}
}

// ProcessLifecycleCandidate is a raw PROCESS_LIFECYCLE record. Argv, environment, and the
// executable path are forbidden and never emitted.
type ProcessLifecycleCandidate struct {
	Transition wire.ProcessLifecyclePayloadTransition
	Identity   wire.ProcessIdentity
	ExitCode   *int32
	Signal     *int32

	Argv           []string          // forbidden
	Environment    map[string]string // forbidden
	ExecutablePath string            // forbidden
}

// TransformProcessLifecycle projects a PROCESS_LIFECYCLE candidate to a clean observation.
func (p Policy) TransformProcessLifecycle(env PolicyEnvelope, raw ProcessLifecycleCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "PROCESS_LIFECYCLE", err)
	}
	obs, err := NewProcessLifecycle(common, ProcessLifecycleInput{
		Transition: raw.Transition,
		Identity:   raw.Identity,
		ExitCode:   raw.ExitCode,
		Signal:     raw.Signal,
	})
	if err != nil {
		return p.failClosed(env, "PROCESS_LIFECYCLE", err)
	}
	return TransformResult{Observation: obs}
}

// ---- run boundary candidates ----

// RunStartedCandidate is a raw RUN_STARTED record. Wrapper argv (which can contain prompt
// text) and environment are forbidden and never emitted.
type RunStartedCandidate struct {
	RunID          string
	BoundarySource wire.RunStartedBoundaryBoundarySource
	WorkItemRefs   []wire.WorkReference

	Argv        []string          // forbidden (may contain prompt text)
	Environment map[string]string // forbidden
}

// TransformRunStarted projects a RUN_STARTED candidate to a clean boundary observation.
func (p Policy) TransformRunStarted(env PolicyEnvelope, raw RunStartedCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	obs, err := NewRunStarted(common, RunStartedInput{
		RunID:          raw.RunID,
		BoundarySource: raw.BoundarySource,
		WorkItemRefs:   raw.WorkItemRefs,
	})
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	return TransformResult{Observation: obs}
}

// RunEndedDrainCandidate is a raw drained RUN_ENDED record.
type RunEndedDrainCandidate struct {
	RunID            string
	BoundarySource   wire.RunEndedBoundaryBoundarySource
	DrainStatus      wire.RunEndedBoundaryDrainStatus
	CoveredWatermark wire.Watermark
}

// TransformRunEndedDrain projects a drained RUN_ENDED candidate to a clean observation. The
// watermark's locator is projected to a root-relative form; an absolute path is dropped.
func (p Policy) TransformRunEndedDrain(env PolicyEnvelope, raw RunEndedDrainCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	wm := wire.Watermark{
		ByteOffset:    raw.CoveredWatermark.ByteOffset,
		SourceLocator: keepRelativeLocatorPtr(raw.CoveredWatermark.SourceLocator, maxSourceLocator),
	}
	obs, err := NewRunEndedDrain(common, RunEndedDrainInput{
		RunID:            raw.RunID,
		BoundarySource:   raw.BoundarySource,
		DrainStatus:      raw.DrainStatus,
		CoveredWatermark: wm,
	})
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	return TransformResult{Observation: obs}
}

// RunEndedLaunchFailureCandidate is a raw launch-failure RUN_ENDED record.
type RunEndedLaunchFailureCandidate struct {
	RunID          string
	BoundarySource wire.RunEndedBoundaryBoundarySource
}

// TransformRunEndedLaunchFailure projects a launch-failure RUN_ENDED candidate.
func (p Policy) TransformRunEndedLaunchFailure(env PolicyEnvelope, raw RunEndedLaunchFailureCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	obs, err := NewRunEndedLaunchFailure(common, RunEndedLaunchFailureInput{
		RunID:          raw.RunID,
		BoundarySource: raw.BoundarySource,
	})
	if err != nil {
		return p.failClosed(env, "RUN_BOUNDARY", err)
	}
	return TransformResult{Observation: obs}
}

// ---- reference candidates (gated by the extraction toggles) ----

// DeclaredWorkReferenceCandidate is a raw DECLARED work reference from the lifecycle API.
type DeclaredWorkReferenceCandidate struct {
	TeamServerProjectID string
	BeadID              string
}

// TransformDeclaredWorkReference projects a DECLARED work reference. DECLARED links are not
// gated by the extraction toggles (those govern EXTRACTED capture only).
func (p Policy) TransformDeclaredWorkReference(env PolicyEnvelope, raw DeclaredWorkReferenceCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "WORK_REFERENCE", err)
	}
	obs, err := NewDeclaredWorkReference(common, DeclaredWorkRefInput{
		TeamServerProjectID: raw.TeamServerProjectID,
		BeadID:              raw.BeadID,
	})
	if err != nil {
		return p.failClosed(env, "WORK_REFERENCE", err)
	}
	return TransformResult{Observation: obs}
}

// ExtractedWorkReferenceCandidate is a raw EXTRACTED bead-ID reference plus its project
// resolver (stamped context and/or configured default).
type ExtractedWorkReferenceCandidate struct {
	BeadID   string
	Resolver ProjectResolver
}

// TransformExtractedWorkReference gates a bead-ID reference on the BeadID toggle and then
// resolves its project. When the toggle is off the reference is dropped entirely; when the
// project is unresolvable a content-free drop diagnostic is emitted (never a partial ref).
func (p Policy) TransformExtractedWorkReference(env PolicyEnvelope, raw ExtractedWorkReferenceCandidate) TransformResult {
	if !p.Extraction.BeadID {
		return TransformResult{Dropped: true}
	}
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "WORK_REFERENCE", err)
	}
	res, err := NewExtractedWorkReference(common, ExtractedWorkRefInput{BeadID: raw.BeadID}, raw.Resolver)
	if err != nil {
		return p.failClosed(env, "WORK_REFERENCE", err)
	}
	if res.Dropped() {
		return TransformResult{Observation: *res.Drop, Diagnostic: true}
	}
	return TransformResult{Observation: *res.Resolved}
}

// CommitReferenceCandidate is a raw COMMIT VCS reference.
type CommitReferenceCandidate struct {
	Identifier string
	RepoSlug   string
	Extraction wire.ExtractionProvenance
}

// TransformCommitReference gates a COMMIT reference on the Commit toggle.
func (p Policy) TransformCommitReference(env PolicyEnvelope, raw CommitReferenceCandidate) TransformResult {
	if !p.Extraction.Commit {
		return TransformResult{Dropped: true}
	}
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "VCS_REFERENCE", err)
	}
	obs, err := NewCommitReference(common, CommitReferenceInput{
		Identifier: raw.Identifier,
		RepoSlug:   raw.RepoSlug,
		Extraction: raw.Extraction,
	})
	if err != nil {
		return p.failClosed(env, "VCS_REFERENCE", err)
	}
	return TransformResult{Observation: obs}
}

// PullRequestReferenceCandidate is a raw PULL_REQUEST VCS reference.
type PullRequestReferenceCandidate struct {
	Identifier string
	RepoSlug   string
	Extraction wire.ExtractionProvenance
}

// TransformPullRequestReference gates a PULL_REQUEST reference on the PullRequest toggle.
func (p Policy) TransformPullRequestReference(env PolicyEnvelope, raw PullRequestReferenceCandidate) TransformResult {
	if !p.Extraction.PullRequest {
		return TransformResult{Dropped: true}
	}
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "VCS_REFERENCE", err)
	}
	obs, err := NewPullRequestReference(common, PullRequestReferenceInput{
		Identifier: raw.Identifier,
		RepoSlug:   raw.RepoSlug,
		Extraction: raw.Extraction,
	})
	if err != nil {
		return p.failClosed(env, "VCS_REFERENCE", err)
	}
	return TransformResult{Observation: obs}
}

// DiagnosticCandidate is a raw CAPTURE_DIAGNOSTIC record. Its context is sanitized by the
// constructor (NewCaptureDiagnostic): an absolute/home/traversal path anywhere in the
// string drops the whole context, otherwise it is truncated to the field bound.
type DiagnosticCandidate struct {
	Code               wire.CaptureDiagnosticPayloadCode
	Severity           wire.CaptureDiagnosticPayloadSeverity
	CompletenessEffect wire.CaptureDiagnosticPayloadCompletenessEffect
	Context            string // sanitized at the constructor choke point
}

// TransformCaptureDiagnostic projects a CAPTURE_DIAGNOSTIC candidate. Context sanitization
// lives in NewCaptureDiagnostic so the guarantee holds for every caller, so the raw context
// is passed straight through to the constructor.
func (p Policy) TransformCaptureDiagnostic(env PolicyEnvelope, raw DiagnosticCandidate) TransformResult {
	common, err := p.common(env)
	if err != nil {
		return p.failClosed(env, "CAPTURE_DIAGNOSTIC", err)
	}
	obs, err := NewCaptureDiagnostic(common, CaptureDiagnosticInput{
		Code:               raw.Code,
		Severity:           raw.Severity,
		CompletenessEffect: raw.CompletenessEffect,
		Context:            raw.Context,
	})
	if err != nil {
		return p.failClosed(env, "CAPTURE_DIAGNOSTIC", err)
	}
	return TransformResult{Observation: obs}
}

// ---- projection helpers ----

// keepBounded returns a pointer to value when it is non-empty and within max, else nil
// (absent-not-empty; over-long optional metadata is dropped rather than truncated so an
// identifier is never silently corrupted).
func keepBounded(value string, max int) *string {
	if value == "" || len(value) > max {
		return nil
	}
	v := value
	return &v
}

// keepRelativeLocator emits a locator only when it is genuinely root-relative and bounded;
// an absolute path, a home path, an over-long value, or a "../"-escaping traversal that
// reconstructs an absolute path is dropped so no absolute locator ever leaves.
func keepRelativeLocator(value string, max int) *string {
	if len(value) > max || !isRootRelativeLocator(value) {
		return nil
	}
	v := value
	return &v
}

func keepRelativeLocatorPtr(value *string, max int) *string {
	if value == nil {
		return nil
	}
	return keepRelativeLocator(*value, max)
}

// keepEnumPtr keeps an optional enum pointer only when it is a member of its closed set.
func keepEnumPtr[T interface{ Valid() bool }](v *T) *T {
	if v == nil || !(*v).Valid() {
		return nil
	}
	return v
}

// keepByteRange keeps an optional byte range only when it satisfies the schema bounds
// (start >= 0, end >= start); an out-of-bounds range is dropped rather than passed through
// to poison the shared provenance (the direct-constructor path still rejects a bad range via
// validateProvenance, so a hand-built Common cannot seal one).
func keepByteRange(r *wire.ByteRange) *wire.ByteRange {
	if r == nil || r.Start < 0 || r.End < r.Start {
		return nil
	}
	return r
}

// keepHash keeps a source hash only when it is a well-formed lowercase 64-hex digest.
func keepHash(value string) *string {
	if len(value) != 64 {
		return nil
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return nil
		}
	}
	v := value
	return &v
}
