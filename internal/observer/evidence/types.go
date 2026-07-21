// Package evidence is the endpoint's typed observation domain: the layer that sits over
// the committed, generated wire types (github.com/gascity/gasworks/internal/observer/wire)
// and is used by the run daemon (E1.6), the Codex hook decoder (E1.7), and the transcript
// parser (E1.8) to build observations, apply the METADATA_ONLY content policy, and run the
// endpoint-side semantic batch validators before a WAL append.
//
// The design goal is to make illegal states unrepresentable where Go allows it:
//
//   - Construction is split per transition/kind, so a RUN_STARTED literally has no field
//     for a drain status and a RUN_ENDED's two legal shapes (drained vs launch-failure)
//     are separate constructors — the drain-pair coupling cannot be violated by building.
//   - There is no run-outcome field anywhere in the observation wire types and no
//     constructor accepts one, so an outcome is not constructible; v1 always projects
//     UNKNOWN server-side.
//   - The content-bearing kinds' constructor inputs carry only bounded metadata — a
//     MessageInput has no body, a ToolCallInput has no command/argv/environment/url — so
//     forbidden content has nowhere to live in a well-typed observation. The policy
//     transform (policy.go) is what turns messy raw adapter candidates into these inputs.
//   - An EXTRACTED work reference whose team_server_project_id cannot be resolved from the
//     stamped run context or the single configured default project is not built at all;
//     the constructor returns a typed drop-with-diagnostic result (spec "Reference
//     extraction").
//
// Observation IDs and source sequence numbers are NOT assigned here: constructors produce
// a pre-sequence PendingObservation, and the spool layer (E1.2) stamps identity and
// sequence via Seal. This keeps sequence assignment single-writer in the spool.
package evidence

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// VCS reference identifier and repo_slug patterns, compiled once from the vendored
// contract (contracts/observer/v1/openapi.json). JSON-Schema pattern does not run at
// ingest — the strict wire decoder enforces shape/enum/sequence only — so these
// constructors are the endpoint's enforcement point for the field charset/format the
// spec ("Reference extraction") makes a privacy rule. A value that fails the pattern is
// rejected with a typed BuildError, and the policy transform then fails closed to a
// content-free CAPTURE_DIAGNOSTIC.
//
// Residual, correctly ceded upstream: a 40- or 64-hex value that IS a hex-encoded secret
// is indistinguishable from a real commit hash at this layer and passes the commit
// pattern. Excluding it is E1.8's job (deterministic anchored git/gh output-shape
// extraction — "the schema is not the defense"); the format/charset guard here is ours.
var (
	commitIdentifierPattern      = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	pullRequestIdentifierPattern = regexp.MustCompile(`^(#[0-9]{1,20}|https://[^ ]{1,240})$`)
	repoSlugPattern              = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,140}$`)
)

// Field-length bounds mirrored from the vendored OpenAPI x-limits/maxLength constraints
// (contracts/observer/v1/openapi.json). JSON-Schema maxLength does not run at ingest, so
// the domain constructors enforce these before a value reaches the WAL or the wire.
const (
	maxObservationID     = 128
	maxRunID             = 128
	maxNativeSessionID   = 128
	maxProvider          = 64
	maxModel             = 128
	maxAdapter           = 64
	maxAdapterVersion    = 64
	maxParserVersion     = 64
	maxTransformVersion  = 64
	maxSourceLocator     = 512
	maxDiagnosticContext = 1024
	maxCommitIdentifier  = 64
	maxPullReqIdentifier = 256
	maxRepoSlug          = 140
	maxTeamServerProject = 128
	maxBeadID            = 128
	maxPatternID         = 128
	maxExtractorVersion  = 64
	maxBootID            = 128
	maxPriceTableVersion = 64
	maxProviderSource    = 64
	maxMessageID         = 128
)

// BuildError is a typed construction failure. It names the offending field and reason so a
// caller (the policy transform, the adapters) can decide to fail closed rather than emit a
// malformed observation.
type BuildError struct {
	Field  string
	Detail string
}

func (e *BuildError) Error() string {
	return fmt.Sprintf("observer evidence: %s: %s", e.Field, e.Detail)
}

func buildErr(field, detail string) *BuildError { return &BuildError{Field: field, Detail: detail} }

// Common is the envelope metadata carried by every observation except its assigned
// identity/sequence: the two timestamps, the policy-clean provenance, and — present only
// for a daemon-stamped declared/inherited/lineage-proven attachment — the run context.
// Passive-session evidence leaves RunContext nil.
type Common struct {
	OccurredAt time.Time
	CapturedAt time.Time
	Provenance wire.Provenance
	// RunContext is stamped only for declared/inherited/lineage-proven attachments; it is
	// nil for passive-session evidence (spec: "Provenance carried by every observation").
	RunContext *wire.RunContext
}

// PendingObservation is a constructed, policy-clean observation that has not yet been
// assigned an observation ID or a source sequence. The spool layer stamps those via Seal.
type PendingObservation struct {
	kind       string
	occurredAt time.Time
	capturedAt time.Time
	// seal stamps identity/sequence and produces the concrete wire.Observation union.
	seal func(seq int64, observationID string) (wire.Observation, error)
}

// Kind reports the observation kind (one of the closed v1 wire kinds).
func (p PendingObservation) Kind() string { return p.kind }

// OccurredAt reports the provider event time.
func (p PendingObservation) OccurredAt() time.Time { return p.occurredAt }

// CapturedAt reports the endpoint capture time.
func (p PendingObservation) CapturedAt() time.Time { return p.capturedAt }

// Seal stamps the spool-assigned observation ID and source sequence and returns the
// concrete wire.Observation. It rejects an out-of-range sequence or an empty/over-long
// observation ID; the spool layer owns generating both.
//
// Producer obligations (NOT guarded here): sequence and observation-ID UNIQUENESS is the
// spool's invariant (E1.2) — Seal does not prevent re-sealing the same PendingObservation
// under two identities, because the spool is the single writer that assigns each exactly
// once. The daemon-stamping discipline for RunContext (a run context is stamped only for a
// declared/inherited/lineage-proven attachment, never for passive-session evidence) is the
// run daemon's / hook decoder's invariant (E1.6/E1.7); this layer copies and validates
// whatever context it is handed but does not decide attachment.
func (p PendingObservation) Seal(seq int64, observationID string) (wire.Observation, error) {
	if p.seal == nil {
		return wire.Observation{}, buildErr("observation", "pending observation is not initialized")
	}
	if seq < wire.SequenceMin || seq > wire.SequenceMax {
		return wire.Observation{}, buildErr("sequence", fmt.Sprintf("%d is outside [1, %d]", seq, wire.SequenceMax))
	}
	if err := boundedNonEmpty("observation_id", observationID, maxObservationID); err != nil {
		return wire.Observation{}, err
	}
	return p.seal(seq, observationID)
}

// ---- shared field validation ----

func boundedNonEmpty(field, value string, max int) error {
	if value == "" {
		return buildErr(field, "must be present and non-empty")
	}
	if len(value) > max {
		return buildErr(field, fmt.Sprintf("length %d exceeds max %d", len(value), max))
	}
	return nil
}

// boundedOptionalPtr enforces absent-not-empty: a non-nil pointer to "" is a build error
// (an optional field is either absent or a bounded non-empty value, never an empty string).
func boundedOptionalPtr(field string, value *string, max int) error {
	if value == nil {
		return nil
	}
	return boundedNonEmpty(field, *value, max)
}

// validEnum reports whether a closed-enum value is a member of its set. It deliberately
// does NOT interpolate the candidate value into the error: for a content-bearing kind the
// enum value comes straight from adapter data (e.g. a cast arbitrary-length role string),
// and that value must never ride an error/log message (spec: logs "never contain ...
// unbounded identifiers"). The field name localizes the failure.
func validEnum(field string, e interface{ Valid() bool }) error {
	if !e.Valid() {
		return buildErr(field, "value is not a member of the closed enum")
	}
	return nil
}

// checkedCount validates an optional min:0 count field against the schema minimum and
// returns a DEFENSIVELY-COPIED pointer, so a caller that mutates the original after
// construction cannot alter the sealed value (the same aliasing class this file closes for
// run_context). A negative count is a typed BuildError (the vendored schema declares
// minimum:0 on every count field; JSON-Schema minimum does not run at ingest).
func checkedCount(field string, v *int64) (*int64, error) {
	if v == nil {
		return nil, nil
	}
	if *v < 0 {
		return nil, buildErr(field, "must be >= 0")
	}
	c := *v
	return &c, nil
}

// nonNegative validates a required min:0 int64 field (Watermark.byte_offset,
// ProcessIdentity.pid/process_start_time).
func nonNegative(field string, v int64) error {
	if v < 0 {
		return buildErr(field, "must be >= 0")
	}
	return nil
}

// cloneRunContext deep-copies a run context and its work-reference slice so a sealed
// observation cannot be retroactively altered through caller-held memory. wire.WorkReference
// is all value (string) fields, so copying the slice elements is a full deep copy.
func cloneRunContext(rc *wire.RunContext) *wire.RunContext {
	if rc == nil {
		return nil
	}
	out := *rc
	if rc.WorkItemRefs != nil {
		refs := make([]wire.WorkReference, len(*rc.WorkItemRefs))
		copy(refs, *rc.WorkItemRefs)
		out.WorkItemRefs = &refs
	}
	return &out
}

// prepareCommon validates the shared envelope and returns a defensively-copied Common: the
// run context (and its work_item_refs) are deep-copied so the value captured by a seal
// closure is immune to post-construction mutation of caller-held memory.
func prepareCommon(c Common) (Common, error) {
	if err := validateCommon(c); err != nil {
		return Common{}, err
	}
	c.RunContext = cloneRunContext(c.RunContext)
	return c, nil
}

// validateCommon checks the shared envelope metadata: both timestamps present, the
// provenance policy-clean and bounded, and a stamped run context (when present) valid and
// within the reference cap.
func validateCommon(c Common) error {
	if c.OccurredAt.IsZero() {
		return buildErr("occurred_at", "must be set")
	}
	if c.CapturedAt.IsZero() {
		return buildErr("captured_at", "must be set")
	}
	if err := validateProvenance(c.Provenance); err != nil {
		return err
	}
	if c.RunContext != nil {
		if err := validateRunContext(*c.RunContext); err != nil {
			return err
		}
	}
	return nil
}

func validateProvenance(p wire.Provenance) error {
	if err := boundedNonEmpty("provenance.adapter", p.Adapter, maxAdapter); err != nil {
		return err
	}
	if err := boundedNonEmpty("provenance.adapter_version", p.AdapterVersion, maxAdapterVersion); err != nil {
		return err
	}
	if err := validEnum("provenance.content_policy", p.ContentPolicy); err != nil {
		return err
	}
	if err := boundedOptionalPtr("provenance.provider", p.Provider, maxProvider); err != nil {
		return err
	}
	if err := boundedOptionalPtr("provenance.native_session_id", p.NativeSessionId, maxNativeSessionID); err != nil {
		return err
	}
	if err := boundedOptionalPtr("provenance.parser_version", p.ParserVersion, maxParserVersion); err != nil {
		return err
	}
	if err := boundedOptionalPtr("provenance.transform_version", p.TransformVersion, maxTransformVersion); err != nil {
		return err
	}
	if err := boundedOptionalPtr("provenance.source_locator", p.SourceLocator, maxSourceLocator); err != nil {
		return err
	}
	if p.Completeness != nil {
		if err := validEnum("provenance.completeness", *p.Completeness); err != nil {
			return err
		}
	}
	if p.CaptureQuality != nil {
		if err := validEnum("provenance.capture_quality", *p.CaptureQuality); err != nil {
			return err
		}
	}
	if p.ByteRange != nil {
		if p.ByteRange.Start < 0 {
			return buildErr("provenance.byte_range.start", "must be >= 0")
		}
		if p.ByteRange.End < p.ByteRange.Start {
			return buildErr("provenance.byte_range.end", "must be >= start")
		}
	}
	return nil
}

func validateRunContext(rc wire.RunContext) error {
	if err := boundedNonEmpty("run_context.run_id", rc.RunId, maxRunID); err != nil {
		return err
	}
	if err := validEnum("run_context.membership_evidence", rc.MembershipEvidence); err != nil {
		return err
	}
	if rc.WorkItemRefs != nil {
		refs := *rc.WorkItemRefs
		if len(refs) > MaxReferencesPerObservation {
			return buildErr("run_context.work_item_refs",
				fmt.Sprintf("%d entries exceeds cap %d", len(refs), MaxReferencesPerObservation))
		}
		for i := range refs {
			if err := validateWorkReference(fmt.Sprintf("run_context.work_item_refs[%d]", i), refs[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateWorkReference(field string, ref wire.WorkReference) error {
	if err := boundedNonEmpty(field+".team_server_project_id", ref.TeamServerProjectId, maxTeamServerProject); err != nil {
		return err
	}
	if err := boundedNonEmpty(field+".bead_id", ref.BeadId, maxBeadID); err != nil {
		return err
	}
	return validEnum(field+".origin", ref.Origin)
}

// ---- run boundary constructors (split per transition) ----

// RunStartedInput builds a RUN_STARTED boundary. There is deliberately no drain field: a
// RUN_STARTED cannot carry drain evidence.
type RunStartedInput struct {
	RunID          string
	BoundarySource wire.RunStartedBoundaryBoundarySource
	WorkItemRefs   []wire.WorkReference // optional; capped at MaxReferencesPerObservation
}

// NewRunStarted builds a pre-sequence RUN_STARTED boundary observation.
func NewRunStarted(c Common, in RunStartedInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("run_boundary.run_id", in.RunID, maxRunID); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("run_boundary.boundary_source", in.BoundarySource); err != nil {
		return PendingObservation{}, err
	}
	refs, err := checkedRefs("run_boundary.work_item_refs", in.WorkItemRefs)
	if err != nil {
		return PendingObservation{}, err
	}
	started := wire.RunStartedBoundary{
		BoundarySource: in.BoundarySource,
		RunId:          in.RunID,
		WorkItemRefs:   refs,
	}
	var payload wire.RunBoundaryPayload
	if err := payload.FromRunStartedBoundary(started); err != nil {
		return PendingObservation{}, err
	}
	return newBoundary(c, payload), nil
}

// RunEndedDrainInput builds a normal RUN_ENDED boundary. The drain status and covered
// watermark travel together by construction, so the drain-pair coupling cannot be broken.
type RunEndedDrainInput struct {
	RunID            string
	BoundarySource   wire.RunEndedBoundaryBoundarySource
	DrainStatus      wire.RunEndedBoundaryDrainStatus
	CoveredWatermark wire.Watermark
}

// NewRunEndedDrain builds a pre-sequence RUN_ENDED boundary carrying both drain fields.
func NewRunEndedDrain(c Common, in RunEndedDrainInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("run_boundary.run_id", in.RunID, maxRunID); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("run_boundary.boundary_source", in.BoundarySource); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("run_boundary.drain_status", in.DrainStatus); err != nil {
		return PendingObservation{}, err
	}
	if err := nonNegative("run_boundary.covered_watermark.byte_offset", in.CoveredWatermark.ByteOffset); err != nil {
		return PendingObservation{}, err
	}
	if err := boundedOptionalPtr("run_boundary.covered_watermark.source_locator", in.CoveredWatermark.SourceLocator, maxSourceLocator); err != nil {
		return PendingObservation{}, err
	}
	drain := in.DrainStatus
	wm := in.CoveredWatermark
	ended := wire.RunEndedBoundary{
		BoundarySource:   in.BoundarySource,
		RunId:            in.RunID,
		DrainStatus:      &drain,
		CoveredWatermark: &wm,
	}
	var payload wire.RunBoundaryPayload
	if err := payload.FromRunEndedBoundary(ended); err != nil {
		return PendingObservation{}, err
	}
	return newBoundary(c, payload), nil
}

// RunEndedLaunchFailureInput builds the launch-failure RUN_ENDED boundary, which carries
// neither a drain status nor a covered watermark.
type RunEndedLaunchFailureInput struct {
	RunID          string
	BoundarySource wire.RunEndedBoundaryBoundarySource
}

// NewRunEndedLaunchFailure builds a pre-sequence RUN_ENDED boundary with no drain fields.
func NewRunEndedLaunchFailure(c Common, in RunEndedLaunchFailureInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("run_boundary.run_id", in.RunID, maxRunID); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("run_boundary.boundary_source", in.BoundarySource); err != nil {
		return PendingObservation{}, err
	}
	ended := wire.RunEndedBoundary{
		BoundarySource: in.BoundarySource,
		RunId:          in.RunID,
	}
	var payload wire.RunBoundaryPayload
	if err := payload.FromRunEndedBoundary(ended); err != nil {
		return PendingObservation{}, err
	}
	return newBoundary(c, payload), nil
}

func newBoundary(c Common, payload wire.RunBoundaryPayload) PendingObservation {
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindRUNBOUNDARY),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.RunBoundaryObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				RunBoundary:   payload,
			}
			var o wire.Observation
			if err := o.FromRunBoundaryObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}
}

// ---- process lifecycle ----

// ProcessLifecycleInput builds a PROCESS_LIFECYCLE observation. It carries only OS process
// identity and exit evidence — never argv, environment, or an executable path.
type ProcessLifecycleInput struct {
	Transition wire.ProcessLifecyclePayloadTransition
	Identity   wire.ProcessIdentity
	ExitCode   *int32 // optional
	Signal     *int32 // optional
}

// NewProcessLifecycle builds a pre-sequence PROCESS_LIFECYCLE observation.
func NewProcessLifecycle(c Common, in ProcessLifecycleInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("process_lifecycle.transition", in.Transition); err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("process_lifecycle.process_identity.boot_id", in.Identity.BootId, maxBootID); err != nil {
		return PendingObservation{}, err
	}
	if err := nonNegative("process_lifecycle.process_identity.pid", in.Identity.Pid); err != nil {
		return PendingObservation{}, err
	}
	if err := nonNegative("process_lifecycle.process_identity.process_start_time", in.Identity.ProcessStartTime); err != nil {
		return PendingObservation{}, err
	}
	payload := wire.ProcessLifecyclePayload{
		Transition:      in.Transition,
		ProcessIdentity: in.Identity,
		ExitCode:        in.ExitCode,
		Signal:          in.Signal,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindPROCESSLIFECYCLE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.ProcessLifecycleObservation{
				Sequence:         seq,
				ObservationId:    id,
				OccurredAt:       c.OccurredAt,
				CapturedAt:       c.CapturedAt,
				Provenance:       c.Provenance,
				RunContext:       c.RunContext,
				ProcessLifecycle: payload,
			}
			var o wire.Observation
			if err := o.FromProcessLifecycleObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- session lifecycle ----

// SessionLifecycleInput builds a SESSION_LIFECYCLE observation. Model is optional and
// absent-not-empty: an empty string becomes an absent field.
type SessionLifecycleInput struct {
	NativeSessionID string
	Provider        string
	StartSource     wire.SessionLifecyclePayloadStartSource
	Transition      wire.SessionLifecyclePayloadTransition
	Model           string // optional
}

// NewSessionLifecycle builds a pre-sequence SESSION_LIFECYCLE observation.
func NewSessionLifecycle(c Common, in SessionLifecycleInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("session_lifecycle.native_session_id", in.NativeSessionID, maxNativeSessionID); err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("session_lifecycle.provider", in.Provider, maxProvider); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("session_lifecycle.start_source", in.StartSource); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("session_lifecycle.transition", in.Transition); err != nil {
		return PendingObservation{}, err
	}
	model, err := optionalString("session_lifecycle.model", in.Model, maxModel)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.SessionLifecyclePayload{
		NativeSessionId: in.NativeSessionID,
		Provider:        in.Provider,
		StartSource:     in.StartSource,
		Transition:      in.Transition,
		Model:           model,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.SessionLifecycleObservation{
				Sequence:         seq,
				ObservationId:    id,
				OccurredAt:       c.OccurredAt,
				CapturedAt:       c.CapturedAt,
				Provenance:       c.Provenance,
				RunContext:       c.RunContext,
				SessionLifecycle: payload,
			}
			var o wire.Observation
			if err := o.FromSessionLifecycleObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- message / tool call / tool result (content-bearing kinds) ----

// MessageInput builds a MESSAGE observation. It carries only role/timing/bounded counts —
// there is no body field, so a transformed body can never be attached under METADATA_ONLY.
type MessageInput struct {
	Role       wire.MessagePayloadRole
	ByteCount  *int64 // optional
	TokenCount *int64 // optional
}

// NewMessage builds a pre-sequence MESSAGE observation.
func NewMessage(c Common, in MessageInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("message.role", in.Role); err != nil {
		return PendingObservation{}, err
	}
	byteCount, err := checkedCount("message.byte_count", in.ByteCount)
	if err != nil {
		return PendingObservation{}, err
	}
	tokenCount, err := checkedCount("message.token_count", in.TokenCount)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.MessagePayload{
		Role:       in.Role,
		ByteCount:  byteCount,
		TokenCount: tokenCount,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindMESSAGE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.MessageObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				Message:       payload,
			}
			var o wire.Observation
			if err := o.FromMessageObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ToolCallInput builds a TOOL_CALL observation. It carries only a normalized category and a
// bounded argument byte count — never a command, argument, environment, url, or MCP name.
type ToolCallInput struct {
	Category          wire.ToolCallPayloadCategory
	ArgumentByteCount *int64 // optional
}

// NewToolCall builds a pre-sequence TOOL_CALL observation.
func NewToolCall(c Common, in ToolCallInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("tool_call.category", in.Category); err != nil {
		return PendingObservation{}, err
	}
	argByteCount, err := checkedCount("tool_call.argument_byte_count", in.ArgumentByteCount)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.ToolCallPayload{
		Category:          in.Category,
		ArgumentByteCount: argByteCount,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindTOOLCALL),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.ToolCallObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				ToolCall:      payload,
			}
			var o wire.Observation
			if err := o.FromToolCallObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ToolResultInput builds a TOOL_RESULT observation. It carries only category/status and a
// bounded result byte count — never a result body.
type ToolResultInput struct {
	Category        wire.ToolResultPayloadCategory
	Status          wire.ToolResultPayloadStatus
	ResultByteCount *int64 // optional
}

// NewToolResult builds a pre-sequence TOOL_RESULT observation.
func NewToolResult(c Common, in ToolResultInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("tool_result.category", in.Category); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("tool_result.status", in.Status); err != nil {
		return PendingObservation{}, err
	}
	resultByteCount, err := checkedCount("tool_result.result_byte_count", in.ResultByteCount)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.ToolResultPayload{
		Category:        in.Category,
		Status:          in.Status,
		ResultByteCount: resultByteCount,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindTOOLRESULT),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.ToolResultObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				ToolResult:    payload,
			}
			var o wire.Observation
			if err := o.FromToolResultObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- usage ----

// UsageInput builds a USAGE observation. Absent token fields stay absent (never coerced to
// zero); an ESTIMATED usage requires a non-empty price_table_version.
type UsageInput struct {
	Quality             wire.UsagePayloadQuality
	InputTokens         *int64
	OutputTokens        *int64
	CacheCreationTokens *int64
	CacheReadTokens     *int64
	ProviderSource      string // optional
	PriceTableVersion   string // required iff ESTIMATED; otherwise optional/absent
	MessageID           string // optional provider message/response id; the read-time spend-join key
}

// NewUsage builds a pre-sequence USAGE observation, enforcing the ESTIMATED price-table
// coupling at construction so an under-specified estimate can never be built.
func NewUsage(c Common, in UsageInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("usage.quality", in.Quality); err != nil {
		return PendingObservation{}, err
	}
	priceTable, err := optionalString("usage.price_table_version", in.PriceTableVersion, maxPriceTableVersion)
	if err != nil {
		return PendingObservation{}, err
	}
	if in.Quality == wire.UsagePayloadQualityESTIMATED && priceTable == nil {
		return PendingObservation{}, buildErr("usage.price_table_version", "ESTIMATED usage requires a non-empty price_table_version")
	}
	providerSource, err := optionalString("usage.provider_source", in.ProviderSource, maxProviderSource)
	if err != nil {
		return PendingObservation{}, err
	}
	messageID, err := optionalString("usage.message_id", in.MessageID, maxMessageID)
	if err != nil {
		return PendingObservation{}, err
	}
	inputTokens, err := checkedCount("usage.input_tokens", in.InputTokens)
	if err != nil {
		return PendingObservation{}, err
	}
	outputTokens, err := checkedCount("usage.output_tokens", in.OutputTokens)
	if err != nil {
		return PendingObservation{}, err
	}
	cacheCreationTokens, err := checkedCount("usage.cache_creation_tokens", in.CacheCreationTokens)
	if err != nil {
		return PendingObservation{}, err
	}
	cacheReadTokens, err := checkedCount("usage.cache_read_tokens", in.CacheReadTokens)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.UsagePayload{
		Quality:             in.Quality,
		InputTokens:         inputTokens,
		OutputTokens:        outputTokens,
		CacheCreationTokens: cacheCreationTokens,
		CacheReadTokens:     cacheReadTokens,
		ProviderSource:      providerSource,
		PriceTableVersion:   priceTable,
		MessageId:           messageID,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindUSAGE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.UsageObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				Usage:         payload,
			}
			var o wire.Observation
			if err := o.FromUsageObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- work references ----

// DeclaredWorkRefInput builds a DECLARED WORK_REFERENCE (from the wrapper/lifecycle API).
type DeclaredWorkRefInput struct {
	TeamServerProjectID string
	BeadID              string
}

// NewDeclaredWorkReference builds a pre-sequence WORK_REFERENCE with origin DECLARED.
func NewDeclaredWorkReference(c Common, in DeclaredWorkRefInput) (PendingObservation, error) {
	ref := wire.WorkReference{
		TeamServerProjectId: in.TeamServerProjectID,
		BeadId:              in.BeadID,
		Origin:              wire.WorkReferenceOriginDECLARED,
	}
	return newWorkReference(c, ref)
}

// ProjectResolver supplies the only two sources a team_server_project_id may come from for
// an EXTRACTED reference (spec "Reference extraction"): the daemon-stamped run context, or
// a single configured default project. The stamped context wins when both are present.
type ProjectResolver struct {
	// StampedProjectID is the project from the daemon-stamped run context ("" if none).
	StampedProjectID string
	// DefaultProjectID is the single configured default project ("" if none).
	DefaultProjectID string
}

func (r ProjectResolver) resolve() (string, bool) {
	if r.StampedProjectID != "" {
		return r.StampedProjectID, true
	}
	if r.DefaultProjectID != "" {
		return r.DefaultProjectID, true
	}
	return "", false
}

// RefDropReason is the typed reason an EXTRACTED reference was dropped.
type RefDropReason string

// RefDropUnresolvableProject means no stamped run context and no configured default project
// could supply a team_server_project_id, so the reference cannot be built.
const RefDropUnresolvableProject RefDropReason = "UNRESOLVABLE_PROJECT"

// ExtractedWorkRefResult is the typed outcome of building an EXTRACTED work reference:
// exactly one of Resolved and Drop is non-nil. When the project resolves, Resolved holds
// the WORK_REFERENCE observation. When it does not, Drop holds a content-free
// CAPTURE_DIAGNOSTIC recording the drop and DropReason names why (spec: "an unresolvable
// match is dropped with a diagnostic").
type ExtractedWorkRefResult struct {
	Resolved   *PendingObservation
	Drop       *PendingObservation
	DropReason RefDropReason
}

// Dropped reports whether the reference was dropped (Resolved is nil).
func (r ExtractedWorkRefResult) Dropped() bool { return r.Resolved == nil }

// ExtractedWorkRefInput builds an EXTRACTED WORK_REFERENCE from a pattern-captured bead ID.
// The team_server_project_id is never taken from the identifier; it is resolved separately.
type ExtractedWorkRefInput struct {
	BeadID string
}

// NewExtractedWorkReference resolves the project for a pattern-captured bead ID and either
// builds the WORK_REFERENCE observation or returns a content-free drop diagnostic. It fails
// closed on a malformed bead ID or bad common metadata (returning a non-nil error), never
// emitting a partially-formed reference.
func NewExtractedWorkReference(c Common, in ExtractedWorkRefInput, resolver ProjectResolver) (ExtractedWorkRefResult, error) {
	if err := boundedNonEmpty("work_reference.bead_id", in.BeadID, maxBeadID); err != nil {
		return ExtractedWorkRefResult{}, err
	}
	projectID, ok := resolver.resolve()
	if !ok {
		diag, err := NewCaptureDiagnostic(c, CaptureDiagnosticInput{
			Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
			Severity:           wire.CaptureDiagnosticPayloadSeverityINFO,
			CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectNONE,
			Context:            "extracted work reference dropped: no stamped or default team-server project",
		})
		if err != nil {
			return ExtractedWorkRefResult{}, err
		}
		return ExtractedWorkRefResult{Drop: &diag, DropReason: RefDropUnresolvableProject}, nil
	}
	ref := wire.WorkReference{
		TeamServerProjectId: projectID,
		BeadId:              in.BeadID,
		Origin:              wire.WorkReferenceOriginEXTRACTED,
	}
	obs, err := newWorkReference(c, ref)
	if err != nil {
		return ExtractedWorkRefResult{}, err
	}
	return ExtractedWorkRefResult{Resolved: &obs}, nil
}

func newWorkReference(c Common, ref wire.WorkReference) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validateWorkReference("work_reference", ref); err != nil {
		return PendingObservation{}, err
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindWORKREFERENCE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.WorkReferenceObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				WorkReference: ref,
			}
			var o wire.Observation
			if err := o.FromWorkReferenceObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- VCS references (split per ref kind) ----

// CommitReferenceInput builds a COMMIT VCS_REFERENCE. The identifier is enforced to be a
// lowercase full 40- or 64-hex string (^([0-9a-f]{40}|[0-9a-f]{64})$) — abbreviated
// hashes, branch names, and non-hex text are rejected with a BuildError. repo_slug, when
// present, must match ^[A-Za-z0-9._/-]{1,140}$. A 40/64-hex value that is itself a
// hex-encoded secret is indistinguishable here and passes the pattern; excluding it is
// E1.8's anchored-extraction concern, correctly ceded upstream.
type CommitReferenceInput struct {
	Identifier string
	RepoSlug   string // optional
	Extraction wire.ExtractionProvenance
}

// NewCommitReference builds a pre-sequence COMMIT VCS_REFERENCE observation.
func NewCommitReference(c Common, in CommitReferenceInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("vcs_reference.identifier", in.Identifier, maxCommitIdentifier); err != nil {
		return PendingObservation{}, err
	}
	if !commitIdentifierPattern.MatchString(in.Identifier) {
		return PendingObservation{}, buildErr("vcs_reference.identifier", "must be a lowercase full 40- or 64-hex commit identifier")
	}
	slug, err := validateRepoSlug(in.RepoSlug)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validateExtraction(in.Extraction); err != nil {
		return PendingObservation{}, err
	}
	commit := wire.CommitVcsReference{
		Identifier: in.Identifier,
		RepoSlug:   slug,
		Extraction: in.Extraction,
	}
	var payload wire.VcsReferencePayload
	if err := payload.FromCommitVcsReference(commit); err != nil {
		return PendingObservation{}, err
	}
	return newVcsReference(c, payload), nil
}

// PullRequestReferenceInput builds a PULL_REQUEST VCS_REFERENCE. The identifier is enforced
// to be an anchored #N or https:// PR-URL form (^(#[0-9]{1,20}|https://[^ ]{1,240})$) —
// bare numbers, prose, and non-https schemes are rejected with a BuildError. repo_slug,
// when present, must match ^[A-Za-z0-9._/-]{1,140}$.
type PullRequestReferenceInput struct {
	Identifier string
	RepoSlug   string // optional
	Extraction wire.ExtractionProvenance
}

// NewPullRequestReference builds a pre-sequence PULL_REQUEST VCS_REFERENCE observation.
func NewPullRequestReference(c Common, in PullRequestReferenceInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := boundedNonEmpty("vcs_reference.identifier", in.Identifier, maxPullReqIdentifier); err != nil {
		return PendingObservation{}, err
	}
	if !pullRequestIdentifierPattern.MatchString(in.Identifier) {
		return PendingObservation{}, buildErr("vcs_reference.identifier", "must be an anchored #N or https:// pull-request identifier")
	}
	slug, err := validateRepoSlug(in.RepoSlug)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validateExtraction(in.Extraction); err != nil {
		return PendingObservation{}, err
	}
	pr := wire.PullRequestVcsReference{
		Identifier: in.Identifier,
		RepoSlug:   slug,
		Extraction: in.Extraction,
	}
	var payload wire.VcsReferencePayload
	if err := payload.FromPullRequestVcsReference(pr); err != nil {
		return PendingObservation{}, err
	}
	return newVcsReference(c, payload), nil
}

// validateRepoSlug enforces the vendored repo_slug pattern (^[A-Za-z0-9._/-]{1,140}$,
// which carries its own length bound). An empty slug is absent-not-empty (nil); a
// non-empty slug that fails the charset/length pattern is a typed BuildError so the policy
// transform fails closed rather than sealing a contract-invalid slug (URLs, query strings,
// scp-style git@host:org/repo remotes, spaces, unicode) into canonical bytes.
func validateRepoSlug(slug string) (*string, error) {
	if slug == "" {
		return nil, nil
	}
	if !repoSlugPattern.MatchString(slug) {
		return nil, buildErr("vcs_reference.repo_slug", "must match [A-Za-z0-9._/-]{1,140}")
	}
	v := slug
	return &v, nil
}

func validateExtraction(e wire.ExtractionProvenance) error {
	if err := validEnum("vcs_reference.extraction.surface", e.Surface); err != nil {
		return err
	}
	if err := boundedNonEmpty("vcs_reference.extraction.pattern_id", e.PatternId, maxPatternID); err != nil {
		return err
	}
	return boundedNonEmpty("vcs_reference.extraction.extractor_version", e.ExtractorVersion, maxExtractorVersion)
}

func newVcsReference(c Common, payload wire.VcsReferencePayload) PendingObservation {
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindVCSREFERENCE),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.VcsReferenceObservation{
				Sequence:      seq,
				ObservationId: id,
				OccurredAt:    c.OccurredAt,
				CapturedAt:    c.CapturedAt,
				Provenance:    c.Provenance,
				RunContext:    c.RunContext,
				VcsReference:  payload,
			}
			var o wire.Observation
			if err := o.FromVcsReferenceObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}
}

// ---- capture diagnostic ----

// CaptureDiagnosticInput builds a content-free CAPTURE_DIAGNOSTIC. Context is optional,
// bounded, and absent-not-empty; it must never carry a raw provider record, path, or
// secret. The constructor sanitizes Context (drops it entirely if it carries an
// absolute/home/traversal path, else truncates to the bound) so the "bounded sanitized
// context" property (spec) holds for EVERY caller — the direct-constructor path E1.4/E1.6-
// E1.8 use for daemon-authored diagnostics, not only the policy transform.
type CaptureDiagnosticInput struct {
	Code               wire.CaptureDiagnosticPayloadCode
	Severity           wire.CaptureDiagnosticPayloadSeverity
	CompletenessEffect wire.CaptureDiagnosticPayloadCompletenessEffect
	Context            string // optional
}

// NewCaptureDiagnostic builds a pre-sequence CAPTURE_DIAGNOSTIC observation.
func NewCaptureDiagnostic(c Common, in CaptureDiagnosticInput) (PendingObservation, error) {
	c, err := prepareCommon(c)
	if err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("capture_diagnostic.code", in.Code); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("capture_diagnostic.severity", in.Severity); err != nil {
		return PendingObservation{}, err
	}
	if err := validEnum("capture_diagnostic.completeness_effect", in.CompletenessEffect); err != nil {
		return PendingObservation{}, err
	}
	context, err := optionalString("capture_diagnostic.context", sanitizeContext(in.Context, maxDiagnosticContext), maxDiagnosticContext)
	if err != nil {
		return PendingObservation{}, err
	}
	payload := wire.CaptureDiagnosticPayload{
		Code:               in.Code,
		Severity:           in.Severity,
		CompletenessEffect: in.CompletenessEffect,
		Context:            context,
	}
	return PendingObservation{
		kind:       string(wire.ObservationEnvelopeKindCAPTUREDIAGNOSTIC),
		occurredAt: c.OccurredAt,
		capturedAt: c.CapturedAt,
		seal: func(seq int64, id string) (wire.Observation, error) {
			v := wire.CaptureDiagnosticObservation{
				Sequence:          seq,
				ObservationId:     id,
				OccurredAt:        c.OccurredAt,
				CapturedAt:        c.CapturedAt,
				Provenance:        c.Provenance,
				RunContext:        c.RunContext,
				CaptureDiagnostic: payload,
			}
			var o wire.Observation
			if err := o.FromCaptureDiagnosticObservation(v); err != nil {
				return wire.Observation{}, err
			}
			return o, nil
		},
	}, nil
}

// ---- shared helpers ----

// optionalString enforces absent-not-empty for an optional bounded string: an empty input
// becomes an absent (nil) field; a non-empty input is bounds-checked and returned by
// pointer.
func optionalString(field, value string, max int) (*string, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > max {
		return nil, buildErr(field, fmt.Sprintf("length %d exceeds max %d", len(value), max))
	}
	v := value
	return &v, nil
}

// isSlugByte reports whether a byte is part of a path/slug token ([A-Za-z0-9._-]). A '/'
// preceded by a non-slug byte marks an embedded absolute path (e.g. "file=/etc", "(/var",
// "\"/home", " /usr"); a '/' preceded by a slug byte is an ordinary in-token separator
// ("codex/2026", "and/or", "50/50").
func isSlugByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '.' || b == '_' || b == '-'
}

// hasEmbeddedAbsolutePath reports whether a string carries an absolute or home path
// ANYWHERE, not just at a whitespace-delimited prefix: a leading '/' or '~', the "~/" home
// form anywhere, or a '/' at a non-slug boundary (an embedded absolute path). This is the
// last privacy gate for a free-text diagnostic context; a false positive only loses a
// diagnostic string, a false negative leaks a filesystem path.
func hasEmbeddedAbsolutePath(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	if strings.Contains(s, "~/") {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '/' && !isSlugByte(s[i-1]) {
			return true
		}
	}
	return false
}

// isRootRelativeLocator reports whether a locator is genuinely root-relative and therefore
// safe to emit as source_locator: non-empty, not absolute ('/') or home ('~'), and — after
// path.Clean — free of any ".." segment, so a "../../../home/alice/.ssh/id_rsa" traversal
// that reconstructs an absolute path is rejected.
func isRootRelativeLocator(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return false
	}
	if strings.ContainsRune(s, 0) {
		return false
	}
	cleaned := path.Clean(s)
	if strings.HasPrefix(cleaned, "/") {
		return false
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// sanitizeContext bounds a diagnostic context and drops it entirely (returns "") if it
// carries an absolute/home/traversal path anywhere, so a diagnostic can never smuggle a
// filesystem locator into canonical bytes. Newlines are flattened before the scan.
func sanitizeContext(s string, max int) string {
	if s == "" {
		return ""
	}
	if strings.ContainsAny(s, "\n\r") {
		s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
	}
	if hasEmbeddedAbsolutePath(s) {
		return ""
	}
	if len(s) > max {
		return s[:max]
	}
	return s
}

// checkedRefs validates an optional work-reference slice against the per-observation cap
// and returns it as the wire optional-slice pointer (nil when empty, preserving
// absent-not-empty for the whole list).
func checkedRefs(field string, refs []wire.WorkReference) (*[]wire.WorkReference, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if len(refs) > MaxReferencesPerObservation {
		return nil, buildErr(field, fmt.Sprintf("%d entries exceeds cap %d", len(refs), MaxReferencesPerObservation))
	}
	for i := range refs {
		if err := validateWorkReference(fmt.Sprintf("%s[%d]", field, i), refs[i]); err != nil {
			return nil, err
		}
	}
	out := make([]wire.WorkReference, len(refs))
	copy(out, refs)
	return &out, nil
}
