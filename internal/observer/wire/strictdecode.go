package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// SequenceMin and SequenceMax are the inclusive wire bounds on a one-based source
// sequence (x-limits sequence_min/sequence_max). SequenceMax matches PostgreSQL BIGINT
// and never wraps.
const (
	SequenceMin int64 = 1
	SequenceMax int64 = math.MaxInt64
)

// SupportedSchemaVersion is the single v1 wire schema version.
const SupportedSchemaVersion int64 = 1

// DecodedBatch is a strictly decoded observation batch: every observation has been
// dispatched to its closed variant, rejected on unknown kind or unknown field, and
// range-checked, so it is safe to hand to the semantic validators and the store.
type DecodedBatch struct {
	SchemaVersion int64
	SourceID      string
	FirstSequence int64
	LastSequence  int64
	Observations  []DecodedObservation
}

// DecodedObservation is one strictly decoded observation. Variant holds the concrete
// generated variant struct; the nested-union fields are populated for the kinds whose
// payload is itself a discriminated union or which a semantic validator inspects.
type DecodedObservation struct {
	Kind          string
	Sequence      int64
	ObservationID string
	RunContext    *RunContext

	// Variant is the concrete strictly-decoded observation (one of the generated
	// *Observation structs).
	Variant any

	// RunStarted / RunEnded are set for a RUN_BOUNDARY, after the nested
	// RunBoundaryPayload union is dispatched on transition.
	RunStarted *RunStartedBoundary
	RunEnded   *RunEndedBoundary

	// Usage is set for a USAGE observation.
	Usage *UsagePayload
}

// DecodeObservationBatch strictly decodes one ingest batch. It rejects, with a typed
// *DecodeError, before any storage-layer use:
//   - malformed JSON, wrong types, or trailing data (ErrMalformedJSON);
//   - unknown top-level or per-observation fields (ErrUnknownField);
//   - an unknown observation kind, run-boundary transition, or vcs ref_kind
//     (ErrUnknownDiscriminator);
//   - an out-of-range source sequence, below 1 or above math.MaxInt64
//     (ErrSequenceOutOfRange);
//   - an unsupported schema_version (ErrSchemaVersionUnsupported).
//
// It does not enforce the demoted semantic couplings (contiguity, drain-pair,
// ESTIMATED price table, caps) — those are the platform validators / S2.4 / E1.1.
func DecodeObservationBatch(data []byte) (*DecodedBatch, error) {
	var hdr struct {
		SchemaVersion json.Number       `json:"schema_version"`
		SourceID      string            `json:"source_id"`
		FirstSequence json.Number       `json:"first_sequence"`
		LastSequence  json.Number       `json:"last_sequence"`
		Observations  []json.RawMessage `json:"observations"`
	}
	if err := strictDecode(data, &hdr); err != nil {
		return nil, classifyDecode(err, "")
	}

	sv, err := hdr.SchemaVersion.Int64()
	if err != nil || sv != SupportedSchemaVersion {
		return nil, decodeErr(ErrSchemaVersionUnsupported, "schema_version",
			fmt.Sprintf("got %q, want %d", hdr.SchemaVersion.String(), SupportedSchemaVersion), err)
	}

	first, err := parseSequence(hdr.FirstSequence, "first_sequence")
	if err != nil {
		return nil, err
	}
	last, err := parseSequence(hdr.LastSequence, "last_sequence")
	if err != nil {
		return nil, err
	}

	out := &DecodedBatch{
		SchemaVersion: sv,
		SourceID:      hdr.SourceID,
		FirstSequence: first,
		LastSequence:  last,
		Observations:  make([]DecodedObservation, 0, len(hdr.Observations)),
	}
	for i, raw := range hdr.Observations {
		obs, err := decodeObservation(raw, i)
		if err != nil {
			return nil, err
		}
		out.Observations = append(out.Observations, obs)
	}
	return out, nil
}

// payloadMemberByKind maps each closed observation kind to its required
// discriminated payload member — the field that must be present and non-null.
var payloadMemberByKind = map[string]string{
	string(ObservationEnvelopeKindRUNBOUNDARY):       "run_boundary",
	string(ObservationEnvelopeKindSESSIONLIFECYCLE):  "session_lifecycle",
	string(ObservationEnvelopeKindMESSAGE):           "message",
	string(ObservationEnvelopeKindTOOLCALL):          "tool_call",
	string(ObservationEnvelopeKindTOOLRESULT):        "tool_result",
	string(ObservationEnvelopeKindUSAGE):             "usage",
	string(ObservationEnvelopeKindWORKREFERENCE):     "work_reference",
	string(ObservationEnvelopeKindVCSREFERENCE):      "vcs_reference",
	string(ObservationEnvelopeKindPROCESSLIFECYCLE):  "process_lifecycle",
	string(ObservationEnvelopeKindCAPTUREDIAGNOSTIC): "capture_diagnostic",
}

// decodeObservation dispatches one observation on its kind and strictly decodes the
// matching variant (and any nested union), rejecting unknown/absent/null payloads and
// out-of-range enum values.
func decodeObservation(raw json.RawMessage, idx int) (DecodedObservation, error) {
	field := fmt.Sprintf("observations[%d]", idx)

	var peek struct {
		Kind     string      `json:"kind"`
		Sequence json.Number `json:"sequence"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return DecodedObservation{}, classifyDecode(err, field)
	}
	seq, err := parseSequence(peek.Sequence, field+".sequence")
	if err != nil {
		return DecodedObservation{}, err
	}
	if member, ok := payloadMemberByKind[peek.Kind]; ok {
		if err := requirePayloadMember(raw, member, field); err != nil {
			return DecodedObservation{}, err
		}
	}

	out := DecodedObservation{Kind: peek.Kind, Sequence: seq}

	switch peek.Kind {
	case string(ObservationEnvelopeKindRUNBOUNDARY):
		var v RunBoundaryObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
		if err := decodeRunBoundary(v.RunBoundary, field+".run_boundary", &out); err != nil {
			return DecodedObservation{}, err
		}
	case string(ObservationEnvelopeKindSESSIONLIFECYCLE):
		var v SessionLifecycleObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindMESSAGE):
		var v MessageObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindTOOLCALL):
		var v ToolCallObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindTOOLRESULT):
		var v ToolResultObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindUSAGE):
		var v UsageObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		usage := v.Usage
		out.Variant, out.ObservationID, out.RunContext, out.Usage = v, v.ObservationId, v.RunContext, &usage
	case string(ObservationEnvelopeKindWORKREFERENCE):
		var v WorkReferenceObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindVCSREFERENCE):
		var v VcsReferenceObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
		if err := decodeVcsReference(v.VcsReference, field+".vcs_reference"); err != nil {
			return DecodedObservation{}, err
		}
	case string(ObservationEnvelopeKindPROCESSLIFECYCLE):
		var v ProcessLifecycleObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	case string(ObservationEnvelopeKindCAPTUREDIAGNOSTIC):
		var v CaptureDiagnosticObservation
		if err := strictDecodeVariant(raw, &v, field); err != nil {
			return DecodedObservation{}, err
		}
		out.Variant, out.ObservationID, out.RunContext = v, v.ObservationId, v.RunContext
	default:
		return DecodedObservation{}, decodeErr(ErrUnknownDiscriminator, field+".kind",
			fmt.Sprintf("kind %q is not in the closed v1 observation set", peek.Kind), nil)
	}
	// Closed-enum membership over the whole decoded variant (envelope kind, provenance
	// policy/quality/completeness, run_context membership_evidence, work-ref origin, …).
	// Nested unions carry raw bytes here and are validated via their own decoded shapes.
	if err := validateEnumMembership(out.Variant, field); err != nil {
		return DecodedObservation{}, err
	}
	return out, nil
}

// requirePayloadMember rejects a discriminated payload member that is absent or JSON
// null, which the generated value-typed structs would otherwise zero-fill silently.
func requirePayloadMember(raw json.RawMessage, member, field string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return classifyDecode(err, field)
	}
	v, ok := members[member]
	if !ok {
		return decodeErr(ErrMissingPayload, field+"."+member, "required payload member is absent", nil)
	}
	if string(v) == "null" {
		return decodeErr(ErrMissingPayload, field+"."+member, "required payload member is null", nil)
	}
	return nil
}

// decodeRunBoundary dispatches the nested RunBoundaryPayload union on transition and
// strictly decodes the matching boundary shape (this is what makes a RUN_STARTED that
// carries drain fields an unknown-field rejection).
func decodeRunBoundary(p RunBoundaryPayload, field string, out *DecodedObservation) error {
	raw, err := p.MarshalJSON()
	if err != nil {
		return decodeErr(ErrMalformedJSON, field, "run boundary payload not readable", err)
	}
	var peek struct {
		Transition string `json:"transition"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return classifyDecode(err, field)
	}
	switch peek.Transition {
	case string(RunStartedBoundaryTransitionRUNSTARTED):
		var b RunStartedBoundary
		if err := strictDecodeVariant(raw, &b, field); err != nil {
			return err
		}
		if err := validateEnumMembership(b, field); err != nil {
			return err
		}
		out.RunStarted = &b
	case string(RunEndedBoundaryTransitionRUNENDED):
		var b RunEndedBoundary
		if err := strictDecodeVariant(raw, &b, field); err != nil {
			return err
		}
		if err := validateEnumMembership(b, field); err != nil {
			return err
		}
		out.RunEnded = &b
	default:
		return decodeErr(ErrUnknownDiscriminator, field+".transition",
			fmt.Sprintf("transition %q is not RUN_STARTED or RUN_ENDED", peek.Transition), nil)
	}
	return nil
}

// decodeVcsReference dispatches the nested VcsReferencePayload union on ref_kind and
// strictly decodes the matching reference shape (defense-in-depth: no validator reads
// it, but an unknown ref_kind or a stray field is still rejected).
func decodeVcsReference(p VcsReferencePayload, field string) error {
	raw, err := p.MarshalJSON()
	if err != nil {
		return decodeErr(ErrMalformedJSON, field, "vcs reference payload not readable", err)
	}
	var peek struct {
		RefKind string `json:"ref_kind"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return classifyDecode(err, field)
	}
	switch peek.RefKind {
	case string(CommitVcsReferenceRefKindCOMMIT):
		var r CommitVcsReference
		if err := strictDecodeVariant(raw, &r, field); err != nil {
			return err
		}
		return validateEnumMembership(r, field)
	case string(PullRequestVcsReferenceRefKindPULLREQUEST):
		var r PullRequestVcsReference
		if err := strictDecodeVariant(raw, &r, field); err != nil {
			return err
		}
		return validateEnumMembership(r, field)
	default:
		return decodeErr(ErrUnknownDiscriminator, field+".ref_kind",
			fmt.Sprintf("ref_kind %q is not COMMIT or PULL_REQUEST", peek.RefKind), nil)
	}
}

// parseSequence range-checks a source sequence into [SequenceMin, SequenceMax]. An
// overflow, a non-integer, or an out-of-bounds value is a typed ErrSequenceOutOfRange.
func parseSequence(n json.Number, field string) (int64, error) {
	v, err := n.Int64()
	if err != nil {
		return 0, decodeErr(ErrSequenceOutOfRange, field,
			fmt.Sprintf("%q is not an int64 in [1, %d]", n.String(), SequenceMax), err)
	}
	if v < SequenceMin || v > SequenceMax {
		return 0, decodeErr(ErrSequenceOutOfRange, field,
			fmt.Sprintf("%d is outside [1, %d]", v, SequenceMax), nil)
	}
	return v, nil
}

// strictDecode decodes into v with unknown-field rejection and no trailing data.
func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errTrailing
	}
	return nil
}

// strictDecodeVariant strictly decodes one variant/nested payload and wraps any
// failure as a typed *DecodeError located at field.
func strictDecodeVariant(data []byte, v any, field string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return classifyDecode(err, field)
	}
	if dec.More() {
		return decodeErr(ErrMalformedJSON, field, "unexpected trailing data", nil)
	}
	return nil
}

var errTrailing = fmt.Errorf("unexpected trailing data")

// classifyDecode maps an encoding/json error to the right typed sentinel.
func classifyDecode(err error, field string) *DecodeError {
	if err == errTrailing {
		return decodeErr(ErrMalformedJSON, field, "unexpected trailing data", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "unknown field") {
		return decodeErr(ErrUnknownField, field, msg, err)
	}
	return decodeErr(ErrMalformedJSON, field, msg, err)
}
