package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// The endpoint-side semantic batch validators. These enforce the demoted wire-contract
// couplings that OpenAPI 3.0 cannot carry and that the strict wire decoder
// (wire.DecodeObservationBatch) deliberately leaves to this layer (see wire/gen.go and
// wire/errors.go for the scope pointer). They run on the endpoint before a batch is
// appended to the WAL, and are a byte-for-byte semantic mirror of the platform's
// gasworks-platform apigen.ValidateBatch, so a batch the endpoint accepts locally is a
// batch the Collector accepts on ingest — and the shared semantic_violation-tagged
// fixture corpus is the negative input for both.
//
// Scope: these are STATELESS, single-batch shape rules. The two stateful conflicts in
// the corpus — SEQUENCE_CONFLICT and OBSERVATION_CONFLICT — are 409s the server storage
// layer raises against prior source bindings, not shape rules a single batch can decide,
// so those fixtures are intentionally accepted here (matching the platform).

// MaxReferencesPerObservation is the per-observation reference cap (x-limits
// max_references_per_observation). It bounds both a RUN_STARTED boundary's
// work_item_refs and any observation's run_context.work_item_refs.
const MaxReferencesPerObservation = 32

// MaxObservationsPerBatch is the batch cardinality ceiling (x-limits
// max_observations_per_batch / the observations maxItems). minItems is 1.
const MaxObservationsPerBatch = 1000

// The three non-VCS field constraints the platform apigen constraint validator added
// (gasworks-platform, commit e505060): observation_id required/non-empty, session
// lifecycle model minLength, and the source_id pattern. OpenAPI 3.0 carries these as
// schema keywords, but the strict wire decoder (wire.DecodeObservationBatch) enforces
// shape/enum/sequence only and leaves these to this layer. The endpoint is the TRUSTED
// producer — observation_id is spool-assigned, source_id is server-assigned at
// enrollment, and an empty model is unrepresentable through the constructors — so these
// are defense-in-depth SYMMETRY with the platform gate, not the load-bearing check. We
// mirror them so a batch the endpoint accepts locally is one the Collector accepts on
// ingest, and so the shared invalid-fixture corpus (missing_observation_id,
// session_model_empty, bad_source_id) rejects identically on both sides.
const (
	// MaxObservationIDLen is the observation_id maxLength (schema maxLength 128).
	MaxObservationIDLen = 128
	// MaxModelLen is the session_lifecycle.model maxLength (schema maxLength 128).
	MaxModelLen = 128
)

// sourceIDPattern is the vendored source_id charset/format (^src_[0-9a-zA-Z]{1,64}$, which
// also carries the minLength:1/maxLength:68 bounds), compiled once from the contract
// (contracts/observer/v1/openapi.json). It mirrors the platform's source_id constraint.
var sourceIDPattern = regexp.MustCompile(`^src_[0-9a-zA-Z]{1,64}$`)

// ValidationRule identifies a demoted wire-contract coupling enforced by these
// validators rather than by the OpenAPI 3.0 schema.
type ValidationRule string

// The demoted couplings pinned by the semantic_violation-tagged fixture corpus.
const (
	// RuleRangeNotContiguous: first_sequence + len - 1 == last_sequence AND every
	// observation.sequence == first_sequence + index (fixture tag RANGE_NOT_CONTIGUOUS).
	RuleRangeNotContiguous ValidationRule = "RANGE_NOT_CONTIGUOUS"
	// RuleDrainPair: on a RUN_ENDED boundary, drain_status and covered_watermark travel
	// together — both present or both absent (fixture tag DRAIN_PAIR).
	RuleDrainPair ValidationRule = "DRAIN_PAIR"
	// RuleEstimatedPriceTable: ESTIMATED usage requires a non-empty price_table_version
	// (fixture tag ESTIMATED_PRICE_TABLE).
	RuleEstimatedPriceTable ValidationRule = "ESTIMATED_PRICE_TABLE"
	// RuleReferenceCap: no observation may carry more than the per-observation reference
	// cap (x-limits max_references_per_observation).
	RuleReferenceCap ValidationRule = "REFERENCE_CAP_EXCEEDED"
	// RuleBatchCardinality: a batch must carry between 1 and max_observations_per_batch
	// observations (x-limits minItems/maxItems) — an empty or oversized batch is rejected
	// before it reaches ingest/watermark logic.
	RuleBatchCardinality ValidationRule = "BATCH_CARDINALITY"
	// RuleObservationIDRequired: every observation carries a present, non-empty
	// observation_id within the schema maxLength (defense-in-depth mirror of the platform's
	// required/non-empty observation_id constraint).
	RuleObservationIDRequired ValidationRule = "OBSERVATION_ID_REQUIRED"
	// RuleModelMinLength: a present session_lifecycle.model is non-empty (minLength 1) and
	// within maxLength — an unknown model must be absent, never the empty string.
	RuleModelMinLength ValidationRule = "MODEL_MIN_LENGTH"
	// RuleSourceIDPattern: the batch source_id matches ^src_[0-9a-zA-Z]{1,64}$.
	RuleSourceIDPattern ValidationRule = "SOURCE_ID_PATTERN"
)

// Sentinel per-rule errors so callers can branch with errors.Is.
var (
	ErrRangeNotContiguous  = errors.New("observer evidence: batch range not contiguous")
	ErrDrainPairMismatch   = errors.New("observer evidence: RUN_ENDED drain_status/covered_watermark must travel together")
	ErrEstimatedPriceTable = errors.New("observer evidence: ESTIMATED usage requires price_table_version")
	ErrReferenceCap        = errors.New("observer evidence: per-observation reference cap exceeded")
	ErrBatchCardinality    = errors.New("observer evidence: batch observation count out of bounds")
	// ErrObservationIDRequired matches a missing/empty/over-long observation_id.
	ErrObservationIDRequired = errors.New("observer evidence: observation_id must be present and non-empty")
	// ErrModelMinLength matches a present-but-empty (or over-long) session_lifecycle.model.
	ErrModelMinLength = errors.New("observer evidence: session_lifecycle.model must be non-empty when present")
	// ErrSourceIDPattern matches a source_id that violates the vendored pattern.
	ErrSourceIDPattern = errors.New("observer evidence: source_id does not match the required pattern")
)

var ruleSentinel = map[ValidationRule]error{
	RuleRangeNotContiguous:    ErrRangeNotContiguous,
	RuleDrainPair:             ErrDrainPairMismatch,
	RuleEstimatedPriceTable:   ErrEstimatedPriceTable,
	RuleReferenceCap:          ErrReferenceCap,
	RuleBatchCardinality:      ErrBatchCardinality,
	RuleObservationIDRequired: ErrObservationIDRequired,
	RuleModelMinLength:        ErrModelMinLength,
	RuleSourceIDPattern:       ErrSourceIDPattern,
}

// ValidationError is a typed semantic-coupling violation. Rule names the demoted
// coupling; errors.Is(err, ErrDrainPairMismatch) and friends match through it.
type ValidationError struct {
	// Rule is the violated coupling.
	Rule ValidationRule
	// ObservationIndex is the zero-based batch index of the offending observation, or -1
	// for a batch-level rule (cardinality/contiguity).
	ObservationIndex int
	// ObservationID is the offending observation's immutable id when known.
	ObservationID string
	// Detail is a human-readable diagnostic.
	Detail string
}

// Error renders the violation with its rule and location.
func (e *ValidationError) Error() string {
	loc := ""
	if e.ObservationIndex >= 0 {
		loc = fmt.Sprintf(" (observations[%d]", e.ObservationIndex)
		if e.ObservationID != "" {
			loc += " " + e.ObservationID
		}
		loc += ")"
	}
	return fmt.Sprintf("%s%s: %s", e.Rule, loc, e.Detail)
}

// Is matches the per-rule sentinel so callers can branch on the violation class.
func (e *ValidationError) Is(target error) bool {
	return errors.Is(ruleSentinel[e.Rule], target)
}

func validationErr(rule ValidationRule, idx int, id, detail string) *ValidationError {
	return &ValidationError{Rule: rule, ObservationIndex: idx, ObservationID: id, Detail: detail}
}

// ValidateBatch enforces the demoted wire-contract couplings over a batch that has
// already passed wire.DecodeObservationBatch:
//
//   - batch cardinality: between 1 and MaxObservationsPerBatch observations;
//   - range contiguity: first_sequence + len - 1 == last_sequence AND every
//     observation.sequence == first_sequence + index (overflow-guarded);
//   - per-observation reference caps (defense-in-depth behind the schema maxItems);
//   - drain-pair: a RUN_ENDED boundary's drain_status and covered_watermark travel
//     together (both present or both absent);
//   - ESTIMATED usage requires a non-empty price_table_version;
//   - the source_id pattern (^src_[0-9a-zA-Z]{1,64}$);
//   - per-observation identity: a present, non-empty, bounded observation_id, and a
//     present session_lifecycle.model that is non-empty and bounded (minLength/maxLength).
//
// The last three are the non-VCS defense-in-depth constraints the platform apigen
// validator enforces; they are mirrored here for parity (the endpoint is the trusted
// producer, so they are symmetry, not the load-bearing gate).
//
// It returns the first violation as a typed *ValidationError (errors.Is matches the
// per-rule sentinels). It performs no cross-batch or stateful checks.
func ValidateBatch(b *wire.DecodedBatch) error {
	if b == nil {
		return errors.New("observer evidence: nil batch")
	}
	if err := validateCardinality(b); err != nil {
		return err
	}
	if err := validateContiguity(b); err != nil {
		return err
	}
	if err := validateSourceID(b.SourceID); err != nil {
		return err
	}
	for i := range b.Observations {
		if err := validateObservation(i, &b.Observations[i]); err != nil {
			return err
		}
		if err := validateObservationIdentity(i, &b.Observations[i]); err != nil {
			return err
		}
	}
	return nil
}

// validateSourceID enforces the vendored source_id pattern. The strict wire decoder carries
// source_id through untouched, so this is the endpoint's mirror of the platform's
// source_id constraint (defense-in-depth: a real source_id is server-assigned at
// enrollment and always conforms).
func validateSourceID(sourceID string) error {
	if !sourceIDPattern.MatchString(sourceID) {
		return validationErr(RuleSourceIDPattern, -1, "",
			"source_id must match ^src_[0-9a-zA-Z]{1,64}$")
	}
	return nil
}

// validateObservationIdentity mirrors the two per-observation non-VCS constraints the
// platform apigen validator adds: a present, non-empty, bounded observation_id, and a
// present session_lifecycle.model that is non-empty (minLength 1) and within maxLength. An
// absent model is legal; only a present-but-empty (or over-long) model is a violation.
func validateObservationIdentity(i int, o *wire.DecodedObservation) error {
	if o.ObservationID == "" {
		return validationErr(RuleObservationIDRequired, i, "",
			"observation_id must be present and non-empty")
	}
	if n := len(o.ObservationID); n > MaxObservationIDLen {
		return validationErr(RuleObservationIDRequired, i, o.ObservationID,
			fmt.Sprintf("observation_id length %d exceeds max %d", n, MaxObservationIDLen))
	}
	if sl, ok := o.Variant.(wire.SessionLifecycleObservation); ok {
		if m := sl.SessionLifecycle.Model; m != nil {
			if *m == "" {
				return validationErr(RuleModelMinLength, i, o.ObservationID,
					"session_lifecycle.model is present but empty (minLength 1); an unknown model must be absent")
			}
			if n := len(*m); n > MaxModelLen {
				return validationErr(RuleModelMinLength, i, o.ObservationID,
					fmt.Sprintf("session_lifecycle.model length %d exceeds max %d", n, MaxModelLen))
			}
		}
	}
	return nil
}

// validateCardinality enforces the batch minItems:1/maxItems:MaxObservationsPerBatch
// bounds — an empty batch (which validateContiguity's arithmetic would otherwise treat as
// a contiguous inverted range) or an oversized one is rejected before ingest.
func validateCardinality(b *wire.DecodedBatch) error {
	n := len(b.Observations)
	if n == 0 {
		return validationErr(RuleBatchCardinality, -1, "",
			"batch carries no observations (minItems is 1)")
	}
	if n > MaxObservationsPerBatch {
		return validationErr(RuleBatchCardinality, -1, "",
			fmt.Sprintf("batch carries %d observations, cap is %d", n, MaxObservationsPerBatch))
	}
	return nil
}

// validateContiguity checks the batch range arithmetic and per-index sequence binding. It
// is called only after validateCardinality guarantees at least one observation.
func validateContiguity(b *wire.DecodedBatch) error {
	n := int64(len(b.Observations))
	// Overflow guard: compute the range end without wrapping past the int64 ceiling (a
	// typed error, never a silent wraparound that aliases a valid last_sequence).
	if b.FirstSequence > wire.SequenceMax-(n-1) {
		return validationErr(RuleRangeNotContiguous, -1, "",
			fmt.Sprintf("first_sequence(%d) + len(%d) - 1 overflows the sequence ceiling %d",
				b.FirstSequence, n, wire.SequenceMax))
	}
	if b.FirstSequence+n-1 != b.LastSequence {
		return validationErr(RuleRangeNotContiguous, -1, "",
			fmt.Sprintf("first_sequence(%d) + len(%d) - 1 = %d != last_sequence(%d)",
				b.FirstSequence, n, b.FirstSequence+n-1, b.LastSequence))
	}
	for i := range b.Observations {
		want := b.FirstSequence + int64(i)
		if got := b.Observations[i].Sequence; got != want {
			return validationErr(RuleRangeNotContiguous, i, b.Observations[i].ObservationID,
				fmt.Sprintf("sequence %d != first_sequence + index (%d)", got, want))
		}
	}
	return nil
}

// validateObservation runs the per-observation couplings and caps.
func validateObservation(i int, o *wire.DecodedObservation) error {
	if o.RunContext != nil && o.RunContext.WorkItemRefs != nil {
		if n := len(*o.RunContext.WorkItemRefs); n > MaxReferencesPerObservation {
			return validationErr(RuleReferenceCap, i, o.ObservationID,
				fmt.Sprintf("run_context.work_item_refs has %d entries, cap is %d", n, MaxReferencesPerObservation))
		}
	}
	if o.RunStarted != nil && o.RunStarted.WorkItemRefs != nil {
		if n := len(*o.RunStarted.WorkItemRefs); n > MaxReferencesPerObservation {
			return validationErr(RuleReferenceCap, i, o.ObservationID,
				fmt.Sprintf("run_boundary.work_item_refs has %d entries, cap is %d", n, MaxReferencesPerObservation))
		}
	}
	if o.RunEnded != nil {
		hasDrain := o.RunEnded.DrainStatus != nil
		hasWatermark := o.RunEnded.CoveredWatermark != nil
		if hasDrain != hasWatermark {
			return validationErr(RuleDrainPair, i, o.ObservationID,
				fmt.Sprintf("drain_status present=%t but covered_watermark present=%t", hasDrain, hasWatermark))
		}
	}
	if o.Usage != nil && o.Usage.Quality == wire.UsagePayloadQualityESTIMATED {
		if o.Usage.PriceTableVersion == nil || strings.TrimSpace(*o.Usage.PriceTableVersion) == "" {
			return validationErr(RuleEstimatedPriceTable, i, o.ObservationID,
				"ESTIMATED usage without a non-empty price_table_version")
		}
	}
	return nil
}
