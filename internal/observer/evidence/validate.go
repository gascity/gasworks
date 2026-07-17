package evidence

import (
	"errors"
	"fmt"
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
)

// Sentinel per-rule errors so callers can branch with errors.Is.
var (
	ErrRangeNotContiguous  = errors.New("observer evidence: batch range not contiguous")
	ErrDrainPairMismatch   = errors.New("observer evidence: RUN_ENDED drain_status/covered_watermark must travel together")
	ErrEstimatedPriceTable = errors.New("observer evidence: ESTIMATED usage requires price_table_version")
	ErrReferenceCap        = errors.New("observer evidence: per-observation reference cap exceeded")
	ErrBatchCardinality    = errors.New("observer evidence: batch observation count out of bounds")
)

var ruleSentinel = map[ValidationRule]error{
	RuleRangeNotContiguous:  ErrRangeNotContiguous,
	RuleDrainPair:           ErrDrainPairMismatch,
	RuleEstimatedPriceTable: ErrEstimatedPriceTable,
	RuleReferenceCap:        ErrReferenceCap,
	RuleBatchCardinality:    ErrBatchCardinality,
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
//   - ESTIMATED usage requires a non-empty price_table_version.
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
	for i := range b.Observations {
		if err := validateObservation(i, &b.Observations[i]); err != nil {
			return err
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
