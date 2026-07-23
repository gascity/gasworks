package evidence

import (
	"errors"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// semanticViolationRule maps a fixture's semantic_violation tag to the validator sentinel
// that must reject it. Tags with no stateless rule (cross-batch conflicts) map to nil: the
// batch is wire-valid and ValidateBatch must accept it, exactly like the platform.
var semanticViolationRule = map[string]error{
	"DRAIN_PAIR":            ErrDrainPairMismatch,
	"ESTIMATED_PRICE_TABLE": ErrEstimatedPriceTable,
	"RANGE_NOT_CONTIGUOUS":  ErrRangeNotContiguous,
	"SEQUENCE_CONFLICT":     nil, // stateful 409; storage layer, not a batch-shape rule
	"OBSERVATION_CONFLICT":  nil, // stateful 409; storage layer, not a batch-shape rule
}

// TestValidateBatchAgainstSemanticFixtures is the core parity proof: for every schema-valid
// ObservationBatch fixture, the endpoint validator rejects exactly the demoted-coupling
// violations (drain-pair, ESTIMATED price table, contiguity) tagged in the manifest — while
// the strict wire decoder accepts all of them — and accepts every batch that carries no
// stateless violation.
func TestValidateBatchAgainstSemanticFixtures(t *testing.T) {
	m := loadManifest(t)
	sawViolation := map[string]bool{}
	for _, fx := range m.Fixtures {
		if fx.Schema != "ObservationBatch" || fx.Expect != "valid" {
			continue
		}
		fx := fx
		t.Run(fx.Path, func(t *testing.T) {
			b, err := wire.DecodeObservationBatch(readFixture(t, fx))
			if err != nil {
				t.Fatalf("strict decode failed (expected wire-valid): %v", err)
			}
			err = ValidateBatch(b)

			want, tagged := semanticViolationRule[fx.SemanticViolation]
			switch {
			case fx.SemanticViolation == "":
				if err != nil {
					t.Fatalf("no semantic_violation tag but ValidateBatch rejected: %v", err)
				}
			case !tagged:
				t.Fatalf("fixture carries unknown semantic_violation tag %q", fx.SemanticViolation)
			case want == nil:
				if err != nil {
					t.Fatalf("stateful-conflict fixture %q must pass the stateless validator, got: %v", fx.SemanticViolation, err)
				}
			default:
				sawViolation[fx.SemanticViolation] = true
				if !errors.Is(err, want) {
					t.Fatalf("want errors.Is(%v) for %q, got %v", want, fx.SemanticViolation, err)
				}
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("want a *ValidationError, got %T", err)
				}
			}
		})
	}
	for _, tag := range []string{"DRAIN_PAIR", "ESTIMATED_PRICE_TABLE", "RANGE_NOT_CONTIGUOUS"} {
		if !sawViolation[tag] {
			t.Errorf("no fixture exercised the %s validator", tag)
		}
	}
}

// TestValidateReferenceCapFromFixture proves the per-observation reference cap using the
// over-cap fixture: it is schema-invalid only on maxItems (Go decode ignores maxItems), so
// the strict decoder accepts it and the validator is the one that rejects it.
func TestValidateReferenceCapFromFixture(t *testing.T) {
	const p = "fixtures/ingest/invalid/work_refs_over_cap.json"
	b, err := wire.DecodeObservationBatch(readCorpusFile(t, p))
	if err != nil {
		t.Fatalf("strict decode should accept an over-cap-only batch, got: %v", err)
	}
	if err := ValidateBatch(b); !errors.Is(err, ErrReferenceCap) {
		t.Fatalf("want ErrReferenceCap, got %v", err)
	}
}

// TestValidateDrainPairBothPresentAndAbsent guards against a false positive: the two
// legitimate RUN_ENDED shapes (both drain fields, and neither) must pass.
func TestValidateDrainPairBothPresentAndAbsent(t *testing.T) {
	for _, p := range []string{
		"fixtures/ingest/valid/run_lifecycle_complete.json", // RUN_ENDED with both
		"fixtures/ingest/valid/launch_failed.json",          // RUN_ENDED with neither
	} {
		b, err := wire.DecodeObservationBatch(readCorpusFile(t, p))
		if err != nil {
			t.Fatalf("decode %s: %v", p, err)
		}
		if err := ValidateBatch(b); err != nil {
			t.Fatalf("%s must pass drain-pair validation, got: %v", p, err)
		}
	}
}

// TestValidateBatchCardinality proves the minItems:1 / maxItems:1000 batch bounds: an empty
// (or inverted, first>last) batch and an oversized batch are both rejected with
// ErrBatchCardinality — an accepted empty range would let ingest advance a source watermark
// over zero observations.
func TestValidateBatchCardinality(t *testing.T) {
	t.Run("empty_inverted_range", func(t *testing.T) {
		b := &wire.DecodedBatch{FirstSequence: 2, LastSequence: 1, Observations: nil}
		if err := ValidateBatch(b); !errors.Is(err, ErrBatchCardinality) {
			t.Fatalf("want ErrBatchCardinality for empty batch, got %v", err)
		}
	})
	t.Run("empty_batch_decodes_but_fails_validate", func(t *testing.T) {
		data := []byte(`{"schema_version":1,"source_id":"src_x","first_sequence":2,"last_sequence":1,"observations":[]}`)
		b, err := wire.DecodeObservationBatch(data)
		if err != nil {
			t.Fatalf("decode empty batch: %v", err)
		}
		if err := ValidateBatch(b); !errors.Is(err, ErrBatchCardinality) {
			t.Fatalf("want ErrBatchCardinality, got %v", err)
		}
	})
	t.Run("oversized_batch", func(t *testing.T) {
		obs := make([]wire.DecodedObservation, MaxObservationsPerBatch+1)
		for i := range obs {
			obs[i] = wire.DecodedObservation{Kind: "MESSAGE", Sequence: int64(1 + i)}
		}
		b := &wire.DecodedBatch{FirstSequence: 1, LastSequence: int64(MaxObservationsPerBatch + 1), Observations: obs}
		if err := ValidateBatch(b); !errors.Is(err, ErrBatchCardinality) {
			t.Fatalf("want ErrBatchCardinality for oversized batch, got %v", err)
		}
	})
	t.Run("exactly_max_is_ok_for_cardinality", func(t *testing.T) {
		obs := make([]wire.DecodedObservation, MaxObservationsPerBatch)
		for i := range obs {
			// A valid source_id and a non-empty observation_id are required now that the
			// defense-in-depth identity/source checks also run; the subtest still exercises
			// the cardinality boundary at exactly MaxObservationsPerBatch.
			obs[i] = wire.DecodedObservation{Kind: "MESSAGE", Sequence: int64(1 + i), ObservationID: "obs_x"}
		}
		b := &wire.DecodedBatch{SourceID: "src_019f7a1000observerpilot0001", FirstSequence: 1, LastSequence: int64(MaxObservationsPerBatch), Observations: obs}
		if err := ValidateBatch(b); err != nil {
			t.Fatalf("a full 1000-observation contiguous batch must pass, got %v", err)
		}
	})
}

// TestValidateContiguityOverflowGuard proves that a range whose end would exceed the int64
// sequence ceiling is a typed RuleRangeNotContiguous error, never a silent wraparound that
// could alias a valid last_sequence.
func TestValidateContiguityOverflowGuard(t *testing.T) {
	b := &wire.DecodedBatch{
		FirstSequence: wire.SequenceMax,
		LastSequence:  wire.SequenceMax,
		Observations: []wire.DecodedObservation{
			{Kind: "MESSAGE", Sequence: wire.SequenceMax, ObservationID: "a"},
			{Kind: "MESSAGE", Sequence: wire.SequenceMax, ObservationID: "b"},
		},
	}
	err := ValidateBatch(b)
	if !errors.Is(err, ErrRangeNotContiguous) {
		t.Fatalf("want ErrRangeNotContiguous (overflow), got %v", err)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || !strings.Contains(ve.Detail, "overflow") {
		t.Fatalf("want an overflow-detail ValidationError, got %v", err)
	}
}
