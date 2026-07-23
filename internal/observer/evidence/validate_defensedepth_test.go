package evidence

import (
	"errors"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// The three defense-in-depth constraints ValidateBatch mirrors from the platform apigen
// constraint validator (observation_id required/non-empty, session_lifecycle.model
// minLength, source_id pattern) are proven here against the shared invalid-fixture corpus,
// so the endpoint's local reject verdict matches the Collector's ingest reject verdict on
// the exact same bytes. A short positive case per constraint guards against a false
// positive on a conforming batch.

// TestValidateSourceIDPattern proves the endpoint rejects a batch whose source_id violates
// the vendored pattern (the corpus bad_source_id fixture) and accepts a conforming one.
func TestValidateSourceIDPattern(t *testing.T) {
	// Negative: the shared bad_source_id fixture ("bogus-source") is wire-valid but fails
	// the pattern, exactly as the platform rejects it.
	b, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/invalid/bad_source_id.json"))
	if err != nil {
		t.Fatalf("strict decode should accept a bad-source_id-only batch, got: %v", err)
	}
	if err := ValidateBatch(b); !errors.Is(err, ErrSourceIDPattern) {
		t.Fatalf("want ErrSourceIDPattern, got %v", err)
	}
	var ve *ValidationError
	if !errors.As(ValidateBatch(b), &ve) || ve.Rule != RuleSourceIDPattern {
		t.Fatalf("want a *ValidationError tagged SOURCE_ID_PATTERN, got %v", ValidateBatch(b))
	}

	// Positive: a conforming source_id passes the batch validator.
	good, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/valid/session_with_model.json"))
	if err != nil {
		t.Fatalf("decode valid fixture: %v", err)
	}
	if err := ValidateBatch(good); err != nil {
		t.Fatalf("a conforming source_id must pass, got %v", err)
	}

	// A few hand-built source_ids around the pattern boundary.
	for _, tc := range []struct {
		id string
		ok bool
	}{
		{"src_0", true},
		{"src_019f7a1000observerpilot0001", true},
		{"src_", false},         // empty ULID part
		{"srcx0", false},        // missing underscore
		{"src_cmd_test", false}, // underscore in the ULID part is not [0-9a-zA-Z]
		{"bogus-source", false}, // wrong prefix/charset
		{"SRC_0", false},        // prefix is lowercase
	} {
		err := validateSourceID(tc.id)
		if tc.ok && err != nil {
			t.Errorf("validateSourceID(%q) = %v, want nil", tc.id, err)
		}
		if !tc.ok && !errors.Is(err, ErrSourceIDPattern) {
			t.Errorf("validateSourceID(%q) = %v, want ErrSourceIDPattern", tc.id, err)
		}
	}
}

// TestValidateObservationIDRequired proves the endpoint rejects a batch whose observation
// carries no observation_id (the corpus missing_observation_id fixture) and accepts one
// with a present id.
func TestValidateObservationIDRequired(t *testing.T) {
	b, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/invalid/missing_observation_id.json"))
	if err != nil {
		t.Fatalf("strict decode should accept a missing-observation_id-only batch, got: %v", err)
	}
	if got := b.Observations[0].ObservationID; got != "" {
		t.Fatalf("fixture precondition: observation_id should decode to empty, got %q", got)
	}
	if err := ValidateBatch(b); !errors.Is(err, ErrObservationIDRequired) {
		t.Fatalf("want ErrObservationIDRequired, got %v", err)
	}
	var ve *ValidationError
	if !errors.As(ValidateBatch(b), &ve) || ve.Rule != RuleObservationIDRequired {
		t.Fatalf("want a *ValidationError tagged OBSERVATION_ID_REQUIRED, got %v", ValidateBatch(b))
	}

	// An over-long observation_id is the same rule.
	over := &wire.DecodedBatch{
		SourceID: "src_019f7a1000observerpilot0001", FirstSequence: 1, LastSequence: 1,
		Observations: []wire.DecodedObservation{{
			Kind: "MESSAGE", Sequence: 1,
			ObservationID: longString(MaxObservationIDLen + 1),
		}},
	}
	if err := ValidateBatch(over); !errors.Is(err, ErrObservationIDRequired) {
		t.Fatalf("want ErrObservationIDRequired for an over-long id, got %v", err)
	}
}

// TestValidateModelMinLength proves the endpoint rejects a SESSION_LIFECYCLE whose model is
// present but empty (the corpus session_model_empty fixture), while an absent model and a
// non-empty model both pass.
func TestValidateModelMinLength(t *testing.T) {
	b, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/invalid/session_model_empty.json"))
	if err != nil {
		t.Fatalf("strict decode should accept an empty-model-only batch, got: %v", err)
	}
	sl, ok := b.Observations[0].Variant.(wire.SessionLifecycleObservation)
	if !ok || sl.SessionLifecycle.Model == nil || *sl.SessionLifecycle.Model != "" {
		t.Fatalf("fixture precondition: model should decode to a present empty string")
	}
	if err := ValidateBatch(b); !errors.Is(err, ErrModelMinLength) {
		t.Fatalf("want ErrModelMinLength, got %v", err)
	}
	var ve *ValidationError
	if !errors.As(ValidateBatch(b), &ve) || ve.Rule != RuleModelMinLength {
		t.Fatalf("want a *ValidationError tagged MODEL_MIN_LENGTH, got %v", ValidateBatch(b))
	}

	// Positive: a session with a present, non-empty model passes; an absent model passes.
	good, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/valid/session_with_model.json"))
	if err != nil {
		t.Fatalf("decode session_with_model: %v", err)
	}
	if err := ValidateBatch(good); err != nil {
		t.Fatalf("a present non-empty model must pass, got %v", err)
	}
	absent, err := wire.DecodeObservationBatch(readCorpusFile(t, "fixtures/ingest/valid/passive_session.json"))
	if err != nil {
		t.Fatalf("decode passive_session: %v", err)
	}
	if err := ValidateBatch(absent); err != nil {
		t.Fatalf("an absent model must pass, got %v", err)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
