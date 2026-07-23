package wire

import (
	"errors"
	"testing"
)

// TestDecodeValidBatchesDecode proves every schema-valid ObservationBatch fixture
// strictly decodes: correct kind dispatch, no unknown-field/discriminator rejection,
// sequences in range. Fixtures whose only defect is a demoted coupling (DRAIN_PAIR,
// ESTIMATED, cross-batch conflicts) are wire-shape valid and decode here too — their
// rejection is the deferred semantic validators' job (E1.1/S2.4), not the decoder's.
func TestDecodeValidBatchesDecode(t *testing.T) {
	m := loadManifest(t)
	seen := 0
	for _, fx := range m.Fixtures {
		if fx.Schema != "ObservationBatch" || fx.Expect != "valid" {
			continue
		}
		fx := fx
		t.Run(fx.Path, func(t *testing.T) {
			b, err := DecodeObservationBatch(readFixture(t, fx))
			if err != nil {
				t.Fatalf("expected strict decode to succeed, got: %v", err)
			}
			if len(b.Observations) == 0 {
				t.Fatal("decoded batch has no observations")
			}
			for i, o := range b.Observations {
				if o.Kind == "" {
					t.Errorf("observations[%d] has empty kind", i)
				}
				if o.Variant == nil {
					t.Errorf("observations[%d] has nil variant", i)
				}
			}
		})
		seen++
	}
	if seen == 0 {
		t.Fatal("no valid ObservationBatch fixtures found")
	}
}

// TestDecodeRejectsWireShapeDefects covers exactly the defects the strict decoder owns
// — unknown discriminator, unknown field on a nested variant, unsupported
// schema_version, out-of-enum, absent/null payload, out-of-range/fractional sequence —
// asserting the typed sentinel each maps to. This is where the P0.4-added number-form,
// enum, and null fixtures are proven rejected at the wire-shape layer.
func TestDecodeRejectsWireShapeDefects(t *testing.T) {
	cases := []struct {
		fixture string
		want    error
	}{
		{"fixtures/ingest/invalid/unknown_kind.json", ErrUnknownDiscriminator},
		{"fixtures/ingest/invalid/run_started_with_drain.json", ErrUnknownField},
		{"fixtures/ingest/invalid/bad_schema_version.json", ErrSchemaVersionUnsupported},
		{"fixtures/ingest/invalid/usage_quality_out_of_enum.json", ErrEnumOutOfRange},
		{"fixtures/ingest/invalid/usage_payload_null.json", ErrMissingPayload},
		{"fixtures/ingest/invalid/num_sequence_fraction.json", ErrSequenceOutOfRange},
	}
	m := loadManifest(t)
	byPath := map[string]fixtureEntry{}
	for _, fx := range m.Fixtures {
		byPath[fx.Path] = fx
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.fixture, func(t *testing.T) {
			fx, ok := byPath[tc.fixture]
			if !ok {
				t.Fatalf("fixture %s not in manifest", tc.fixture)
			}
			_, err := DecodeObservationBatch(readFixture(t, fx))
			if err == nil {
				t.Fatalf("expected strict decode to reject %s", tc.fixture)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("want errors.Is(%v), got %v", tc.want, err)
			}
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("want a *DecodeError, got %T", err)
			}
		})
	}
}

// TestDecodeRejectsUnknownTopLevelField proves batch-level additionalProperties:false is
// enforced by the strict decoder, not only the schema gate.
func TestDecodeRejectsUnknownTopLevelField(t *testing.T) {
	data := []byte(`{"schema_version":1,"source_id":"src_x","first_sequence":1,"last_sequence":1,"observations":[],"extra":true}`)
	if _, err := DecodeObservationBatch(data); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("want ErrUnknownField, got %v", err)
	}
}

// TestDecodeRejectsAbsentPayloadMember proves the dispatched payload member must be
// present, not merely non-null: a USAGE observation with no usage member is rejected
// rather than zero-filled.
func TestDecodeRejectsAbsentPayloadMember(t *testing.T) {
	data := []byte(`{
		"schema_version":1,"source_id":"src_x","first_sequence":1,"last_sequence":1,
		"observations":[{
			"sequence":1,"observation_id":"obs_1","kind":"USAGE",
			"occurred_at":"2026-07-16T10:00:00Z","captured_at":"2026-07-16T10:00:00Z",
			"provenance":{"adapter":"a","adapter_version":"1","content_policy":"METADATA_ONLY","provider":"p","completeness":"COMPLETE"}
		}]
	}`)
	if _, err := DecodeObservationBatch(data); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("want ErrMissingPayload for absent usage member, got %v", err)
	}
}
