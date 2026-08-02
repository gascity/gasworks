package executionadapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gastownhall/gascity/pkg/eventexport"
)

func TestDecodeBatchWrapsPinnedProducerBatchWithSparseSequences(t *testing.T) {
	producer := eventexport.Batch{
		CityHash:      "7f3a9c1e5b2d4068",
		SchemaVersion: eventexport.SchemaVersion,
		Events: []eventexport.Envelope{
			{Seq: 41, Type: "bead.closed", TS: "2026-08-02T08:00:00Z", ActorHash: "0123456789abcdef", Ref: "bead-41", RunID: "formula-root-opaque", SessionID: "gc-session-opaque", StepID: "formula-step-opaque", Title: "Investigate execution", Formula: "execution-review"},
			{Seq: 44, Type: "session.stopped", TS: "2026-08-02T08:01:00Z", RunID: "formula-root-opaque", SessionID: "gc-session-opaque", StepID: "formula-step-opaque"},
		},
	}
	if eventexport.SchemaVersion != RecordSchemaVersion {
		t.Fatalf("pinned producer schema = %d, adapter schema = %d", eventexport.SchemaVersion, RecordSchemaVersion)
	}
	if err := eventexport.ValidateBatch(producer); err != nil {
		t.Fatalf("producer fixture is not authoritative v2: %v", err)
	}
	input, err := json.Marshal(producer)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if batch.PartitionID != "7f3a9c1e5b2d4068" || len(batch.Records) != 2 || batch.Records[0].ProducerSeq != 41 || batch.Records[1].ProducerSeq != 44 {
		t.Fatalf("batch=%+v", batch)
	}
	want := `{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","actor_hash":"0123456789abcdef","ref":"bead-41","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque","title":"Investigate execution","formula":"execution-review"}}`
	if got := string(batch.Records[0].Payload); got != want {
		t.Fatalf("record bytes=%s\nwant=%s", got, want)
	}
}

func TestDecodeBatchMatchesAuthoritativeEventexportValidation(t *testing.T) {
	valid := eventexport.Batch{
		CityHash:      "7f3a9c1e5b2d4068",
		SchemaVersion: eventexport.SchemaVersion,
		Events:        []eventexport.Envelope{{Seq: 1, Type: "bead.closed", TS: "2026-08-02T08:00:00Z"}},
	}
	cases := map[string]eventexport.Batch{
		"ref on ineligible type": {
			CityHash:      valid.CityHash,
			SchemaVersion: valid.SchemaVersion,
			Events:        []eventexport.Envelope{{Seq: 1, Type: "order.completed", TS: "2026-08-02T08:00:00Z", Ref: "bead-1"}},
		},
		"mail reduced shape": {
			CityHash:      valid.CityHash,
			SchemaVersion: valid.SchemaVersion,
			Events:        []eventexport.Envelope{{Seq: 1, Type: "mail.sent", TS: "2026-08-02T08:00:00Z", ActorHash: "0123456789abcdef"}},
		},
		"zero timestamp": {
			CityHash:      valid.CityHash,
			SchemaVersion: valid.SchemaVersion,
			Events:        []eventexport.Envelope{{Seq: 1, Type: "bead.closed", TS: "0001-01-01T00:00:00Z"}},
		},
		"over-cap content": {
			CityHash:      valid.CityHash,
			SchemaVersion: valid.SchemaVersion,
			Events:        []eventexport.Envelope{{Seq: 1, Type: "bead.closed", TS: "2026-08-02T08:00:00Z", Title: strings.Repeat("x", 257)}},
		},
	}
	for name, producer := range cases {
		t.Run(name, func(t *testing.T) {
			if err := eventexport.ValidateBatch(producer); err == nil {
				t.Fatal("test fixture must fail authoritative validation")
			}
			input, err := json.Marshal(producer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeBatch(input); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("DecodeBatch = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestDecodeBatchAcceptsPinnedAllFilteredInterval(t *testing.T) {
	input, err := json.Marshal(eventexport.Batch{
		CityHash:      "7f3a9c1e5b2d4068",
		SchemaVersion: eventexport.SchemaVersion,
		Events:        []eventexport.Envelope{},
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if batch.PartitionID != "7f3a9c1e5b2d4068" || len(batch.Records) != 0 {
		t.Fatalf("all-filtered batch = %+v", batch)
	}
}

func TestDecodeBatchStrictlyRejectsUnsupportedOrInvalidProducerBatches(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"city_hash":"7f3a9c1e5b2d4068","schema_version":1,"events":[]}`),
		[]byte(`{"city_hash":"7f3a9c1e5b2d4068","schema_version":3,"events":[]}`),
		[]byte(`{"city_hash":"7f3a9c1e5b2d4068","schema_version":2,"events":[],"extra":true}`),
		[]byte(`{"city_hash":"7f3a9c1e5b2d4068","schema_version":2,"events":[{"seq":2,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"},{"seq":1,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}]}`),
	}
	for _, input := range cases {
		if _, err := DecodeBatch(input); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("DecodeBatch(%s)=%v", input, err)
		}
	}
}
