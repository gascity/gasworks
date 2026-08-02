package executionadapter

import (
	"errors"
	"testing"
)

func TestDecodeBatchWrapsFrozenProducerBatchWithSparseSequences(t *testing.T) {
	input := []byte(`{"city_hash":"7f3a9c1e5b2d4068","schema_version":2,"events":[{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"},{"seq":44,"type":"session.stopped","ts":"2026-08-02T08:01:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}]}`)
	batch, err := DecodeBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if batch.PartitionID != "7f3a9c1e5b2d4068" || len(batch.Records) != 2 || batch.Records[0].ProducerSeq != 41 || batch.Records[1].ProducerSeq != 44 {
		t.Fatalf("batch=%+v", batch)
	}
	want := `{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}}`
	if got := string(batch.Records[0].Payload); got != want {
		t.Fatalf("record bytes=%s\nwant=%s", got, want)
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
