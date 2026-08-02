package executionadapter

import (
	"errors"
	"testing"
)

func TestDecodeBatchAcceptsSparseV2RecordsWithoutAliasingArtifactSequence(t *testing.T) {
	batch, err := DecodeBatch([][]byte{
		[]byte(`{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}}`),
		[]byte(`{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":44,"event":{"seq":44,"type":"session.stopped","ts":"2026-08-02T08:01:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}}`),
	})
	if err != nil {
		t.Fatalf("DecodeBatch: %v", err)
	}
	if got, want := len(batch.Records), 2; got != want {
		t.Fatalf("records = %d, want %d", got, want)
	}
	if got, want := batch.PartitionID, "7f3a9c1e5b2d4068"; got != want {
		t.Fatalf("partition = %q, want %q", got, want)
	}
	if got, want := batch.Records[1].ProducerSeq, uint64(44); got != want {
		t.Fatalf("producer sequence = %d, want %d", got, want)
	}
	if got := string(batch.Records[0].Payload); got != `{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}}` {
		t.Fatalf("payload changed: %s", got)
	}
}

func TestDecodeBatchRejectsUnsupportedOrInvalidRecordsBeforeAnyMapping(t *testing.T) {
	valid := `{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"formula-root-opaque","session_id":"gc-session-opaque","step_id":"formula-step-opaque"}}`
	cases := []struct {
		name    string
		records [][]byte
	}{
		{name: "older schema", records: [][]byte{[]byte(`{"schema":"execution-event-envelope","schema_version":1,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}}`)}},
		{name: "newer schema", records: [][]byte{[]byte(`{"schema":"execution-event-envelope","schema_version":3,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}}`)}},
		{name: "unknown member", records: [][]byte{[]byte(valid[:len(valid)-1] + `,"extra":true}`)}},
		{name: "mismatched sequence", records: [][]byte{[]byte(`{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":42,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}}`)}},
		{name: "partition changes in batch", records: [][]byte{[]byte(valid), []byte(`{"schema":"execution-event-envelope","schema_version":2,"partition_id":"0123456789abcdef","producer_seq":42,"event":{"seq":42,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}}`)}},
		{name: "not strictly increasing", records: [][]byte{[]byte(valid), []byte(`{"schema":"execution-event-envelope","schema_version":2,"partition_id":"7f3a9c1e5b2d4068","producer_seq":41,"event":{"seq":41,"type":"bead.closed","ts":"2026-08-02T08:00:00Z"}}`)}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBatch(tt.records)
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("DecodeBatch error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}
