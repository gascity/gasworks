package upload

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"testing"

	observerv1 "github.com/gascity/gasworks/contracts/observer/v1"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

func TestFormBatchContiguousRangeSetsInFlight(t *testing.T) {
	ack := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ack, SourceID: testSourceID}

	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if plan.Range != (wire.SequenceRange{FirstSequence: 1, LastSequence: 5}) {
		t.Fatalf("range = %+v, want [1,5]", plan.Range)
	}
	if r, in := ack.InFlight(); !in || r != plan.Range {
		t.Fatalf("in-flight = %+v/%v, want %+v", r, in, plan.Range)
	}
	// Body decodes as a strict ObservationBatch of the right shape.
	var batch wire.ObservationBatch
	dec := json.NewDecoder(bytes.NewReader(plan.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if batch.FirstSequence != 1 || batch.LastSequence != 5 || len(batch.Observations) != 5 {
		t.Fatalf("batch = first %d last %d obs %d", batch.FirstSequence, batch.LastSequence, len(batch.Observations))
	}
	if batch.SourceId != testSourceID {
		t.Fatalf("source = %q", batch.SourceId)
	}
}

func TestFormBatchClampsToObservationCap(t *testing.T) {
	ack := newAckState(t, 100)
	p := &Planner{Store: newMemStore(t, 1, 100, 0), Ack: ack, SourceID: testSourceID, Caps: Caps{MaxObservations: 10}}

	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if plan.Range.LastSequence != 10 {
		t.Fatalf("last = %d, want 10 (clamped to obs cap)", plan.Range.LastSequence)
	}
}

func TestFormBatchClampsToByteCap(t *testing.T) {
	// Each padded payload is ~1 KiB; a 4 KiB byte cap should admit only a few.
	ack := newAckState(t, 100)
	p := &Planner{Store: newMemStore(t, 1, 100, 1024), Ack: ack, SourceID: testSourceID, Caps: Caps{MaxBatchBytes: 4096}}

	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if int64(len(plan.Body)) > 4096 {
		t.Fatalf("body %d bytes exceeds cap 4096", len(plan.Body))
	}
	n := plan.Range.LastSequence - plan.Range.FirstSequence + 1
	if n < 1 || n >= 100 {
		t.Fatalf("clamped range length = %d, want a small positive count", n)
	}
}

func TestOversizedSingleItemFormsBatchOfOne(t *testing.T) {
	// One record far larger than the byte cap must still form a batch-of-one so the
	// sequence advances instead of wedging.
	m := &memStore{recs: map[int64][]byte{
		1: canonPayload(t, 1, 8192),
		2: canonPayload(t, 2, 8192),
	}}
	ack := newAckState(t, 2)
	p := &Planner{Store: m, Ack: ack, SourceID: testSourceID, Caps: Caps{MaxBatchBytes: 1024}}

	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if plan.Range != (wire.SequenceRange{FirstSequence: 1, LastSequence: 1}) {
		t.Fatalf("range = %+v, want batch-of-one [1,1]", plan.Range)
	}
}

func TestReplayIsByteIdentical(t *testing.T) {
	ack := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 64), Ack: ack, SourceID: testSourceID}

	first, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next#1: ok=%v err=%v", ok, err)
	}
	// A second Next while the range is in flight replays the identical range and bytes.
	second, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next#2: ok=%v err=%v", ok, err)
	}
	if first.Range != second.Range {
		t.Fatalf("replay range %+v != %+v", second.Range, first.Range)
	}
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatalf("replay body not byte-identical")
	}
}

func TestNothingOwed(t *testing.T) {
	ack := newAckState(t, 0) // fresh, no durable frames
	p := &Planner{Store: newMemStore(t, 1, 0, 0), Ack: ack, SourceID: testSourceID}
	if _, ok, err := p.Next(); ok || err != nil {
		t.Fatalf("Next on empty spool: ok=%v err=%v, want (false,nil)", ok, err)
	}
}

func TestNextStartsAfterAcknowledged(t *testing.T) {
	ack := newAckState(t, 10)
	// Acknowledge through 3 by first sending [1,3] then advancing.
	if err := ack.SetInFlight(wire.SequenceRange{FirstSequence: 1, LastSequence: 3}); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	if err := ack.Acknowledge(3); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	p := &Planner{Store: newMemStore(t, 1, 10, 0), Ack: ack, SourceID: testSourceID}
	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if plan.Range.FirstSequence != 4 {
		t.Fatalf("first = %d, want 4 (after acknowledged 3)", plan.Range.FirstSequence)
	}
}

func TestOneInFlightDisciplineRejectsDifferentRange(t *testing.T) {
	ack := newAckState(t, 10)
	p := &Planner{Store: newMemStore(t, 1, 10, 0), Ack: ack, SourceID: testSourceID, Caps: Caps{MaxObservations: 3}}
	if _, ok, err := p.Next(); !ok || err != nil {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	// While [1,3] is in flight, a different range is rejected by AckState.
	if err := ack.SetInFlight(wire.SequenceRange{FirstSequence: 1, LastSequence: 5}); !errors.Is(err, spool.ErrInFlightConflict) {
		t.Fatalf("SetInFlight different range = %v, want ErrInFlightConflict", err)
	}
}

func TestSpoolFrameStoreReadsRealMultiSegmentWAL(t *testing.T) {
	dir := t.TempDir()
	want := writeWAL(t, dir, 1, 12, 32, 5) // 3 segments: [1..5][6..10][11..12]
	store := SpoolFrameStore{Dir: dir}

	recs, err := store.ReadRange(3, 11)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if len(recs) != 9 {
		t.Fatalf("got %d records, want 9", len(recs))
	}
	for i, rec := range recs {
		wantSeq := int64(3 + i)
		if rec.Sequence != wantSeq {
			t.Fatalf("record %d sequence %d, want %d", i, rec.Sequence, wantSeq)
		}
		if !bytes.Equal(rec.Payload, want[wantSeq]) {
			t.Fatalf("record %d payload mismatch", wantSeq)
		}
	}
}

func TestSpoolFrameStoreEndToEndBatch(t *testing.T) {
	dir := t.TempDir()
	writeWAL(t, dir, 1, 7, 16, 3)
	ack := newAckState(t, 7)
	p := &Planner{Store: SpoolFrameStore{Dir: dir}, Ack: ack, SourceID: testSourceID}

	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if plan.Range != (wire.SequenceRange{FirstSequence: 1, LastSequence: 7}) {
		t.Fatalf("range = %+v, want [1,7]", plan.Range)
	}
	var batch wire.ObservationBatch
	if err := json.Unmarshal(plan.Body, &batch); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	if len(batch.Observations) != 7 {
		t.Fatalf("obs = %d, want 7", len(batch.Observations))
	}
}

func TestSpoolFrameStoreMissingWALIsEmpty(t *testing.T) {
	store := SpoolFrameStore{Dir: t.TempDir()}
	recs, err := store.ReadRange(1, 5)
	if err != nil {
		t.Fatalf("ReadRange on missing WAL: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records, want 0", len(recs))
	}
}

func TestBodyByteLenMatchesEncoding(t *testing.T) {
	// The byte-budget arithmetic must exactly equal the encoded body length for a range of
	// canonical payloads, otherwise the clamp could over- or under-shoot the server cap.
	recs := []Record{
		{1, canonPayload(t, 1, 0)},
		{2, canonPayload(t, 2, 40)},
		{3, canonPayload(t, 3, 4000)},
	}
	r := wire.SequenceRange{FirstSequence: 1, LastSequence: 3}
	body, err := EncodeBatchBody(testSourceID, r, recs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := bodyByteLen(testSourceID, 1, 3, recs); got != int64(len(body)) {
		t.Fatalf("bodyByteLen = %d, actual encoded = %d", got, len(body))
	}
}

// TestEncodeBatchBodyMatchesCorpus validates the batch encoder against the shared wire
// fixture corpus (contracts/observer/v1): reconstructing a batch from its per-observation
// canonical payloads must reproduce the canonical bytes of the whole fixture batch.
func TestEncodeBatchBodyMatchesCorpus(t *testing.T) {
	fixtures := []string{
		"fixtures/ingest/valid/usage.json",
		"fixtures/ingest/valid/tools.json",
		"fixtures/ingest/valid/run_lifecycle_complete.json",
		"fixtures/ingest/valid/passive_session.json",
		"fixtures/ingest/valid/work_references.json",
	}
	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			raw, err := observerv1.Corpus.ReadFile(path.Join("testdata", fx))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var batch wire.ObservationBatch
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&batch); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			// Per-observation canonical payloads == what the WAL would have made durable.
			recs := make([]Record, len(batch.Observations))
			for i, obs := range batch.Observations {
				p, err := wire.CanonicalBytes(obs)
				if err != nil {
					t.Fatalf("canonical obs %d: %v", i, err)
				}
				recs[i] = Record{Sequence: batch.FirstSequence + int64(i), Payload: p}
			}
			got, err := EncodeBatchBody(batch.SourceId,
				wire.SequenceRange{FirstSequence: batch.FirstSequence, LastSequence: batch.LastSequence}, recs)
			if err != nil {
				t.Fatalf("EncodeBatchBody: %v", err)
			}
			want, err := wire.CanonicalBytes(batch)
			if err != nil {
				t.Fatalf("canonical fixture: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoder output != canonical corpus batch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}
