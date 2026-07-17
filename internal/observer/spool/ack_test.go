package spool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func loadAck(t *testing.T, dir string, highestDurable int64) *AckState {
	t.Helper()
	a, err := LoadAckState(dir, highestDurable, AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	return a
}

func rng(first, last int64) wire.SequenceRange {
	return wire.SequenceRange{FirstSequence: first, LastSequence: last}
}

func TestAckLoadEmptyIsZero(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)
	if got := a.AcknowledgedThrough(); got != 0 {
		t.Fatalf("fresh acknowledged_through = %d, want 0", got)
	}
	if _, ok := a.InFlight(); ok {
		t.Fatalf("fresh AckState reports an in-flight range")
	}
}

func TestAckSetInFlightMustBeContiguous(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)

	// A range that does not begin at acknowledged_through+1 (==1) is a gap.
	if err := a.SetInFlight(rng(2, 5)); !errors.Is(err, ErrAckGap) {
		t.Fatalf("gap range: err = %v, want ErrAckGap", err)
	}
	// The contiguous range starting at 1 is accepted.
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("contiguous SetInFlight: %v", err)
	}
	got, ok := a.InFlight()
	if !ok || got != rng(1, 5) {
		t.Fatalf("InFlight = %v ok=%v, want [1,5]", got, ok)
	}
}

func TestAckSetInFlightBounds(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 5)

	if err := a.SetInFlight(rng(1, 6)); !errors.Is(err, ErrInFlightRange) {
		t.Fatalf("beyond-durable range: err = %v, want ErrInFlightRange", err)
	}
	if err := a.SetInFlight(rng(3, 1)); !errors.Is(err, ErrInFlightRange) {
		t.Fatalf("inverted range: err = %v, want ErrInFlightRange", err)
	}
	a2, err := LoadAckState(dir, 5000, AckOptions{MaxInFlight: 3})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	if err := a2.SetInFlight(rng(1, 4)); !errors.Is(err, ErrInFlightRange) {
		t.Fatalf("over-bound range: err = %v, want ErrInFlightRange", err)
	}
	if err := a2.SetInFlight(rng(1, 3)); err != nil {
		t.Fatalf("at-bound range: %v", err)
	}
}

func TestAckSingleInFlight(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	// The identical range is an idempotent replay.
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("replay identical range: %v", err)
	}
	// A different range while one is outstanding is rejected.
	if err := a.SetInFlight(rng(1, 6)); !errors.Is(err, ErrInFlightConflict) {
		t.Fatalf("conflicting range: err = %v, want ErrInFlightConflict", err)
	}
}

func TestAckAcknowledgeFullClearsInFlightAndPersists(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	if err := a.Acknowledge(5); err != nil {
		t.Fatalf("Acknowledge(5): %v", err)
	}
	if got := a.AcknowledgedThrough(); got != 5 {
		t.Fatalf("acknowledged_through = %d, want 5", got)
	}
	if _, ok := a.InFlight(); ok {
		t.Fatalf("in-flight not cleared after full ack")
	}
	// Durable across reload.
	reloaded := loadAck(t, dir, 10)
	if got := reloaded.AcknowledgedThrough(); got != 5 {
		t.Fatalf("reloaded acknowledged_through = %d, want 5", got)
	}
}

func TestAckAcknowledgePartialAdvancesAndShrinks(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	if err := a.Acknowledge(3); err != nil {
		t.Fatalf("Acknowledge(3): %v", err)
	}
	if got := a.AcknowledgedThrough(); got != 3 {
		t.Fatalf("acknowledged_through = %d, want 3", got)
	}
	got, ok := a.InFlight()
	if !ok || got != rng(4, 5) {
		t.Fatalf("in-flight after partial ack = %v ok=%v, want [4,5]", got, ok)
	}
	// The next in-flight must still be contiguous with the new watermark.
	if err := a.SetInFlight(rng(4, 5)); err != nil {
		t.Fatalf("replay shrunk range: %v", err)
	}
}

func TestAckRejectsGapBeyondSentAndBeyondDurable(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 10)
	if err := a.SetInFlight(rng(1, 5)); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	// Larger than the sent contiguous range (last=5).
	if err := a.Acknowledge(6); !errors.Is(err, ErrAckBeyondSent) {
		t.Fatalf("ack beyond sent: err = %v, want ErrAckBeyondSent", err)
	}
	// Nothing advanced.
	if got := a.AcknowledgedThrough(); got != 0 {
		t.Fatalf("acknowledged_through advanced on rejected ack: %d", got)
	}

	// With nothing in flight, any forward ack is beyond the sent range.
	b := loadAck(t, dir, 10)
	if err := b.Acknowledge(1); !errors.Is(err, ErrAckBeyondSent) {
		t.Fatalf("ack with nothing in flight: err = %v, want ErrAckBeyondSent", err)
	}

	// An ack beyond the highest durable sequence is rejected before the in-flight check.
	c := loadAck(t, dir, 5)
	if err := c.Acknowledge(9); !errors.Is(err, ErrAckBeyondDurable) {
		t.Fatalf("ack beyond durable: err = %v, want ErrAckBeyondDurable", err)
	}
}

func TestAckRejectsBackwardAndAllowsDuplicate(t *testing.T) {
	dir := recoverDir(t)
	if err := writeAck(dir, 5); err != nil {
		t.Fatalf("seed ack: %v", err)
	}
	a := loadAck(t, dir, 10)
	// A duplicate at the current watermark is an idempotent no-op.
	if err := a.Acknowledge(5); err != nil {
		t.Fatalf("duplicate ack: %v", err)
	}
	// A regression is rejected.
	if err := a.Acknowledge(4); !errors.Is(err, ErrAckBackward) {
		t.Fatalf("backward ack: err = %v, want ErrAckBackward", err)
	}
	if got := a.AcknowledgedThrough(); got != 5 {
		t.Fatalf("acknowledged_through = %d, want 5", got)
	}
}

func TestAckCorruptSidecarIsUnhealthyNeverReset(t *testing.T) {
	dir := recoverDir(t)
	if err := writeAck(dir, 7); err != nil {
		t.Fatalf("seed ack: %v", err)
	}
	ackPath := filepath.Join(dir, ackFilename)
	original, err := os.ReadFile(ackPath)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	// Flip a byte inside the checksummed region.
	corrupt := append([]byte(nil), original...)
	corrupt[4] ^= 0xFF
	if err := os.WriteFile(ackPath, corrupt, fileMode); err != nil {
		t.Fatalf("write corrupt ack: %v", err)
	}
	if _, err := LoadAckState(dir, 10, AckOptions{}); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("corrupt ack load: err = %v, want ErrChecksumMismatch", err)
	}
	// The corrupt sidecar was held, not reset to empty.
	after, err := os.ReadFile(ackPath)
	if err != nil {
		t.Fatalf("read ack after: %v", err)
	}
	if len(after) != len(corrupt) || after[4] != corrupt[4] {
		t.Fatalf("corrupt ack was rewritten/reset instead of held")
	}
}

func TestAckLoadPostCompactionAckAboveHighestDurableLoads(t *testing.T) {
	// After compaction removes whole acknowledged segments, acknowledged_through legitimately
	// exceeds the surviving highest durable sequence. LoadAckState must NOT reject this: it
	// seeds the advancement ceiling as max(highest, ack).
	dir := recoverDir(t)
	if err := writeAck(dir, 20); err != nil {
		t.Fatalf("seed ack: %v", err)
	}
	a, err := LoadAckState(dir, 10, AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState with ack>highestDurable: %v", err)
	}
	if got := a.AcknowledgedThrough(); got != 20 {
		t.Fatalf("acknowledged_through = %d, want 20", got)
	}
	if got := a.HighestDurable(); got != 20 {
		t.Fatalf("seeded highest durable = %d, want 20 (max of 10, 20)", got)
	}
}

func TestAckLoadHealthyPostCompactionWALEndToEnd(t *testing.T) {
	// Real-filesystem regression for the MAJOR wedge: build [1,10], rotate to an empty tail
	// segment 11, acknowledge through 10, compact [1,10] away, restart. Recover is clean and
	// LoadAckState must succeed with acknowledged_through=10 (not wedge the source).
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 10) // [1,10]
	tail, err := CreateSegment(walOf(dir), SegmentOptions{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 11})
	if err != nil {
		t.Fatalf("CreateSegment(11): %v", err)
	}
	if err := tail.Close(); err != nil {
		t.Fatalf("Close tail: %v", err)
	}
	if err := writeAck(dir, 10); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	res, err := Compact(dir, 10)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(res.RemovedSegments) != 1 {
		t.Fatalf("compaction removed %v, want seg [1,10]", res.RemovedSegments)
	}

	// --- restart ---
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover after compaction: %v", err)
	}
	if rec.Outcome != OutcomeClean {
		t.Fatalf("recovery outcome = %v, want clean", rec.Outcome)
	}
	if rec.HighestDurableSequence != 0 || rec.AcknowledgedThrough != 10 || rec.NextSequence != 11 {
		t.Fatalf("recovery highest=%d ack=%d next=%d, want 0/10/11",
			rec.HighestDurableSequence, rec.AcknowledgedThrough, rec.NextSequence)
	}
	a, err := LoadAckState(dir, rec.HighestDurableSequence, AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState on healthy post-compaction WAL wedged the source: %v", err)
	}
	if got := a.AcknowledgedThrough(); got != 10 {
		t.Fatalf("acknowledged_through = %d, want 10", got)
	}
}

func TestAckNoteDurableRaisesCeiling(t *testing.T) {
	dir := recoverDir(t)
	a := loadAck(t, dir, 3)
	if err := a.SetInFlight(rng(1, 3)); err != nil {
		t.Fatalf("SetInFlight: %v", err)
	}
	if err := a.Acknowledge(3); err != nil {
		t.Fatalf("Acknowledge(3): %v", err)
	}
	// The writer appends more frames, raising the durable ceiling.
	a.NoteDurable(6)
	if got := a.HighestDurable(); got != 6 {
		t.Fatalf("HighestDurable = %d, want 6", got)
	}
	if err := a.SetInFlight(rng(4, 6)); err != nil {
		t.Fatalf("SetInFlight after NoteDurable: %v", err)
	}
	if err := a.Acknowledge(6); err != nil {
		t.Fatalf("Acknowledge(6): %v", err)
	}
	// NoteDurable never lowers the ceiling.
	a.NoteDurable(2)
	if got := a.HighestDurable(); got != 6 {
		t.Fatalf("HighestDurable after stale NoteDurable = %d, want 6", got)
	}
}
