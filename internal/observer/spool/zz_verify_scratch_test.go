package spool

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Independent adversarial verification of the codec-lens BLOCKER: a sub-MaxFramePayload
// upward flip of the LAST frame's payload_length is misclassified as a torn tail via the
// REAL durability path (CreateSegment+Append), silently truncating a durable frame and
// reusing its sequence.
func TestVERIFY_LastFrameSubMaxLenInflationMisclassified(t *testing.T) {
	dir := recoverDir(t)
	walDir := walOf(dir)
	// Real writer path: two durable, fsync'd frames.
	buildSegment(t, walDir, 1, 2)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}

	// Locate frame 2's payload_length field on disk.
	segHdrLen := len(rawSegmentBytes(t, SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1}))
	f1Len := len(mustEncode(t, frameN(1)))
	payLenOff := segHdrLen + f1Len + offFramePayLen

	path := filepath.Join(walDir, segmentFilename(1))
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seg: %v", err)
	}
	trueLen := binary.BigEndian.Uint32(full[payLenOff:])
	inflated := trueLen ^ 0x00000100 // +256, provably sub-max
	if int(inflated) > MaxFramePayload {
		t.Fatalf("setup: inflated %d exceeds max", inflated)
	}
	binary.BigEndian.PutUint32(full[payLenOff:], inflated)
	if err := os.WriteFile(path, full, fileMode); err != nil {
		t.Fatalf("rewrite seg: %v", err)
	}
	sizeBefore := fileSize(t, path)

	rec, err := Recover(dir)
	if err != nil {
		var cerr *CorruptionError
		if errors.As(err, &cerr) {
			t.Logf("REFUTED: handled as CorruptionError: %v", err)
			return
		}
		t.Fatalf("unexpected err: %v", err)
	}
	sizeAfter := fileSize(t, path)
	t.Logf("outcome=%d highest=%d next=%d discarded=%d truncated=%q size %d->%d",
		rec.Outcome, rec.HighestDurableSequence, rec.NextSequence, rec.DiscardedBytes,
		rec.TruncatedSegment, sizeBefore, sizeAfter)
	if rec.Outcome == OutcomeTruncatedTail && rec.HighestDurableSequence == 1 && rec.NextSequence == 2 {
		t.Errorf("SUSTAINED: durable frame 2 (sub-max len corruption) truncated as torn tail; "+
			"highest=%d next=%d (SEQUENCE REUSE of 2) discarded=%d", rec.HighestDurableSequence,
			rec.NextSequence, rec.DiscardedBytes)
	}
}
