package spool

import (
	"os"
	"path/filepath"
	"testing"
)

// mustRecover runs startup recovery and fails the test on error.
func mustRecover(t *testing.T, dir string) *Recovery {
	t.Helper()
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return rec
}

// segCount returns the number of .seg files under wal/.
func segCount(t *testing.T, dir string) int {
	t.Helper()
	paths, err := listSegments(walOf(dir))
	if err != nil {
		t.Fatalf("listSegments: %v", err)
	}
	return len(paths)
}

func TestCompactRemovesOnlyFullyAckedInactiveSegments(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5)  // [1,5]
	buildSegment(t, walOf(dir), 6, 5)  // [6,10]
	buildSegment(t, walOf(dir), 11, 5) // [11,15] active tail

	res, err := Compact(dir, 10)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(res.RemovedSegments) != 2 {
		t.Fatalf("removed %v, want 2 segments (seq<=10)", res.RemovedSegments)
	}
	if res.RemovedBytes <= 0 {
		t.Fatalf("RemovedBytes = %d, want > 0", res.RemovedBytes)
	}
	if got := segCount(t, dir); got != 1 {
		t.Fatalf("remaining segments = %d, want 1 (the active tail)", got)
	}
	// The surviving segment is the active tail [11,15]; recovery stays clean.
	rec := mustRecover(t, dir)
	if rec.Outcome != OutcomeClean || rec.HighestDurableSequence != 15 {
		t.Fatalf("after compaction: outcome=%v highest=%d, want clean/15", rec.Outcome, rec.HighestDurableSequence)
	}
}

func TestCompactNeverEvictsUnacknowledgedByte(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5) // [1,5]
	buildSegment(t, walOf(dir), 6, 5) // [6,10] active tail

	// acknowledged_through lands mid-first-segment: no whole segment is fully acknowledged.
	res, err := Compact(dir, 4)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(res.RemovedSegments) != 0 {
		t.Fatalf("removed %v with an unacknowledged byte present, want none", res.RemovedSegments)
	}
	if got := segCount(t, dir); got != 2 {
		t.Fatalf("segments = %d, want 2", got)
	}
}

func TestCompactNeverRemovesActiveTailSegment(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5) // [1,5] single, active

	res, err := Compact(dir, 5) // fully acknowledged but it is the active tail
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(res.RemovedSegments) != 0 {
		t.Fatalf("removed the sole active segment: %v", res.RemovedSegments)
	}
	if got := segCount(t, dir); got != 1 {
		t.Fatalf("segments = %d, want 1", got)
	}
}

func TestCompactFullyCompactedPreservesNextSequence(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 5)  // [1,5]
	buildSegment(t, walOf(dir), 6, 5)  // [6,10]
	buildSegment(t, walOf(dir), 11, 5) // [11,15] active tail
	if err := writeAck(dir, 15); err != nil {
		t.Fatalf("writeAck: %v", err)
	}

	// Everything below the active tail is acknowledged and compacted; the tail stays.
	if _, err := Compact(dir, 15); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if got := segCount(t, dir); got != 1 {
		t.Fatalf("segments = %d, want 1 tail", got)
	}
	rec := mustRecover(t, dir)
	if rec.NextSequence != 16 {
		t.Fatalf("NextSequence = %d, want 16", rec.NextSequence)
	}
	if rec.AcknowledgedThrough != 15 {
		t.Fatalf("AcknowledgedThrough = %d, want 15", rec.AcknowledgedThrough)
	}
}

func TestCompactCrashMidCompactionRecoversAndResumes(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 5)  // [1,5]
	buildSegment(t, walOf(dir), 6, 5)  // [6,10]
	buildSegment(t, walOf(dir), 11, 5) // [11,15] active tail
	if err := writeAck(dir, 10); err != nil {
		t.Fatalf("writeAck: %v", err)
	}

	// Simulate a crash after the first eligible segment was removed but before the second:
	// each Compact removal is an independent durable os.Remove+dir-fsync, so a mid-compaction
	// crash leaves a clean contiguous suffix.
	if err := os.Remove(filepath.Join(walOf(dir), segmentFilename(1))); err != nil {
		t.Fatalf("simulate crash remove seg 1: %v", err)
	}

	// Recovery must be clean over the surviving contiguous suffix [6,15] with next_sequence
	// still 16 (ack preserves it even though seq 1..5 are gone).
	rec := mustRecover(t, dir)
	if rec.Outcome != OutcomeClean {
		t.Fatalf("recovery outcome after crash = %v, want clean", rec.Outcome)
	}
	if rec.HighestDurableSequence != 15 || rec.NextSequence != 16 {
		t.Fatalf("recovery highest=%d next=%d, want 15/16", rec.HighestDurableSequence, rec.NextSequence)
	}

	// Resuming compaction removes the second eligible segment; the active tail survives.
	res, err := Compact(dir, 10)
	if err != nil {
		t.Fatalf("resume Compact: %v", err)
	}
	if len(res.RemovedSegments) != 1 {
		t.Fatalf("resume removed %v, want 1 (seg 6)", res.RemovedSegments)
	}
	if got := segCount(t, dir); got != 1 {
		t.Fatalf("segments after resume = %d, want 1 tail", got)
	}
}

func TestReclaimInterruptedCreateFreesTheSlot(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 5) // [1,5]

	// A crash during CreateSegment(6) left a zero-length trailing segment at the next slot.
	slot := filepath.Join(walOf(dir), segmentFilename(6))
	if err := os.WriteFile(slot, nil, fileMode); err != nil {
		t.Fatalf("seed interrupted-create slot: %v", err)
	}

	rec := mustRecover(t, dir)
	if rec.Outcome != OutcomeInterruptedCreate {
		t.Fatalf("outcome = %v, want OutcomeInterruptedCreate", rec.Outcome)
	}
	if rec.InterruptedCreateSegment != slot {
		t.Fatalf("InterruptedCreateSegment = %q, want %q", rec.InterruptedCreateSegment, slot)
	}
	if rec.NextSequence != 6 {
		t.Fatalf("NextSequence = %d, want 6", rec.NextSequence)
	}

	// Rotation reclaims the slot before allocating the next segment.
	reclaimed, err := ReclaimInterruptedCreate(dir, rec)
	if err != nil {
		t.Fatalf("ReclaimInterruptedCreate: %v", err)
	}
	if !reclaimed {
		t.Fatalf("reclaimed = false, want true")
	}
	if _, err := os.Stat(slot); !os.IsNotExist(err) {
		t.Fatalf("interrupted-create slot still present after reclaim: %v", err)
	}

	// CreateSegment at NextSequence now succeeds: O_EXCL no longer collides.
	seg, err := CreateSegment(walOf(dir), SegmentOptions{FormatVersion: 1, SourceID: testSourceID, FirstSequence: rec.NextSequence})
	if err != nil {
		t.Fatalf("CreateSegment after reclaim: %v", err)
	}
	if err := seg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reclaim is idempotent (a crash between remove and dir-fsync retries cleanly).
	again, err := ReclaimInterruptedCreate(dir, rec)
	if err != nil {
		t.Fatalf("idempotent ReclaimInterruptedCreate: %v", err)
	}
	if !again {
		t.Fatalf("idempotent reclaim = false, want true")
	}
}

func TestReclaimInterruptedCreateNoopOnCleanRecovery(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5)
	rec := mustRecover(t, dir)
	if rec.Outcome != OutcomeClean {
		t.Fatalf("outcome = %v, want clean", rec.Outcome)
	}
	reclaimed, err := ReclaimInterruptedCreate(dir, rec)
	if err != nil {
		t.Fatalf("ReclaimInterruptedCreate on clean: %v", err)
	}
	if reclaimed {
		t.Fatalf("reclaimed = true on a clean recovery, want false")
	}
}
