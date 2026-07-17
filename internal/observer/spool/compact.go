package spool

// compact.go (E1.3) owns whole-segment compaction and the interrupted-create slot reclaim
// that rotation performs before allocating a new segment.
//
// Compaction unit: a whole segment, removed ONLY when every frame it holds is at or below
// acknowledged_through (fully acknowledged) and it is inactive (not the tail segment the
// writer is appending to). No unacknowledged byte is ever evicted. Because segments are
// contiguous and named by first_sequence, a segment's last sequence is the next segment's
// first_sequence-1, so compaction needs no frame read: it removes a prefix of fully
// acknowledged inactive segments and stops at the first that is not fully acknowledged.
//
// Crash safety: removal is os.Remove followed by a directory fsync. A crash mid-compaction
// leaves a contiguous suffix of segments plus the durable ack sidecar; startup Recover
// reconstructs next_sequence as max(highest durable, acknowledged_through)+1 regardless of how
// many acknowledged segments were removed, so a partial compaction is simply resumed on the
// next Compact call. Nothing that was removed held an unacknowledged or un-reconstructable
// byte.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CompactionResult reports what a Compact call removed.
type CompactionResult struct {
	// RemovedSegments is the basenames of the segments deleted, in ascending sequence order.
	RemovedSegments []string
	// RemovedBytes is the total on-disk size reclaimed.
	RemovedBytes int64
	// RemainingSegments is the segment count left under wal/ after compaction.
	RemainingSegments int
}

// Compact removes whole segments that lie entirely at or below acknowledgedThrough, from the
// front of the WAL, never touching the active (tail) segment. It stops at the first segment
// that still holds an unacknowledged frame, so a compactable prefix is reclaimed while every
// unacknowledged byte is preserved. Each removal is made durable with a directory fsync before
// the next, so a crash leaves a clean contiguous suffix that Recover and a later Compact
// resume from.
//
// Boot-order contract (see ReconcileReserves): Compact MUST run only after
// Recover → ScanRunEvents → ReconcileReserves has re-derived reserve state from the
// pre-compaction frame set, and a RUN_STARTED whose terminal reserve is not yet durably recorded
// in the reserves sidecar MUST NOT be compacted. Compacting a still-open run's RUN_STARTED before
// its reserve is durable would leave a crash window that strands the run without terminal
// capacity, and compacting before reconciliation would erase the cross-check frames the sidecar
// reconciliation relies on.
func Compact(dir string, acknowledgedThrough int64) (CompactionResult, error) {
	walDir := filepath.Join(dir, walDirName)
	segPaths, err := listSegments(walDir)
	if err != nil {
		return CompactionResult{}, err
	}
	res := CompactionResult{RemainingSegments: len(segPaths)}
	if len(segPaths) < 2 {
		// Zero or one segment: the sole segment is the active tail and is never removed.
		return res, nil
	}
	firstSeqs := make([]int64, len(segPaths))
	for i, p := range segPaths {
		fs, err := parseSegmentFirstSequence(filepath.Base(p))
		if err != nil {
			return CompactionResult{}, err
		}
		firstSeqs[i] = fs
	}
	// Iterate every segment except the last (active) one. Segment i's last sequence is
	// firstSeqs[i+1]-1 (contiguity), so it is fully acknowledged iff that value <= ack.
	for i := 0; i < len(segPaths)-1; i++ {
		lastSeq := firstSeqs[i+1] - 1
		if lastSeq > acknowledgedThrough {
			break // this segment holds an unacknowledged frame; nothing after it is compactable.
		}
		path := segPaths[i]
		info, statErr := os.Stat(path)
		if err := os.Remove(path); err != nil {
			return res, fmt.Errorf("observer spool: remove compacted segment %s: %w", filepath.Base(path), err)
		}
		if err := fsyncDir(walDir); err != nil {
			return res, err
		}
		res.RemovedSegments = append(res.RemovedSegments, filepath.Base(path))
		if statErr == nil {
			res.RemovedBytes += info.Size()
		}
		res.RemainingSegments--
	}
	return res, nil
}

// ReclaimInterruptedCreate removes the trailing headerless segment left by a crash during
// CreateSegment, per the E1.2 reclaim contract on Recover. Rotation MUST call this before
// allocating the next segment: CreateSegment uses O_EXCL, and the interrupted file's name is
// the intended first_sequence, which collides with NextSequence. The interrupted-create
// segment holds no durable or acknowledged evidence (Recover proved it too small to hold a
// frame), so removing it never drops evidence, and NextSequence was already reconstructed
// without it. Returns false with no error when there is nothing to reclaim (idempotent, so a
// crash between the remove and the directory fsync is safe to retry).
func ReclaimInterruptedCreate(dir string, rec *Recovery) (bool, error) {
	if rec == nil || rec.Outcome != OutcomeInterruptedCreate || rec.InterruptedCreateSegment == "" {
		return false, nil
	}
	walDir := filepath.Join(dir, walDirName)
	path := rec.InterruptedCreateSegment
	// Defend against reclaiming anything outside this WAL directory.
	if filepath.Dir(path) != walDir {
		return false, fmt.Errorf("observer spool: interrupted-create segment %s is not under %s", path, walDir)
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return true, nil // already reclaimed on a prior interrupted attempt.
		}
		return false, fmt.Errorf("observer spool: reclaim interrupted-create segment %s: %w", filepath.Base(path), err)
	}
	if err := fsyncDir(walDir); err != nil {
		return false, err
	}
	return true, nil
}

// parseSegmentFirstSequence extracts the first_sequence encoded in a segment basename
// (the 20-digit zero-padded name written by segmentFilename).
func parseSegmentFirstSequence(base string) (int64, error) {
	stem := strings.TrimSuffix(base, ".seg")
	if stem == base {
		return 0, fmt.Errorf("observer spool: segment name %q missing .seg suffix", base)
	}
	v, err := strconv.ParseInt(stem, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("observer spool: segment name %q is not a numeric first_sequence: %w", base, err)
	}
	return v, nil
}
