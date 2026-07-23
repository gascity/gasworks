package spool

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- recovery test scaffolding ----

func frameN(seq int64) Frame {
	return Frame{Sequence: seq, Payload: []byte("obs-payload-" + time.Unix(seq, 0).UTC().Format("150405"))}
}

// buildSegment writes wal/<first>.seg via the real writer path (CreateSegment+Append) for
// the contiguous range [first, first+count-1].
func buildSegment(t *testing.T, walDir string, first, count int64) {
	t.Helper()
	seg, err := CreateSegment(walDir, SegmentOptions{FormatVersion: 1, SourceID: testSourceID, FirstSequence: first})
	if err != nil {
		t.Fatalf("CreateSegment(%d): %v", first, err)
	}
	for i := int64(0); i < count; i++ {
		if err := seg.Append(frameN(first + i)); err != nil {
			t.Fatalf("Append %d: %v", first+i, err)
		}
	}
	if err := seg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// rawSegmentBytes assembles a segment file's bytes from a header and pre-encoded frames,
// bypassing the writer's contiguity checks so tests can craft gaps and corruption.
func rawSegmentBytes(t *testing.T, hdr SegmentHeader, frames ...Frame) []byte {
	t.Helper()
	out, err := encodeSegmentHeader(hdr)
	if err != nil {
		t.Fatalf("encodeSegmentHeader: %v", err)
	}
	for _, f := range frames {
		fb, err := EncodeFrame(f)
		if err != nil {
			t.Fatalf("EncodeFrame: %v", err)
		}
		out = append(out, fb...)
	}
	return out
}

func writeRawSegment(t *testing.T, walDir string, first int64, data []byte) string {
	t.Helper()
	if err := ensureDir(walDir); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	path := filepath.Join(walDir, segmentFilename(first))
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatalf("write raw segment: %v", err)
	}
	return path
}

func recoverDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "observer")
	if err := ensureDir(dir); err != nil {
		t.Fatalf("ensureDir observer: %v", err)
	}
	return dir
}

func walOf(dir string) string { return filepath.Join(dir, walDirName) }

// ---- next_sequence cases ----

func TestRecoverEmptyWAL(t *testing.T) {
	dir := recoverDir(t)
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.NextSequence != 1 {
		t.Fatalf("next = %d, want 1", rec.NextSequence)
	}
	if rec.HighestDurableSequence != 0 || rec.AcknowledgedThrough != 0 {
		t.Fatalf("highest=%d ack=%d, want 0/0", rec.HighestDurableSequence, rec.AcknowledgedThrough)
	}
	if rec.Outcome != OutcomeClean {
		t.Fatalf("outcome = %v, want clean", rec.Outcome)
	}
}

func TestRecoverNormal(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 3)
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.HighestDurableSequence != 3 || rec.NextSequence != 4 {
		t.Fatalf("highest=%d next=%d, want 3/4", rec.HighestDurableSequence, rec.NextSequence)
	}
	if rec.SourceID != testSourceID {
		t.Fatalf("source id = %q", rec.SourceID)
	}
}

func TestRecoverAckLagging(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 3)
	if err := writeAck(dir, 2); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.AcknowledgedThrough != 2 || rec.NextSequence != 4 {
		t.Fatalf("ack=%d next=%d, want 2/4", rec.AcknowledgedThrough, rec.NextSequence)
	}
}

func TestRecoverFullyCompacted(t *testing.T) {
	// Every acknowledged segment was compacted away: only the ack sidecar remains.
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	if err := writeAck(dir, 10); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.HighestDurableSequence != 0 || rec.AcknowledgedThrough != 10 || rec.NextSequence != 11 {
		t.Fatalf("highest=%d ack=%d next=%d, want 0/10/11", rec.HighestDurableSequence, rec.AcknowledgedThrough, rec.NextSequence)
	}
}

func TestRecoverCompactedPrefix(t *testing.T) {
	// A contiguous acknowledged prefix was compacted: the remaining segment starts past 1.
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 4, 3) // frames 4,5,6
	if err := writeAck(dir, 3); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.HighestDurableSequence != 6 || rec.NextSequence != 7 {
		t.Fatalf("highest=%d next=%d, want 6/7", rec.HighestDurableSequence, rec.NextSequence)
	}
}

// ---- partial-tail recovery at every byte boundary ----

func TestRecoverPartialTailEveryByteBoundary(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	f1, f2, f3 := frameN(1), frameN(2), frameN(3)
	full := rawSegmentBytes(t, hdr, f1, f2, f3)
	lastFrameLen := len(mustEncode(t, f3))
	prefixLen := len(full) - lastFrameLen // bytes through the end of frame 2

	// Baseline: the fully-intact segment acknowledges all three frames.
	t.Run("intact", func(t *testing.T) {
		dir := recoverDir(t)
		writeRawSegment(t, walOf(dir), 1, full)
		rec, err := Recover(dir)
		if err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if rec.HighestDurableSequence != 3 || rec.NextSequence != 4 || rec.Outcome != OutcomeClean {
			t.Fatalf("intact recover = %+v, want highest 3 / next 4 / clean", rec)
		}
	})

	// Truncate the final frame one byte at a time. Every partial (k in [1, lastFrameLen-1])
	// is a torn tail; k == lastFrameLen lands exactly on the frame-2 boundary (clean).
	for k := 1; k <= lastFrameLen; k++ {
		dir := recoverDir(t)
		writeRawSegment(t, walOf(dir), 1, full[:len(full)-k])

		rec, err := Recover(dir)
		if err != nil {
			t.Fatalf("k=%d: Recover: %v", k, err)
		}
		// A torn tail must never be acknowledged: durable frames are exactly {1,2}.
		if rec.HighestDurableSequence != 2 {
			t.Fatalf("k=%d: highest=%d, want 2 (torn frame 3 not acknowledged)", k, rec.HighestDurableSequence)
		}
		if rec.NextSequence != 3 {
			t.Fatalf("k=%d: next=%d, want 3 (no reuse of a durable sequence)", k, rec.NextSequence)
		}
		partial := k < lastFrameLen
		wantOutcome := OutcomeClean
		if partial {
			wantOutcome = OutcomeTruncatedTail
		}
		if rec.Outcome != wantOutcome {
			t.Fatalf("k=%d: outcome = %v, want %v", k, rec.Outcome, wantOutcome)
		}
		// The segment on disk is truncated to the last valid byte and re-reads cleanly.
		seg, err := OpenSegment(filepath.Join(walOf(dir), segmentFilename(1)), SegmentOptions{})
		if err != nil {
			t.Fatalf("k=%d: OpenSegment after recovery: %v", k, err)
		}
		frames, err := seg.ReadAll()
		seg.Close()
		if err != nil {
			t.Fatalf("k=%d: ReadAll after recovery: %v", k, err)
		}
		if len(frames) != 2 || frames[0].Sequence != 1 || frames[1].Sequence != 2 {
			t.Fatalf("k=%d: recovered frames = %d, want exactly {1,2}", k, len(frames))
		}
		if got := fileSize(t, seg.Path()); got != int64(prefixLen) {
			t.Fatalf("k=%d: truncated size = %d, want %d", k, got, prefixLen)
		}
		// A recovery diagnostic is preserved exactly when a torn tail was discarded. The
		// discarded count is the torn frame's present bytes (lastFrameLen-k), not the k
		// bytes stripped from the file.
		if partial {
			if want := lastFrameLen - k; rec.DiscardedBytes != want {
				t.Fatalf("k=%d: discarded=%d, want %d", k, rec.DiscardedBytes, want)
			}
			assertRecoveryDiagnostic(t, dir)
		}
	}
}

func assertRecoveryDiagnostic(t *testing.T, dir string) {
	t.Helper()
	recDir := filepath.Join(dir, recoveryDirName)
	entries, err := os.ReadDir(recDir)
	if err != nil {
		t.Fatalf("read recovery dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no recovery diagnostic preserved")
	}
	di, err := os.Stat(recDir)
	if err != nil {
		t.Fatalf("stat recovery dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("recovery dir mode = %o, want 700", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(recDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("stat diagnostic: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("diagnostic mode = %o, want 600", fi.Mode().Perm())
	}
}

// ---- interior corruption is a hard error, not a torn tail ----

func TestRecoverInteriorCorruptionHardError(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	f1, f2, f3 := frameN(1), frameN(2), frameN(3)
	full := rawSegmentBytes(t, hdr, f1, f2, f3)

	// Flip a byte inside the complete, non-final frame 2 (its payload region).
	f1Len := len(mustEncode(t, f1))
	corruptOffset := len(rawSegmentBytes(t, hdr)) + f1Len + fixedFrameHeaderLen + 1
	corrupt := append([]byte(nil), full...)
	corrupt[corruptOffset] ^= 0xFF

	dir := recoverDir(t)
	path := writeRawSegment(t, walOf(dir), 1, corrupt)
	sizeBefore := fileSize(t, path)

	_, err := Recover(dir)
	if err == nil {
		t.Fatalf("interior corruption must be a hard error")
	}
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want *CorruptionError", err)
	}
	// The corrupt segment must be preserved untouched (E1.4 owns quarantine/rotation).
	if got := fileSize(t, path); got != sizeBefore {
		t.Fatalf("corrupt segment was modified: size %d, want %d", got, sizeBefore)
	}
}

func TestRecoverInteriorCorruptBadMagic(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	f1, f2 := frameN(1), frameN(2)
	full := rawSegmentBytes(t, hdr, f1, f2)
	f1Len := len(mustEncode(t, f1))
	magicOffset := len(rawSegmentBytes(t, hdr)) + f1Len // start of frame 2's magic
	corrupt := append([]byte(nil), full...)
	corrupt[magicOffset] ^= 0xFF

	dir := recoverDir(t)
	writeRawSegment(t, walOf(dir), 1, corrupt)
	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("bad interior magic err = %v, want *CorruptionError", err)
	}
}

// ---- sequence monotonicity / contiguity ----

func TestRecoverNonMonotonicSequenceWithinSegment(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	// frame seq 1 then seq 3 (skips 2): a non-monotonic/contiguity break inside a segment.
	data := rawSegmentBytes(t, hdr, frameN(1), frameN(3))
	dir := recoverDir(t)
	writeRawSegment(t, walOf(dir), 1, data)
	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("sequence gap err = %v, want *CorruptionError", err)
	}
}

func TestRecoverCrossSegmentContiguity(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 3) // 1,2,3
	buildSegment(t, walOf(dir), 4, 3) // 4,5,6
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.HighestDurableSequence != 6 || rec.NextSequence != 7 {
		t.Fatalf("highest=%d next=%d, want 6/7", rec.HighestDurableSequence, rec.NextSequence)
	}
}

// TestRecoverLastSegmentLengthInflationIsCorruption is the recovery-level regression for the
// closed BLOCKER: inflating a complete interior frame's payload_length in the LAST segment
// (the vulnerable window) so that need == remaining and need == remaining+1 must both be
// interior corruption (via the frame header CRC), never a torn-tail truncation. The
// need==remaining+1 case is the exact boundary that previously flipped to FrameIncomplete
// and silently truncated durable frames.
func TestRecoverLastSegmentLengthInflationIsCorruption(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	f1, f2, f3 := frameN(1), frameN(2), frameN(3) // equal payload sizes
	full := rawSegmentBytes(t, hdr, f1, f2, f3)
	segHeaderLen := len(rawSegmentBytes(t, hdr))
	frameLen := len(mustEncode(t, f1))
	frame2Start := segHeaderLen + frameLen
	remaining := len(full) - frame2Start // bytes from frame 2 to EOF (== 2*frameLen)

	for _, delta := range []int{0, 1} { // need==remaining, need==remaining+1
		newLen := remaining - (fixedFrameHeaderLen + frameCRCLen) + delta
		if newLen <= 0 || newLen > MaxFramePayload {
			t.Fatalf("test setup: newLen %d out of range", newLen)
		}
		corrupt := append([]byte(nil), full...)
		binary.BigEndian.PutUint32(corrupt[frame2Start+offFramePayLen:frame2Start+offFramePayLen+4], uint32(newLen))

		dir := recoverDir(t)
		if err := writeIdentity(dir, testSourceID, 1); err != nil {
			t.Fatalf("writeIdentity: %v", err)
		}
		path := writeRawSegment(t, walOf(dir), 1, corrupt)
		sizeBefore := fileSize(t, path)

		_, err := Recover(dir)
		var cerr *CorruptionError
		if !errors.As(err, &cerr) {
			t.Fatalf("delta=%d (need==remaining%+d): err = %v, want *CorruptionError (not torn tail)", delta, delta, err)
		}
		if got := fileSize(t, path); got != sizeBefore {
			t.Fatalf("delta=%d: corrupt segment was truncated: %d != %d", delta, got, sizeBefore)
		}
	}
}

// TestRecoverHandAuthoredFixtureBytes pins the on-disk format independently of the encoder
// under test: the segment header and frame are assembled from literal bytes with CRCs/SHA
// computed directly, then recovered.
func TestRecoverHandAuthoredFixtureBytes(t *testing.T) {
	table := crc32.MakeTable(crc32.Castagnoli)
	payload := []byte(`{"a":1}`)

	// Hand-authored segment header: OSG1, format 1, first_sequence 1, time 0, source id.
	sh := make([]byte, 26+len(testSourceID)+4)
	binary.BigEndian.PutUint32(sh[0:], 0x4F534731)
	binary.BigEndian.PutUint32(sh[4:], 1)
	binary.BigEndian.PutUint64(sh[8:], 1)
	binary.BigEndian.PutUint64(sh[16:], 0)
	binary.BigEndian.PutUint16(sh[24:], uint16(len(testSourceID)))
	copy(sh[26:], testSourceID)
	binary.BigEndian.PutUint32(sh[len(sh)-4:], crc32.Checksum(sh[:len(sh)-4], table))

	// Hand-authored frame: OFR1, version 2, flags 0, header_length 56, then payload+CRCs.
	fr := make([]byte, 56+len(payload)+4)
	binary.BigEndian.PutUint32(fr[0:], 0x4F465231)
	fr[4] = 2
	fr[5] = 0
	binary.BigEndian.PutUint16(fr[6:], 56)
	binary.BigEndian.PutUint32(fr[8:], uint32(len(payload)))
	binary.BigEndian.PutUint64(fr[12:], 1)
	sum := sha256.Sum256(payload)
	copy(fr[20:52], sum[:])
	binary.BigEndian.PutUint32(fr[52:56], crc32.Checksum(fr[:52], table))
	copy(fr[56:], payload)
	binary.BigEndian.PutUint32(fr[len(fr)-4:], crc32.Checksum(fr[:56+len(payload)], table))

	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	writeRawSegment(t, walOf(dir), 1, append(append([]byte(nil), sh...), fr...))

	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover hand-authored fixture: %v", err)
	}
	if rec.HighestDurableSequence != 1 || rec.NextSequence != 2 || rec.Outcome != OutcomeClean {
		t.Fatalf("hand-authored recover = %+v, want highest 1 / next 2 / clean", rec)
	}
}

// ---- interrupted-create classification (E1.3 reclaim seam) ----

func TestRecoverInterruptedCreateTrailingEmptySegment(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 3) // durable frames 1..3
	writeRawSegment(t, walOf(dir), 4, []byte{})

	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.Outcome != OutcomeInterruptedCreate {
		t.Fatalf("outcome = %v, want OutcomeInterruptedCreate", rec.Outcome)
	}
	if rec.HighestDurableSequence != 3 || rec.NextSequence != 4 {
		t.Fatalf("highest=%d next=%d, want 3/4 (durable frames intact)", rec.HighestDurableSequence, rec.NextSequence)
	}
	if want := filepath.Join(walOf(dir), segmentFilename(4)); rec.InterruptedCreateSegment != want {
		t.Fatalf("InterruptedCreateSegment = %q, want %q", rec.InterruptedCreateSegment, want)
	}
}

func TestRecoverInterruptedCreatePartialHeader(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 2)
	writeRawSegment(t, walOf(dir), 3, make([]byte, 10)) // 10-byte partial header

	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.Outcome != OutcomeInterruptedCreate || rec.HighestDurableSequence != 2 || rec.NextSequence != 3 {
		t.Fatalf("partial-header recover = %+v, want interrupted-create / highest 2 / next 3", rec)
	}
}

// TestRecoverInterruptedCreateReclaimable proves the documented E1.3 reclaim contract: after
// removing the recorded interrupted-create file, CreateSegment can allocate the next segment
// at the reconstructed NextSequence without an O_EXCL collision.
func TestRecoverInterruptedCreateReclaimable(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 3)
	writeRawSegment(t, walOf(dir), 4, []byte{})

	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if err := os.Remove(rec.InterruptedCreateSegment); err != nil {
		t.Fatalf("reclaim remove: %v", err)
	}
	seg, err := CreateSegment(walOf(dir), SegmentOptions{FormatVersion: 1, SourceID: testSourceID, FirstSequence: rec.NextSequence})
	if err != nil {
		t.Fatalf("CreateSegment after reclaim: %v", err)
	}
	defer seg.Close()
	if err := seg.Append(frameN(rec.NextSequence)); err != nil {
		t.Fatalf("Append after reclaim: %v", err)
	}
}

func TestRecoverHeaderlessNonTrailingSegmentIsCorruption(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	writeRawSegment(t, walOf(dir), 1, []byte{}) // empty non-trailing segment
	buildSegment(t, walOf(dir), 4, 2)           // a later, valid segment makes seg 1 non-trailing

	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("headerless non-trailing err = %v, want *CorruptionError", err)
	}
}

// TestRecoverTrailingHeaderCorruptWithFramesIsCorruption pins the safety bound: a trailing
// segment whose header is corrupt but which is LARGER than one header write (so it may still
// hold a durable frame) must be preserved as corruption, never silently reclaimed.
func TestRecoverTrailingHeaderCorruptWithFramesIsCorruption(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	data := rawSegmentBytes(t, hdr, frameN(1), frameN(2)) // header + two durable frames
	segHeaderLen := len(rawSegmentBytes(t, hdr))
	data[segHeaderLen-1] ^= 0xFF // corrupt the segment header CRC (decode fails)
	path := writeRawSegment(t, walOf(dir), 1, data)
	sizeBefore := fileSize(t, path)

	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("header-corrupt-with-frames err = %v, want *CorruptionError (never reclaim)", err)
	}
	if got := fileSize(t, path); got != sizeBefore {
		t.Fatalf("corrupt segment was modified: %d != %d", got, sizeBefore)
	}
}

func TestRecoverTornFrameInNonFinalSegmentIsCorruption(t *testing.T) {
	// An earlier, already-rotated segment is immutable and complete; a short read inside it
	// is corruption, never a torn tail (truncating it would drop the later segment's frames).
	dir := recoverDir(t)
	hdr1 := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	full1 := rawSegmentBytes(t, hdr1, frameN(1), frameN(2))
	writeRawSegment(t, walOf(dir), 1, full1[:len(full1)-2]) // torn frame 2 in segment #1
	buildSegment(t, walOf(dir), 3, 2)                       // a later, complete segment

	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("torn non-final segment err = %v, want *CorruptionError", err)
	}
}

func TestRecoverCrossSegmentGapIsCorruption(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 3) // 1,2,3
	// Second segment starts at 5, leaving a gap at 4.
	data := rawSegmentBytes(t,
		SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 5, CreationTime: time.Unix(1000, 0).UTC()},
		frameN(5), frameN(6))
	writeRawSegment(t, walOf(dir), 5, data)
	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("cross-segment gap err = %v, want *CorruptionError", err)
	}
}

// ---- identity / ack validation and interrupted replacement ----

func TestRecoverIdentityChecksumMismatch(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	corruptFileByte(t, filepath.Join(dir, identityFilename), 6)
	_, err := Recover(dir)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
}

func TestRecoverAckChecksumMismatch(t *testing.T) {
	dir := recoverDir(t)
	if err := writeAck(dir, 4); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	corruptFileByte(t, filepath.Join(dir, ackFilename), 5)
	_, err := Recover(dir)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
}

func TestRecoverIdentitySourceMismatchIsCorruption(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, "src_019f7a1000observerpilot9999", 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegment(t, walOf(dir), 1, 2) // header carries testSourceID
	_, err := Recover(dir)
	var cerr *CorruptionError
	if !errors.As(err, &cerr) {
		t.Fatalf("source mismatch err = %v, want *CorruptionError", err)
	}
}

// TestRecoverInterruptedAckReplacement proves an interrupted atomic ack replacement (a
// stray temp file, and an old/absent committed ack) never lets recovery reuse a durable
// sequence: next stays above the highest durable frame.
func TestRecoverInterruptedAckReplacement(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5) // durable frames 1..5
	if err := writeAck(dir, 3); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	// Simulate a crash mid-replacement: a leftover temp for the next ack value.
	stray := filepath.Join(dir, ".tmp-"+ackFilename+"-interrupted")
	if err := os.WriteFile(stray, encodeAck(4), fileMode); err != nil {
		t.Fatalf("write stray temp: %v", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.AcknowledgedThrough != 3 {
		t.Fatalf("ack = %d, want committed 3 (stray temp ignored)", rec.AcknowledgedThrough)
	}
	if rec.NextSequence != 6 {
		t.Fatalf("next = %d, want 6 (no reuse of durable 1..5)", rec.NextSequence)
	}
}

func TestRecoverInterruptedAckReplacementNoCommittedAck(t *testing.T) {
	dir := recoverDir(t)
	buildSegment(t, walOf(dir), 1, 5)
	stray := filepath.Join(dir, ".tmp-"+ackFilename+"-interrupted")
	if err := os.WriteFile(stray, encodeAck(9), fileMode); err != nil {
		t.Fatalf("write stray temp: %v", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rec.AcknowledgedThrough != 0 {
		t.Fatalf("ack = %d, want 0 (no committed ack)", rec.AcknowledgedThrough)
	}
	if rec.NextSequence != 6 {
		t.Fatalf("next = %d, want 6 (max(highest 5, ack 0)+1)", rec.NextSequence)
	}
}

func TestRecoverIdempotentAfterTruncation(t *testing.T) {
	hdr := SegmentHeader{FormatVersion: 1, SourceID: testSourceID, FirstSequence: 1, CreationTime: time.Unix(1000, 0).UTC()}
	full := rawSegmentBytes(t, hdr, frameN(1), frameN(2), frameN(3))
	dir := recoverDir(t)
	writeRawSegment(t, walOf(dir), 1, full[:len(full)-3]) // torn final frame

	first, err := Recover(dir)
	if err != nil {
		t.Fatalf("first Recover: %v", err)
	}
	if first.Outcome != OutcomeTruncatedTail {
		t.Fatalf("first outcome = %v, want truncated", first.Outcome)
	}
	second, err := Recover(dir)
	if err != nil {
		t.Fatalf("second Recover: %v", err)
	}
	if second.Outcome != OutcomeClean || second.NextSequence != 3 || second.HighestDurableSequence != 2 {
		t.Fatalf("second recover not clean/idempotent: %+v", second)
	}
}

func corruptFileByte(t *testing.T, path string, off int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if off >= len(data) {
		t.Fatalf("offset %d beyond file len %d", off, len(data))
	}
	data[off] ^= 0xFF
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
