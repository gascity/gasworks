package spool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testSourceID = "src_019f7a1000observerpilot0001"

// SequenceMaxForTest mirrors wire.SequenceMax (math.MaxInt64) without importing wire here.
const SequenceMaxForTest int64 = 1<<63 - 1

func mustEncode(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	return b
}

func newSegment(t *testing.T, opts SegmentOptions) (*Segment, string) {
	t.Helper()
	walDir := filepath.Join(t.TempDir(), "wal")
	if opts.SourceID == "" {
		opts.SourceID = testSourceID
	}
	if opts.FirstSequence == 0 {
		opts.FirstSequence = 1
	}
	seg, err := CreateSegment(walDir, opts)
	if err != nil {
		t.Fatalf("CreateSegment: %v", err)
	}
	return seg, walDir
}

func TestCreateSegmentHeaderRoundTrip(t *testing.T) {
	created := time.Date(2026, 7, 16, 12, 0, 0, 123456789, time.UTC)
	seg, _ := newSegment(t, SegmentOptions{
		FormatVersion: 1,
		SourceID:      testSourceID,
		FirstSequence: 5,
		CreationTime:  created,
	})
	path := seg.Path()
	if err := seg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := OpenSegment(path, SegmentOptions{})
	if err != nil {
		t.Fatalf("OpenSegment: %v", err)
	}
	defer reopened.Close()
	if reopened.SourceID() != testSourceID {
		t.Fatalf("source id = %q", reopened.SourceID())
	}
	if reopened.FirstSequence() != 5 {
		t.Fatalf("first sequence = %d, want 5", reopened.FirstSequence())
	}
	if reopened.FormatVersion() != 1 {
		t.Fatalf("format version = %d", reopened.FormatVersion())
	}
	if !reopened.CreationTime().Equal(created) {
		t.Fatalf("creation time = %v, want %v", reopened.CreationTime(), created)
	}
}

func TestSegmentFilenameEncodesFirstSequence(t *testing.T) {
	seg, walDir := newSegment(t, SegmentOptions{FirstSequence: 4097})
	defer seg.Close()
	want := filepath.Join(walDir, "00000000000000004097.seg")
	if seg.Path() != want {
		t.Fatalf("path = %q, want %q", seg.Path(), want)
	}
}

func TestSegmentAppendReadRoundTrip(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 1})
	defer seg.Close()
	for seq := int64(1); seq <= 4; seq++ {
		if err := seg.Append(Frame{Sequence: seq, Payload: []byte("payload-" + string(rune('0'+seq)))}); err != nil {
			t.Fatalf("Append seq %d: %v", seq, err)
		}
	}
	if seg.LastSequence() != 4 {
		t.Fatalf("last sequence = %d, want 4", seg.LastSequence())
	}
	frames, err := seg.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 4 {
		t.Fatalf("read %d frames, want 4", len(frames))
	}
	for i, f := range frames {
		if f.Sequence != int64(i+1) {
			t.Fatalf("frame %d sequence = %d", i, f.Sequence)
		}
	}
}

// TestSegmentAppendFsyncBeforeSuccess proves the frame bytes are durable before Append
// reports success: the injected fsync seam observes the appended frame already on disk, and
// Append does not return until the seam has run.
func TestSegmentAppendFsyncBeforeSuccess(t *testing.T) {
	walDir := filepath.Join(t.TempDir(), "wal")
	segPath := filepath.Join(walDir, "00000000000000000001.seg")
	frame := Frame{Sequence: 1, Payload: []byte("durable-before-ack")}
	encoded := mustEncode(t, frame)

	var appendSyncCalls int
	var sawFrameOnDisk bool
	inAppend := false

	seg, err := CreateSegment(walDir, SegmentOptions{
		FormatVersion: 1,
		SourceID:      testSourceID,
		FirstSequence: 1,
		Sync: func(f *os.File) error {
			if inAppend {
				appendSyncCalls++
				// A fresh read must already see the frame the writer is fsyncing.
				if onDisk, rerr := os.ReadFile(segPath); rerr == nil && bytes.HasSuffix(onDisk, encoded) {
					sawFrameOnDisk = true
				}
			}
			return f.Sync()
		},
	})
	if err != nil {
		t.Fatalf("CreateSegment: %v", err)
	}
	defer seg.Close()

	inAppend = true
	if err := seg.Append(frame); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if appendSyncCalls == 0 {
		t.Fatalf("fsync seam never ran before success")
	}
	if !sawFrameOnDisk {
		t.Fatalf("frame was not on disk when fsync ran (write must precede fsync)")
	}
}

func TestSegmentSyncErrorRollsBack(t *testing.T) {
	failNext := false
	seg, _ := newSegment(t, SegmentOptions{
		FirstSequence: 1,
		Sync: func(f *os.File) error {
			if failNext {
				return errors.New("simulated fsync failure")
			}
			return f.Sync()
		},
	})
	defer seg.Close()

	if err := seg.Append(Frame{Sequence: 1, Payload: []byte("first")}); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	sizeAfterFirst := fileSize(t, seg.Path())

	failNext = true
	err := seg.Append(Frame{Sequence: 2, Payload: []byte("second")})
	if err == nil {
		t.Fatalf("Append should fail when fsync fails")
	}
	if seg.LastSequence() != 1 {
		t.Fatalf("last sequence advanced to %d despite fsync failure", seg.LastSequence())
	}
	if got := fileSize(t, seg.Path()); got != sizeAfterFirst {
		t.Fatalf("file not rolled back: size %d, want %d", got, sizeAfterFirst)
	}
	frames, err := seg.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("read %d frames after rollback, want 1", len(frames))
	}
}

func TestSegmentAppendNonContiguousRejected(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 1})
	defer seg.Close()
	if err := seg.Append(Frame{Sequence: 1, Payload: []byte("a")}); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if err := seg.Append(Frame{Sequence: 3, Payload: []byte("gap")}); !errors.Is(err, ErrNonContiguous) {
		t.Fatalf("gap append err = %v, want ErrNonContiguous", err)
	}
	if err := seg.Append(Frame{Sequence: 1, Payload: []byte("reuse")}); !errors.Is(err, ErrNonContiguous) {
		t.Fatalf("reuse append err = %v, want ErrNonContiguous", err)
	}
	// The rejected records must not have grown the log.
	frames, err := seg.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("read %d frames, want 1", len(frames))
	}
}

func TestSegmentFirstAppendMustMatchFirstSequence(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 10})
	defer seg.Close()
	if err := seg.Append(Frame{Sequence: 11, Payload: []byte("x")}); !errors.Is(err, ErrNonContiguous) {
		t.Fatalf("first append not matching first_sequence err = %v, want ErrNonContiguous", err)
	}
	if err := seg.Append(Frame{Sequence: 10, Payload: []byte("x")}); err != nil {
		t.Fatalf("first append at first_sequence: %v", err)
	}
}

func TestSegmentCeilingRecordNeverCrosses(t *testing.T) {
	frame := Frame{Sequence: 1, Payload: []byte("bounded-record")}
	recordLen := len(mustEncode(t, frame))
	// Ceiling admits exactly two records past the header, never a third.
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 1, Ceiling: int64(seg0HeaderLen() + recordLen*2)})
	defer seg.Close()

	if err := seg.Append(Frame{Sequence: 1, Payload: []byte("bounded-record")}); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if err := seg.Append(Frame{Sequence: 2, Payload: []byte("bounded-record")}); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	sizeAtCeiling := fileSize(t, seg.Path())
	err := seg.Append(Frame{Sequence: 3, Payload: []byte("bounded-record")})
	if !errors.Is(err, ErrSegmentFull) {
		t.Fatalf("third append err = %v, want ErrSegmentFull", err)
	}
	if got := fileSize(t, seg.Path()); got != sizeAtCeiling {
		t.Fatalf("full segment grew: size %d, want %d", got, sizeAtCeiling)
	}
	if got := fileSize(t, seg.Path()); got > int64(seg0HeaderLen()+recordLen*2) {
		t.Fatalf("segment exceeded ceiling: %d", got)
	}
}

func TestSegmentAppendSequenceExhaustion(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: SequenceMaxForTest})
	defer seg.Close()
	// The terminal sequence is appendable exactly once.
	if err := seg.Append(Frame{Sequence: SequenceMaxForTest, Payload: []byte("last")}); err != nil {
		t.Fatalf("Append at SequenceMax: %v", err)
	}
	// Any further append is a clean exhaustion refusal — never a wrap to a negative sequence.
	sizeBefore := fileSize(t, seg.Path())
	err := seg.Append(Frame{Sequence: 1, Payload: []byte("wrap")})
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("post-exhaustion append err = %v, want ErrSequenceExhausted", err)
	}
	if got := fileSize(t, seg.Path()); got != sizeBefore {
		t.Fatalf("exhausted segment grew: size %d, want %d", got, sizeBefore)
	}
	frames, err := seg.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 1 || frames[0].Sequence != SequenceMaxForTest {
		t.Fatalf("read %d frames; want exactly the SequenceMax frame", len(frames))
	}
}

func TestSegmentAppendRejectsOutOfRangeSequence(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 1})
	defer seg.Close()
	sizeBefore := fileSize(t, seg.Path())
	for _, seq := range []int64{0, -1, -9223372036854775808} {
		err := seg.Append(Frame{Sequence: seq, Payload: []byte("x")})
		if !errors.Is(err, ErrSequenceOutOfRange) {
			t.Fatalf("seq %d: err = %v, want ErrSequenceOutOfRange", seq, err)
		}
	}
	if got := fileSize(t, seg.Path()); got != sizeBefore {
		t.Fatalf("out-of-range append wrote to the segment: size %d, want %d", got, sizeBefore)
	}
}

func TestSegmentAppendOversizedRecord(t *testing.T) {
	seg, _ := newSegment(t, SegmentOptions{FirstSequence: 1})
	defer seg.Close()
	err := seg.Append(Frame{Sequence: 1, Payload: make([]byte, MaxFramePayload+1)})
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized append err = %v, want ErrRecordTooLarge", err)
	}
}

func TestSegmentOwnerOnlyModes(t *testing.T) {
	seg, walDir := newSegment(t, SegmentOptions{FirstSequence: 1})
	defer seg.Close()
	fi, err := os.Stat(seg.Path())
	if err != nil {
		t.Fatalf("stat segment: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("segment file mode = %o, want 600", got)
	}
	di, err := os.Stat(walDir)
	if err != nil {
		t.Fatalf("stat wal dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Fatalf("wal dir mode = %o, want 700", got)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// seg0HeaderLen returns the on-disk length of a segment header for the standard test
// source id (used to size ceilings precisely).
func seg0HeaderLen() int {
	b, _ := encodeSegmentHeader(SegmentHeader{
		FormatVersion: 1,
		SourceID:      testSourceID,
		FirstSequence: 1,
		CreationTime:  time.Unix(0, 0).UTC(),
	})
	return len(b)
}
