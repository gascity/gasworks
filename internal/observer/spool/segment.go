package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// SegmentMagic ("OSG1") marks the start of a segment header.
const SegmentMagic uint32 = 0x4F534731

// DefaultSegmentCeiling is the default per-segment byte ceiling (64 MiB). A record never
// crosses a segment boundary: an append that would push the file past the ceiling returns
// ErrSegmentFull so the caller rotates to a fresh segment.
const DefaultSegmentCeiling int64 = 64 << 20

// maxSourceIDLen bounds the source id embedded in a segment header (mirrors the domain's
// source-id bound). A header claiming a longer id is corruption.
const maxSourceIDLen = 128

// Segment header geometry. The header is variable length (it carries the source id) but
// self-delimiting:
//
//	magic(4) format_version(4) first_sequence(8) creation_time_unix_nanos(8)
//	source_id_length(2) source_id(source_id_length) header_crc32c(4)
const (
	segFixedPrefixLen = 26 // magic..source_id_length
	segHeaderCRCLen   = 4

	offSegMagic    = 0
	offSegFormat   = 4
	offSegFirstSeq = 8
	offSegTime     = 16
	offSegIDLen    = 24
	// source id begins at segFixedPrefixLen (26); CRC follows the id.
)

// Owner-only modes: directories 0700, regular files 0600.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// Errors returned by the segment writer.
var (
	// ErrSegmentFull means the record would push the segment past its ceiling; the caller
	// rotates. The record is not written.
	ErrSegmentFull = errors.New("observer spool: segment ceiling reached")
	// ErrNonContiguous means the appended frame's sequence is not exactly the segment's
	// next expected sequence (single-writer contiguity).
	ErrNonContiguous = errors.New("observer spool: non-contiguous sequence")
	// ErrBadSegmentHeader means a segment header failed magic/length/CRC validation.
	ErrBadSegmentHeader = errors.New("observer spool: invalid segment header")
	// ErrSequenceExhausted means the source sequence space is exhausted: the segment's last
	// frame carries wire.SequenceMax, so no further sequence can be allocated without
	// wrapping past math.MaxInt64. Append refuses cleanly and never wraps.
	ErrSequenceExhausted = errors.New("observer spool: source sequence space exhausted at math.MaxInt64")
)

// SegmentHeader is the decoded fixed metadata at the start of a .seg file.
type SegmentHeader struct {
	FormatVersion uint32
	SourceID      string
	FirstSequence int64
	CreationTime  time.Time
}

// SegmentOptions configures CreateSegment/OpenSegment. On CreateSegment the header fields
// (FormatVersion, SourceID, FirstSequence, CreationTime) are written; on OpenSegment they
// are ignored (the on-disk header is authoritative) and only Ceiling and Sync apply.
type SegmentOptions struct {
	FormatVersion uint32
	SourceID      string
	FirstSequence int64
	CreationTime  time.Time
	// Ceiling is the per-segment byte ceiling; 0 selects DefaultSegmentCeiling.
	Ceiling int64
	// Sync is the fsync seam. It receives the segment file and must make its bytes durable
	// before returning nil. nil selects (*os.File).Sync. Tests inject a spy to assert the
	// write-before-fsync and fsync-before-success ordering.
	Sync func(*os.File) error
}

// Segment is a single append-only .seg file with a serialized single writer. It tracks its
// own byte size and last appended sequence so appends are contiguous and bounded without
// re-reading the file.
type Segment struct {
	file    *os.File
	path    string
	header  SegmentHeader
	ceiling int64
	size    int64
	last    int64 // last appended sequence; 0 when the segment holds no frames yet
	sync    func(*os.File) error
}

// segmentFilename is the 20-digit zero-padded first-sequence name (matching the on-disk
// layout wal/00000000000000000001.seg).
func segmentFilename(firstSequence int64) string {
	return fmt.Sprintf("%020d.seg", firstSequence)
}

// CreateSegment creates wal/<first>.seg with a durable header. The directory (0700) and
// file (0600) are owner-only; the header and the directory entry are fsynced before the
// segment is returned, so an empty-but-created segment survives a crash.
func CreateSegment(walDir string, opts SegmentOptions) (*Segment, error) {
	if opts.FirstSequence < 1 {
		return nil, fmt.Errorf("observer spool: first sequence %d must be >= 1", opts.FirstSequence)
	}
	if err := ensureDir(walDir); err != nil {
		return nil, err
	}
	hdr := SegmentHeader{
		FormatVersion: opts.FormatVersion,
		SourceID:      opts.SourceID,
		FirstSequence: opts.FirstSequence,
		CreationTime:  opts.CreationTime,
	}
	hdrBytes, err := encodeSegmentHeader(hdr)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(walDir, segmentFilename(opts.FirstSequence))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return nil, fmt.Errorf("observer spool: create segment: %w", err)
	}
	// Defend against a permissive umask: force the exact owner-only mode.
	if err := f.Chmod(fileMode); err != nil {
		f.Close()
		return nil, fmt.Errorf("observer spool: chmod segment: %w", err)
	}
	seg := &Segment{
		file:    f,
		path:    path,
		header:  hdr,
		ceiling: ceilingOrDefault(opts.Ceiling),
		sync:    syncerOrDefault(opts.Sync),
	}
	if _, err := f.WriteAt(hdrBytes, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("observer spool: write segment header: %w", err)
	}
	if err := seg.sync(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("observer spool: fsync segment header: %w", err)
	}
	if err := fsyncDir(walDir); err != nil {
		f.Close()
		return nil, err
	}
	seg.size = int64(len(hdrBytes))
	return seg, nil
}

// OpenSegment opens an existing clean segment for continued append. It validates the
// header and scans the frames to recover the last sequence and byte size. It requires a
// clean tail: a torn or corrupt frame is an error (recovery must run first).
func OpenSegment(path string, opts SegmentOptions) (*Segment, error) {
	f, err := os.OpenFile(path, os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("observer spool: open segment: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("observer spool: read segment: %w", err)
	}
	hdr, hdrLen, err := decodeSegmentHeader(data)
	if err != nil {
		f.Close()
		return nil, err
	}
	seg := &Segment{
		file:    f,
		path:    path,
		header:  hdr,
		ceiling: ceilingOrDefault(opts.Ceiling),
		size:    int64(hdrLen),
		sync:    syncerOrDefault(opts.Sync),
	}
	off := hdrLen
	expected := hdr.FirstSequence
	for off < len(data) {
		fr, n, status := DecodeFrame(data[off:])
		if status != FrameOK {
			f.Close()
			return nil, fmt.Errorf("observer spool: open segment %s: unclean frame at offset %d (recover first)", filepath.Base(path), off)
		}
		if fr.Sequence != expected {
			f.Close()
			return nil, fmt.Errorf("observer spool: open segment %s: sequence %d at offset %d, want %d", filepath.Base(path), fr.Sequence, off, expected)
		}
		expected++
		seg.last = fr.Sequence
		off += n
		seg.size = int64(off)
	}
	return seg, nil
}

// Append writes one frame, fsyncs, and only then reports success. It rejects an exhausted
// sequence space (ErrSequenceExhausted), an out-of-range sequence (ErrSequenceOutOfRange),
// a non-contiguous sequence (ErrNonContiguous), an oversized record (*RecordTooLargeError),
// and a record that would cross the ceiling (ErrSegmentFull); in every rejection nothing is
// written. If the fsync seam fails, the partial write is rolled back to the last durable
// boundary and the error is returned, so the segment's tracked state always matches a
// clean frame boundary.
func (s *Segment) Append(f Frame) error {
	expected, exhausted := s.nextExpected()
	if exhausted {
		return ErrSequenceExhausted
	}
	encoded, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	if f.Sequence != expected {
		return fmt.Errorf("%w: got %d, want %d", ErrNonContiguous, f.Sequence, expected)
	}
	if s.size+int64(len(encoded)) > s.ceiling {
		return ErrSegmentFull
	}
	if _, err := s.file.WriteAt(encoded, s.size); err != nil {
		s.rollback()
		return fmt.Errorf("observer spool: write frame: %w", err)
	}
	if err := s.sync(s.file); err != nil {
		s.rollback()
		return fmt.Errorf("observer spool: fsync frame: %w", err)
	}
	s.size += int64(len(encoded))
	s.last = f.Sequence
	return nil
}

// rollback truncates any bytes written past the last durable boundary, so a failed append
// leaves the file exactly at s.size (a clean frame boundary). Best effort: a truncate
// failure does not mask the originating error.
func (s *Segment) rollback() {
	_ = s.file.Truncate(s.size)
}

// nextExpected is the sequence the next appended frame must carry, and whether the sequence
// space is exhausted. It never overflows: once the last frame is wire.SequenceMax the space
// is exhausted rather than wrapping to a negative sequence (mirroring the recovery-side
// exhaustion clamp in nextSequence).
func (s *Segment) nextExpected() (seq int64, exhausted bool) {
	if s.last == 0 {
		return s.header.FirstSequence, false
	}
	if s.last >= wire.SequenceMax {
		return 0, true
	}
	return s.last + 1, false
}

// ReadAll returns the segment's frames in order. A torn or corrupt frame is an error; use
// Recover for a segment that may have an unclean tail.
func (s *Segment) ReadAll() ([]Frame, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("observer spool: read segment: %w", err)
	}
	_, hdrLen, err := decodeSegmentHeader(data)
	if err != nil {
		return nil, err
	}
	var frames []Frame
	off := hdrLen
	for off < len(data) {
		fr, n, status := DecodeFrame(data[off:])
		if status != FrameOK {
			return nil, fmt.Errorf("observer spool: read segment %s: unclean frame at offset %d", filepath.Base(s.path), off)
		}
		frames = append(frames, fr)
		off += n
	}
	return frames, nil
}

// Path returns the segment file path.
func (s *Segment) Path() string { return s.path }

// FirstSequence returns the header's first source sequence.
func (s *Segment) FirstSequence() int64 { return s.header.FirstSequence }

// LastSequence returns the last appended sequence (0 if the segment holds no frames).
func (s *Segment) LastSequence() int64 { return s.last }

// SourceID returns the header source id.
func (s *Segment) SourceID() string { return s.header.SourceID }

// FormatVersion returns the header WAL format version.
func (s *Segment) FormatVersion() uint32 { return s.header.FormatVersion }

// CreationTime returns the header creation time.
func (s *Segment) CreationTime() time.Time { return s.header.CreationTime }

// Close closes the underlying file.
func (s *Segment) Close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}

// encodeSegmentHeader serializes a segment header with its trailing CRC32C.
func encodeSegmentHeader(h SegmentHeader) ([]byte, error) {
	if len(h.SourceID) == 0 || len(h.SourceID) > maxSourceIDLen {
		return nil, fmt.Errorf("observer spool: segment source id length %d out of [1, %d]", len(h.SourceID), maxSourceIDLen)
	}
	total := segFixedPrefixLen + len(h.SourceID) + segHeaderCRCLen
	buf := make([]byte, total)
	binary.BigEndian.PutUint32(buf[offSegMagic:], SegmentMagic)
	binary.BigEndian.PutUint32(buf[offSegFormat:], h.FormatVersion)
	binary.BigEndian.PutUint64(buf[offSegFirstSeq:], uint64(h.FirstSequence))
	binary.BigEndian.PutUint64(buf[offSegTime:], uint64(h.CreationTime.UnixNano()))
	binary.BigEndian.PutUint16(buf[offSegIDLen:], uint16(len(h.SourceID)))
	copy(buf[segFixedPrefixLen:], h.SourceID)
	crc := crc32.Checksum(buf[:total-segHeaderCRCLen], castagnoli)
	binary.BigEndian.PutUint32(buf[total-segHeaderCRCLen:], crc)
	return buf, nil
}

// decodeSegmentHeader validates and decodes a segment header from the front of data,
// returning the header and the number of header bytes consumed.
func decodeSegmentHeader(data []byte) (SegmentHeader, int, error) {
	if len(data) < segFixedPrefixLen {
		return SegmentHeader{}, 0, fmt.Errorf("%w: short header (%d bytes)", ErrBadSegmentHeader, len(data))
	}
	if binary.BigEndian.Uint32(data[offSegMagic:]) != SegmentMagic {
		return SegmentHeader{}, 0, fmt.Errorf("%w: bad magic", ErrBadSegmentHeader)
	}
	idLen := int(binary.BigEndian.Uint16(data[offSegIDLen:]))
	if idLen == 0 || idLen > maxSourceIDLen {
		return SegmentHeader{}, 0, fmt.Errorf("%w: source id length %d", ErrBadSegmentHeader, idLen)
	}
	total := segFixedPrefixLen + idLen + segHeaderCRCLen
	if len(data) < total {
		return SegmentHeader{}, 0, fmt.Errorf("%w: truncated header", ErrBadSegmentHeader)
	}
	stored := binary.BigEndian.Uint32(data[total-segHeaderCRCLen : total])
	if crc32.Checksum(data[:total-segHeaderCRCLen], castagnoli) != stored {
		return SegmentHeader{}, 0, fmt.Errorf("%w: header CRC mismatch", ErrBadSegmentHeader)
	}
	h := SegmentHeader{
		FormatVersion: binary.BigEndian.Uint32(data[offSegFormat:]),
		FirstSequence: int64(binary.BigEndian.Uint64(data[offSegFirstSeq:])),
		CreationTime:  time.Unix(0, int64(binary.BigEndian.Uint64(data[offSegTime:]))).UTC(),
		SourceID:      string(data[segFixedPrefixLen : segFixedPrefixLen+idLen]),
	}
	return h, total, nil
}

func ceilingOrDefault(c int64) int64 {
	if c <= 0 {
		return DefaultSegmentCeiling
	}
	return c
}

func syncerOrDefault(s func(*os.File) error) func(*os.File) error {
	if s != nil {
		return s
	}
	return func(f *os.File) error { return f.Sync() }
}

// ---- owner-only filesystem helpers (shared by segment.go and recover.go) ----

// ensureDir creates dir (and parents) with owner-only mode, forcing 0700 even under a
// permissive umask. When it actually creates the leaf directory it fsyncs the parent once so
// the new directory entry is durable before any file is written into it — otherwise a crash
// after the first CreateSegment/torn-tail diagnostic on a fresh install could lose the whole
// subdirectory (and the fsynced files within it) before the filesystem's background commit
// persists the new dirent.
func ensureDir(dir string) error {
	created := false
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		created = true
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("observer spool: create dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("observer spool: chmod dir %s: %w", dir, err)
	}
	if created {
		parent := filepath.Dir(dir)
		if _, err := os.Stat(parent); err == nil {
			if err := fsyncDir(parent); err != nil {
				return err
			}
		}
	}
	return nil
}

// fsyncDir fsyncs a directory so a rename/create in it is durable (the directory entry,
// not just the file contents).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("observer spool: open dir for fsync %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("observer spool: fsync dir %s: %w", dir, err)
	}
	return nil
}

// atomicWriteFile writes data to path via a temp file, file fsync, rename, and directory
// fsync, leaving path either fully old or fully new across a crash. Files are owner-only
// (0600). This is the replacement discipline the identity/ack sidecars use.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("observer spool: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("observer spool: chmod temp for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("observer spool: write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("observer spool: fsync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("observer spool: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("observer spool: rename temp for %s: %w", path, err)
	}
	return fsyncDir(dir)
}
