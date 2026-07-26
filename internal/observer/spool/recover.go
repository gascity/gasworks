package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// On-disk names under the observer state root.
const (
	walDirName       = "wal"
	recoveryDirName  = "recovery"
	identityFilename = "identity"
	ackFilename      = "ack"
)

// CurrentFormatVersion is the durable WAL/identity format written by a spool
// whose caller does not explicitly select a version.
const CurrentFormatVersion uint32 = 1

// Sidecar magics.
const (
	identityMagic uint32 = 0x4F494431 // "OID1"
	ackMagic      uint32 = 0x4F414B31 // "OAK1"
)

// ErrChecksumMismatch is returned when a checksummed sidecar (identity/ack) fails its
// CRC32C. The store is unhealthy; recovery does not guess past a corrupt control file.
var ErrChecksumMismatch = errors.New("observer spool: sidecar checksum mismatch")

// ErrIdentityMismatch is returned when a configured source or format would
// rebind an existing durable spool to a different identity.
var ErrIdentityMismatch = errors.New("observer spool: durable source identity mismatch")

// RecoveryOutcome classifies what recovery had to do to the WAL.
type RecoveryOutcome int

const (
	// OutcomeClean means every durable frame validated and nothing was truncated.
	OutcomeClean RecoveryOutcome = iota
	// OutcomeTruncatedTail means a partial final frame was truncated to the last valid
	// byte after preserving a recovery diagnostic.
	OutcomeTruncatedTail
	// OutcomeInterruptedCreate means the trailing (last-position) segment has no valid
	// header and no frames — a crash during CreateSegment left a zero-length or
	// partial/CRC-failed header. This is a benign interrupted create (it holds no durable
	// or acknowledged evidence), NOT interior corruption. Recovery leaves the file in place
	// and records it in InterruptedCreateSegment; E1.3's rotation reclaims the slot (see the
	// reclaim contract on Recover).
	OutcomeInterruptedCreate
)

// Recovery is the result of startup recovery over the WAL.
type Recovery struct {
	// SourceID and FormatVersion come from the identity sidecar, or are recovered from
	// consistent segment headers when repairing a missing sidecar.
	SourceID      string
	FormatVersion uint32
	// HighestDurableSequence is the highest valid durable frame sequence (0 if none).
	HighestDurableSequence int64
	// AcknowledgedThrough is the acknowledged-through sequence from the ack sidecar (0 if
	// none acknowledged).
	AcknowledgedThrough int64
	// NextSequence is max(HighestDurableSequence, AcknowledgedThrough) + 1 — the sequence
	// the writer must allocate next, defined for empty and fully-compacted WALs.
	NextSequence int64
	// Exhausted is set when the sequence space is exhausted at math.MaxInt64; NextSequence
	// is clamped and never wraps.
	Exhausted bool
	// Outcome reports clean vs truncated-tail recovery.
	Outcome RecoveryOutcome
	// TruncatedSegment is the basename of the segment whose tail was truncated (empty when
	// clean).
	TruncatedSegment string
	// DiscardedBytes is the number of torn-tail bytes discarded (0 when clean).
	DiscardedBytes int
	// DiagnosticPath is the preserved torn-tail forensic file (empty when clean).
	DiagnosticPath string
	// InterruptedCreateSegment is the full path of a trailing headerless segment left by an
	// interrupted CreateSegment (empty unless Outcome is OutcomeInterruptedCreate). E1.3's
	// rotation must reclaim this slot before allocating the next segment (reclaim contract
	// on Recover).
	InterruptedCreateSegment string
}

// CorruptionError is a typed hard error: corruption inside a complete frame, a bad segment
// header, a non-contiguous durable sequence, or an identity/segment source mismatch. It is
// distinct from a torn tail — recovery does NOT truncate; it leaves the WAL intact for the
// E1.4 quarantine/rotation path.
type CorruptionError struct {
	Segment  string
	Offset   int64
	Sequence int64
	Detail   string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("observer spool: interior corruption in %s at offset %d (seq %d): %s",
		e.Segment, e.Offset, e.Sequence, e.Detail)
}

// Recover validates the identity and ack sidecars, walks every segment under wal/
// validating headers and frames (length, monotonic sequence, SHA-256, CRC), truncates a
// partial final frame after preserving a recovery diagnostic, and reconstructs
// next_sequence. Interior corruption of a complete frame is returned as a *CorruptionError
// without modifying the WAL.
//
// Reclaim contract for E1.3 (interrupted create): if the trailing segment is a headerless
// interrupted CreateSegment, Recover returns Outcome OutcomeInterruptedCreate with the file
// path in InterruptedCreateSegment and no error. That file holds no durable/acknowledged
// evidence, so recovery leaves it in place rather than treating it as corruption. Before
// allocating the next segment, E1.3's rotation MUST reclaim that slot — remove the recorded
// file — because its name (the intended first_sequence) collides with the next segment and
// CreateSegment uses O_EXCL. next_sequence is already reconstructed correctly (the
// interrupted-create segment contributes no durable frame), so reclaiming and re-creating at
// NextSequence never reuses a sequence.
func Recover(dir string) (*Recovery, error) {
	return recover(dir, nil)
}

// RecoverBound performs startup recovery only after every durable identity
// sidecar and segment header encountered has been verified against the
// configured source and format. A binding mismatch is returned before recovery
// diagnostics, truncation, or interrupted-create reclamation can mutate the
// spool.
func RecoverBound(dir, sourceID string, formatVersion uint32) (*Recovery, error) {
	return recover(dir, &configuredBinding{
		sourceID:      sourceID,
		formatVersion: formatVersion,
	})
}

type configuredBinding struct {
	sourceID      string
	formatVersion uint32
}

func recover(dir string, binding *configuredBinding) (*Recovery, error) {
	rec := &Recovery{Outcome: OutcomeClean}

	sourceID, formatVersion, ok, err := readIdentity(dir)
	if err != nil {
		return nil, err
	}
	if ok {
		rec.SourceID = sourceID
		rec.FormatVersion = formatVersion
		if binding != nil &&
			(sourceID != binding.sourceID || formatVersion != binding.formatVersion) {
			return nil, bindingMismatchError(
				binding,
				sourceID,
				formatVersion,
			)
		}
	}

	ack, ackOK, err := readAck(dir)
	if err != nil {
		return nil, err
	}
	if ackOK {
		rec.AcknowledgedThrough = ack
	}

	segPaths, err := listSegments(filepath.Join(dir, walDirName))
	if err != nil {
		return nil, err
	}

	expected := int64(0) // 0 means "not yet established"; the first segment sets it.
	for i, path := range segPaths {
		isLast := i == len(segPaths)-1
		if err := recoverSegment(dir, path, rec, ok, sourceID, binding, &expected, isLast); err != nil {
			return nil, err
		}
	}

	rec.NextSequence, rec.Exhausted = nextSequence(rec.HighestDurableSequence, rec.AcknowledgedThrough)
	return rec, nil
}

func bindingMismatchError(binding *configuredBinding, sourceID string, formatVersion uint32) error {
	return fmt.Errorf(
		"%w: configured %q/v%d, durable %q/v%d",
		ErrIdentityMismatch,
		binding.sourceID,
		binding.formatVersion,
		sourceID,
		formatVersion,
	)
}

// recoverSegment validates one segment's header and frames, updating rec.HighestDurable and
// the running expected sequence. A torn tail (only legal as the physical last frame of the
// last, actively-appended segment) is truncated after a diagnostic; interior corruption —
// including a short read in an already-rotated, immutable earlier segment — returns a
// *CorruptionError.
func recoverSegment(
	dir string,
	path string,
	rec *Recovery,
	identityPresent bool,
	identitySource string,
	binding *configuredBinding,
	expected *int64,
	isLast bool,
) error {
	base := filepath.Base(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("observer spool: read segment %s: %w", base, err)
	}
	hdr, hdrLen, err := decodeSegmentHeader(data)
	if err != nil {
		// A trailing segment whose header does not decode is a benign interrupted
		// CreateSegment ONLY when it is provably too small to hold a frame. CreateSegment
		// writes (and fsyncs) the whole header before any frame is appended, so a segment
		// that ever held a durable frame has size strictly greater than its header. The
		// safe bound is therefore the header length: zero-length, a partial header, or a
		// corrupted-but-complete header with no trailing frame bytes (len <= headerLen)
		// cannot have held a frame and is reclaimable; anything larger — or any non-trailing
		// headerless segment — is corruption we must preserve for E1.4 (never delete a
		// header-corrupted segment that may still hold a durable frame).
		if isLast && len(data) <= interruptedCreateBound(identityPresent, identitySource) {
			rec.Outcome = OutcomeInterruptedCreate
			rec.InterruptedCreateSegment = path
			return nil
		}
		return &CorruptionError{Segment: base, Offset: 0, Detail: err.Error()}
	}
	if rec.SourceID == "" {
		if binding != nil &&
			(hdr.SourceID != binding.sourceID || hdr.FormatVersion != binding.formatVersion) {
			return bindingMismatchError(binding, hdr.SourceID, hdr.FormatVersion)
		}
		rec.SourceID = hdr.SourceID
		rec.FormatVersion = hdr.FormatVersion
	} else if hdr.SourceID != rec.SourceID {
		return &CorruptionError{Segment: base, Offset: 0,
			Detail: "segment source id does not match identity sidecar"}
	} else if hdr.FormatVersion != rec.FormatVersion {
		return &CorruptionError{Segment: base, Offset: 0,
			Detail: "segment format version does not match durable identity"}
	}
	if *expected == 0 {
		*expected = hdr.FirstSequence
	} else if hdr.FirstSequence != *expected {
		return &CorruptionError{Segment: base, Offset: 0, Sequence: hdr.FirstSequence,
			Detail: fmt.Sprintf("segment first_sequence %d breaks contiguity (want %d)", hdr.FirstSequence, *expected)}
	}

	off := hdrLen
	for off < len(data) {
		fr, n, status := DecodeFrame(data[off:])
		switch status {
		case FrameOK:
			if fr.Sequence != *expected {
				return &CorruptionError{Segment: base, Offset: int64(off), Sequence: fr.Sequence,
					Detail: fmt.Sprintf("frame sequence %d breaks monotonic contiguity (want %d)", fr.Sequence, *expected)}
			}
			rec.HighestDurableSequence = fr.Sequence
			*expected++
			off += n
		case FrameIncomplete:
			// A partial final frame is legal only as the tail of the last, actively-appended
			// segment. A short read inside an already-rotated, immutable earlier segment is
			// corruption — truncating it would silently drop later valid segments.
			if !isLast {
				return &CorruptionError{Segment: base, Offset: int64(off),
					Detail: "short read inside a non-final (immutable) segment is not a torn tail"}
			}
			return truncateTornTail(dir, path, data, off, rec)
		case FrameCorrupt:
			return &CorruptionError{Segment: base, Offset: int64(off),
				Detail: "corruption inside a complete frame (CRC/SHA/format)"}
		}
	}
	return nil
}

// truncateTornTail preserves the discarded bytes as a recovery diagnostic, truncates the
// segment to the last valid byte (validEnd), and records the outcome. The diagnostic is
// written and fsynced before the destructive truncate so the discarded tail is never lost;
// the truncate itself is made durable with a FILE fsync before the directory fsync — a
// directory fsync persists the dirent, not the inode's new size — matching the append
// path's fsync-before-report discipline so Recover never reports a truncated tail that is
// not yet durable.
func truncateTornTail(dir, path string, data []byte, validEnd int, rec *Recovery) error {
	base := filepath.Base(path)
	discarded := data[validEnd:]
	diagPath, err := writeRecoveryDiagnostic(dir, base, validEnd, discarded)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, fileMode)
	if err != nil {
		return fmt.Errorf("observer spool: open torn segment %s: %w", base, err)
	}
	if err := f.Truncate(int64(validEnd)); err != nil {
		f.Close()
		return fmt.Errorf("observer spool: truncate torn tail of %s: %w", base, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("observer spool: fsync truncated segment %s: %w", base, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("observer spool: close truncated segment %s: %w", base, err)
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	rec.Outcome = OutcomeTruncatedTail
	rec.TruncatedSegment = base
	rec.DiscardedBytes = len(discarded)
	rec.DiagnosticPath = diagPath
	return nil
}

// writeRecoveryDiagnostic durably records a torn tail under observer/recovery/ before the
// segment is truncated. The filename encodes the segment and the valid-end offset; the file
// holds the discarded bytes for forensics. Owner-only (dir 0700, file 0600).
func writeRecoveryDiagnostic(dir, segment string, validEnd int, discarded []byte) (string, error) {
	recDir := filepath.Join(dir, recoveryDirName)
	if err := ensureDir(recDir); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s.%d.%d.torn-tail", segment, validEnd, time.Now().UnixNano())
	diagPath := filepath.Join(recDir, name)
	if err := atomicWriteFile(diagPath, discarded); err != nil {
		return "", err
	}
	return diagPath, nil
}

// interruptedCreateBound is the largest a trailing headerless segment may be and still be a
// benign interrupted create (provably no durable frame). When the identity sidecar is
// present, every segment's header is exactly segFixedPrefixLen + len(source_id) +
// segHeaderCRCLen bytes, so a file no larger than that could not have reached the first
// frame append. Without identity we cannot know the header length, so we fall back to the
// fixed prefix (a file that cannot even hold a full segment-header prefix cannot hold a
// frame); any larger corrupt-header trailing segment is preserved as corruption.
func interruptedCreateBound(identityPresent bool, identitySource string) int {
	if identityPresent {
		return segFixedPrefixLen + len(identitySource) + segHeaderCRCLen
	}
	return segFixedPrefixLen
}

// nextSequence reconstructs the next allocatable sequence as max(highest, ack)+1, never
// wrapping past the int64 ceiling (sequence exhaustion is clamped, matching PostgreSQL
// BIGINT). Empty WAL (0/0) yields 1; fully-compacted (0/ack) yields ack+1.
func nextSequence(highest, ack int64) (int64, bool) {
	max := highest
	if ack > max {
		max = ack
	}
	if max >= wire.SequenceMax {
		return wire.SequenceMax, true
	}
	return max + 1, false
}

// listSegments returns the wal/*.seg paths sorted ascending by first-sequence (their
// zero-padded filenames sort lexicographically in sequence order).
func listSegments(walDir string) ([]string, error) {
	entries, err := os.ReadDir(walDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("observer spool: list wal dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".seg" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = filepath.Join(walDir, n)
	}
	return paths, nil
}

// ---- identity sidecar ----

// encodeIdentity serializes the checksummed source id + WAL format version.
//
//	magic(4) format_version(4) source_id_length(2) source_id(n) crc32c(4)
func encodeIdentity(sourceID string, formatVersion uint32) []byte {
	buf := make([]byte, 10+len(sourceID)+4)
	binary.BigEndian.PutUint32(buf[0:], identityMagic)
	binary.BigEndian.PutUint32(buf[4:], formatVersion)
	binary.BigEndian.PutUint16(buf[8:], uint16(len(sourceID)))
	copy(buf[10:], sourceID)
	crc := crc32.Checksum(buf[:len(buf)-4], castagnoli)
	binary.BigEndian.PutUint32(buf[len(buf)-4:], crc)
	return buf
}

func decodeIdentity(data []byte) (string, uint32, error) {
	if len(data) < 14 {
		return "", 0, fmt.Errorf("%w: identity too short", ErrChecksumMismatch)
	}
	if binary.BigEndian.Uint32(data[0:]) != identityMagic {
		return "", 0, fmt.Errorf("%w: identity bad magic", ErrChecksumMismatch)
	}
	idLen := int(binary.BigEndian.Uint16(data[8:]))
	total := 10 + idLen + 4
	if idLen == 0 || idLen > maxSourceIDLen || len(data) != total {
		return "", 0, fmt.Errorf("%w: identity length inconsistent", ErrChecksumMismatch)
	}
	stored := binary.BigEndian.Uint32(data[total-4:])
	if crc32.Checksum(data[:total-4], castagnoli) != stored {
		return "", 0, ErrChecksumMismatch
	}
	return string(data[10 : 10+idLen]), binary.BigEndian.Uint32(data[4:]), nil
}

// writeIdentity atomically writes the identity sidecar (E1.2 bootstrap/tests; setup owns
// the real one-time creation).
func writeIdentity(dir, sourceID string, formatVersion uint32) error {
	if sourceID == "" || len(sourceID) > maxSourceIDLen {
		return fmt.Errorf("observer spool: identity source id length %d out of range", len(sourceID))
	}
	return atomicWriteFile(filepath.Join(dir, identityFilename), encodeIdentity(sourceID, formatVersion))
}

// readIdentity reads and validates the identity sidecar. The bool is false when the file is
// absent (a fresh install); a present-but-corrupt file is ErrChecksumMismatch.
func readIdentity(dir string) (string, uint32, bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, identityFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("observer spool: read identity: %w", err)
	}
	id, ver, err := decodeIdentity(data)
	if err != nil {
		return "", 0, false, err
	}
	return id, ver, true, nil
}

// BindIdentity creates the checksummed identity sidecar for a recovered spool,
// or verifies that the existing sidecar names the same source and format. The
// caller must recover and compare any surviving segment headers before binding
// a previously absent sidecar.
func BindIdentity(dir, sourceID string, formatVersion uint32) error {
	existingSource, existingVersion, ok, err := readIdentity(dir)
	if err != nil {
		return err
	}
	if ok {
		if existingSource != sourceID || existingVersion != formatVersion {
			return fmt.Errorf(
				"%w: configured %q/v%d, durable %q/v%d",
				ErrIdentityMismatch,
				sourceID,
				formatVersion,
				existingSource,
				existingVersion,
			)
		}
		return nil
	}
	return writeIdentity(dir, sourceID, formatVersion)
}

// ---- ack sidecar ----

// encodeAck serializes the checksummed acknowledged-through sequence.
//
//	magic(4) acknowledged_through(8) crc32c(4)
func encodeAck(ackThrough int64) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[0:], ackMagic)
	binary.BigEndian.PutUint64(buf[4:], uint64(ackThrough))
	crc := crc32.Checksum(buf[:12], castagnoli)
	binary.BigEndian.PutUint32(buf[12:], crc)
	return buf
}

func decodeAck(data []byte) (int64, error) {
	if len(data) != 16 {
		return 0, fmt.Errorf("%w: ack wrong length", ErrChecksumMismatch)
	}
	if binary.BigEndian.Uint32(data[0:]) != ackMagic {
		return 0, fmt.Errorf("%w: ack bad magic", ErrChecksumMismatch)
	}
	stored := binary.BigEndian.Uint32(data[12:])
	if crc32.Checksum(data[:12], castagnoli) != stored {
		return 0, ErrChecksumMismatch
	}
	v := int64(binary.BigEndian.Uint64(data[4:]))
	if v < 0 {
		return 0, fmt.Errorf("%w: ack negative", ErrChecksumMismatch)
	}
	return v, nil
}

// writeAck atomically writes the ack sidecar. E1.3 owns the ack advancement policy
// (contiguity, corrupt-ack rejection); this is the durable write primitive plus test setup.
func writeAck(dir string, ackThrough int64) error {
	return atomicWriteFile(filepath.Join(dir, ackFilename), encodeAck(ackThrough))
}

// readAck reads and validates the ack sidecar. The bool is false when the file is absent
// (nothing acknowledged); a present-but-corrupt file is ErrChecksumMismatch.
func readAck(dir string) (int64, bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, ackFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("observer spool: read ack: %w", err)
	}
	v, err := decodeAck(data)
	if err != nil {
		return 0, false, err
	}
	return v, true, nil
}
