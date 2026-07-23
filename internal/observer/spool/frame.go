// Package spool implements the endpoint's owner-only durable write-ahead log: the
// checksum-framed segmented WAL that holds captured observations until every required
// acknowledgement, with a serialized single writer and no embedded database.
//
// This file (E1.2) owns the on-disk codecs and startup recovery:
//
//   - frame.go   — the observation-frame codec (this file);
//   - segment.go — the segment-header codec and a single .seg file the writer appends to
//     with fsync-before-success and a byte ceiling a record never crosses;
//   - recover.go — startup recovery over wal/: validate identity/ack, walk every segment
//     validating headers and frames, truncate a partial final frame, reject interior
//     corruption, and reconstruct next_sequence.
//
// Acknowledgement, compaction, capacity accounting, quarantine, and audited rotation are
// deliberately NOT here — they are E1.3/E1.4 and build on these codecs.
//
// On-disk integer fields are big-endian. A frame carries THREE checksums, each with a
// distinct job:
//
//   - a CRC32C over the fixed 52-byte header prefix (the "header CRC"), verified before any
//     header field — critically payload_length — is trusted. A torn write only truncates
//     the tail and never scrambles already-written header bytes, so a valid header CRC plus
//     a short payload is a genuine torn tail, while a corrupted payload_length fails the
//     header CRC and is classified as interior corruption instead of masquerading as a
//     short read (the durability-boundary defect this format closes);
//   - a CRC32C over header+payload (the "frame CRC") catching accidental bit rot anywhere
//     in a complete record;
//   - the canonical-payload SHA-256, the content identity that also equals the server-side
//     ingest dedup hash (wire.CanonicalHash), binding a surviving frame to exactly the
//     bytes the Collector will later deduplicate on.
package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// FrameMagic ("OFR1") marks the start of an observation frame. It is the first field of a
// frame header, so a byte-for-byte prefix truncation of the actively-written frame always
// leaves the magic intact and recovery can tell an unfinished tail from a scrambled
// interior record.
const FrameMagic uint32 = 0x4F465231

// frameVersion is the frame layout version. v2 adds the fixed-header CRC over the 52-byte
// prefix (v1 was never written to a real WAL, so this is a pre-commit format change, not a
// migration). A decoded frame carrying any other version is corruption at this layer.
const frameVersion uint8 = 2

// Fixed frame-header geometry. The header is a fixed 56-byte record:
//
//	magic(4) version(1) flags(1) header_length(2) payload_length(4)
//	sequence(8) payload_sha256(32) header_crc32c(4)
//
// followed by payload_length canonical-JSON bytes and a 4-byte frame CRC32C over
// header+payload. The header CRC covers the first 52 bytes (everything up to itself);
// header_length is the full 56.
const (
	headerPrefixLen     = 52 // bytes covered by the fixed-header CRC
	fixedFrameHeaderLen = 56 // headerPrefixLen + headerCRC; the header_length field value
	frameCRCLen         = 4

	offFrameMagic     = 0
	offFrameVersion   = 4
	offFrameFlags     = 5
	offFrameHeaderLen = 6
	offFramePayLen    = 8
	offFrameSequence  = 12
	offFrameSHA       = 20 // 32 bytes: [20:52]
	offFrameHeaderCRC = 52 // 4 bytes: [52:56]
)

// MaxFramePayload is the published maximum canonical payload a single frame may carry (4
// MiB, matching the per-batch uncompressed JSON cap). A record over this ceiling never
// reaches the WAL: EncodeFrame returns a typed *RecordTooLargeError so the caller can turn
// it into a content-free CAPTURE_DIAGNOSTIC rather than silently drop it. It also bounds
// the payload_length field on decode.
//
// Layout decision left open for E1.3/E1.4: this ceiling must stay strictly below the
// segment ceiling (a record never crosses a segment) and should be re-pinned against the
// qualification benchmark alongside the capacity formula.
const MaxFramePayload = 4 << 20

// castagnoli is the shared CRC32C table (Castagnoli polynomial).
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Frame is one decoded observation frame. On encode the caller supplies Sequence, Flags,
// and the canonical Payload; the SHA256 is computed from Payload and written. On decode
// SHA256 holds the on-disk hash (already verified against the payload).
type Frame struct {
	// Sequence is the one-based source sequence stamped into the observation. It must be in
	// [wire.SequenceMin, wire.SequenceMax]; EncodeFrame rejects an out-of-range value.
	Sequence int64
	// Flags is a reserved frame-flags byte (v2 writes 0); it is covered by the header CRC
	// and carried through decode for E1.3/E1.4 use.
	Flags uint8
	// Payload is the canonical typed-JSON bytes (wire.CanonicalBytes of the sealed
	// observation).
	Payload []byte
	// SHA256 is the canonical-payload SHA-256 (== wire.CanonicalHash of the observation).
	SHA256 [32]byte
}

// RecordTooLargeError reports a record whose canonical payload exceeds MaxFramePayload. The
// caller converts it into a typed capture diagnostic; the record is never silently dropped.
type RecordTooLargeError struct {
	Size int
	Max  int
}

func (e *RecordTooLargeError) Error() string {
	return fmt.Sprintf("observer spool: record payload %d bytes exceeds published max %d", e.Size, e.Max)
}

// ErrRecordTooLarge is the sentinel matched by errors.Is for an oversized record.
var ErrRecordTooLarge = errors.New("observer spool: record exceeds published maximum")

// Is lets errors.Is(err, ErrRecordTooLarge) match a *RecordTooLargeError.
func (e *RecordTooLargeError) Is(target error) bool { return target == ErrRecordTooLarge }

// ErrSequenceOutOfRange is returned by EncodeFrame (and surfaced by Segment.Append) for a
// sequence outside [wire.SequenceMin, wire.SequenceMax]; a negative/zero/overflowed
// sequence must never be encoded to the durability boundary.
var ErrSequenceOutOfRange = errors.New("observer spool: sequence outside [1, math.MaxInt64]")

// FrameStatus classifies a single frame decode for the recovery walk.
type FrameStatus int

const (
	// FrameOK means a complete frame whose header CRC, lengths, frame CRC, and payload
	// SHA-256 all validated.
	FrameOK FrameStatus = iota
	// FrameIncomplete means the fixed header validated but there were not enough bytes for
	// the declared payload (a partial final write / torn tail), or fewer than the fixed
	// header bytes are present. It is recoverable only as the last frame in the last
	// segment.
	FrameIncomplete
	// FrameCorrupt means a present frame failed an integrity check (bad header CRC, magic,
	// version, header length, payload-length bound, frame CRC, or SHA). This is never a torn
	// tail — it is a hard error the recovery layer reports for quarantine (E1.4).
	FrameCorrupt
)

// EncodeFrame validates and serializes one frame to its on-disk bytes. It computes the
// header CRC over the fixed prefix, the payload SHA-256, and the header+payload CRC; the
// Frame.SHA256 input is ignored (the stored hash is always the hash of the bytes actually
// written). A payload over MaxFramePayload returns a *RecordTooLargeError, and a sequence
// outside [1, math.MaxInt64] returns ErrSequenceOutOfRange; in both cases no bytes.
//
// Payload contract: callers MUST pass canonical bytes (wire.CanonicalBytes of the sealed
// observation). EncodeFrame is a low-level primitive and does not re-canonicalize; the
// production path is EncodeObservationFrame, which always canonicalizes.
func EncodeFrame(f Frame) ([]byte, error) {
	if f.Sequence < wire.SequenceMin || f.Sequence > wire.SequenceMax {
		return nil, fmt.Errorf("%w: %d", ErrSequenceOutOfRange, f.Sequence)
	}
	if len(f.Payload) > MaxFramePayload {
		return nil, &RecordTooLargeError{Size: len(f.Payload), Max: MaxFramePayload}
	}
	total := fixedFrameHeaderLen + len(f.Payload) + frameCRCLen
	buf := make([]byte, total)
	binary.BigEndian.PutUint32(buf[offFrameMagic:], FrameMagic)
	buf[offFrameVersion] = frameVersion
	buf[offFrameFlags] = f.Flags
	binary.BigEndian.PutUint16(buf[offFrameHeaderLen:], uint16(fixedFrameHeaderLen))
	binary.BigEndian.PutUint32(buf[offFramePayLen:], uint32(len(f.Payload)))
	binary.BigEndian.PutUint64(buf[offFrameSequence:], uint64(f.Sequence))
	sum := sha256.Sum256(f.Payload)
	copy(buf[offFrameSHA:headerPrefixLen], sum[:])
	headerCRC := crc32.Checksum(buf[:headerPrefixLen], castagnoli)
	binary.BigEndian.PutUint32(buf[offFrameHeaderCRC:fixedFrameHeaderLen], headerCRC)
	copy(buf[fixedFrameHeaderLen:], f.Payload)
	crc := crc32.Checksum(buf[:fixedFrameHeaderLen+len(f.Payload)], castagnoli)
	binary.BigEndian.PutUint32(buf[total-frameCRCLen:], crc)
	return buf, nil
}

// EncodeObservationFrame serializes a sealed observation into a frame: its payload is
// wire.CanonicalBytes(obs) and its sequence is the observation's own stamped sequence, so
// the frame header and the payload can never disagree on identity. It is the production
// bridge from evidence.Seal (which stamps sequence + observation_id) to the WAL.
func EncodeObservationFrame(obs wire.Observation) ([]byte, error) {
	payload, err := wire.CanonicalBytes(obs)
	if err != nil {
		return nil, fmt.Errorf("observer spool: canonical bytes for frame: %w", err)
	}
	seq, err := observationSequence(obs)
	if err != nil {
		return nil, err
	}
	return EncodeFrame(Frame{Sequence: seq, Payload: payload})
}

// observationSequence extracts the one-based source sequence from a sealed observation
// without depending on the union's unexported shape: it marshals the union and reads the
// envelope's sequence field.
func observationSequence(obs wire.Observation) (int64, error) {
	raw, err := obs.MarshalJSON()
	if err != nil {
		return 0, fmt.Errorf("observer spool: marshal observation for sequence: %w", err)
	}
	var env struct {
		Sequence json.Number `json:"sequence"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		return 0, fmt.Errorf("observer spool: read observation sequence: %w", err)
	}
	seq, err := env.Sequence.Int64()
	if err != nil {
		return 0, fmt.Errorf("observer spool: observation sequence %q is not an int64: %w", env.Sequence.String(), err)
	}
	if seq < wire.SequenceMin || seq > wire.SequenceMax {
		return 0, fmt.Errorf("observer spool: observation sequence %d outside [1, %d]", seq, wire.SequenceMax)
	}
	return seq, nil
}

// DecodeFrame decodes one frame from the front of data. It returns the decoded frame, the
// number of bytes the frame occupies, and a status:
//
//   - FrameOK: a complete, integrity-checked frame; n is its on-disk length.
//   - FrameIncomplete: not enough bytes for a full frame (a partial final write); n is 0.
//   - FrameCorrupt: a present frame failed an integrity check; n is 0.
//
// The torn-vs-corrupt decision is made only after the fixed header's own CRC is verified,
// so payload_length is trusted only once it is proven intact. A short read past a valid
// header is a genuine torn tail (FrameIncomplete); a corrupted header — including an
// inflated payload_length — fails the header CRC and is corruption (FrameCorrupt), never a
// short read. This is the whole basis for "truncate a partial final frame but hard-fail on
// interior corruption": trailing truncation only ever removes bytes from the end, so the
// actively-written frame's header is always intact, while a bit flip in an already-complete
// frame's header fails the header CRC and a flip in its body fails the frame CRC/SHA.
func DecodeFrame(data []byte) (Frame, int, FrameStatus) {
	if len(data) < fixedFrameHeaderLen {
		// The fixed header is not fully present: a torn tail (the header itself was
		// truncated by an interrupted write).
		return Frame{}, 0, FrameIncomplete
	}
	// Validate the fixed-header CRC BEFORE trusting any header field. A corrupted
	// payload_length can never masquerade as a short read once this holds.
	storedHeaderCRC := binary.BigEndian.Uint32(data[offFrameHeaderCRC:fixedFrameHeaderLen])
	if crc32.Checksum(data[:headerPrefixLen], castagnoli) != storedHeaderCRC {
		return Frame{}, 0, FrameCorrupt
	}
	if binary.BigEndian.Uint32(data[offFrameMagic:]) != FrameMagic {
		return Frame{}, 0, FrameCorrupt
	}
	if data[offFrameVersion] != frameVersion {
		return Frame{}, 0, FrameCorrupt
	}
	if int(binary.BigEndian.Uint16(data[offFrameHeaderLen:])) != fixedFrameHeaderLen {
		return Frame{}, 0, FrameCorrupt
	}
	payloadLen := int(binary.BigEndian.Uint32(data[offFramePayLen:]))
	if payloadLen > MaxFramePayload {
		return Frame{}, 0, FrameCorrupt
	}
	seq := int64(binary.BigEndian.Uint64(data[offFrameSequence:]))
	if seq < wire.SequenceMin {
		// A negative (top-bit-set) or zero sequence is out of range; never valid.
		return Frame{}, 0, FrameCorrupt
	}
	need := fixedFrameHeaderLen + payloadLen + frameCRCLen
	if len(data) < need {
		// Header is intact (its CRC verified) but the payload is short: a genuine torn tail.
		return Frame{}, 0, FrameIncomplete
	}
	body := data[:fixedFrameHeaderLen+payloadLen]
	storedCRC := binary.BigEndian.Uint32(data[fixedFrameHeaderLen+payloadLen : need])
	if crc32.Checksum(body, castagnoli) != storedCRC {
		return Frame{}, 0, FrameCorrupt
	}
	payload := make([]byte, payloadLen)
	copy(payload, data[fixedFrameHeaderLen:fixedFrameHeaderLen+payloadLen])
	var sha [32]byte
	copy(sha[:], data[offFrameSHA:headerPrefixLen])
	if sha256.Sum256(payload) != sha {
		return Frame{}, 0, FrameCorrupt
	}
	return Frame{
		Sequence: seq,
		Flags:    data[offFrameFlags],
		Payload:  payload,
		SHA256:   sha,
	}, need, FrameOK
}
