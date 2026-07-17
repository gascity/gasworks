package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// sealedMessage builds and seals one real MESSAGE observation so frame tests exercise the
// exact evidence.Seal -> wire.CanonicalBytes edge the WAL frame carries.
func sealedMessage(t *testing.T, seq int64, id string) wire.Observation {
	t.Helper()
	occ := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
	c := evidence.Common{
		OccurredAt: occ,
		CapturedAt: occ.Add(50 * time.Millisecond),
		Provenance: wire.Provenance{
			Adapter:        "codex-hook",
			AdapterVersion: "1.0.0",
			ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		},
	}
	p, err := evidence.NewMessage(c, evidence.MessageInput{Role: wire.MessagePayloadRoleUSER})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	o, err := p.Seal(seq, id)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return o
}

func TestEncodeDecodeFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"a":1,"b":"two"}`)
	enc, err := EncodeFrame(Frame{Sequence: 7, Flags: 0, Payload: payload})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	got, n, status := DecodeFrame(enc)
	if status != FrameOK {
		t.Fatalf("status = %v, want FrameOK", status)
	}
	if n != len(enc) {
		t.Fatalf("consumed %d, want %d", n, len(enc))
	}
	if got.Sequence != 7 {
		t.Fatalf("sequence = %d, want 7", got.Sequence)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, payload)
	}
	want := sha256.Sum256(payload)
	if got.SHA256 != want {
		t.Fatalf("sha mismatch")
	}
}

// TestFrameCarriesCanonicalPayloadHash proves the frame's payload is exactly
// wire.CanonicalBytes(obs) and the stored SHA-256 equals wire.CanonicalHash(obs).
func TestFrameCarriesCanonicalPayloadHash(t *testing.T) {
	obs := sealedMessage(t, 3, "obs_msg_3")
	enc, err := EncodeObservationFrame(obs)
	if err != nil {
		t.Fatalf("EncodeObservationFrame: %v", err)
	}
	got, _, status := DecodeFrame(enc)
	if status != FrameOK {
		t.Fatalf("status = %v, want FrameOK", status)
	}
	canon, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if !bytes.Equal(got.Payload, canon) {
		t.Fatalf("frame payload is not the canonical bytes")
	}
	hexHash, err := wire.CanonicalHash(obs)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	sum := sha256.Sum256(canon)
	if hexHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("precondition: canonical hash helper disagrees")
	}
	if got.SHA256 != sum {
		t.Fatalf("frame SHA-256 does not match canonical payload hash")
	}
	if got.Sequence != 3 {
		t.Fatalf("frame sequence = %d, want 3 (from sealed observation)", got.Sequence)
	}
}

func TestDecodeFrameTornTail(t *testing.T) {
	enc, err := EncodeFrame(Frame{Sequence: 1, Payload: []byte("hello-payload")})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	// Every strict prefix of a frame is a torn tail: not enough bytes for a full frame.
	for k := 1; k < len(enc); k++ {
		_, _, status := DecodeFrame(enc[:k])
		if status != FrameIncomplete {
			t.Fatalf("prefix len %d: status = %v, want FrameIncomplete", k, status)
		}
	}
}

func TestDecodeFrameCRCMismatchIsCorrupt(t *testing.T) {
	enc, err := EncodeFrame(Frame{Sequence: 9, Payload: []byte("integrity")})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	// Flip a payload byte: SHA and CRC both detect it, and the frame is fully present.
	corrupt := append([]byte(nil), enc...)
	corrupt[fixedFrameHeaderLen+2] ^= 0xFF
	if _, _, status := DecodeFrame(corrupt); status != FrameCorrupt {
		t.Fatalf("payload flip: status = %v, want FrameCorrupt", status)
	}
	// Flip the trailing CRC only (payload intact so SHA passes, CRC must catch it).
	crcOnly := append([]byte(nil), enc...)
	crcOnly[len(crcOnly)-1] ^= 0xFF
	if _, _, status := DecodeFrame(crcOnly); status != FrameCorrupt {
		t.Fatalf("crc flip: status = %v, want FrameCorrupt", status)
	}
}

func TestDecodeFrameBadMagicIsCorrupt(t *testing.T) {
	enc, err := EncodeFrame(Frame{Sequence: 2, Payload: []byte("x")})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	corrupt := append([]byte(nil), enc...)
	corrupt[0] ^= 0xFF
	if _, _, status := DecodeFrame(corrupt); status != FrameCorrupt {
		t.Fatalf("bad magic: status = %v, want FrameCorrupt", status)
	}
}

func TestDecodeFrameCorruptLengthIsCorruptNotTorn(t *testing.T) {
	// A corrupted payload_length beyond the published max must be classified corrupt, not
	// torn (a corrupt length must never masquerade as a recoverable partial tail).
	enc, err := EncodeFrame(Frame{Sequence: 4, Payload: []byte("len")})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	corrupt := append([]byte(nil), enc...)
	binary.BigEndian.PutUint32(corrupt[8:12], uint32(MaxFramePayload)+1)
	if _, _, status := DecodeFrame(corrupt); status != FrameCorrupt {
		t.Fatalf("oversized length: status = %v, want FrameCorrupt", status)
	}
}

func TestEncodeFrameOversizedRecord(t *testing.T) {
	big := make([]byte, MaxFramePayload+1)
	_, err := EncodeFrame(Frame{Sequence: 1, Payload: big})
	if err == nil {
		t.Fatalf("want oversize error")
	}
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("err = %v, want ErrRecordTooLarge", err)
	}
	var rerr *RecordTooLargeError
	if !errors.As(err, &rerr) {
		t.Fatalf("err = %v, want *RecordTooLargeError", err)
	}
	if rerr.Size != MaxFramePayload+1 || rerr.Max != MaxFramePayload {
		t.Fatalf("rerr = %+v", rerr)
	}
}

func TestFrameHeaderLayout(t *testing.T) {
	// Literal offsets/lengths (not the package constants) so a silent layout change is
	// caught. The v2 header is 56 bytes: magic(4) version(1) flags(1) header_length(2)
	// payload_length(4) sequence(8) sha256(32) header_crc32c(4), then payload, then frame
	// crc32c(4).
	payload := []byte("layout")
	enc, err := EncodeFrame(Frame{Sequence: 0x0102030405060708, Flags: 0xA5, Payload: payload})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	crcTable := crc32.MakeTable(crc32.Castagnoli)
	if got := binary.BigEndian.Uint32(enc[0:4]); got != FrameMagic {
		t.Fatalf("magic = %08x, want %08x", got, FrameMagic)
	}
	if enc[4] != 2 {
		t.Fatalf("frame version = %d, want 2", enc[4])
	}
	if enc[5] != 0xA5 {
		t.Fatalf("flags byte = %02x, want a5", enc[5])
	}
	if got := binary.BigEndian.Uint16(enc[6:8]); got != 56 {
		t.Fatalf("header_length = %d, want 56", got)
	}
	if got := binary.BigEndian.Uint32(enc[8:12]); int(got) != len(payload) {
		t.Fatalf("payload_length = %d, want %d", got, len(payload))
	}
	if got := int64(binary.BigEndian.Uint64(enc[12:20])); got != 0x0102030405060708 {
		t.Fatalf("sequence = %x", got)
	}
	// SHA-256 of the payload occupies bytes [20:52], independently computed.
	wantSHA := sha256.Sum256(payload)
	if got := enc[20:52]; !bytes.Equal(got, wantSHA[:]) {
		t.Fatalf("sha field mismatch")
	}
	// Header CRC over the fixed 52-byte prefix, big-endian at [52:56].
	wantHeaderCRC := crc32.Checksum(enc[:52], crcTable)
	if got := binary.BigEndian.Uint32(enc[52:56]); got != wantHeaderCRC {
		t.Fatalf("header crc = %08x, want %08x", got, wantHeaderCRC)
	}
	// Frame CRC over header(56)+payload, big-endian at the tail.
	body := enc[:56+len(payload)]
	wantCRC := crc32.Checksum(body, crcTable)
	if got := binary.BigEndian.Uint32(enc[len(enc)-4:]); got != wantCRC {
		t.Fatalf("frame crc = %08x, want %08x", got, wantCRC)
	}
	if len(enc) != 56+len(payload)+4 {
		t.Fatalf("frame length = %d, want %d", len(enc), 56+len(payload)+4)
	}
}

// TestDecodeFrameSubMaxLengthInflationShortIsCorrupt is the core regression for the closed
// BLOCKER: inflating a complete frame's payload_length so that the declared length exceeds
// the bytes present (need > remaining) while staying <= MaxFramePayload must be classified
// interior corruption via the header CRC, NOT a torn tail. Before the header CRC this
// returned FrameIncomplete and drove a destructive recovery truncation.
func TestDecodeFrameSubMaxLengthInflationShortIsCorrupt(t *testing.T) {
	enc, err := EncodeFrame(Frame{Sequence: 5, Payload: []byte("thirteen-byte")}) // 13-byte payload
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	// Inflate payload_length far past what is present but well under MaxFramePayload; the
	// header CRC (over payload_length) must reject it before need is derived.
	corrupt := append([]byte(nil), enc...)
	binary.BigEndian.PutUint32(corrupt[8:12], 1<<20) // 1 MiB, <= MaxFramePayload
	if _, _, status := DecodeFrame(corrupt); status != FrameCorrupt {
		t.Fatalf("sub-max inflation (short) status = %v, want FrameCorrupt (not torn)", status)
	}
}

// TestDecodeFrameSubMaxLengthInflationFullyPresentIsCorrupt covers the fully-present arm:
// even when enough bytes exist for the inflated length, the header CRC catches it.
func TestDecodeFrameSubMaxLengthInflationFullyPresentIsCorrupt(t *testing.T) {
	enc, err := EncodeFrame(Frame{Sequence: 5, Payload: []byte("thirteen-byte")})
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	newLen := 1024
	corrupt := append([]byte(nil), enc...)
	binary.BigEndian.PutUint32(corrupt[8:12], uint32(newLen))
	// Pad so len(data) >= need = 56 + newLen + 4, making the frame "fully present".
	corrupt = append(corrupt, make([]byte, 56+newLen+4)...)
	if _, _, status := DecodeFrame(corrupt); status != FrameCorrupt {
		t.Fatalf("sub-max inflation (fully present) status = %v, want FrameCorrupt", status)
	}
}

func TestEncodeFrameRejectsOutOfRangeSequence(t *testing.T) {
	for _, seq := range []int64{0, -1, wire.SequenceMin - 1, -9223372036854775808} {
		_, err := EncodeFrame(Frame{Sequence: seq, Payload: []byte("x")})
		if !errors.Is(err, ErrSequenceOutOfRange) {
			t.Fatalf("seq %d: err = %v, want ErrSequenceOutOfRange", seq, err)
		}
	}
	// The inclusive bounds are accepted.
	if _, err := EncodeFrame(Frame{Sequence: wire.SequenceMin, Payload: []byte("x")}); err != nil {
		t.Fatalf("SequenceMin should encode: %v", err)
	}
	if _, err := EncodeFrame(Frame{Sequence: wire.SequenceMax, Payload: []byte("x")}); err != nil {
		t.Fatalf("SequenceMax should encode: %v", err)
	}
}
