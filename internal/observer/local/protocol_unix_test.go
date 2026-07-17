//go:build linux

package local

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func TestRequestCodecRoundTrip(t *testing.T) {
	t.Parallel()
	req := Request{Kind: KindReserveRun, ReserveRun: &RunReserveRequest{RunID: "run_abc"}}
	data, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	got, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if got.Kind != KindReserveRun || got.ReserveRun == nil || got.ReserveRun.RunID != "run_abc" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestDecodeRequestRejectsUnknownKind(t *testing.T) {
	t.Parallel()
	_, err := DecodeRequest([]byte(`{"kind":"NOPE"}`))
	if !errors.Is(err, ErrUnknownRequestKind) {
		t.Fatalf("want ErrUnknownRequestKind, got %v", err)
	}
}

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	t.Parallel()
	_, err := DecodeRequest([]byte(`{"kind":"STATUS","bogus":1}`))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Fatalf("want ErrMalformedRequest, got %v", err)
	}
}

func TestDecodeRequestRejectsMissingBody(t *testing.T) {
	t.Parallel()
	_, err := DecodeRequest([]byte(`{"kind":"APPEND_OBSERVATION"}`))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Fatalf("want ErrMalformedRequest, got %v", err)
	}
}

func TestMessageFramingRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	payload := []byte(`{"kind":"STATUS"}`)
	if err := writeMessage(&buf, payload, DefaultMaxMessageBytes); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
	got, err := readMessage(&buf, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}
}

func TestReadMessageRejectsOversizedPrefix(t *testing.T) {
	t.Parallel()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 4096)
	r := bytes.NewReader(hdr[:])
	_, err := readMessage(r, 1024)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestWriteMessageRejectsOversizedPayload(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := writeMessage(&buf, make([]byte, 2048), 1024)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing should be written on rejection, wrote %d bytes", buf.Len())
	}
}

func TestReadMessageRejectsEmpty(t *testing.T) {
	t.Parallel()
	var hdr [4]byte // length 0
	_, err := readMessage(bytes.NewReader(hdr[:]), DefaultMaxMessageBytes)
	if !errors.Is(err, ErrEmptyMessage) {
		t.Fatalf("want ErrEmptyMessage, got %v", err)
	}
}

// TestAppendRequestCarriesTypedObservation proves the append body round-trips a real
// wire.Observation union through the codec without an untyped map.
func TestAppendRequestCarriesTypedObservation(t *testing.T) {
	t.Parallel()
	obs := sealMessage(t, 1, "obs_pending")
	req := Request{Kind: KindAppendObservation, Append: &AppendObservationRequest{Observation: obs}}
	data, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	got, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	wantBytes, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	gotBytes, err := wire.CanonicalBytes(got.Append.Observation)
	if err != nil {
		t.Fatalf("CanonicalBytes(decoded): %v", err)
	}
	if !bytes.Equal(wantBytes, gotBytes) {
		t.Fatalf("observation did not survive the codec")
	}
}
