// Package executionadapter adapts the frozen eventexport producer batch to the
// Observer raw-artifact stream. It is default-off until explicitly configured.
package executionadapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gastownhall/gascity/pkg/eventexport"
)

const (
	RecordSchema        = "execution-event-envelope"
	RecordSchemaVersion = eventexport.SchemaVersion
)

var ErrInvalidRecord = errors.New("execution-event adapter: invalid producer record")

type Record struct {
	PartitionID string
	ProducerSeq uint64
	Event       eventexport.Envelope
	Payload     []byte
	PayloadHash [sha256.Size]byte
}
type Batch struct {
	PartitionID string
	Records     []Record
}
type rawRecord struct {
	Schema        string               `json:"schema"`
	SchemaVersion int                  `json:"schema_version"`
	PartitionID   string               `json:"partition_id"`
	ProducerSeq   uint64               `json:"producer_seq"`
	Event         eventexport.Envelope `json:"event"`
}

// DecodeBatch strictly validates one frozen eventexport batch before unwrapping it. It uses city_hash
// as the opaque source partition and deterministically emits v2 artifact records with sparse event
// sequence values preserved as producer_seq.
func DecodeBatch(payload []byte) (Batch, error) {
	var input eventexport.Batch
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return Batch{}, fmt.Errorf("%w: decode batch: %v", ErrInvalidRecord, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Batch{}, fmt.Errorf("%w: trailing batch JSON", ErrInvalidRecord)
	}
	if err := eventexport.ValidateBatch(input); err != nil {
		return Batch{}, fmt.Errorf("%w: validate producer batch: %w", ErrInvalidRecord, err)
	}
	out := Batch{PartitionID: input.CityHash}
	for i, event := range input.Events {
		if i > 0 && event.Seq <= input.Events[i-1].Seq {
			return Batch{}, fmt.Errorf("batch event %d: %w: sequences must increase", i, ErrInvalidRecord)
		}
		body, err := json.Marshal(rawRecord{Schema: RecordSchema, SchemaVersion: RecordSchemaVersion, PartitionID: input.CityHash, ProducerSeq: event.Seq, Event: event})
		if err != nil {
			return Batch{}, fmt.Errorf("encode v2 record: %w", err)
		}
		out.Records = append(out.Records, Record{PartitionID: input.CityHash, ProducerSeq: event.Seq, Event: event, Payload: body, PayloadHash: sha256.Sum256(body)})
	}
	return out, nil
}
func ensureEOF(d *json.Decoder) error {
	var extra any
	err := d.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON")
	}
	return err
}
