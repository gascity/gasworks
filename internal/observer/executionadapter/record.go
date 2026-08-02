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
	"time"
)

const (
	RecordSchema        = "execution-event-envelope"
	RecordSchemaVersion = 2
)

var ErrInvalidRecord = errors.New("execution-event adapter: invalid producer record")

// Event mirrors the frozen eventexport envelope. The adapter retains all producer-approved fields
// but never adds content or derives a formula.
type Event struct {
	Seq       uint64 `json:"seq"`
	Type      string `json:"type"`
	TS        string `json:"ts"`
	ActorHash string `json:"actor_hash,omitempty"`
	Ref       string `json:"ref,omitempty"`
	RunID     string `json:"run_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`
	Title     string `json:"title,omitempty"`
	Formula   string `json:"formula,omitempty"`
}
type Record struct {
	PartitionID string
	ProducerSeq uint64
	Event       Event
	Payload     []byte
	PayloadHash [sha256.Size]byte
}
type Batch struct {
	PartitionID string
	Records     []Record
}
type producerBatch struct {
	CityHash      string  `json:"city_hash"`
	SchemaVersion int     `json:"schema_version"`
	Events        []Event `json:"events"`
}
type rawRecord struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	PartitionID   string `json:"partition_id"`
	ProducerSeq   uint64 `json:"producer_seq"`
	Event         Event  `json:"event"`
}

// DecodeBatch strictly validates one frozen eventexport batch before unwrapping it. It uses city_hash
// as the opaque source partition and deterministically emits v2 artifact records with sparse event
// sequence values preserved as producer_seq.
func DecodeBatch(payload []byte) (Batch, error) {
	var input producerBatch
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return Batch{}, fmt.Errorf("%w: decode batch: %v", ErrInvalidRecord, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Batch{}, fmt.Errorf("%w: trailing batch JSON", ErrInvalidRecord)
	}
	if input.SchemaVersion != RecordSchemaVersion || !isLowerHex16(input.CityHash) {
		return Batch{}, fmt.Errorf("%w: batch schema or city_hash", ErrInvalidRecord)
	}
	out := Batch{PartitionID: input.CityHash}
	for i, event := range input.Events {
		if err := validateEvent(event); err != nil {
			return Batch{}, fmt.Errorf("batch event %d: %w", i, err)
		}
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
func validateEvent(e Event) error {
	if e.Seq == 0 || !allowedEventType(e.Type) {
		return fmt.Errorf("%w: event sequence or type", ErrInvalidRecord)
	}
	if _, err := time.Parse(time.RFC3339, e.TS); err != nil {
		return fmt.Errorf("%w: event timestamp", ErrInvalidRecord)
	}
	if !opaqueID(e.Ref) || !opaqueID(e.RunID) || !opaqueID(e.SessionID) || !opaqueID(e.StepID) {
		return fmt.Errorf("%w: event opaque id", ErrInvalidRecord)
	}
	if e.ActorHash != "" && !isLowerHex16(e.ActorHash) {
		return fmt.Errorf("%w: actor hash", ErrInvalidRecord)
	}
	if len(e.Title) > 256 || len(e.Formula) > 256 {
		return fmt.Errorf("%w: content length", ErrInvalidRecord)
	}
	return nil
}
func isLowerHex16(v string) bool {
	if len(v) != 16 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
func opaqueID(v string) bool {
	if v == "" {
		return true
	}
	if len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return (v[0] >= 'a' && v[0] <= 'z') || (v[0] >= '0' && v[0] <= '9')
}
func allowedEventType(v string) bool {
	switch v {
	case "bead.created", "bead.closed", "order.fired", "order.completed", "order.failed", "session.woke", "session.stopped", "session.draining", "session.stranded", "convoy.closed", "controller.started", "events.rotated", "session.drain_acked_with_assigned_work", "session.reset_stalled", "project.identity.stamped", "gc.store.maintenance.done", "mail.sent":
		return true
	}
	return false
}
