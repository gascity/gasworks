// Package executionadapter adapts validated producer execution-event records to
// the Observer raw-artifact stream. It owns no activation policy; callers must
// explicitly configure and bootstrap an Adapter before it can publish.
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
	// RecordSchema is the closed producer record schema accepted by this adapter.
	RecordSchema = "execution-event-envelope"
	// RecordSchemaVersion is the only producer schema version accepted by this adapter.
	RecordSchemaVersion = 2
)

// ErrInvalidRecord marks an untrusted producer record or batch that failed strict validation.
var ErrInvalidRecord = errors.New("execution-event adapter: invalid producer record")

// Event is the execution-event envelope retained inside the versioned producer record.
// Formula is deliberately optional; this adapter does not create or infer it.
type Event struct {
	Seq       uint64 `json:"seq"`
	Type      string `json:"type"`
	TS        string `json:"ts"`
	RunID     string `json:"run_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`
	Formula   string `json:"formula,omitempty"`
}

// Record is one strict v2 producer record. Payload holds the original record bytes exactly as
// supplied, rather than a re-marshaled representation, so retry comparisons are byte-for-byte.
type Record struct {
	PartitionID string
	ProducerSeq uint64
	Event       Event
	Payload     []byte
	PayloadHash [sha256.Size]byte
}

// Batch is a fully validated same-partition, increasing-producer-sequence batch.
type Batch struct {
	PartitionID string
	Records     []Record
}

type rawRecord struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	PartitionID   string `json:"partition_id"`
	ProducerSeq   uint64 `json:"producer_seq"`
	Event         Event  `json:"event"`
}

// DecodeBatch strictly validates every supplied record before returning any mapped record. Sparse
// producer sequences are intentional and preserved; only duplicate or descending sequences within
// one batch are invalid.
func DecodeBatch(payloads [][]byte) (Batch, error) {
	batch := Batch{}
	for i, payload := range payloads {
		record, err := decodeRecord(payload)
		if err != nil {
			return Batch{}, fmt.Errorf("batch record %d: %w", i, err)
		}
		if i == 0 {
			batch.PartitionID = record.PartitionID
		} else {
			if record.PartitionID != batch.PartitionID {
				return Batch{}, fmt.Errorf("batch record %d: %w: partition differs within batch", i, ErrInvalidRecord)
			}
			if record.ProducerSeq <= batch.Records[len(batch.Records)-1].ProducerSeq {
				return Batch{}, fmt.Errorf("batch record %d: %w: producer sequences must increase", i, ErrInvalidRecord)
			}
		}
		batch.Records = append(batch.Records, record)
	}
	return batch, nil
}

func decodeRecord(payload []byte) (Record, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return Record{}, fmt.Errorf("%w: empty payload", ErrInvalidRecord)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var raw rawRecord
	if err := decoder.Decode(&raw); err != nil {
		return Record{}, fmt.Errorf("%w: decode: %v", ErrInvalidRecord, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Record{}, fmt.Errorf("%w: trailing JSON", ErrInvalidRecord)
	}
	if raw.Schema != RecordSchema {
		return Record{}, fmt.Errorf("%w: schema %q", ErrInvalidRecord, raw.Schema)
	}
	if raw.SchemaVersion != RecordSchemaVersion {
		return Record{}, fmt.Errorf("%w: schema_version %d", ErrInvalidRecord, raw.SchemaVersion)
	}
	if !isLowerHex16(raw.PartitionID) {
		return Record{}, fmt.Errorf("%w: partition_id", ErrInvalidRecord)
	}
	if raw.ProducerSeq == 0 || raw.Event.Seq != raw.ProducerSeq {
		return Record{}, fmt.Errorf("%w: producer_seq must equal event.seq and be positive", ErrInvalidRecord)
	}
	if !allowedEventType(raw.Event.Type) {
		return Record{}, fmt.Errorf("%w: event type", ErrInvalidRecord)
	}
	if _, err := time.Parse(time.RFC3339, raw.Event.TS); err != nil {
		return Record{}, fmt.Errorf("%w: event timestamp", ErrInvalidRecord)
	}
	if !opaqueID(raw.Event.RunID) || !opaqueID(raw.Event.SessionID) || !opaqueID(raw.Event.StepID) {
		return Record{}, fmt.Errorf("%w: event correlation id", ErrInvalidRecord)
	}
	if len(raw.Event.Formula) > 256 {
		return Record{}, fmt.Errorf("%w: formula too long", ErrInvalidRecord)
	}
	copyPayload := append([]byte(nil), payload...)
	return Record{
		PartitionID: raw.PartitionID,
		ProducerSeq: raw.ProducerSeq,
		Event:       raw.Event,
		Payload:     copyPayload,
		PayloadHash: sha256.Sum256(copyPayload),
	}, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}

func isLowerHex16(value string) bool {
	if len(value) != 16 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func opaqueID(value string) bool {
	if value == "" || len(value) > 64 {
		return value == ""
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9'
}

func allowedEventType(value string) bool {
	switch value {
	case "bead.created", "bead.closed", "order.fired", "order.completed", "order.failed",
		"session.woke", "session.stopped", "session.draining", "session.stranded",
		"convoy.closed", "controller.started", "events.rotated",
		"session.drain_acked_with_assigned_work", "session.reset_stalled",
		"project.identity.stamped", "gc.store.maintenance.done", "mail.sent":
		return true
	default:
		return false
	}
}
