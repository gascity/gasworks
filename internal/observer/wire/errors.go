package wire

import (
	"errors"
	"fmt"
)

// Typed decode errors for the Observer wire contract, mirrored from the platform so
// endpoint and server reject the same wire shapes with the same failure classes.
//
// The strict decoder rejects bad input with these sentinels so a caller (the WAL
// append path, later the Collector) can branch on the failure class via errors.Is,
// before any storage-layer use, rather than string matching. DecodeError covers
// wire-shape rejection.
//
// The demoted semantic couplings the OpenAPI 3.0 schema cannot carry (contiguity,
// drain-pair, ESTIMATED price table, reference/batch caps) are NOT enforced here.
// Their server-side validators (platform apigen.ValidateBatch, the S2.4 track) and the
// endpoint-side evidence/policy validation are E1.1 scope; this package intentionally
// stops at wire-shape strictness. See gen.go for the scope pointer.

// Decode-failure classes. A *DecodeError wraps exactly one of these.
var (
	// ErrMalformedJSON is returned when a payload is not the JSON shape its schema
	// requires (bad syntax, wrong types, trailing data).
	ErrMalformedJSON = errors.New("observer wire: malformed JSON")
	// ErrUnknownField is returned when a payload carries a property absent from its
	// closed schema (additionalProperties:false is enforced by the generated decoders).
	ErrUnknownField = errors.New("observer wire: unknown field")
	// ErrUnknownDiscriminator is returned when a discriminated union carries a
	// discriminator value outside the closed v1 set (kind, transition, ref_kind).
	ErrUnknownDiscriminator = errors.New("observer wire: unknown discriminator")
	// ErrSequenceOutOfRange is returned when a source sequence is below 1 or above
	// the wire ceiling math.MaxInt64 (the PostgreSQL BIGINT / x-limits sequence_max).
	ErrSequenceOutOfRange = errors.New("observer wire: sequence out of range")
	// ErrSchemaVersionUnsupported is returned when schema_version is not the single
	// supported v1 value (1).
	ErrSchemaVersionUnsupported = errors.New("observer wire: unsupported schema_version")
	// ErrEnumOutOfRange is returned when a closed enum field carries a value outside
	// its generated membership set (checked via the generated Valid() methods). The
	// JSON-Schema enum constraint does not run at ingest time, so the decoder enforces
	// it before the value reaches the store.
	ErrEnumOutOfRange = errors.New("observer wire: enum value out of range")
	// ErrMissingPayload is returned when the discriminated payload member for an
	// observation's kind is absent or JSON null (e.g. kind USAGE with usage:null),
	// which would otherwise decode into a zero-valued payload.
	ErrMissingPayload = errors.New("observer wire: missing or null payload member")
)

// DecodeError is a typed wire-decode failure. Class is one of the Err* sentinels
// above; errors.Is(err, ErrUnknownField) and friends match through it.
type DecodeError struct {
	// Class is the failure sentinel (one of the Err* values).
	Class error
	// Field is the offending property path when known (e.g. "observations[3].sequence").
	Field string
	// Detail is a human-readable diagnostic.
	Detail string
	// wrapped is the underlying error (e.g. the encoding/json error), if any.
	wrapped error
}

// Error renders the decode failure with its class and location.
func (e *DecodeError) Error() string {
	loc := ""
	if e.Field != "" {
		loc = " at " + e.Field
	}
	if e.Detail != "" {
		return fmt.Sprintf("%s%s: %s", e.Class, loc, e.Detail)
	}
	return fmt.Sprintf("%s%s", e.Class, loc)
}

// Is reports whether the error matches the target class sentinel.
func (e *DecodeError) Is(target error) bool { return errors.Is(e.Class, target) }

// Unwrap exposes the underlying encoding/json error for callers that want it.
func (e *DecodeError) Unwrap() error { return e.wrapped }

func decodeErr(class error, field, detail string, wrapped error) *DecodeError {
	return &DecodeError{Class: class, Field: field, Detail: detail, wrapped: wrapped}
}
