package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalEncodingVersion is the version tag of the canonical-JSON algorithm below.
// It matches the platform's version-1 canonical form byte-for-byte: the endpoint WAL
// frame payload and the ingest dedup hash are computed over CanonicalBytes output, so
// endpoint and server must agree on every byte. Bump this only on a breaking change
// to the canonicalization rules, and re-pin the vendored golden hashes when you do.
const CanonicalEncodingVersion = 1

// CanonicalBytes returns the deterministic version-1 canonical JSON encoding of a
// generated wire value. This is the exact byte form the endpoint WAL frame's payload
// SHA-256 and the ingest deduplication hash are computed over, and it is byte-identical
// to the platform's apigen.CanonicalBytes for the same logical value (the cross-repo
// contract the vendored canonical golden hashes pin).
//
// The canonical form is defined so that two semantically-equal payloads always
// produce identical bytes:
//   - the value is first marshaled through the generated types, so absent optional
//     fields are dropped and timestamps are normalized to RFC 3339 (this typed
//     round-trip is what makes ".000Z" and "Z" hash alike — a raw byte-preserving
//     canonicalizer would diverge here);
//   - object members are emitted in ascending UTF-8 byte order of their names,
//     recursively (Go map/struct field order never leaks in);
//   - no insignificant whitespace;
//   - numbers are preserved verbatim from the typed marshal — integers stay integers
//     (json.Number keeps int64 precision to math.MaxInt64; nothing is coerced to
//     float64, which cannot represent the sequence/token ceiling exactly);
//   - strings are escaped by encoding/json with HTML-safe escaping disabled.
//
// Precondition: v MUST be the result of a strict decode (DecodeObservationBatch for
// ingest; a DisallowUnknownFields decode for the response schemas). CanonicalBytes
// only serializes what the generated type models — plain json.Unmarshal would silently
// drop members absent from the type and synthesize zero values for absent required
// members, so two distinct wire payloads could hash alike. Strict decoding upstream is
// what makes the closed schema hold. Passing a value that fails to marshal returns the
// marshal error.
func CanonicalBytes(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("observer wire: marshal for canonical encode: %w", err)
	}
	return canonicalizeJSON(raw)
}

// CanonicalHash returns the lowercase-hex SHA-256 of CanonicalBytes(v). This is the
// value pinned by the vendored fixture golden hashes and, at runtime, the WAL payload
// hash.
func CanonicalHash(v any) (string, error) {
	b, err := CanonicalBytes(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalizeJSON re-emits already-valid JSON bytes in canonical form: recursively
// key-sorted objects, compact separators, verbatim numbers. It parses with UseNumber
// so no integer loses precision on the round trip.
func canonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("observer wire: parse for canonical encode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical emits one JSON value in canonical form.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(x.String())
	case string:
		return writeCanonicalString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("observer wire: unexpected JSON value %T in canonical encode", v)
	}
	return nil
}

// writeCanonicalString emits a JSON string with encoding/json escaping and without the
// HTML-safe angle-bracket/ampersand escaping, so the bytes are stable and minimal.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("observer wire: encode string in canonical form: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; trim it.
	buf.Truncate(buf.Len() - 1)
	return nil
}
