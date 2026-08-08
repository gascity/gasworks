// Package upload (E1.9) forms one bounded contiguous batch from the durable spool,
// delivers it to the authenticated Collector over mandatory HTTPS, and advances the
// local acknowledgement only on a valid capped-contiguous server ack.
//
// The three files split the concern cleanly:
//
//   - batch.go  — batch FORMATION: read the next unacknowledged contiguous range of
//     durable frames (clamped to the delivery defaults and the server-advertised caps),
//     encode it to the canonical wire body, and record the single in-flight range so it
//     replays byte-for-byte until acknowledged.
//   - client.go — the authenticated HTTPS TRANSPORT: HTTPS floor, redirect refusal,
//     additive customer CA, per-attempt credential read (rotating file or fixed-argv
//     helper), corporate egress-proxy support, and typed response decode.
//   - retry.go  — the delivery LOOP: bounded timeouts, retry/hold classification
//     (429/5xx/transport retry; 401/403/schema/conflict/corrupt-ack hold), and the
//     single advancement point through spool.AckState.
//
// The package owns no persistence policy of its own: the one-bounded-in-flight-range
// contract, the ack-beyond-sent rejection, and the never-reset-on-corruption rules all
// live in spool.AckState (E1.3). batch.go drives that surface; it never re-implements it.
package upload

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Delivery defaults from the plan ("delivery defaults: 1s flush, <=1000 obs, <=4 MiB
// uncompressed JSON per batch, clamped to server capabilities"). These are the local
// ceilings; the effective ceiling is always the minimum of these and the server's
// advertised capabilities.
const (
	// DefaultMaxObservations bounds a single batch to at most 1,000 observations.
	DefaultMaxObservations = 1000
	// DefaultMaxBatchBytes bounds a single batch body to at most 4 MiB of uncompressed
	// JSON, matching the WAL's per-frame ceiling so a maximal single record always fits
	// in a batch of one.
	DefaultMaxBatchBytes int64 = 4 << 20
)

// walSubdir is the on-disk WAL directory name inside a spool directory (the layout the
// spool package documents as wal/<first>.seg). batch.go reads it through the spool's
// exported OpenSegment/ReadAll surface; it never re-implements segment framing.
const walSubdir = "wal"

// Caps is the effective per-batch ceiling: the minimum of the local delivery defaults
// and the server-advertised capabilities. Zero-valued fields select the local default,
// so an uninitialised Caps clamps to the defaults alone.
type Caps struct {
	// MaxObservations is the most observations one batch may carry.
	MaxObservations int
	// MaxBatchBytes is the most encoded JSON bytes one batch body may carry.
	MaxBatchBytes int64
}

// CapsFromCapabilities clamps the local delivery defaults against a probed
// CapabilitiesResponse. The effective ceiling is min(local, server) on each axis, so the
// endpoint never sends a batch the server has said it will reject with 413. A server that
// advertises a larger ceiling than the local default does not raise the local default.
func CapsFromCapabilities(c wire.CapabilitiesResponse) Caps {
	caps := Caps{MaxObservations: DefaultMaxObservations, MaxBatchBytes: DefaultMaxBatchBytes}
	if v := int(c.MaxObservationsPerBatch); v > 0 && v < caps.MaxObservations {
		caps.MaxObservations = v
	}
	if v := c.MaxBatchBytes; v > 0 && v < caps.MaxBatchBytes {
		caps.MaxBatchBytes = v
	}
	return caps
}

// resolve fills zero fields with the local defaults so callers can pass a partial Caps.
func (c Caps) resolve() Caps {
	if c.MaxObservations <= 0 {
		c.MaxObservations = DefaultMaxObservations
	}
	if c.MaxBatchBytes <= 0 {
		c.MaxBatchBytes = DefaultMaxBatchBytes
	}
	return c
}

// Record is one durable observation drawn from the spool: its one-based source sequence
// and the canonical typed-JSON payload the WAL made durable (wire.CanonicalBytes of the
// sealed observation). The payload is used verbatim as one element of the batch body, so
// replay is byte-for-byte identical.
type Record struct {
	Sequence int64
	Payload  []byte
}

// FrameStore reads a contiguous range of durable frames from the spool. It is the single
// seam batch formation needs from the durability layer; the daemon (E1.10) wires the
// concrete SpoolFrameStore, and tests substitute an in-memory double.
type FrameStore interface {
	// ReadRange returns the records for sequences in [first, last] inclusive, in ascending
	// sequence order, each carrying its durable canonical payload. It returns only frames
	// that are actually durable; a caller must not ask for a range beyond the highest
	// durable sequence.
	ReadRange(first, last int64) ([]Record, error)
}

// Plan is one formed batch: the inclusive source-sequence range it covers and the exact
// canonical JSON body to POST. The same range always encodes to the same bytes, which is
// what makes the single in-flight batch replay byte-for-byte until acknowledged.
type Plan struct {
	Range wire.SequenceRange
	Body  []byte
}

// Planner forms the next batch from the spool over the shared AckState. It holds no
// mutable state of its own; the in-flight range and acknowledgement watermark live in
// Ack (spool.AckState), so a restarted planner resumes exactly where the durable state
// left off.
type Planner struct {
	Store    FrameStore
	Ack      *spool.AckState
	Caps     Caps
	SourceID string
}

// Next returns the batch to deliver now, or ok=false when nothing is owed.
//
//   - If a range is already in flight (spool.AckState.InFlight), Next re-forms exactly
//     that range and returns the identical bytes — the byte-for-byte replay of the single
//     bounded in-flight batch. It does not recompute the clamp, so a mid-run change to the
//     server caps can never repartition an outstanding batch.
//   - Otherwise Next forms the next unacknowledged contiguous range starting at
//     acknowledged_through+1, bounded by the highest durable sequence, the observation
//     count cap, and the byte cap. It always includes at least one record when any is
//     owed, so a single item larger than the byte budget becomes a batch-of-one rather
//     than a permanently unsendable sequence. It records the range as in flight before
//     returning.
func (p *Planner) Next() (Plan, bool, error) {
	if r, ok := p.Ack.InFlight(); ok {
		body, err := p.encodeRange(r)
		if err != nil {
			return Plan{}, false, err
		}
		return Plan{Range: r, Body: body}, true, nil
	}

	caps := p.Caps.resolve()
	first := p.Ack.AcknowledgedThrough() + 1
	highest := p.Ack.HighestDurable()
	if first > highest {
		return Plan{}, false, nil // nothing owed
	}

	// Upper bound by observation count before touching disk.
	tentativeLast := first + int64(caps.MaxObservations) - 1
	if tentativeLast > highest {
		tentativeLast = highest
	}
	records, err := p.Store.ReadRange(first, tentativeLast)
	if err != nil {
		return Plan{}, false, fmt.Errorf("observer upload: read range [%d, %d]: %w", first, tentativeLast, err)
	}
	if len(records) == 0 {
		return Plan{}, false, fmt.Errorf("observer upload: spool reported durable through %d but returned no frame at %d", highest, first)
	}
	if err := verifyContiguous(records, first); err != nil {
		return Plan{}, false, err
	}

	cut := byteBudgetCut(p.SourceID, records, caps.MaxBatchBytes)
	records = records[:cut]
	last := records[len(records)-1].Sequence

	r := wire.SequenceRange{FirstSequence: first, LastSequence: last}
	if err := p.Ack.SetInFlight(r); err != nil {
		return Plan{}, false, fmt.Errorf("observer upload: record in-flight range [%d, %d]: %w", first, last, err)
	}
	body, err := EncodeBatchBody(p.SourceID, r, records)
	if err != nil {
		return Plan{}, false, err
	}
	return Plan{Range: r, Body: body}, true, nil
}

// First returns a one-record prefix of the currently in-flight range. It does not change the
// in-flight range: a successful delivery of the returned plan is still acknowledged through the
// ordinary AckState path, which advances only that record and shrinks the remaining in-flight
// suffix. The daemon uses this only to prove/recover a typed sequence-straddle; it never skips or
// resequences durable frames.
func (p *Planner) First() (Plan, error) {
	r, ok := p.Ack.InFlight()
	if !ok {
		return Plan{}, errors.New("observer upload: no in-flight range to prefix")
	}
	first := wire.SequenceRange{FirstSequence: r.FirstSequence, LastSequence: r.FirstSequence}
	body, err := p.encodeRange(first)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Range: first, Body: body}, nil
}

// encodeRange re-reads and re-encodes an already-in-flight range, guaranteeing a
// byte-identical replay body.
func (p *Planner) encodeRange(r wire.SequenceRange) ([]byte, error) {
	records, err := p.Store.ReadRange(r.FirstSequence, r.LastSequence)
	if err != nil {
		return nil, fmt.Errorf("observer upload: replay read [%d, %d]: %w", r.FirstSequence, r.LastSequence, err)
	}
	if err := verifyContiguous(records, r.FirstSequence); err != nil {
		return nil, err
	}
	if n := int64(len(records)); n != r.LastSequence-r.FirstSequence+1 {
		return nil, fmt.Errorf("observer upload: replay range [%d, %d] expected %d frames, got %d",
			r.FirstSequence, r.LastSequence, r.LastSequence-r.FirstSequence+1, n)
	}
	return EncodeBatchBody(p.SourceID, r, records)
}

// verifyContiguous rejects a records slice that is not exactly first, first+1, ... so a
// gap or reorder in the durable range never produces a batch whose observation sequences
// disagree with its declared range (a 422 RANGE_NOT_CONTIGUOUS at the server).
func verifyContiguous(records []Record, first int64) error {
	want := first
	for i, rec := range records {
		if rec.Sequence != want {
			return fmt.Errorf("observer upload: non-contiguous durable range at index %d: sequence %d, want %d", i, rec.Sequence, want)
		}
		want++
	}
	return nil
}

// byteBudgetCut returns how many leading records fit within maxBatchBytes, always at
// least one. A single record larger than the whole budget still forms a batch-of-one so
// the sequence advances (the server may then 413 it, which the retry layer surfaces as an
// operator error — it is never silently stranded).
func byteBudgetCut(sourceID string, records []Record, maxBatchBytes int64) int {
	n := 1
	for n < len(records) {
		if bodyByteLen(sourceID, records[0].Sequence, records[n].Sequence, records[:n+1]) > maxBatchBytes {
			break
		}
		n++
	}
	return n
}

// bodyByteLen is the exact byte length of EncodeBatchBody's canonical output for the
// given range and records, computed without encoding. The canonical body is
//
//	{"first_sequence":F,"last_sequence":L,"observations":[P0,...,Pk],"schema_version":1,"source_id":"S"}
//
// with keys in ascending order and no insignificant whitespace, so its length is the
// fixed skeleton plus the decimal digits of F and L, the JSON-escaped source id, the sum
// of the (already canonical) payload lengths, and one comma between each pair of payloads.
func bodyByteLen(sourceID string, first, last int64, records []Record) int64 {
	const skeleton = int64(88) // fixed key/punctuation bytes; see the doc comment
	total := skeleton
	total += int64(len(strconv.FormatInt(first, 10)))
	total += int64(len(strconv.FormatInt(last, 10)))
	total += int64(jsonStringLen(sourceID)) - 2 // skeleton already counts the two quotes
	for i, rec := range records {
		total += int64(len(rec.Payload))
		if i > 0 {
			total++ // comma between array elements
		}
	}
	return total
}

// jsonStringLen returns the length of the canonical JSON encoding of s including its two
// surrounding quotes, accounting for escaping. Source ids are ASCII-safe in practice, but
// this stays exact for any string.
func jsonStringLen(s string) int {
	n := 2 // quotes
	for _, r := range s {
		switch r {
		case '"', '\\', '\n', '\r', '\t', '\b', '\f':
			n += 2
		default:
			if r < 0x20 {
				n += 6 // \u00XX
			} else {
				n += len(string(r))
			}
		}
	}
	return n
}

// EncodeBatchBody encodes one contiguous batch to its canonical wire body. The
// observations are the durable canonical payloads used verbatim, so the same range always
// produces identical bytes. The result is the exact form wire.CanonicalBytes defines: keys
// in ascending order, no insignificant whitespace, integers preserved — which is also the
// form the shared wire fixture corpus is pinned against.
func EncodeBatchBody(sourceID string, r wire.SequenceRange, records []Record) ([]byte, error) {
	obs := make([]wire.Observation, len(records))
	for i, rec := range records {
		if err := obs[i].UnmarshalJSON(rec.Payload); err != nil {
			return nil, fmt.Errorf("observer upload: decode durable payload at sequence %d: %w", rec.Sequence, err)
		}
	}
	batch := wire.ObservationBatch{
		SchemaVersion: wire.ObservationBatchSchemaVersionN1,
		SourceId:      sourceID,
		FirstSequence: r.FirstSequence,
		LastSequence:  r.LastSequence,
		Observations:  obs,
	}
	body, err := wire.CanonicalBytes(batch)
	if err != nil {
		return nil, fmt.Errorf("observer upload: canonical batch body: %w", err)
	}
	return body, nil
}

// SpoolFrameStore reads durable frames from a spool directory through the spool package's
// exported segment surface. It is the production FrameStore the daemon wires; it opens no
// segment the range does not need and never crosses into the interrupted-create tail
// (whose first sequence is above any durable sequence).
type SpoolFrameStore struct {
	// Dir is the spool directory (the parent of wal/), owner-only 0700.
	Dir string
}

// ReadRange returns the durable canonical payloads for [first, last]. It reads only the
// segments whose first sequence is within the range and filters each to the requested
// window, so a large WAL costs only the segments the batch actually spans.
func (s SpoolFrameStore) ReadRange(first, last int64) ([]Record, error) {
	if first < wire.SequenceMin || last < first {
		return nil, fmt.Errorf("observer upload: bad read range [%d, %d]", first, last)
	}
	walDir := filepath.Join(s.Dir, walSubdir)
	segs, err := listSegmentPaths(walDir)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, seg := range segs {
		// A segment starting past `last` (including the interrupted-create tail) holds no
		// sequence we need; stop, since segments are ordered by ascending first sequence.
		if seg.first > last {
			break
		}
		frames, err := readSegmentFrames(seg.path)
		if err != nil {
			return nil, err
		}
		for _, f := range frames {
			if f.Sequence < first || f.Sequence > last {
				continue
			}
			payload := make([]byte, len(f.Payload))
			copy(payload, f.Payload)
			out = append(out, Record{Sequence: f.Sequence, Payload: payload})
		}
	}
	return out, nil
}

// segmentRef is a WAL segment path and the first sequence parsed from its filename.
type segmentRef struct {
	path  string
	first int64
}

// listSegmentPaths returns the WAL's .seg files ordered by ascending first sequence
// (parsed from the 20-digit zero-padded filename). A missing WAL directory is an empty
// list, not an error, so batch formation over a fresh spool is a clean no-op.
func listSegmentPaths(walDir string) ([]segmentRef, error) {
	entries, err := os.ReadDir(walDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("observer upload: read wal dir: %w", err)
	}
	var refs []segmentRef
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".seg") {
			continue
		}
		first, err := strconv.ParseInt(strings.TrimSuffix(name, ".seg"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("observer upload: unparseable segment name %q: %w", name, err)
		}
		refs = append(refs, segmentRef{path: filepath.Join(walDir, name), first: first})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].first < refs[j].first })
	return refs, nil
}

// readSegmentFrames opens one segment through the spool surface and returns its frames.
func readSegmentFrames(path string) ([]spool.Frame, error) {
	seg, err := spool.OpenSegment(path, spool.SegmentOptions{})
	if err != nil {
		return nil, fmt.Errorf("observer upload: open segment %s: %w", filepath.Base(path), err)
	}
	defer seg.Close()
	frames, err := seg.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("observer upload: read segment %s: %w", filepath.Base(path), err)
	}
	return frames, nil
}
