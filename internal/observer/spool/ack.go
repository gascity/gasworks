package spool

// ack.go (E1.3) owns the acknowledgement ADVANCEMENT policy over the durable `ack` sidecar
// whose read/checksum-validate primitive E1.2 provides (readAck/writeAck in recover.go).
//
// The rules the spec fixes (docs/design/gasworks-observer-mvp.md "Durable endpoint spool"):
//
//   - one bounded in-flight range per source, replayed byte-for-byte until acknowledged;
//   - acknowledgement advancement only through a contiguous accepted sequence;
//   - an acknowledgement larger than the sent contiguous range is rejected locally;
//   - an acknowledgement beyond the highest durable sequence is rejected;
//   - a corrupt/oversized ack sidecar holds state and surfaces unhealthy — it is NEVER reset
//     to an empty acknowledged_through=0 (that would silently re-send or, worse, permit an
//     eviction of already-acknowledged data).

import (
	"errors"
	"fmt"
	"sync"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// DefaultMaxInFlightRecords bounds a single in-flight range's length, mirroring the delivery
// default of at most 1,000 observations per batch. A range longer than this is rejected so a
// single request can never grow unbounded.
const DefaultMaxInFlightRecords int64 = 1000

// Typed advancement errors. All are matchable with errors.Is; none ever advance the
// acknowledged-through watermark or reset it.
var (
	// ErrAckBackward is a regression: an acknowledgement below the current watermark.
	ErrAckBackward = errors.New("observer spool: acknowledgement regresses below acknowledged_through")
	// ErrAckGap is a non-contiguous acknowledgement: the accepted range does not begin exactly
	// at acknowledged_through+1, so advancing would skip an unacknowledged sequence.
	ErrAckGap = errors.New("observer spool: non-contiguous acknowledgement (gap before acknowledged_through+1)")
	// ErrAckBeyondDurable is an acknowledgement past the highest durable frame — the server
	// claims to have accepted a sequence the WAL never made durable.
	ErrAckBeyondDurable = errors.New("observer spool: acknowledgement beyond highest durable sequence")
	// ErrAckBeyondSent is an acknowledgement larger than the sent contiguous range (rejected
	// locally per the delivery contract).
	ErrAckBeyondSent = errors.New("observer spool: acknowledgement larger than the sent contiguous range")
	// ErrInFlightConflict is set when a different range is offered while one is already in
	// flight — exactly one request may be outstanding per source.
	ErrInFlightConflict = errors.New("observer spool: a different range is already in flight")
	// ErrInFlightRange is a malformed or out-of-bounds in-flight range.
	ErrInFlightRange = errors.New("observer spool: malformed in-flight range")
)

// AckState is the in-memory acknowledgement policy over the durable ack sidecar. It tracks
// the persisted acknowledged_through watermark, the highest durable sequence (the ceiling for
// advancement, grown by the writer via NoteDurable), and the single bounded in-flight range.
// It is safe for concurrent use: the uploader advances it while the writer appends.
type AckState struct {
	mu                  sync.Mutex
	dir                 string
	acknowledgedThrough int64
	highestDurable      int64
	maxInFlight         int64
	inFlight            *wire.SequenceRange
}

// AckOptions configures AckState. MaxInFlight bounds the in-flight range length (0 selects
// DefaultMaxInFlightRecords).
type AckOptions struct {
	MaxInFlight int64
}

// LoadAckState reads and validates the durable ack sidecar and returns the advancement policy
// seeded with the recovered highest durable sequence. A present-but-corrupt/oversized ack
// sidecar returns ErrChecksumMismatch (the store is unhealthy) — the caller must surface that
// and hold; it must NOT construct a zeroed AckState, which would silently reset acknowledgement
// to empty. An absent sidecar means nothing acknowledged (acknowledged_through=0), which is a
// clean fresh-install state, not a reset.
//
// A loaded acknowledged_through may legitimately exceed the surviving highest durable sequence:
// compaction removes whole acknowledged segments, so after "ack N; compact away [1..N]" the
// highest durable frame is below N (or the WAL is empty). Recover already treats this as clean
// (next_sequence = max(highest, ack)+1). Because "ack of compacted-away data" is
// indistinguishable from "ack from the future" using only the surviving highest durable, there
// is no sound hard guard here; the ack sidecar's CRC already protects the value's integrity. So
// LoadAckState never rejects on ack > highestDurable — it seeds the advancement ceiling as
// max(recovered highest, ack) so a durably acknowledged watermark is always loadable and
// self-consistent.
func LoadAckState(dir string, highestDurable int64, opts AckOptions) (*AckState, error) {
	ack, _, err := readAck(dir)
	if err != nil {
		return nil, err
	}
	ceiling := highestDurable
	if ack > ceiling {
		ceiling = ack
	}
	return &AckState{
		dir:                 dir,
		acknowledgedThrough: ack,
		highestDurable:      ceiling,
		maxInFlight:         maxInFlightOrDefault(opts.MaxInFlight),
	}, nil
}

func maxInFlightOrDefault(m int64) int64 {
	if m <= 0 {
		return DefaultMaxInFlightRecords
	}
	return m
}

// AcknowledgedThrough returns the durable acknowledged-through watermark.
func (a *AckState) AcknowledgedThrough() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acknowledgedThrough
}

// HighestDurable returns the current advancement ceiling.
func (a *AckState) HighestDurable() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.highestDurable
}

// NoteDurable raises the highest-durable ceiling as the writer appends frames. It never
// lowers it (a caller passing a stale value is ignored). The ack policy uses this ceiling to
// reject an acknowledgement beyond durable data.
func (a *AckState) NoteDurable(seq int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if seq > a.highestDurable {
		a.highestDurable = seq
	}
}

// InFlight returns the single bounded in-flight range and whether one is outstanding. This is
// the accessor the delivery loop (E1.9) reads to replay the same range byte-for-byte until it
// is acknowledged.
func (a *AckState) InFlight() (wire.SequenceRange, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight == nil {
		return wire.SequenceRange{}, false
	}
	return *a.inFlight, true
}

// SetInFlight records the single bounded contiguous range the delivery loop has sent. The
// range must begin exactly at acknowledged_through+1 (contiguity), be well-formed
// (first<=last), stay within the highest durable sequence, and not exceed the configured
// bound. Exactly one range may be outstanding: offering the identical range again while it is
// in flight is idempotent (a byte-for-byte replay), but a different range is ErrInFlightConflict.
func (a *AckState) SetInFlight(r wire.SequenceRange) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.FirstSequence < wire.SequenceMin || r.LastSequence < r.FirstSequence {
		return fmt.Errorf("%w: [%d, %d]", ErrInFlightRange, r.FirstSequence, r.LastSequence)
	}
	if r.LastSequence > a.highestDurable {
		return fmt.Errorf("%w: last %d exceeds highest durable %d", ErrInFlightRange, r.LastSequence, a.highestDurable)
	}
	if r.LastSequence-r.FirstSequence+1 > a.maxInFlight {
		return fmt.Errorf("%w: range length %d exceeds bound %d", ErrInFlightRange,
			r.LastSequence-r.FirstSequence+1, a.maxInFlight)
	}
	if r.FirstSequence != a.acknowledgedThrough+1 {
		return fmt.Errorf("%w: range starts at %d, want %d", ErrAckGap, r.FirstSequence, a.acknowledgedThrough+1)
	}
	if a.inFlight != nil && *a.inFlight != r {
		return fmt.Errorf("%w: outstanding [%d, %d], offered [%d, %d]", ErrInFlightConflict,
			a.inFlight.FirstSequence, a.inFlight.LastSequence, r.FirstSequence, r.LastSequence)
	}
	rr := r
	a.inFlight = &rr
	return nil
}

// Acknowledge advances the durable acknowledged-through watermark to `through` on a valid
// server acknowledgement and returns after the ack sidecar is durably rewritten. It advances
// ONLY through a contiguous accepted sequence within the one outstanding in-flight range:
//
//   - through == acknowledgedThrough is an idempotent no-op (a duplicate/stale ack);
//   - through < acknowledgedThrough is ErrAckBackward;
//   - through > highestDurable is ErrAckBeyondDurable;
//   - with no range in flight, any advance is ErrAckBeyondSent (nothing was sent);
//   - through > inFlight.LastSequence is ErrAckBeyondSent (larger than the sent range).
//
// A full acknowledgement (through == inFlight.LastSequence) clears the in-flight range; a
// partial one advances the watermark and shrinks the range to the still-owed remainder so the
// delivery loop keeps replaying it. On any rejection nothing is written and no state changes.
func (a *AckState) Acknowledge(through int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if through < a.acknowledgedThrough {
		return fmt.Errorf("%w: ack %d < acknowledged_through %d", ErrAckBackward, through, a.acknowledgedThrough)
	}
	if through == a.acknowledgedThrough {
		return nil // idempotent duplicate; the watermark already covers it.
	}
	if through > a.highestDurable {
		return fmt.Errorf("%w: ack %d > highest durable %d", ErrAckBeyondDurable, through, a.highestDurable)
	}
	if a.inFlight == nil {
		return fmt.Errorf("%w: ack %d with nothing in flight", ErrAckBeyondSent, through)
	}
	if through > a.inFlight.LastSequence {
		return fmt.Errorf("%w: ack %d > sent last %d", ErrAckBeyondSent, through, a.inFlight.LastSequence)
	}
	// through is in (acknowledgedThrough, inFlight.LastSequence]; the range began at
	// acknowledgedThrough+1 (SetInFlight enforced it), so [acknowledgedThrough+1, through] is
	// contiguous and fully accepted. Persist before mutating in-memory state.
	if err := writeAck(a.dir, through); err != nil {
		return err
	}
	a.acknowledgedThrough = through
	if through == a.inFlight.LastSequence {
		a.inFlight = nil
	} else {
		a.inFlight = &wire.SequenceRange{FirstSequence: through + 1, LastSequence: a.inFlight.LastSequence}
	}
	return nil
}
