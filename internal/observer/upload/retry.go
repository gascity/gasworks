package upload

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Disposition classifies one delivery attempt into the three delivery behaviors the spec
// fixes ("Delivery behavior"):
//
//   - Success: a 200 whose ack advances the local watermark through the sent range.
//   - Retry:   429 (honor Retry-After) and transport/5xx (capped jittered backoff). No
//     state mutation; the same batch replays byte-for-byte.
//   - Hold:    401/403, schema (400), conflict (409), size (413), unprocessable/
//     non-contiguous (422), an unsupported response encoding, a source-binding mismatch,
//     and a corrupt acknowledgement. The spool holds, an operator error surfaces, and no
//     evidence is discarded or acknowledged.
type Disposition int

const (
	// DispositionSuccess means the attempt returned a 200 to validate and acknowledge.
	DispositionSuccess Disposition = iota
	// DispositionRetry means the attempt failed transiently; retry without mutation.
	DispositionRetry
	// DispositionHold means the attempt failed in a way that must not be retried blindly;
	// hold the spool and surface an operator error.
	DispositionHold
)

func (d Disposition) String() string {
	switch d {
	case DispositionSuccess:
		return "success"
	case DispositionRetry:
		return "retry"
	case DispositionHold:
		return "hold"
	default:
		return "unknown"
	}
}

// ErrHeld matches any operator-actionable hold via errors.Is. A held delivery advanced
// nothing and discarded nothing.
var ErrHeld = errors.New("observer upload: delivery held; operator action required")

// ErrRetriesExhausted matches a transient delivery that exhausted its retry budget. It is
// NOT a hold: the batch is unchanged and the next delivery tick replays it byte-for-byte.
var ErrRetriesExhausted = errors.New("observer upload: delivery retries exhausted")

// OperatorError is a surfaced, content-free hold. It carries the classification, the HTTP
// status (0 for a local hold), and the server's typed code/message verbatim when present.
// It never advances or discards the spool.
type OperatorError struct {
	// Reason is a short, bounded class (e.g. "unauthenticated", "sequence conflict",
	// "corrupt acknowledgement").
	Reason string
	// Status is the HTTP status, or 0 for a locally-detected hold.
	Status int
	// Code is the server's typed error code, when a typed body decoded.
	Code wire.ObserverErrorBodyCode
	// Message is the server's content-free message, when present.
	Message string
}

// Error renders the hold without any captured content.
func (e *OperatorError) Error() string {
	s := "observer upload: held — " + e.Reason
	if e.Status != 0 {
		s += fmt.Sprintf(" (status %d", e.Status)
		if e.Code != "" {
			s += ", code " + string(e.Code)
		}
		s += ")"
	}
	return s
}

// Is lets errors.Is(err, ErrHeld) match any OperatorError.
func (e *OperatorError) Is(target error) bool { return target == ErrHeld }

// Sender performs one HTTP round trip for a formed batch. *Client satisfies it; tests
// substitute a scripted double.
type Sender interface {
	Send(ctx context.Context, plan Plan) (*Attempt, error)
}

// RetryPolicy bounds the delivery retry loop. All delays are bounded; the seams make the
// timing deterministic under test without real sleeping.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts including the first (0 selects 6).
	MaxAttempts int
	// BaseDelay is the first backoff step (0 selects 200ms).
	BaseDelay time.Duration
	// MaxDelay caps a single computed backoff step (0 selects 30s). It does not cap an
	// explicit Retry-After, which is honored as asked.
	MaxDelay time.Duration
	// Sleep waits for d or until ctx is done (nil selects a context-aware timer sleep).
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter returns a value in [0,1) for the backoff jitter (nil selects math/rand/v2).
	Jitter func() float64
}

func (p RetryPolicy) maxAttempts() int {
	if p.MaxAttempts <= 0 {
		return 6
	}
	return p.MaxAttempts
}

func (p RetryPolicy) baseDelay() time.Duration {
	if p.BaseDelay <= 0 {
		return 200 * time.Millisecond
	}
	return p.BaseDelay
}

func (p RetryPolicy) maxDelay() time.Duration {
	if p.MaxDelay <= 0 {
		return 30 * time.Second
	}
	return p.MaxDelay
}

func (p RetryPolicy) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p RetryPolicy) jitter() float64 {
	if p.Jitter != nil {
		return p.Jitter()
	}
	return rand.Float64()
}

// backoff computes the delay before the given retry. An explicit Retry-After is honored
// exactly; otherwise the step is equal-jittered capped exponential
// (computed/2 + jitter*computed/2), so concurrent sources do not resynchronize.
func (p RetryPolicy) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	computed := p.baseDelay() << (attempt - 1)
	if computed <= 0 || computed > p.maxDelay() {
		computed = p.maxDelay()
	}
	half := computed / 2
	return half + time.Duration(p.jitter()*float64(half))
}

// Deliverer drives one batch to durable acknowledgement. It advances the spool through
// exactly one point — spool.AckState.Acknowledge on a validated 200 — so no failure path
// can move or discard the local watermark.
type Deliverer struct {
	// Sender performs the HTTP round trips.
	Sender Sender
	// Ack is the durable acknowledgement policy (E1.3). Deliverer never writes it except
	// through Acknowledge.
	Ack *spool.AckState
	// SourceID is the credential-bound source; a server ack claiming a different source is
	// a corrupt acknowledgement.
	SourceID string
	// Policy bounds the retry loop.
	Policy RetryPolicy
}

// Deliver sends plan and retries transient failures until the batch is acknowledged, the
// spool is held, or the retry budget is exhausted:
//
//   - a validated 200 advances the acknowledgement through the sent range and returns nil;
//   - a hold returns an *OperatorError (errors.Is ErrHeld) with nothing advanced or
//     discarded;
//   - an exhausted retry budget returns ErrRetriesExhausted, again with nothing advanced.
//
// The same plan.Body is resent on every attempt, so a retry is a byte-for-byte replay.
func (d *Deliverer) Deliver(ctx context.Context, plan Plan) error {
	// Fail closed on an empty binding: the credential is source-bound, so an empty
	// Deliverer.SourceID would silently disable the ack-source-binding check in acknowledge.
	if d.SourceID == "" {
		return ErrEmptySourceID
	}
	maxAttempts := d.Policy.maxAttempts()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		att, err := d.Sender.Send(ctx, plan)
		disp, opErr := Classify(att, err)
		switch disp {
		case DispositionSuccess:
			return d.acknowledge(att, plan)
		case DispositionHold:
			return opErr
		case DispositionRetry:
			lastErr = retryCause(att, err)
			if attempt == maxAttempts {
				return fmt.Errorf("%w after %d attempts: %v", ErrRetriesExhausted, attempt, lastErr)
			}
			// Retry-After is honored ONLY for 429 (rate limiting). Transport failures and
			// 5xx always use the computed capped jittered backoff, so a server cannot use a
			// 5xx Retry-After to resynchronize every source onto one wake instant (thundering
			// herd) and defeat the equal-jitter.
			var retryAfter time.Duration
			if att != nil && att.StatusCode == http.StatusTooManyRequests {
				retryAfter = att.RetryAfter
			}
			if serr := d.Policy.sleep(ctx, d.Policy.backoff(attempt, retryAfter)); serr != nil {
				return serr
			}
		}
	}
	return fmt.Errorf("%w: %v", ErrRetriesExhausted, lastErr)
}

// Classify maps one attempt outcome to a Disposition and, for a hold, the operator error.
// It is pure and total: every status and transport error resolves to exactly one behavior.
//
// Classification table:
//
//	transport / redirect / timeout        → Retry
//	unsupported Content-Encoding          → Hold  (protocol)
//	source-binding mismatch (local)       → Hold
//	empty/failed credential               → Retry (rotation window; bounded)
//	200                                   → Success (ack validated separately)
//	400 malformed / unsupported schema    → Hold
//	401 unauthenticated                   → Hold
//	403 forbidden                         → Hold
//	409 sequence/binding/observation      → Hold
//	413 payload too large                 → Hold
//	422 unprocessable / non-contiguous    → Hold
//	429 rate limited                      → Retry (honor Retry-After)
//	5xx sink/server                       → Retry (capped jittered backoff)
//	any other status                      → Hold (fail closed)
func Classify(att *Attempt, err error) (Disposition, *OperatorError) {
	if err != nil {
		switch {
		case errors.Is(err, ErrUnsupportedContentEncoding):
			return DispositionHold, &OperatorError{Reason: "unsupported response content-encoding"}
		case errors.Is(err, ErrSourceMismatch):
			return DispositionHold, &OperatorError{Reason: "batch source_id does not match source binding"}
		default:
			// Transport, redirect refusal, TLS, timeout, and transient credential failures
			// all retry without mutation.
			return DispositionRetry, nil
		}
	}
	if att == nil {
		return DispositionRetry, nil
	}
	switch att.StatusCode {
	case http.StatusOK:
		return DispositionSuccess, nil
	case http.StatusTooManyRequests:
		return DispositionRetry, nil
	case http.StatusBadRequest:
		return DispositionHold, holdError("schema / unsupported schema version", att)
	case http.StatusUnauthorized:
		return DispositionHold, holdError("unauthenticated", att)
	case http.StatusForbidden:
		return DispositionHold, holdError("forbidden", att)
	case http.StatusConflict:
		return DispositionHold, holdError("sequence / binding / observation conflict", att)
	case http.StatusRequestEntityTooLarge:
		return DispositionHold, holdError("payload too large", att)
	case http.StatusUnprocessableEntity:
		return DispositionHold, holdError("unprocessable / range not contiguous", att)
	default:
		if att.StatusCode >= 500 && att.StatusCode <= 599 {
			return DispositionRetry, nil
		}
		return DispositionHold, holdError("unexpected status", att)
	}
}

// holdError builds an operator error from a typed attempt, copying only the server's
// content-free code/message.
func holdError(reason string, att *Attempt) *OperatorError {
	oe := &OperatorError{Reason: reason, Status: att.StatusCode}
	if att.ErrorBody != nil {
		oe.Code = att.ErrorBody.Code
		oe.Message = att.ErrorBody.Message
	}
	return oe
}

// retryCause extracts a human-readable cause for a retry, for the exhausted-budget error.
func retryCause(att *Attempt, err error) error {
	if err != nil {
		return err
	}
	if att != nil {
		return fmt.Errorf("status %d", att.StatusCode)
	}
	return errors.New("no response")
}

// acknowledge validates a 200's ack against the sent range and advances the local
// watermark through exactly one point. Any inconsistency — a nil/undecodable ack, a
// source mismatch, an accepted+duplicates that does not sum to the range length, an
// acknowledged_through that is not the sent last, or an AckState rejection (ack beyond the
// sent range) — is a corrupt acknowledgement that HOLDS the spool.
func (d *Deliverer) acknowledge(att *Attempt, plan Plan) error {
	ack := att.Ack
	if ack == nil {
		return &OperatorError{Reason: "corrupt acknowledgement (undecodable ack body)", Status: att.StatusCode}
	}
	// d.SourceID is guaranteed non-empty by Deliver, so this binding check is unconditional:
	// an ack claiming a different source is always a corrupt acknowledgement.
	if ack.SourceId != d.SourceID {
		return &OperatorError{Reason: "corrupt acknowledgement (source binding mismatch)", Status: att.StatusCode}
	}
	rangeLen := plan.Range.LastSequence - plan.Range.FirstSequence + 1
	// The Collector returns success only after the complete range is durable, capped at
	// the request's last_sequence; a 200 that acks a different head or a count that does
	// not sum to the range length is corrupt.
	if ack.AcknowledgedThroughSequence != plan.Range.LastSequence {
		return &OperatorError{
			Reason: fmt.Sprintf("corrupt acknowledgement (ack head %d != sent last %d)",
				ack.AcknowledgedThroughSequence, plan.Range.LastSequence),
			Status: att.StatusCode,
		}
	}
	if ack.Accepted+ack.Duplicates != rangeLen {
		return &OperatorError{
			Reason: fmt.Sprintf("corrupt acknowledgement (accepted %d + duplicates %d != range length %d)",
				ack.Accepted, ack.Duplicates, rangeLen),
			Status: att.StatusCode,
		}
	}
	// Advance through the single durable point. AckState independently rejects an ack
	// beyond the sent range or beyond durable data — belt-and-suspenders against a server
	// that overshoots.
	if err := d.Ack.Acknowledge(ack.AcknowledgedThroughSequence); err != nil {
		if isAckRejection(err) {
			return &OperatorError{
				Reason: "corrupt acknowledgement (" + err.Error() + ")",
				Status: att.StatusCode,
			}
		}
		// A durability (sidecar write) failure is transient, not a hold: nothing advanced,
		// so the next tick replays the batch.
		return fmt.Errorf("observer upload: persist acknowledgement: %w", err)
	}
	return nil
}

// isAckRejection reports whether an AckState error is a semantic rejection of the server's
// acknowledgement (a corrupt ack) rather than a durability failure.
func isAckRejection(err error) bool {
	return errors.Is(err, spool.ErrAckBeyondSent) ||
		errors.Is(err, spool.ErrAckBeyondDurable) ||
		errors.Is(err, spool.ErrAckBackward) ||
		errors.Is(err, spool.ErrAckGap)
}
