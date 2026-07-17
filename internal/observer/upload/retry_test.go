package upload

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// scriptedSender returns pre-programmed outcomes and records every plan it was asked to
// send, so a test can assert byte-identical replay across attempts.
type scriptedSender struct {
	steps []func(plan Plan) (*Attempt, error)
	calls int
	seen  []Plan
}

func (s *scriptedSender) Send(_ context.Context, plan Plan) (*Attempt, error) {
	s.seen = append(s.seen, plan)
	i := s.calls
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	s.calls++
	return s.steps[i](plan)
}

func noSleep(context.Context, time.Duration) error { return nil }

func zeroJitter() float64 { return 0 }

func TestDeliverSuccessAdvancesAck(t *testing.T) {
	ackDir := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(pl Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{
				SourceId: testSourceID, AcknowledgedThroughSequence: 5, Accepted: 5,
			}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID, Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if ackDir.AcknowledgedThrough() != 5 {
		t.Fatalf("acknowledged = %d, want 5", ackDir.AcknowledgedThrough())
	}
	if _, in := ackDir.InFlight(); in {
		t.Fatalf("range still in flight after full ack")
	}
}

func TestNeverAdvanceOnFailureReplaysByteIdentical(t *testing.T) {
	ackDir := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 64), Ack: ackDir, SourceID: testSourceID}
	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return &Attempt{StatusCode: 500}, nil },
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID,
		Policy: RetryPolicy{MaxAttempts: 3, Sleep: noSleep, Jitter: zeroJitter}}
	err = d.Deliver(context.Background(), plan)
	if !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("Deliver = %v, want ErrRetriesExhausted", err)
	}
	// Nothing advanced; the range stays in flight.
	if ackDir.AcknowledgedThrough() != 0 {
		t.Fatalf("acknowledged = %d, want 0 (no advance on failure)", ackDir.AcknowledgedThrough())
	}
	if r, in := ackDir.InFlight(); !in || r != plan.Range {
		t.Fatalf("in-flight = %+v/%v, want %+v held", r, in, plan.Range)
	}
	// Every attempt resent the identical bytes.
	for i := 1; i < len(sender.seen); i++ {
		if !bytes.Equal(sender.seen[0].Body, sender.seen[i].Body) {
			t.Fatalf("attempt %d body not byte-identical to attempt 0", i)
		}
	}
	if len(sender.seen) != 3 {
		t.Fatalf("attempts = %d, want 3", len(sender.seen))
	}
}

func TestHoldStatusesSurfaceOperatorErrorNoAdvance(t *testing.T) {
	holds := []struct {
		status int
		code   wire.ObserverErrorBodyCode
	}{
		{http.StatusBadRequest, wire.ObserverErrorBodyCodeMALFORMEDREQUEST},
		{http.StatusUnauthorized, wire.ObserverErrorBodyCodeUNAUTHENTICATED},
		{http.StatusForbidden, wire.ObserverErrorBodyCodeFORBIDDEN},
		{http.StatusConflict, wire.ObserverErrorBodyCodeSEQUENCECONFLICT},
		{http.StatusRequestEntityTooLarge, wire.ObserverErrorBodyCodePAYLOADTOOLARGE},
		{http.StatusUnprocessableEntity, wire.ObserverErrorBodyCodeRANGENOTCONTIGUOUS},
	}
	for _, h := range holds {
		t.Run(http.StatusText(h.status), func(t *testing.T) {
			ackDir := newAckState(t, 5)
			p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
			plan, _, err := p.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
				func(Plan) (*Attempt, error) {
					return &Attempt{StatusCode: h.status, ErrorBody: &wire.ObserverErrorBody{Code: h.code, Message: "x"}}, nil
				},
			}}
			d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID,
				Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
			err = d.Deliver(context.Background(), plan)
			var oe *OperatorError
			if !errors.As(err, &oe) || !errors.Is(err, ErrHeld) {
				t.Fatalf("Deliver = %v, want *OperatorError (ErrHeld)", err)
			}
			if oe.Status != h.status || oe.Code != h.code {
				t.Fatalf("operator error = status %d code %s, want %d/%s", oe.Status, oe.Code, h.status, h.code)
			}
			if ackDir.AcknowledgedThrough() != 0 {
				t.Fatalf("acknowledged advanced on hold")
			}
			if _, in := ackDir.InFlight(); !in {
				t.Fatalf("in-flight cleared on hold")
			}
			if len(sender.seen) != 1 {
				t.Fatalf("hold retried: attempts = %d, want 1", len(sender.seen))
			}
		})
	}
}

func TestRetryAfterHonored(t *testing.T) {
	ackDir := newAckState(t, 3)
	p := &Planner{Store: newMemStore(t, 1, 3, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()

	var slept []time.Duration
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return &Attempt{StatusCode: 429, RetryAfter: 2 * time.Second}, nil },
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: testSourceID, AcknowledgedThroughSequence: 3, Accepted: 3}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID, Policy: RetryPolicy{
		MaxAttempts: 3, Jitter: zeroJitter,
		Sleep: func(_ context.Context, dd time.Duration) error { slept = append(slept, dd); return nil },
	}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(slept) != 1 || slept[0] != 2*time.Second {
		t.Fatalf("slept = %v, want exactly [2s] from Retry-After", slept)
	}
	if ackDir.AcknowledgedThrough() != 3 {
		t.Fatalf("acknowledged = %d, want 3", ackDir.AcknowledgedThrough())
	}
}

func TestTransportRetryThenSuccess(t *testing.T) {
	ackDir := newAckState(t, 3)
	p := &Planner{Store: newMemStore(t, 1, 3, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()

	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return nil, &TransportError{err: errors.New("dial reset")} },
		func(Plan) (*Attempt, error) { return nil, &TransportError{err: errors.New("tls timeout")} },
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: testSourceID, AcknowledgedThroughSequence: 3, Accepted: 3}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID,
		Policy: RetryPolicy{MaxAttempts: 5, Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if ackDir.AcknowledgedThrough() != 3 {
		t.Fatalf("acknowledged = %d, want 3", ackDir.AcknowledgedThrough())
	}
}

func TestCorruptAckBeyondSentHeldLocally(t *testing.T) {
	cases := map[string]*wire.IngestAck{
		"head beyond sent":   {SourceId: testSourceID, AcknowledgedThroughSequence: 9, Accepted: 5},
		"head short of sent": {SourceId: testSourceID, AcknowledgedThroughSequence: 3, Accepted: 3},
		"counts do not sum":  {SourceId: testSourceID, AcknowledgedThroughSequence: 5, Accepted: 2, Duplicates: 1},
		"source id mismatch": {SourceId: "src_other", AcknowledgedThroughSequence: 5, Accepted: 5},
	}
	for name, ack := range cases {
		t.Run(name, func(t *testing.T) {
			ackDir := newAckState(t, 5)
			p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
			plan, _, _ := p.Next()
			sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
				func(Plan) (*Attempt, error) { return &Attempt{StatusCode: 200, Ack: ack}, nil },
			}}
			d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID,
				Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
			err := d.Deliver(context.Background(), plan)
			if !errors.Is(err, ErrHeld) {
				t.Fatalf("Deliver = %v, want ErrHeld (corrupt ack)", err)
			}
			if ackDir.AcknowledgedThrough() != 0 {
				t.Fatalf("advanced on corrupt ack")
			}
		})
	}
}

func TestCorruptAckUndecodableHeld(t *testing.T) {
	ackDir := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return &Attempt{StatusCode: 200, Ack: nil}, nil }, // undecodable
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID,
		Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); !errors.Is(err, ErrHeld) {
		t.Fatalf("Deliver = %v, want ErrHeld", err)
	}
}

func TestClassifyTable(t *testing.T) {
	tests := []struct {
		name string
		att  *Attempt
		err  error
		want Disposition
	}{
		{"200", &Attempt{StatusCode: 200}, nil, DispositionSuccess},
		{"400", &Attempt{StatusCode: 400}, nil, DispositionHold},
		{"401", &Attempt{StatusCode: 401}, nil, DispositionHold},
		{"403", &Attempt{StatusCode: 403}, nil, DispositionHold},
		{"409", &Attempt{StatusCode: 409}, nil, DispositionHold},
		{"413", &Attempt{StatusCode: 413}, nil, DispositionHold},
		{"422", &Attempt{StatusCode: 422}, nil, DispositionHold},
		{"429", &Attempt{StatusCode: 429}, nil, DispositionRetry},
		{"500", &Attempt{StatusCode: 500}, nil, DispositionRetry},
		{"503", &Attempt{StatusCode: 503}, nil, DispositionRetry},
		{"404 fail-closed", &Attempt{StatusCode: 404}, nil, DispositionHold},
		{"transport", nil, &TransportError{err: errors.New("x")}, DispositionRetry},
		{"redirect", nil, ErrRedirectRefused, DispositionRetry},
		{"content-encoding", nil, ErrUnsupportedContentEncoding, DispositionHold},
		{"source mismatch", nil, ErrSourceMismatch, DispositionHold},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := Classify(tc.att, tc.err)
			if got != tc.want {
				t.Fatalf("Classify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBackoffCappedJittered(t *testing.T) {
	p := RetryPolicy{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, Jitter: zeroJitter}
	// With zero jitter, delay = computed/2, computed = base<<(attempt-1), capped at MaxDelay.
	if d := p.backoff(1, 0); d != 50*time.Millisecond {
		t.Fatalf("attempt1 = %v, want 50ms", d)
	}
	if d := p.backoff(2, 0); d != 100*time.Millisecond {
		t.Fatalf("attempt2 = %v, want 100ms", d)
	}
	// Large attempt caps at MaxDelay/2.
	if d := p.backoff(20, 0); d != 500*time.Millisecond {
		t.Fatalf("attempt20 = %v, want 500ms (capped)", d)
	}
	// Retry-After overrides the computed backoff.
	if d := p.backoff(2, 7*time.Second); d != 7*time.Second {
		t.Fatalf("retry-after = %v, want 7s", d)
	}
}

// TestDeliverIntegrationRealClient drives the full stack (real Client over a loopback HTTP
// server in dev mode) through a 5xx-then-200 sequence and asserts the ack advances only on
// the validated success, replaying identical bytes in between.
func TestDeliverIntegrationRealClient(t *testing.T) {
	ackDir := newAckState(t, 4)
	p := &Planner{Store: newMemStore(t, 1, 4, 8), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()

	h := &recordingHandler{respond: func(n int, _ recordedRequest) (int, http.Header, []byte) {
		if n == 0 {
			return http.StatusServiceUnavailable, nil, errorJSON(t, wire.ObserverErrorBodyCodeSINKUNAVAILABLE, true)
		}
		return http.StatusOK, nil, ackJSON(t, testSourceID, 1, 4)
	}}
	srv := newHTTPServer(t, h)
	client := loopbackClient(t, srv, staticToken("tok-abc"))

	d := &Deliverer{Sender: client, Ack: ackDir, SourceID: testSourceID,
		Policy: RetryPolicy{MaxAttempts: 4, Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if ackDir.AcknowledgedThrough() != 4 {
		t.Fatalf("acknowledged = %d, want 4", ackDir.AcknowledgedThrough())
	}
	reqs := h.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(reqs))
	}
	if !bytes.Equal(reqs[0].body, reqs[1].body) {
		t.Fatalf("replay body not byte-identical across the 503 retry")
	}
	if reqs[0].path != ingestPath {
		t.Fatalf("path = %q, want %q", reqs[0].path, ingestPath)
	}
}
