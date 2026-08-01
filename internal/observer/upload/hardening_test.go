package upload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// --- Finding 1 (MAJOR): empty SourceID must fail closed on both controls ------

func TestNewClientRejectsEmptySourceID(t *testing.T) {
	_, err := NewClient(Config{
		Endpoint:   mustURL(t, "https://collector.example.com"),
		Credential: staticToken("tok"),
		// SourceID intentionally empty.
	})
	if !errors.Is(err, ErrEmptySourceID) {
		t.Fatalf("NewClient with empty SourceID = %v, want ErrEmptySourceID", err)
	}
}

func TestEmptySourceBodyStillRefusedWhenClientBound(t *testing.T) {
	// A correctly-bound client refuses a body claiming a different source unconditionally.
	h := &recordingHandler{}
	base := newHTTPServer(t, h)
	client, err := NewClient(Config{Endpoint: mustURL(t, base), SourceID: "bound-source", Credential: staticToken("t"), AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// planFor builds a body with testSourceID != "bound-source".
	if _, err := client.Send(context.Background(), planFor(t, 1, 2)); !errors.Is(err, ErrSourceMismatch) {
		t.Fatalf("Send = %v, want ErrSourceMismatch", err)
	}
	if len(h.snapshot()) != 0 {
		t.Fatalf("mismatched body reached the server")
	}
}

func TestDeliverRejectsEmptySourceID(t *testing.T) {
	ackDir := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()
	// A Deliverer with an empty SourceID: even an ack claiming a foreign source must not be
	// silently accepted — Deliver fails closed before any send.
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: "src_ATTACKER", AcknowledgedThroughSequence: 5, Accepted: 5}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: "", Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); !errors.Is(err, ErrEmptySourceID) {
		t.Fatalf("Deliver with empty SourceID = %v, want ErrEmptySourceID", err)
	}
	if ackDir.AcknowledgedThrough() != 0 {
		t.Fatalf("advanced with empty SourceID (fail-open)")
	}
	if len(sender.seen) != 0 {
		t.Fatalf("Deliver sent before failing closed on empty SourceID")
	}
}

func TestAckSourceMismatchHeldWhenBound(t *testing.T) {
	// The bound Deliverer holds a foreign-source ack unconditionally (regression for the
	// removed `!= ""` conditional).
	ackDir := newAckState(t, 5)
	p := &Planner{Store: newMemStore(t, 1, 5, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: "src_ATTACKER", AcknowledgedThroughSequence: 5, Accepted: 5}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID, Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}
	if err := d.Deliver(context.Background(), plan); !errors.Is(err, ErrHeld) {
		t.Fatalf("Deliver = %v, want ErrHeld (foreign-source ack)", err)
	}
	if ackDir.AcknowledgedThrough() != 0 {
		t.Fatalf("advanced on foreign-source ack")
	}
}

// --- Finding 2 (MINOR): TLS floor clamped to >= 1.2 ---------------------------

func TestTLSFloorClampedToTLS12(t *testing.T) {
	cases := []struct {
		name string
		in   uint16
		want uint16
	}{
		{"unset", 0, tls.VersionTLS12},
		{"tls10 raised", tls.VersionTLS10, tls.VersionTLS12},
		{"tls11 raised", tls.VersionTLS11, tls.VersionTLS12},
		{"tls12 kept", tls.VersionTLS12, tls.VersionTLS12},
		{"tls13 preserved", tls.VersionTLS13, tls.VersionTLS13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := buildTLSConfig(Config{TLSMinVersion: tc.in})
			if err != nil {
				t.Fatalf("buildTLSConfig: %v", err)
			}
			if cfg.MinVersion != tc.want {
				t.Fatalf("MinVersion = 0x%04x, want 0x%04x", cfg.MinVersion, tc.want)
			}
			if cfg.InsecureSkipVerify {
				t.Fatalf("InsecureSkipVerify set")
			}
		})
	}
}

// --- Finding 3 (MINOR): additive CA never silently drops system roots ---------

func TestAdditiveCASystemPoolFailureRejected(t *testing.T) {
	ca := newTestCA(t)
	orig := systemCertPool
	t.Cleanup(func() { systemCertPool = orig })

	// (a) SystemCertPool returns an error → construction fails, trust never narrowed.
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("simulated store failure") }
	if _, err := buildTLSConfig(Config{CustomCAs: caCerts(ca)}); !errors.Is(err, ErrSystemCertPoolUnavailable) {
		t.Fatalf("buildTLSConfig on pool error = %v, want ErrSystemCertPoolUnavailable", err)
	}
	// (b) SystemCertPool returns nil pool → same fail-closed outcome.
	systemCertPool = func() (*x509.CertPool, error) { return nil, nil }
	if _, err := buildTLSConfig(Config{CustomCAs: caCerts(ca)}); !errors.Is(err, ErrSystemCertPoolUnavailable) {
		t.Fatalf("buildTLSConfig on nil pool = %v, want ErrSystemCertPoolUnavailable", err)
	}
	// (c) With no custom CA, a pool failure is irrelevant (system roots used directly).
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("still failing") }
	if _, err := buildTLSConfig(Config{}); err != nil {
		t.Fatalf("buildTLSConfig without custom CA = %v, want ok", err)
	}
}

func TestAdditiveCASuccessKeepsSystemRoots(t *testing.T) {
	ca := newTestCA(t)
	// Normal path: system roots load and the custom CA is added on top (additive). The pool
	// object is the system pool (not a fresh custom-only pool), and a leaf signed by the
	// custom CA now verifies against it — proving the custom anchor was added.
	cfg, err := buildTLSConfig(Config{CustomCAs: caCerts(ca)})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatalf("RootCAs nil; expected system roots + custom CA")
	}
	leaf := ca.issueLeaf(t, []string{"host.test"}, nil).Leaf
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     cfg.RootCAs,
		DNSName:   "host.test",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("custom CA not present in additive pool: %v", err)
	}
}

// --- Finding 4 (MINOR): Retry-After honored only on 429 -----------------------

func TestRetryAfterIgnoredOn5xx(t *testing.T) {
	ackDir := newAckState(t, 3)
	p := &Planner{Store: newMemStore(t, 1, 3, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()

	var slept []time.Duration
	// A 503 carrying a large Retry-After, then success. The backoff must ignore the header
	// and use the computed equal-jitter step (base 100ms, zero jitter → 50ms).
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return &Attempt{StatusCode: 503, RetryAfter: 7 * time.Second}, nil },
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: testSourceID, AcknowledgedThroughSequence: 3, Accepted: 3}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID, Policy: RetryPolicy{
		MaxAttempts: 3, BaseDelay: 100 * time.Millisecond, Jitter: zeroJitter,
		Sleep: func(_ context.Context, dd time.Duration) error { slept = append(slept, dd); return nil },
	}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(slept) != 1 || slept[0] != 50*time.Millisecond {
		t.Fatalf("slept = %v, want [50ms] (jittered backoff, NOT the 7s 5xx Retry-After)", slept)
	}
}

func TestRetryAfterIgnoredOnTransport(t *testing.T) {
	ackDir := newAckState(t, 3)
	p := &Planner{Store: newMemStore(t, 1, 3, 0), Ack: ackDir, SourceID: testSourceID}
	plan, _, _ := p.Next()
	var slept []time.Duration
	// A transport error carries no Attempt, so there is no Retry-After to honor; the backoff
	// is the computed step.
	sender := &scriptedSender{steps: []func(Plan) (*Attempt, error){
		func(Plan) (*Attempt, error) { return nil, &TransportError{err: errors.New("reset")} },
		func(Plan) (*Attempt, error) {
			return &Attempt{StatusCode: 200, Ack: &wire.IngestAck{SourceId: testSourceID, AcknowledgedThroughSequence: 3, Accepted: 3}}, nil
		},
	}}
	d := &Deliverer{Sender: sender, Ack: ackDir, SourceID: testSourceID, Policy: RetryPolicy{
		MaxAttempts: 3, BaseDelay: 100 * time.Millisecond, Jitter: zeroJitter,
		Sleep: func(_ context.Context, dd time.Duration) error { slept = append(slept, dd); return nil },
	}}
	if err := d.Deliver(context.Background(), plan); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(slept) != 1 || slept[0] != 50*time.Millisecond {
		t.Fatalf("slept = %v, want [50ms] (computed backoff on transport)", slept)
	}
}

// --- Finding 5 (MINOR): helper WaitDelay reason is distinct + token-free ------

func TestHelperWaitDelayReasonDistinct(t *testing.T) {
	// The helper prints a valid token, backgrounds a sleep that inherits and holds stdout,
	// then exits 0. WaitDelay closes the pipe; the surfaced reason must be distinct from
	// "not executable" and must not leak the token.
	secret := "SECRET-TOKEN-waitdelay"
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sh")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%s'\nsleep 30 &\nexit 0\n", secret)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	start := time.Now()
	_, err := (HelperSource{Argv: []string{path}}).Token(context.Background())
	if !errors.Is(err, ErrHelperFailed) {
		t.Fatalf("helper = %v, want ErrHelperFailed", err)
	}
	var he *HelperError
	if !errors.As(err, &he) || he.Reason != "helper i/o not closed" {
		t.Fatalf("reason = %q, want %q", errReason(err), "helper i/o not closed")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("token leaked into WaitDelay error: %q", err.Error())
	}
	// WaitDelay (1s) bounds it; must not run to the 30s sleep.
	if time.Since(start) > 5*time.Second {
		t.Fatalf("WaitDelay not honored: took %v", time.Since(start))
	}
}

func errReason(err error) string {
	var he *HelperError
	if errors.As(err, &he) {
		return he.Reason
	}
	return err.Error()
}

// --- Finding 6 (MINOR): a 200 with a bad ack body fails closed to Hold e2e ----

func TestBadAckBodyHeldEndToEnd(t *testing.T) {
	validAck := string(ackJSON(t, testSourceID, 1, 4))
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown field", []byte(`{"source_id":"` + testSourceID + `","acknowledged_through_sequence":4,"accepted":4,"duplicates":0,"surprise":true}`)},
		{"trailing non-whitespace", []byte(validAck + "garbage")},
		{"second top-level value", []byte(validAck + `{}`)},
		{"truncated json", []byte(`{"source_id":"` + testSourceID + `","acknowledged_through_sequence":4,`)},
		{"empty body", []byte(``)},
		// Oversized: a valid ack followed by >maxResponseBytes of non-whitespace, so the
		// LimitReader-truncated body has trailing garbage → undecodable → Hold.
		{"oversized trailing garbage", append([]byte(validAck), []byte(strings.Repeat("x", int(maxResponseBytes)+64))...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			h := &recordingHandler{respond: func(int, recordedRequest) (int, http.Header, []byte) {
				return http.StatusOK, nil, body
			}}
			base := newHTTPServer(t, h)
			client := loopbackClient(t, base, staticToken("tok"))

			ackDir := newAckState(t, 4)
			p := &Planner{Store: newMemStore(t, 1, 4, 0), Ack: ackDir, SourceID: testSourceID}
			plan, _, _ := p.Next()
			d := &Deliverer{Sender: client, Ack: ackDir, SourceID: testSourceID,
				Policy: RetryPolicy{Sleep: noSleep, Jitter: zeroJitter}}

			err := d.Deliver(context.Background(), plan)
			if !errors.Is(err, ErrHeld) {
				t.Fatalf("Deliver = %v, want ErrHeld (fail closed on bad ack body)", err)
			}
			if ackDir.AcknowledgedThrough() != 0 {
				t.Fatalf("acknowledged advanced on a bad ack body")
			}
		})
	}
}
