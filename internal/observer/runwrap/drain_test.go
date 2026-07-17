package runwrap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestDrainTimeoutClamp proves the drain bound is the 2s default and is configurable only
// downward: a larger value is clamped to the default, a smaller positive value is honored, and
// a non-positive value selects the default.
func TestDrainTimeoutClamp(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, DefaultDrainTimeout},
		{-5 * time.Second, DefaultDrainTimeout},
		{5 * time.Second, DefaultDrainTimeout},
		{200 * time.Millisecond, 200 * time.Millisecond},
		{DefaultDrainTimeout, DefaultDrainTimeout},
	}
	for _, c := range cases {
		if got := (Config{DrainTimeout: c.in}).drainTimeout(); got != c.want {
			t.Fatalf("drainTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestTerminalOrderParserLag proves parser-lagged transcript records that the daemon drains
// after child exit land in the authoritative run in the normative order — PROCESS_EXITED, then
// the drained records, then RUN_ENDED — with a COMPLETE drain and no partial-capture diagnostic.
func TestTerminalOrderParserLag(t *testing.T) {
	d := newRecordingDaemon()
	d.drainFn = func(_ context.Context, dd *recordingDaemon, runID string) (DrainOutcome, error) {
		if err := dd.appendTranscript(runID, wire.MessagePayloadRoleASSISTANT); err != nil {
			return DrainOutcome{}, err
		}
		if err := dd.appendTranscript(runID, wire.MessagePayloadRoleASSISTANT); err != nil {
			return DrainOutcome{}, err
		}
		return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
	}
	res, err := Run(context.Background(), d, baseConfig(childExit(t, 0)...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertLabels(t, d.labels(), []string{
		"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "MESSAGE", "MESSAGE", "RUN_ENDED",
	})
	if res.DrainStatus != wire.RunEndedBoundaryDrainStatusCOMPLETE {
		t.Fatalf("drain status = %q, want COMPLETE", res.DrainStatus)
	}
	if s := runEndedDrainStatus(t, d); s != "COMPLETE" {
		t.Fatalf("RUN_ENDED drain_status = %q, want COMPLETE", s)
	}
}

// TestTerminalPartialTimeout proves a bounded drain that does not complete closes the run
// PARTIAL_TIMEOUT with a partial-capture diagnostic emitted before RUN_ENDED, and that the drain
// honored the wrapper's bounded (downward-configured) deadline rather than blocking unboundedly.
func TestTerminalPartialTimeout(t *testing.T) {
	d := newRecordingDaemon()
	d.drainFn = func(ctx context.Context, _ *recordingDaemon, _ string) (DrainOutcome, error) {
		<-ctx.Done() // respect the wrapper's bounded deadline
		return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusPARTIALTIMEOUT}, nil
	}
	cfg := baseConfig(childExit(t, 0)...)
	cfg.DrainTimeout = 100 * time.Millisecond
	start := time.Now()
	res, err := Run(context.Background(), d, cfg)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("drain was not bounded by the configured deadline: took %v", elapsed)
	}
	assertLabels(t, d.labels(), []string{
		"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "CAPTURE_DIAGNOSTIC:PARTIAL_CAPTURE", "RUN_ENDED",
	})
	if res.DrainStatus != wire.RunEndedBoundaryDrainStatusPARTIALTIMEOUT {
		t.Fatalf("drain status = %q, want PARTIAL_TIMEOUT", res.DrainStatus)
	}
	if s := runEndedDrainStatus(t, d); s != "PARTIAL_TIMEOUT" {
		t.Fatalf("RUN_ENDED drain_status = %q, want PARTIAL_TIMEOUT", s)
	}
	if !d.released {
		t.Fatal("reserve not released after a partial-timeout close")
	}
}

// TestTerminalDrainFailed proves a drain error closes the run FAILED with a partial-capture
// diagnostic, still in the normative order, and still with an UNKNOWN run outcome.
func TestTerminalDrainFailed(t *testing.T) {
	d := newRecordingDaemon()
	d.drainFn = func(_ context.Context, _ *recordingDaemon, _ string) (DrainOutcome, error) {
		return DrainOutcome{}, errors.New("provider file vanished")
	}
	res, err := Run(context.Background(), d, baseConfig(childExit(t, 0)...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertLabels(t, d.labels(), []string{
		"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "CAPTURE_DIAGNOSTIC:PARTIAL_CAPTURE", "RUN_ENDED",
	})
	if res.DrainStatus != wire.RunEndedBoundaryDrainStatusFAILED {
		t.Fatalf("drain status = %q, want FAILED", res.DrainStatus)
	}
	if s := runEndedDrainStatus(t, d); s != "FAILED" {
		t.Fatalf("RUN_ENDED drain_status = %q, want FAILED", s)
	}
}

func runEndedDrainStatus(t *testing.T, d *recordingDaemon) string {
	t.Helper()
	for _, a := range d.appends {
		if a.label != "RUN_ENDED" {
			continue
		}
		var p struct {
			RunBoundary struct {
				DrainStatus string `json:"drain_status"`
			} `json:"run_boundary"`
		}
		if err := json.Unmarshal(a.bytes, &p); err != nil {
			t.Fatalf("unmarshal RUN_ENDED: %v", err)
		}
		return p.RunBoundary.DrainStatus
	}
	t.Fatal("no RUN_ENDED recorded")
	return ""
}
