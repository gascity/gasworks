package runwrap

import (
	"context"
	"fmt"
	"strings"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// terminalExit runs the normative terminal sequence for a child that ran to completion:
//
//	PROCESS_EXITED  ->  drained transcript records (appended by the daemon)  ->  RUN_ENDED
//
// A non-COMPLETE drain additionally emits a PARTIAL_CAPTURE diagnostic before RUN_ENDED, so
// RUN_ENDED remains the single closing boundary. The exit code rides PROCESS_EXITED as
// process evidence only; it never becomes a run outcome. The terminal reserve preallocated on
// RUN_STARTED is released only after RUN_ENDED is durable — if any terminal append is not
// durable the reserve is kept and the run stays OPEN (recovery reconciles it), because the
// wrapper never synthesizes the missing boundary.
func (r *runner) terminalExit(ctx context.Context, id wire.ProcessIdentity, exitCode int, signaled bool, signal int) (wire.RunEndedBoundaryDrainStatus, error) {
	exited, err := evidence.NewProcessLifecycle(r.common(r.cfg.clock()()), processExitInput(id, exitCode, signaled, signal))
	if err != nil {
		return "", fmt.Errorf("observer runwrap: build PROCESS_EXITED: %w", err)
	}
	if err := r.d.Append(ctx, exited); err != nil {
		return "", fmt.Errorf("observer runwrap: append PROCESS_EXITED: %w", err)
	}

	// Bounded drain through a stable watermark. A drain error is not fatal: the run still
	// closes, marked FAILED with a partial-capture diagnostic.
	drainCtx, cancel := context.WithTimeout(ctx, r.cfg.drainTimeout())
	outcome, derr := r.d.Drain(drainCtx, r.runID)
	cancel()
	if derr != nil {
		outcome = DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusFAILED}
	}

	if outcome.Status != wire.RunEndedBoundaryDrainStatusCOMPLETE {
		diag, derr := evidence.NewCaptureDiagnostic(r.common(r.cfg.clock()()), evidence.CaptureDiagnosticInput{
			Code:               wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE,
			Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
			CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
			Context:            "post-exit transcript drain did not complete",
		})
		if derr != nil {
			return outcome.Status, fmt.Errorf("observer runwrap: build partial-capture diagnostic: %w", derr)
		}
		if derr := r.d.Append(ctx, diag); derr != nil {
			return outcome.Status, fmt.Errorf("observer runwrap: append partial-capture diagnostic: %w", derr)
		}
	}

	ended, err := evidence.NewRunEndedDrain(r.common(r.cfg.clock()()), evidence.RunEndedDrainInput{
		RunID:            r.runID,
		BoundarySource:   wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		DrainStatus:      outcome.Status,
		CoveredWatermark: outcome.CoveredWatermark,
	})
	if err != nil {
		return outcome.Status, fmt.Errorf("observer runwrap: build RUN_ENDED: %w", err)
	}
	if err := r.d.Append(ctx, ended); err != nil {
		return outcome.Status, fmt.Errorf("observer runwrap: append RUN_ENDED: %w", err)
	}

	if err := r.d.ReleaseTerminal(ctx, r.runID); err != nil {
		return outcome.Status, fmt.Errorf("observer runwrap: release terminal reserve: %w", err)
	}
	return outcome.Status, nil
}

// terminalLaunchFailure runs the launch-failure terminal sequence and MUST reach RUN_ENDED +
// release on every sub-case so a failed launch never leaks the reserve or strands the run OPEN.
//
// When a real child identity was proven (the shim registered, then exec failed), the sequence is
// PROCESS_LAUNCH_FAILED then RUN_ENDED. When the launch failed BEFORE any identity was known
// (spawn/pipe/identity-read failure), the identity is the zero value — which the committed
// PROCESS_LIFECYCLE constructor rejects (boot_id must be non-empty) — so PROCESS_LAUNCH_FAILED is
// SKIPPED and the run is still closed with RUN_ENDED (launch failure, no drain) + release. The
// wrapper is alive and knows the child never launched; this is not the wrapper-crash carve-out.
//
// RUN_ENDED carries NO drain (there was no child transcript to drain). The reserve is released
// only after RUN_ENDED is durable.
func (r *runner) terminalLaunchFailure(ctx context.Context, id wire.ProcessIdentity) error {
	if id.BootId != "" {
		failed, err := evidence.NewProcessLifecycle(r.common(r.cfg.clock()()), evidence.ProcessLifecycleInput{
			Transition: wire.ProcessLifecyclePayloadTransitionPROCESSLAUNCHFAILED,
			Identity:   id,
		})
		if err != nil {
			return fmt.Errorf("observer runwrap: build PROCESS_LAUNCH_FAILED: %w", err)
		}
		if err := r.d.Append(ctx, failed); err != nil {
			return fmt.Errorf("observer runwrap: append PROCESS_LAUNCH_FAILED: %w", err)
		}
	}

	ended, err := evidence.NewRunEndedLaunchFailure(r.common(r.cfg.clock()()), evidence.RunEndedLaunchFailureInput{
		RunID:          r.runID,
		BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	if err != nil {
		return fmt.Errorf("observer runwrap: build RUN_ENDED (launch failure): %w", err)
	}
	if err := r.d.Append(ctx, ended); err != nil {
		return fmt.Errorf("observer runwrap: append RUN_ENDED (launch failure): %w", err)
	}

	if err := r.d.ReleaseTerminal(ctx, r.runID); err != nil {
		return fmt.Errorf("observer runwrap: release terminal reserve: %w", err)
	}
	return nil
}

// processExitInput encodes a terminated child as PROCESS_EXITED evidence. A signal death
// carries the signal number and no exit code; a normal exit carries the exit code and no
// signal. The reserve identity is the proven same-PID launch identity.
func processExitInput(id wire.ProcessIdentity, exitCode int, signaled bool, signal int) evidence.ProcessLifecycleInput {
	in := evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionPROCESSEXITED,
		Identity:   id,
	}
	if signaled {
		s := int32(signal)
		in.Signal = &s
	} else {
		c := int32(exitCode)
		in.ExitCode = &c
	}
	return in
}

// ---- environment helpers (RunIDEnvVar is the only variable the wrapper ever touches) ----

// withRunID returns a copy of env with RunIDEnvVar set to runID, replacing any inherited
// value so the nearest wrapper's run id is what the child sees.
func withRunID(env []string, runID string) []string {
	out := withoutRunID(env)
	return append(out, RunIDEnvVar+"="+runID)
}

// withoutRunID returns a copy of env with every RunIDEnvVar entry removed.
func withoutRunID(env []string) []string {
	prefix := RunIDEnvVar + "="
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// envLookup returns the value of key in a KEY=VALUE slice, or "" when absent.
func envLookup(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}
