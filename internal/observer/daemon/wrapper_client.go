//go:build linux

package daemon

import (
	"context"
	"fmt"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// WrapperDaemonClient adapts the owner-only local socket client to the runwrap.DaemonClient seam
// the explicit-run wrapper (E1.6) reserves, appends, and releases through. runwrap deliberately
// never imports the socket package, so this adapter — living in the daemon wiring layer — is what
// the `run` CLI hands it. It maps each seam call onto a typed local round-trip.
type WrapperDaemonClient struct {
	client *local.Client
}

// NewWrapperDaemonClient wraps client as a runwrap.DaemonClient.
func NewWrapperDaemonClient(client *local.Client) *WrapperDaemonClient {
	return &WrapperDaemonClient{client: client}
}

// WrapperDaemonClient satisfies the wrapper's daemon seam.
var _ runwrap.DaemonClient = (*WrapperDaemonClient)(nil)

// ReserveTerminal reserves the run's terminal capacity before RUN_STARTED. The local daemon
// reserves and then reports whether a new explicit run is admissible under the byte ceiling; under
// hard pressure the reserve is undone and runwrap.ErrCapacityRefused is returned so the wrapper
// refuses the run before any boundary is written, leaving nothing reserved.
func (a *WrapperDaemonClient) ReserveTerminal(ctx context.Context, runID string) error {
	ack, err := a.client.ReserveRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("observer daemon: reserve terminal: %w", err)
	}
	if !ack.AdmitNewRun {
		// Hard capacity pressure: release the speculative reserve and refuse, so the failed
		// admission reserves nothing (the wrapper's ReserveTerminal contract).
		_, _ = a.client.ReleaseRun(ctx, runID)
		return runwrap.ErrCapacityRefused
	}
	return nil
}

// Append durably appends one pending observation, returning only after the WAL fsync ack. A
// non-nil error means the observation is NOT durable.
func (a *WrapperDaemonClient) Append(ctx context.Context, obs evidence.PendingObservation) error {
	if _, err := a.client.AppendObservation(ctx, obs); err != nil {
		return err
	}
	return nil
}

// Drain reports a completed drain with an empty covered watermark. The pilot local daemon exposes
// no synchronous post-exit transcript-drain kind on the socket protocol (E1.5): transcript records
// are ingested asynchronously by the always-running watcher, not pulled through the wrapper. The
// wrapper therefore closes the run with drain_status COMPLETE — nothing is owed synchronously —
// rather than fabricating a partial-capture diagnostic on every wrapped run.
func (a *WrapperDaemonClient) Drain(ctx context.Context, runID string) (runwrap.DrainOutcome, error) {
	return runwrap.DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
}

// ReleaseTerminal frees the run's terminal reserve after RUN_ENDED is durable.
func (a *WrapperDaemonClient) ReleaseTerminal(ctx context.Context, runID string) error {
	if _, err := a.client.ReleaseRun(ctx, runID); err != nil {
		return err
	}
	return nil
}
