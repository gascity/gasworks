//go:build linux || darwin

package daemon

import (
	"context"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// DaemonSeamAdapter adapts a local.Client to the codex.DaemonSeam the committed Codex hook (E1.7)
// depends on. The hook never imports internal/observer/local; this adapter is the wiring the CLI
// hands it, translating each seam call into a typed local round-trip and mapping the local wire
// status back onto the hook's InheritedResolution vocabulary. It lives in the daemon package
// precisely so the codex closure boundary stays intact.
type DaemonSeamAdapter struct {
	client *local.Client
}

// NewDaemonSeamAdapter wraps client as a codex.DaemonSeam.
func NewDaemonSeamAdapter(client *local.Client) *DaemonSeamAdapter {
	return &DaemonSeamAdapter{client: client}
}

// DaemonSeamAdapter satisfies the hook's daemon seam.
var _ codex.DaemonSeam = (*DaemonSeamAdapter)(nil)

// CaptureSessionLifecycle durably appends the SESSION_LIFECYCLE observation through the daemon and
// returns only after the local WAL fsync ack. A non-nil error means capture is NOT durable, so the
// hook surfaces its bounded capture-failure systemMessage rather than pretend success.
func (a *DaemonSeamAdapter) CaptureSessionLifecycle(ctx context.Context, obs codex.PendingObservation) (codex.CaptureAck, error) {
	ack, err := a.client.CaptureObservation(ctx, obs)
	if err != nil {
		return codex.CaptureAck{}, err
	}
	return codex.CaptureAck{Sequence: ack.Sequence}, nil
}

// LookupRegisteredProcess asks the daemon registry whether id was registered by a wrapper and, if
// so, the run it opened. found=false is the ordinary miss; err is reserved for a transport/query
// failure. The identity is echoed from the request onto the returned ancestor, since the wire
// answer carries only the run.
func (a *DaemonSeamAdapter) LookupRegisteredProcess(ctx context.Context, id wire.ProcessIdentity) (codex.RegisteredAncestor, bool, error) {
	runID, found, err := a.client.LookupRegisteredProcess(ctx, id)
	if err != nil {
		return codex.RegisteredAncestor{}, false, err
	}
	if !found {
		return codex.RegisteredAncestor{}, false, nil
	}
	return codex.RegisteredAncestor{Identity: id, RunID: runID}, true, nil
}

// ResolveInheritedRun classifies how runID resolves in this source's boundary index, mapping the
// local wire status onto the hook's InheritedResolution. A transport/query failure returns err.
func (a *DaemonSeamAdapter) ResolveInheritedRun(ctx context.Context, runID, workspace string) (codex.InheritedResolution, error) {
	status, err := a.client.ResolveInheritedRun(ctx, runID, workspace)
	if err != nil {
		return codex.InheritedResolution{}, err
	}
	return codex.InheritedResolution{Status: inheritedStatus(status)}, nil
}

// inheritedStatus maps the local wire classification onto the codex hook's InheritedStatus. An
// unrecognized status maps to InheritedUnknown — the safe fail-closed default (a quarantine
// input), so a future wire value can never be silently read as a trustworthy attachment.
func inheritedStatus(s local.InheritedRunStatus) codex.InheritedStatus {
	switch s {
	case local.InheritedRunOpenSameScope:
		return codex.InheritedOpenSameScope
	case local.InheritedRunClosed:
		return codex.InheritedClosed
	case local.InheritedRunCrossWorkspace:
		return codex.InheritedCrossWorkspace
	default:
		return codex.InheritedUnknown
	}
}
