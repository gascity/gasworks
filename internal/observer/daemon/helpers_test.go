//go:build linux

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// testBase is a fixed capture/occurred timestamp so sealed observations are deterministic.
var testBase = time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

// wrapperCommon mirrors the E1.6 wrapper's observation envelope: metadata-only provenance and a
// run context stamped with runID under DECLARED_BOUNDARY membership.
func wrapperCommon(runID string) evidence.Common {
	return evidence.Common{
		OccurredAt: testBase,
		CapturedAt: testBase,
		Provenance: wire.Provenance{
			Adapter:        "gasworks-wrapper",
			AdapterVersion: "0.1.0",
			ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		},
		RunContext: &wire.RunContext{
			RunId:              runID,
			MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY,
		},
	}
}

func registeredPending(t *testing.T, id wire.ProcessIdentity, runID string) evidence.PendingObservation {
	t.Helper()
	p, err := evidence.NewProcessLifecycle(wrapperCommon(runID), evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionREGISTERED,
		Identity:   id,
	})
	if err != nil {
		t.Fatalf("NewProcessLifecycle: %v", err)
	}
	return p
}

func runStartedPending(t *testing.T, runID string) evidence.PendingObservation {
	t.Helper()
	p, err := evidence.NewRunStarted(wrapperCommon(runID), evidence.RunStartedInput{
		RunID:          runID,
		BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	if err != nil {
		t.Fatalf("NewRunStarted: %v", err)
	}
	return p
}

func runEndedPending(t *testing.T, runID string) evidence.PendingObservation {
	t.Helper()
	p, err := evidence.NewRunEndedLaunchFailure(wrapperCommon(runID), evidence.RunEndedLaunchFailureInput{
		RunID:          runID,
		BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	if err != nil {
		t.Fatalf("NewRunEndedLaunchFailure: %v", err)
	}
	return p
}

// sealObs seals a pending observation with a placeholder sequence/id for folding directly (the
// registry fold ignores sequence and observation id).
func sealObs(t *testing.T, p evidence.PendingObservation, seq int64) wire.Observation {
	t.Helper()
	obs, err := p.Seal(seq, fmt.Sprintf("obs_%020d", seq))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return obs
}

func permissiveCapacity() spool.CapacityConfig {
	return spool.CapacityConfig{
		CeilingBytes:         1 << 30,
		TerminalReserveBytes: 1 << 20,
		MaxSegmentBytes:      spool.DefaultSegmentCeiling,
		ScratchBytes:         1 << 20,
		SafetyMarginRatio:    spool.MinSafetyMarginRatio,
	}
}

func newSpoolWriter(t *testing.T, dir string) *local.SpoolWriter {
	t.Helper()
	w, err := local.NewSpoolWriter(local.SpoolConfig{
		Dir:      dir,
		SourceID: "src_test",
		Capacity: permissiveCapacity(),
	})
	if err != nil {
		t.Fatalf("NewSpoolWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// startDaemonServer starts a real owner-only socket server backed by the given spool and registry,
// using a deterministic peer-uid seam so the connecting client is accepted. The spool is the
// local.Spool interface so a test can inject a fault-injecting wrapper over a real writer.
func startDaemonServer(t *testing.T, dir string, sp local.Spool, reg local.Registry) *local.Server {
	t.Helper()
	srv, err := local.NewServer(local.ServerConfig{
		Dir:      dir,
		Spool:    sp,
		Registry: reg,
		PeerUID:  func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv
}

// mustAppend durably appends one pending observation through the socket client, failing the test on
// any non-durable ack.
func mustAppend(t *testing.T, client *local.Client, p evidence.PendingObservation) {
	t.Helper()
	if _, err := client.AppendObservation(context.Background(), p); err != nil {
		t.Fatalf("AppendObservation: %v", err)
	}
}

// appendToWriter appends a sealed observation directly through the spool writer, populating the WAL
// so a later ReplayWAL can rebuild the projection. It fails the test on any non-durable ack.
func appendToWriter(t *testing.T, w *local.SpoolWriter, obs wire.Observation) {
	t.Helper()
	if _, err := w.AppendObservation(obs); err != nil {
		t.Fatalf("AppendObservation: %v", err)
	}
}
