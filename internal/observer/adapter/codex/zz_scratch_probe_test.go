//go:build unix

package codex

import (
	"bytes"
	"context"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// Probe: does OpensInterval / quarantine disposition ever influence the DURABLE wire bytes?
// The Builder (E1.8/S2.6) reconstructs intervals from durable observations, not the in-memory
// Decision. If a quarantined RESUME's canonical bytes carry NO run context and NO inherited run
// id, then OpensInterval cannot cause the Builder to close a prior HIGH interval any differently
// than the designed inferred/passive path — the "false merge / rewrite" harm requires a wire
// signal that does not exist.
func TestProbeQuarantineWireHasNoRunContext(t *testing.T) {
	capture := func(seam *fakeSeam) capturedObs {
		cfg := HookConfig{SourceID: "src_1", InheritedRunID: "gwr_x", HookPID: 1}
		in := hookInput{SessionID: "sess-1", CWD: "/w"}
		source := wire.SessionLifecyclePayloadStartSourceRESUME
		dec := Decide(context.Background(), seam, AttachInput{
			SourceID: cfg.SourceID, Provider: Provider, NativeSessionID: in.SessionID,
			Workspace: "/w", StartSource: source, InheritedRunID: cfg.InheritedRunID, HookPID: cfg.hookPID(),
		})
		obs, ok := buildObservation(cfg, in, source, "", dec)
		if !ok {
			t.Fatal("buildObservation failed")
		}
		if _, err := seam.CaptureSessionLifecycle(context.Background(), obs); err != nil {
			t.Fatalf("capture: %v", err)
		}
		return seam.lastAppend(t)
	}

	// Quarantine: inherited id resolves CLOSED -> quarantine, OpensInterval=true.
	qSeam := newFakeSeam()
	qSeam.resolve("gwr_x", InheritedClosed)
	qDec := Decide(context.Background(), qSeam, AttachInput{
		SourceID: "src_1", Provider: Provider, NativeSessionID: "sess-1", Workspace: "/w",
		StartSource: wire.SessionLifecyclePayloadStartSourceRESUME, InheritedRunID: "gwr_x", HookPID: 1,
	})
	if qDec.Disposition != DispositionQuarantine || !qDec.OpensInterval {
		t.Fatalf("precondition: want quarantine+OpensInterval, got disp=%v opens=%v", qDec.Disposition, qDec.OpensInterval)
	}
	q := capture(qSeam)

	// Inferred: transport error resolving -> inferred, OpensInterval=true.
	iSeam := newFakeSeam()
	iSeam.resolveErr = context.DeadlineExceeded
	i := capture(iSeam)

	// The quarantined resume's durable bytes must NOT carry the refused inherited run id nor a
	// run_context block. If it did, that would be the actual false-merge BLOCKER.
	if bytes.Contains(q.canon, []byte("gwr_x")) {
		t.Fatalf("QUARANTINE leaked the refused inherited run id onto the wire:\n%s", q.canon)
	}
	if bytes.Contains(q.canon, []byte("run_context")) {
		t.Fatalf("QUARANTINE stamped a run_context onto the wire:\n%s", q.canon)
	}
	if bytes.Contains(i.canon, []byte("run_context")) {
		t.Fatalf("INFERRED unexpectedly stamped a run_context:\n%s", i.canon)
	}
	// Both are RESUMED, run-context-free observations. The only difference the Builder can see is
	// the (identical) transition; OpensInterval is absent from the wire entirely.
	t.Logf("QUARANTINE canon (%d bytes):\n%s", len(q.canon), q.canon)
	t.Logf("INFERRED  canon (%d bytes):\n%s", len(i.canon), i.canon)
}
