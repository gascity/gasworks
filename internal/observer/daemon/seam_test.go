//go:build linux

package daemon

import (
	"context"
	"testing"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// compile-time proof the adapter satisfies the committed hook seam.
var _ codex.DaemonSeam = (*DaemonSeamAdapter)(nil)

// TestDaemonSeamAdapterRoundTrips drives the two new protocol round-trips end to end over a real
// socket, a real WAL, and a real registry: appends REGISTERED/RUN_STARTED/RUN_ENDED through the
// socket (the server folds them), then queries the ancestry and boundary indexes through the seam
// adapter the committed hook uses.
func TestDaemonSeamAdapterRoundTrips(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	reg := NewRegistry("src_test", "ws_main")
	srv := startDaemonServer(t, dir, w, reg)
	client := local.NewClient(srv.SocketPath())
	ctx := context.Background()

	id := wire.ProcessIdentity{BootId: "boot-abc", Pid: 4242, ProcessStartTime: 777}
	mustAppend(t, client, registeredPending(t, id, "run_open"))
	mustAppend(t, client, runStartedPending(t, "run_open"))
	mustAppend(t, client, runStartedPending(t, "run_closed"))
	mustAppend(t, client, runEndedPending(t, "run_closed"))

	adapter := NewDaemonSeamAdapter(client)

	// A registered id looked up returns its run, with the identity echoed onto the ancestor.
	anc, found, err := adapter.LookupRegisteredProcess(ctx, id)
	if err != nil {
		t.Fatalf("LookupRegisteredProcess(registered): %v", err)
	}
	if !found || anc.RunID != "run_open" || anc.Identity != id {
		t.Fatalf("LookupRegisteredProcess = (%+v, %v), want run_open + echoed identity", anc, found)
	}

	// An unknown id returns found=false, NOT an error.
	unknown := wire.ProcessIdentity{BootId: "boot-nope", Pid: 1, ProcessStartTime: 1}
	if _, found, err := adapter.LookupRegisteredProcess(ctx, unknown); err != nil || found {
		t.Fatalf("LookupRegisteredProcess(unknown) = (found=%v, err=%v), want (false, nil)", found, err)
	}

	// The inherited-run resolver classifies all four cases correctly.
	cases := []struct {
		name      string
		runID     string
		workspace string
		want      codex.InheritedStatus
	}{
		{"open same scope", "run_open", "ws_main", codex.InheritedOpenSameScope},
		{"open cross workspace", "run_open", "ws_other", codex.InheritedCrossWorkspace},
		{"closed", "run_closed", "ws_main", codex.InheritedClosed},
		{"unknown", "run_absent", "ws_main", codex.InheritedUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := adapter.ResolveInheritedRun(ctx, tc.runID, tc.workspace)
			if err != nil {
				t.Fatalf("ResolveInheritedRun: %v", err)
			}
			if res.Status != tc.want {
				t.Fatalf("ResolveInheritedRun status = %v, want %v", res.Status, tc.want)
			}
		})
	}
}

// TestSeamAdapterFeedsCommittedDecide proves the adapter is drop-in for codex.Decide: an inherited
// run that resolves OPEN in the same workspace yields a HIGH inherited-run-id attachment.
func TestSeamAdapterFeedsCommittedDecide(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	reg := NewRegistry("src_test", "ws_main")
	srv := startDaemonServer(t, dir, w, reg)
	client := local.NewClient(srv.SocketPath())
	ctx := context.Background()

	mustAppend(t, client, runStartedPending(t, "run_open"))
	adapter := NewDaemonSeamAdapter(client)

	dec := codex.Decide(ctx, adapter, codex.AttachInput{
		SourceID:        "src_test",
		Provider:        "codex",
		NativeSessionID: "sess-1",
		Workspace:       "ws_main",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		InheritedRunID:  "run_open",
		HookPID:         1, // no proven lineage; the inherited proof stands on its own
	})
	if dec.Disposition != codex.DispositionAttachHigh || dec.RunID != "run_open" {
		t.Fatalf("Decide = %+v, want AttachHigh on run_open", dec)
	}
	if dec.Membership != wire.RunContextMembershipEvidenceINHERITEDRUNID {
		t.Fatalf("membership = %v, want INHERITED_RUN_ID", dec.Membership)
	}
}

// TestRegistryUnavailableCodesAreContentFree proves the two new kinds surface a content-free error
// code (no path leak) when the daemon has no registry wired in.
func TestRegistryUnavailableCodesAreContentFree(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, nil) // no registry
	client := local.NewClient(srv.SocketPath())
	ctx := context.Background()

	_, _, err := client.LookupRegisteredProcess(ctx, wire.ProcessIdentity{BootId: "boot-1", Pid: 1, ProcessStartTime: 1})
	assertContentFreeServerError(t, err, local.CodeLookupFailed, dir)

	_, err = client.ResolveInheritedRun(ctx, "run_1", "ws_main")
	assertContentFreeServerError(t, err, local.CodeResolveFailed, dir)
}

func assertContentFreeServerError(t *testing.T, err error, wantCode, dir string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	msg := err.Error()
	if !contains(msg, wantCode) {
		t.Fatalf("error %q does not carry expected code %q", msg, wantCode)
	}
	if contains(msg, dir) || contains(msg, "/") {
		t.Fatalf("error %q leaks a path", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
