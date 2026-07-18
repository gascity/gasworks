//go:build linux

package local

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// fakeRegistry is a deterministic in-test Registry so the local layer's two new query kinds can be
// exercised without the daemon package (which imports local).
type fakeRegistry struct {
	registered map[wire.ProcessIdentity]string
	statuses   map[string]InheritedRunStatus
	folded     []wire.Observation
}

func (f *fakeRegistry) Fold(obs wire.Observation) error {
	f.folded = append(f.folded, obs)
	return nil
}

func (f *fakeRegistry) LookupRegistered(id wire.ProcessIdentity) (string, bool) {
	runID, ok := f.registered[id]
	return runID, ok
}

func (f *fakeRegistry) ResolveInherited(runID, _ string) InheritedRunStatus {
	if s, ok := f.statuses[runID]; ok {
		return s
	}
	return InheritedRunUnknown
}

// TestLookupResolveRoundTripWithRegistry proves the two new client methods round-trip through the
// server against an injected registry: a registered id returns its run, an unknown id returns
// found=false (not an error), and each inherited-run status crosses the wire intact.
func TestLookupResolveRoundTripWithRegistry(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	id := wire.ProcessIdentity{BootId: "boot-1", Pid: 10, ProcessStartTime: 20}
	reg := &fakeRegistry{
		registered: map[wire.ProcessIdentity]string{id: "run_open"},
		statuses: map[string]InheritedRunStatus{
			"run_open":   InheritedRunOpenSameScope,
			"run_closed": InheritedRunClosed,
			"run_cross":  InheritedRunCrossWorkspace,
		},
	}
	srv := startServer(t, ServerConfig{
		Dir:      dir,
		Spool:    w,
		Registry: reg,
		PeerUID:  func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	client := NewClient(srv.SocketPath())
	ctx := context.Background()

	if runID, found, err := client.LookupRegisteredProcess(ctx, id); err != nil || !found || runID != "run_open" {
		t.Fatalf("LookupRegisteredProcess(registered) = (%q,%v,%v), want (run_open,true,nil)", runID, found, err)
	}
	other := wire.ProcessIdentity{BootId: "boot-2", Pid: 11, ProcessStartTime: 21}
	if runID, found, err := client.LookupRegisteredProcess(ctx, other); err != nil || found || runID != "" {
		t.Fatalf("LookupRegisteredProcess(unknown) = (%q,%v,%v), want (\"\",false,nil)", runID, found, err)
	}

	for runID, want := range map[string]InheritedRunStatus{
		"run_open":    InheritedRunOpenSameScope,
		"run_closed":  InheritedRunClosed,
		"run_cross":   InheritedRunCrossWorkspace,
		"run_missing": InheritedRunUnknown,
	} {
		got, err := client.ResolveInheritedRun(ctx, runID, "ws_main")
		if err != nil {
			t.Fatalf("ResolveInheritedRun(%s): %v", runID, err)
		}
		if got != want {
			t.Fatalf("ResolveInheritedRun(%s) = %q, want %q", runID, got, want)
		}
	}
}

// TestNewKindsRegistryUnavailableContentFree proves the two new kinds return a content-free error
// code when no registry is wired in, and the surfaced error leaks no filesystem path.
func TestNewKindsRegistryUnavailableContentFree(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	srv := startServer(t, ServerConfig{
		Dir:     dir,
		Spool:   w,
		PeerUID: func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	client := NewClient(srv.SocketPath())
	ctx := context.Background()

	_, _, err := client.LookupRegisteredProcess(ctx, wire.ProcessIdentity{BootId: "b", Pid: 1, ProcessStartTime: 1})
	assertServerCode(t, err, CodeLookupFailed, dir)

	_, err = client.ResolveInheritedRun(ctx, "run_1", "ws")
	assertServerCode(t, err, CodeResolveFailed, dir)
}

// TestNewKindDecodeFailsClosed proves a malformed body for each new kind is rejected fail-closed by
// the strict decoder, never accepted as a partial value.
func TestNewKindDecodeFailsClosed(t *testing.T) {
	// LOOKUP with no body / empty boot_id.
	if _, err := DecodeRequest([]byte(`{"kind":"LOOKUP_REGISTERED_PROCESS"}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("lookup without body: err = %v, want ErrMalformedRequest", err)
	}
	if _, err := DecodeRequest([]byte(`{"kind":"LOOKUP_REGISTERED_PROCESS","lookup_registered":{"identity":{"boot_id":"","pid":1,"process_start_time":1}}}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("lookup with empty boot_id: err = %v, want ErrMalformedRequest", err)
	}
	// RESOLVE with no body / empty run_id.
	if _, err := DecodeRequest([]byte(`{"kind":"RESOLVE_INHERITED_RUN"}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("resolve without body: err = %v, want ErrMalformedRequest", err)
	}
	if _, err := DecodeRequest([]byte(`{"kind":"RESOLVE_INHERITED_RUN","resolve_inherited":{"run_id":"","workspace":"w"}}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("resolve with empty run_id: err = %v, want ErrMalformedRequest", err)
	}
	// An unknown field on a new body is rejected (strict decode).
	if _, err := DecodeRequest([]byte(`{"kind":"RESOLVE_INHERITED_RUN","resolve_inherited":{"run_id":"r","workspace":"w","extra":1}}`)); err == nil {
		t.Errorf("resolve with unknown field: want a strict-decode error, got nil")
	}
}

func assertServerCode(t *testing.T, err error, wantCode, dir string) {
	t.Helper()
	if err == nil || !errors.Is(err, ErrServerError) {
		t.Fatalf("err = %v, want a server error", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, wantCode) {
		t.Fatalf("error %q missing code %q", msg, wantCode)
	}
	if strings.Contains(msg, dir) {
		t.Fatalf("error %q leaks a path", msg)
	}
}
