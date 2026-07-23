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
	registered  map[wire.ProcessIdentity]string
	statuses    map[string]InheritedRunStatus
	folded      []wire.Observation
	sessionRuns map[string]string
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

func (f *fakeRegistry) BindSession(nativeSessionID, runID string) {
	if f.sessionRuns == nil {
		f.sessionRuns = map[string]string{}
	}
	f.sessionRuns[nativeSessionID] = runID
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

// TestBindSessionRoundTrip proves the wrapper's bind-session verb round-trips through the server
// into the registry: the client's BindSession records a native-session→run mapping the daemon's
// sink later reads to stamp run_context. This is the explicit-run usage-binding seam.
func TestBindSessionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w := newWriter(t, dir, nil)
	reg := &fakeRegistry{}
	srv := startServer(t, ServerConfig{
		Dir:      dir,
		Spool:    w,
		Registry: reg,
		PeerUID:  func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	client := NewClient(srv.SocketPath())

	if err := client.BindSession(context.Background(), "sess-native-01", "run_bead01"); err != nil {
		t.Fatalf("BindSession: %v", err)
	}
	if got := reg.sessionRuns["sess-native-01"]; got != "run_bead01" {
		t.Fatalf("registry recorded run %q for the session, want run_bead01", got)
	}
}

// TestNewKindsRegistryUnavailableContentFree proves the three registry-backed kinds return a
// content-free error code when no registry is wired in, and the surfaced error leaks no path.
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

	err = client.BindSession(ctx, "sess", "run_1")
	assertServerCode(t, err, CodeBindFailed, dir)
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
	// BIND with no body / empty native_session_id / empty run_id.
	if _, err := DecodeRequest([]byte(`{"kind":"BIND_SESSION"}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("bind without body: err = %v, want ErrMalformedRequest", err)
	}
	if _, err := DecodeRequest([]byte(`{"kind":"BIND_SESSION","bind_session":{"native_session_id":"","run_id":"r"}}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("bind with empty native_session_id: err = %v, want ErrMalformedRequest", err)
	}
	if _, err := DecodeRequest([]byte(`{"kind":"BIND_SESSION","bind_session":{"native_session_id":"s","run_id":""}}`)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("bind with empty run_id: err = %v, want ErrMalformedRequest", err)
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
