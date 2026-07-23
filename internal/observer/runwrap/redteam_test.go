//go:build unix

package runwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestLaunchFailureBeforeIdentityClosesAndReleases (red-team finding 0+1, BLOCKER) proves that
// when the launch fails BEFORE the child identity is known — the identity is the zero value that
// the committed PROCESS_LIFECYCLE constructor rejects — the wrapper still durably closes the run
// with RUN_ENDED, releases the terminal reserve (back to zero on the real spool.Reserves), leaves
// the run CLOSED (not stranded OPEN), and surfaces the REAL cause rather than the constructor
// error. Exercised over two real sub-cases: a spawn failure and an identity-read failure.
func TestLaunchFailureBeforeIdentityClosesAndReleases(t *testing.T) {
	cases := []struct {
		name string
		shim func(t *testing.T) ShimSpec
	}{
		{
			name: "spawn-fail",
			shim: func(t *testing.T) ShimSpec {
				return ShimSpec{Path: filepath.Join(t.TempDir(), "nonexistent-shim-binary")}
			},
		},
		{
			name: "identity-read-fail",
			// A stand-in "shim" that exits without ever writing the identity, so the parent's
			// identity read fails with the zero identity.
			shim: func(t *testing.T) ShimSpec {
				return ShimSpec{Path: shPath(t), PrefixArgs: []string{"-c", "exit 0"}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newSpoolDaemon(t, capacityConfig())
			cfg := baseConfig(childExit(t, 0)...)
			cfg.Shim = tc.shim(t)

			res, err := Run(context.Background(), d, cfg)
			if err == nil {
				t.Fatal("expected a launch failure error")
			}
			var be *evidence.BuildError
			if errors.As(err, &be) {
				t.Fatalf("Run surfaced the constructor error, not the real spawn/identity cause: %v", err)
			}
			// Zero identity => no PROCESS_LAUNCH_FAILED, but the run is still closed.
			assertLabels(t, d.labels(), []string{"RUN_STARTED", "RUN_ENDED"})
			if d.openReserveBytes() != 0 {
				t.Fatalf("terminal reserve leaked: %d bytes still open", d.openReserveBytes())
			}
			if res.RunID != "" && d.isOpen(res.RunID) {
				t.Fatalf("run %q left OPEN after a pre-identity launch failure", res.RunID)
			}
		})
	}
}

// TestReadLaunchStatusClassification (red-team finding 2, MAJOR) proves launch success is
// POSITIVELY asserted by the pre-exec marker, never inferred from a bare EOF: a marker-less EOF
// (pre-exec death) is a launch failure, and only marker-then-EOF is a launched run.
func TestReadLaunchStatusClassification(t *testing.T) {
	id := wire.ProcessIdentity{BootId: "b", Pid: 1, ProcessStartTime: 1}
	cases := []struct {
		name     string
		bytes    []byte
		launched bool
	}{
		{"marker-then-eof-is-launched", []byte{shimStatusPreExec}, true},
		{"bare-eof-is-preexec-death", nil, false},
		{"exec-failed-first", []byte{shimStatusExecFailed}, false},
		{"marker-then-exec-failed", []byte{shimStatusPreExec, shimStatusExecFailed}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lerr := readLaunchStatus(bytes.NewReader(tc.bytes), id)
			if tc.launched && lerr != nil {
				t.Fatalf("want launched, got launch failure: %v", lerr)
			}
			if !tc.launched && lerr == nil {
				t.Fatal("want launch failure, got launched")
			}
		})
	}
}

// TestLaunchPreExecDeathNotLaunched (red-team finding 2, MAJOR) is the real-subprocess proof: a
// shim SIGKILLed squarely in the post-ack / pre-execve window is classified as a launch failure
// (PROCESS_LAUNCH_FAILED then RUN_ENDED, reserve released) and NEVER as a launched run with a
// spurious PROCESS_EXITED.
func TestLaunchPreExecDeathNotLaunched(t *testing.T) {
	hangFile := filepath.Join(t.TempDir(), "shim.pid")
	d := newSpoolDaemon(t, capacityConfig())
	cfg := baseConfig(childExit(t, 0)...)
	cfg.Shim = ShimSpec{ExtraEnv: []string{
		"RUNWRAP_HELPER_MODE=shim",
		"RUNWRAP_SHIM_PREEXEC_HANG=" + hangFile,
	}}

	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := Run(context.Background(), d, cfg)
		done <- outcome{r, e}
	}()

	pid := waitForPidFile(t, hangFile, 10*time.Second)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill shim pid %d: %v", pid, err)
	}

	var got outcome
	select {
	case got = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the shim was killed in the pre-exec window")
	}
	if got.err == nil {
		t.Fatal("a pre-exec shim death must be a launch failure")
	}
	labels := d.labels()
	assertLabels(t, labels, []string{"RUN_STARTED", "REGISTERED", "PROCESS_LAUNCH_FAILED", "RUN_ENDED"})
	for _, l := range labels {
		if l == "PROCESS_EXITED" {
			t.Fatal("pre-exec death was misclassified as launched (spurious PROCESS_EXITED)")
		}
	}
	if d.openReserveBytes() != 0 {
		t.Fatalf("terminal reserve leaked after pre-exec death: %d bytes", d.openReserveBytes())
	}
}

// TestReadIdentityRejectsIncomplete (red-team finding 3, MINOR) proves the parent never registers
// an identity missing its pid-reuse-disambiguating component: a zero (or negative)
// process_start_time is rejected alongside an empty boot id and a non-positive pid.
func TestReadIdentityRejectsIncomplete(t *testing.T) {
	bad := []wire.ProcessIdentity{
		{BootId: "b", Pid: 5, ProcessStartTime: 0},
		{BootId: "b", Pid: 5, ProcessStartTime: -1},
		{BootId: "", Pid: 5, ProcessStartTime: 5},
		{BootId: "b", Pid: 0, ProcessStartTime: 5},
	}
	for _, id := range bad {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(id); err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := readIdentity(&buf); err == nil {
			t.Fatalf("readIdentity accepted an incomplete identity: %+v", id)
		}
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(wire.ProcessIdentity{BootId: "b", Pid: 5, ProcessStartTime: 5}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := readIdentity(&buf); err != nil {
		t.Fatalf("readIdentity rejected a complete identity: %v", err)
	}
}

func waitForPidFile(t *testing.T, path string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for shim pid file %s", path)
	return 0
}
