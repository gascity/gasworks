//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/runwrap"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestMain mirrors main's shim guard: when the wrapper re-execs THIS test binary as the same-PID
// identity shim (RUNWRAP_SHIM set), it dispatches to runwrap.RunShim before running any test, so the
// real subprocess run tests exercise the production re-exec path.
func TestMain(m *testing.M) {
	if os.Getenv(shimEnvVar) != "" {
		if err := runwrap.RunShim(); err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func permissiveCap() spool.CapacityConfig {
	return spool.CapacityConfig{
		CeilingBytes:         1 << 30,
		TerminalReserveBytes: 1 << 20,
		MaxSegmentBytes:      spool.DefaultSegmentCeiling,
		ScratchBytes:         1 << 20,
		SafetyMarginRatio:    spool.MinSafetyMarginRatio,
	}
}

func TestObserverSocketPathRejectsUnmanagedDirectory(t *testing.T) {
	stateDir := t.TempDir()
	_, err := observerSocketPath(filepath.Join(t.TempDir(), "socket"), stateDir)
	if err == nil || !strings.Contains(err.Error(), "dedicated runtime directory") {
		t.Fatalf("observerSocketPath error = %v, want dedicated runtime directory refusal", err)
	}
}

// startBareDaemon starts an assembled endpoint with only the socket server (no uploader/watcher) so
// the run/hook subcommands have a real daemon to reserve/append/release through.
func startBareDaemon(t *testing.T, dir string) *daemon.Service {
	t.Helper()
	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:               dir,
		SourceID:          "src_cmd_test",
		Capacity:          permissiveCap(),
		RegistrySource:    "src_cmd_test",
		RegistryWorkspace: "ws",
		PeerUID:           func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})
	return svc
}

// walLabels reads every durable WAL frame under dir and classifies it by its most specific
// transition/kind, so the terminal-order assertions can find RUN_STARTED/REGISTERED/PROCESS_EXITED/
// RUN_ENDED.
func walLabels(t *testing.T, dir string) []string {
	t.Helper()
	recs, err := upload.SpoolFrameStore{Dir: dir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, classify(rec.Payload))
	}
	return out
}

func classify(payload []byte) string {
	var p struct {
		Kind        string `json:"kind"`
		RunBoundary *struct {
			Transition string `json:"transition"`
		} `json:"run_boundary"`
		ProcessLifecycle *struct {
			Transition string `json:"transition"`
		} `json:"process_lifecycle"`
	}
	_ = json.Unmarshal(payload, &p)
	switch {
	case p.RunBoundary != nil && p.RunBoundary.Transition != "":
		return p.RunBoundary.Transition
	case p.ProcessLifecycle != nil && p.ProcessLifecycle.Transition != "":
		return p.ProcessLifecycle.Transition
	default:
		return p.Kind
	}
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// TestDeclareWorkAppendsCurrentExplicitRunReferenceEndToEnd proves the dynamic claim-time
// command uses only the wrapper-authored GASWORKS_RUN_ID and durably appends the exact
// (project, bead) tuple as a DECLARED work reference through the real local daemon.
func TestDeclareWorkAppendsCurrentExplicitRunReferenceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	startBareDaemon(t, dir)
	t.Setenv(runwrap.RunIDEnvVar, "gwr_declared_test")

	code := dispatch([]string{
		"declare-work",
		"-dir", dir,
		"-beads-project", "prj_test",
		"-work-item", "mc-test",
	})
	if code != 0 {
		t.Fatalf("declare-work exit code = %d, want 0", code)
	}

	recs, err := upload.SpoolFrameStore{Dir: dir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("durable WAL frames = %d, want 1", len(recs))
	}
	var obs wire.Observation
	if err := obs.UnmarshalJSON(recs[0].Payload); err != nil {
		t.Fatalf("decode durable observation: %v", err)
	}
	work, err := obs.AsWorkReferenceObservation()
	if err != nil {
		t.Fatalf("decode durable work reference: %v", err)
	}
	if got := work.WorkReference; got.TeamServerProjectId != "prj_test" ||
		got.BeadId != "mc-test" || got.Origin != wire.WorkReferenceOriginDECLARED {
		t.Fatalf("work reference = %+v, want exact DECLARED project/bead tuple", got)
	}
	if work.RunContext == nil || work.RunContext.RunId != "gwr_declared_test" ||
		work.RunContext.MembershipEvidence != wire.RunContextMembershipEvidenceDECLAREDBOUNDARY {
		t.Fatalf("run context = %+v, want current explicit run with DECLARED_BOUNDARY", work.RunContext)
	}
	if work.Provenance.Adapter != "gasworks-wrapper" ||
		work.Provenance.ContentPolicy != wire.ProvenanceContentPolicyMETADATAONLY {
		t.Fatalf("provenance = %+v, want wrapper METADATA_ONLY provenance", work.Provenance)
	}
}

// TestDeclareWorkRejectsMissingExplicitRun proves an unwrapped process cannot manufacture a
// dynamic association: without GASWORKS_RUN_ID the command fails before contacting the daemon.
func TestDeclareWorkRejectsMissingExplicitRun(t *testing.T) {
	dir := t.TempDir()
	startBareDaemon(t, dir)
	t.Setenv(runwrap.RunIDEnvVar, "")

	code := dispatch([]string{
		"declare-work",
		"-dir", dir,
		"-beads-project", "prj_test",
		"-work-item", "mc-test",
	})
	if code == 0 {
		t.Fatal("declare-work without GASWORKS_RUN_ID succeeded")
	}

	recs, err := upload.SpoolFrameStore{Dir: dir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("durable WAL frames = %d, want 0", len(recs))
	}
}

func TestDeclareWorkRequiresCompleteProjectAndBeadTuple(t *testing.T) {
	for _, args := range [][]string{
		{"declare-work", "-beads-project", "prj_test"},
		{"declare-work", "-work-item", "mc-test"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Setenv(runwrap.RunIDEnvVar, "gwr_declared_test")
			if code := dispatch(args); code != 2 {
				t.Fatalf("dispatch(%v) exit code = %d, want usage error 2", args, code)
			}
		})
	}
}

func shPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	return p
}

// TestRunObservedEndToEnd wraps a child command through the `run` subcommand against a real daemon.
// It proves the durable boundary sequence lands (RUN_STARTED, REGISTERED — which proves the
// RUNWRAP_SHIM re-exec dispatched, PROCESS_EXITED, RUN_ENDED), and the child exit code passes
// through.
func TestRunObservedEndToEnd(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir()
	svc := startBareDaemon(t, dir)

	code := runRun([]string{"-dir", dir, "--", sh, "-c", "exit 7"})
	if code != 7 {
		t.Fatalf("run exit code = %d, want 7 (child exit passes through)", code)
	}
	// The daemon appended the whole boundary sequence durably.
	labels := walLabels(t, filepath.Dir(svc.SocketPath()))
	for _, want := range []string{"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "RUN_ENDED"} {
		if !containsLabel(labels, want) {
			t.Fatalf("durable WAL missing %s; got %v", want, labels)
		}
	}
}

func TestRunObservedUsesExplicitRuntimeSocket(t *testing.T) {
	sh := shPath(t)
	stateDir := t.TempDir()
	socketPath := filepath.Join(
		t.TempDir(),
		"gasworks-observer-"+strconv.Itoa(os.Geteuid()),
		"socket",
	)
	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:               stateDir,
		SocketPath:        socketPath,
		SourceID:          "src_cmd_socket",
		Capacity:          permissiveCap(),
		RegistrySource:    "src_cmd_socket",
		RegistryWorkspace: "ws",
		PeerUID:           func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })

	code := runRun([]string{"-dir", stateDir, "-socket", socketPath, "--", sh, "-c", "exit 0"})
	if code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	if labels := walLabels(t, stateDir); !containsLabel(labels, "RUN_ENDED") {
		t.Fatalf("durable WAL under state dir missing RUN_ENDED: %v", labels)
	}
}

// TestRunAllowUnobservedContactsDaemonZeroTimes proves -allow-unobserved runs the child bare: no
// daemon socket is dialed (there is none), no observer state is created, and the exit code still
// passes through.
func TestRunAllowUnobservedContactsDaemonZeroTimes(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir() // deliberately no daemon here

	code := runRun([]string{"-allow-unobserved", "-dir", dir, "--", sh, "-c", "exit 3"})
	if code != 3 {
		t.Fatalf("unobserved run exit code = %d, want 3", code)
	}
	// Zero daemon contact: the unobserved path neither dials the socket nor creates any spool state.
	if _, err := os.Stat(socketPathFor(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path exists after an unobserved run: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WAL created during an unobserved run: err=%v", err)
	}
}

// withStdio swaps os.Stdin/os.Stdout for the duration of fn, feeding stdinData and returning what fn
// wrote to stdout.
func withStdio(t *testing.T, stdinData string, fn func()) string {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	go func() {
		_, _ = inW.WriteString(stdinData)
		_ = inW.Close()
	}()
	captured := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		captured <- string(b)
	}()

	fn()
	_ = outW.Close()
	out := <-captured
	_ = inR.Close()
	_ = outR.Close()
	return out
}

// TestHookCodexEndToEnd feeds a Codex SessionStart on stdin through the `hook codex` subcommand
// against a real daemon and proves a durable SESSION_LIFECYCLE lands via the seam with an empty
// (success) stdout.
func TestHookCodexEndToEnd(t *testing.T) {
	dir := t.TempDir()
	svc := startBareDaemon(t, dir)

	in := `{"session_id":"sess-e2e","cwd":"/tmp/work","source":"startup"}`
	var code int
	out := withStdio(t, in, func() {
		code = runHook([]string{"codex", "-dir", dir, "-source-id", "src_cmd_test"})
	})
	if code != 0 {
		t.Fatalf("hook exit code = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("successful hook wrote to stdout: %q", out)
	}
	labels := walLabels(t, filepath.Dir(svc.SocketPath()))
	if !containsLabel(labels, string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE)) {
		t.Fatalf("durable WAL missing SESSION_LIFECYCLE; got %v", labels)
	}
}

// TestHookCodexCaptureFailureIsContentFree proves that with no reachable daemon the hook never
// stalls startup: it exits 0 within the hook budget and emits only a fixed, content-free
// systemMessage (no session id).
func TestHookCodexCaptureFailureIsContentFree(t *testing.T) {
	dir := t.TempDir() // no daemon: the socket dial fails

	in := `{"session_id":"sess-secret","cwd":"/tmp/work","source":"startup"}`
	var code int
	start := time.Now()
	out := withStdio(t, in, func() {
		code = runHook([]string{"codex", "-dir", dir, "-source-id", "src_cmd_test"})
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("hook took %v; the 2s budget must bound an unreachable daemon", elapsed)
	}
	if code != 0 {
		t.Fatalf("hook exit code = %d, want 0 (never stalls startup)", code)
	}
	var resp struct {
		Continue      bool   `json:"continue"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("hook stdout is not a JSON response: %q (%v)", out, err)
	}
	if !resp.Continue || resp.SystemMessage == "" {
		t.Fatalf("expected a continue=true systemMessage response, got %q", out)
	}
	if strings.Contains(out, "sess-secret") {
		t.Fatalf("capture-failure response leaked the session id: %q", out)
	}
}

// TestShimGuardDispatchesToRunShim proves main's RUNWRAP_SHIM guard routes to runwrap.RunShim before
// any subcommand parsing: re-running this binary with RUNWRAP_SHIM set but no handshake fds fails in
// the shim (an "observer runwrap" error), not in usage/dispatch.
func TestShimGuardDispatchesToRunShim(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), shimEnvVar+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("shim re-exec without handshake fds unexpectedly succeeded; output=%q", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("shim re-exec failed to start: %v", err)
	}
	if !strings.Contains(string(out), "runwrap") {
		t.Fatalf("shim guard did not dispatch to RunShim; output=%q", out)
	}
}

// terminalFailSpool wraps a real writer and fails appends whose classified label is in failLabels,
// simulating a terminal-sequence durability failure AFTER the child has already run to completion.
type terminalFailSpool struct {
	inner      *local.SpoolWriter
	failLabels map[string]bool
}

func (f *terminalFailSpool) AppendObservation(obs wire.Observation) (local.AppendAck, error) {
	if raw, err := obs.MarshalJSON(); err == nil && f.failLabels[classify(raw)] {
		return local.AppendAck{}, errors.New("terminalFailSpool: injected non-durable terminal append")
	}
	return f.inner.AppendObservation(obs)
}

func (f *terminalFailSpool) ReserveRun(runID string) (local.RunReserveAck, error) {
	return f.inner.ReserveRun(runID)
}
func (f *terminalFailSpool) ReleaseRun(runID string) (local.RunReserveAck, error) {
	return f.inner.ReleaseRun(runID)
}
func (f *terminalFailSpool) Health() (local.HealthSnapshot, error) { return f.inner.Health() }

// TestRunTerminalAppendFailureStillPassesExitCode proves an observer-side terminal-append durability
// failure (PROCESS_EXITED / RUN_ENDED) does NOT mask a launched child's real exit code: a child that
// exits 7 is reported as 7, not synthesized to 1.
func TestRunTerminalAppendFailureStillPassesExitCode(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir()

	writer, err := local.NewSpoolWriter(local.SpoolConfig{Dir: dir, SourceID: "src_cmd_test", Capacity: permissiveCap()})
	if err != nil {
		t.Fatalf("NewSpoolWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	sp := &terminalFailSpool{inner: writer, failLabels: map[string]bool{"PROCESS_EXITED": true, "RUN_ENDED": true}}

	srv, err := local.NewServer(local.ServerConfig{
		Dir:     dir,
		Spool:   sp,
		PeerUID: func(*net.UnixConn) (uint32, error) { return uint32(os.Geteuid()), nil },
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

	code := runRun([]string{"-dir", dir, "--", sh, "-c", "exit 7"})
	if code != 7 {
		t.Fatalf("run exit code = %d, want 7 — a terminal-append durability hiccup must not mask the child exit", code)
	}
	// The RUN_STARTED and REGISTERED appends (which do not fail) prove the run was genuinely observed;
	// the injected PROCESS_EXITED failure aborts the terminal sequence, so RUN_ENDED never lands.
	// That proves the exit code passed through DESPITE a real terminal-append failure, not on a happy
	// path that coincidentally returned 7.
	labels := walLabels(t, dir)
	if !containsLabel(labels, "RUN_STARTED") || !containsLabel(labels, "REGISTERED") {
		t.Fatalf("expected an observed run before the terminal failure; got %v", labels)
	}
	if containsLabel(labels, "RUN_ENDED") {
		t.Fatalf("expected the injected terminal failure to abort before RUN_ENDED; got %v", labels)
	}
}

// TestUnobservedStripsControlEnv proves the --allow-unobserved child sees the same sanitized
// environment the observed shim hands its child: no RUNWRAP_* control variable and no inherited
// GASWORKS_RUN_ID leak through, even when they are set in the parent env.
func TestUnobservedStripsControlEnv(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir()
	t.Setenv("RUNWRAP_SHIM", "1")
	t.Setenv("RUNWRAP_PROBE", "leak")
	t.Setenv("GASWORKS_RUN_ID", "outer-run")

	var code int
	out := withStdio(t, "", func() {
		code = runRun([]string{"-allow-unobserved", "-dir", dir, "--", sh, "-c", "env"})
	})
	if code != 0 {
		t.Fatalf("unobserved env run exit = %d, want 0; out=%q", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "RUNWRAP_") {
			t.Fatalf("unobserved child saw a wrapper control variable: %q", line)
		}
		if strings.HasPrefix(line, "GASWORKS_RUN_ID=") {
			t.Fatalf("unobserved child saw an inherited run id: %q", line)
		}
	}
	// Sanity: the child DID inherit ordinary vars, so we captured a real (non-empty) env.
	if !strings.Contains(out, "PATH=") {
		t.Fatalf("did not capture the child environment (no PATH= present); out=%q", out)
	}
}
