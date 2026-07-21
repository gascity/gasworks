package runwrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestMain dispatches the two re-exec-self helper roles this package's real-subprocess tests
// need, before falling through to the normal test run:
//
//   - "shim": act as the same-PID identity shim (RunShim), reading fds 3/4/5 and exec-ing the
//     target — this is what launchObserved spawns in place of the production shim subcommand;
//   - "wrapper": run a full wrapper process (for the crash and signal-forwarding tests) that a
//     test can SIGKILL or signal from the outside.
//
// The trigger is an environment variable (controlEnvPrefix-scoped) so the shim strips it before
// exec-ing the child and it never contaminates a nested re-exec.
func TestMain(m *testing.M) {
	switch os.Getenv("RUNWRAP_HELPER_MODE") {
	case "shim":
		if err := RunShim(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "wrapper":
		os.Exit(runWrapperHelper())
	}
	os.Exit(m.Run())
}

// testShimSpec points the shim at the test binary (os.Executable, resolved by ShimSpec) and
// triggers shim mode through the environment.
func testShimSpec() ShimSpec {
	return ShimSpec{ExtraEnv: []string{"RUNWRAP_HELPER_MODE=shim"}}
}

// fixedClock returns a deterministic clock so observation timestamps are stable.
func fixedClock() func() time.Time {
	t := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// baseConfig is a valid observed-run config for an in-process test: a deterministic run id and
// clock, the test shim, and a declared work reference.
func baseConfig(target ...string) Config {
	n := 0
	return Config{
		Target:         target,
		BeadsProjectID: "btsproj_0123456789",
		WorkItemBeadID: "bd-42",
		Shim:           testShimSpec(),
		now:            fixedClock(),
		newRunID: func() (string, error) {
			n++
			return fmt.Sprintf("run_test_%08d", n), nil
		},
	}
}

// ---- scriptable recording daemon (the DaemonClient seam double) ----

type recordedObs struct {
	label string
	bytes []byte
	obs   wire.Observation
}

// recordingDaemon is an in-process DaemonClient double. It seals every appended observation
// (the spool's single-writer role in production), records an ordered event/label log, and
// exposes hooks to script capacity refusal, non-durable appends, and drain behavior.
type recordingDaemon struct {
	mu          sync.Mutex
	seq         int64
	events      []string
	appends     []recordedObs
	reserveErr    error
	boundSessions map[string]string
	reserved      bool
	released    bool
	drainFn     func(ctx context.Context, d *recordingDaemon, runID string) (DrainOutcome, error)
	appendErrOn map[string]error
}

func newRecordingDaemon() *recordingDaemon {
	return &recordingDaemon{appendErrOn: map[string]error{}}
}

func (d *recordingDaemon) ReserveTerminal(_ context.Context, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "RESERVE")
	if d.reserveErr != nil {
		return d.reserveErr
	}
	d.reserved = true
	return nil
}

func (d *recordingDaemon) Append(_ context.Context, obs evidence.PendingObservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.appendLocked(obs)
}

func (d *recordingDaemon) appendLocked(obs evidence.PendingObservation) error {
	d.seq++
	sealed, err := obs.Seal(d.seq, fmt.Sprintf("obs_%08d", d.seq))
	if err != nil {
		return err
	}
	b, err := wire.CanonicalBytes(sealed)
	if err != nil {
		return err
	}
	label := classify(b)
	if e := d.appendErrOn[label]; e != nil {
		return e // simulate a non-durable append: nothing is recorded.
	}
	d.appends = append(d.appends, recordedObs{label: label, bytes: b, obs: sealed})
	d.events = append(d.events, "APPEND:"+label)
	return nil
}

func (d *recordingDaemon) Drain(ctx context.Context, runID string) (DrainOutcome, error) {
	d.mu.Lock()
	fn := d.drainFn
	d.events = append(d.events, "DRAIN")
	d.mu.Unlock()
	if fn == nil {
		return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
	}
	return fn(ctx, d, runID)
}

func (d *recordingDaemon) ReleaseTerminal(_ context.Context, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.released = true
	d.events = append(d.events, "RELEASE")
	return nil
}

func (d *recordingDaemon) BindSession(_ context.Context, nativeSessionID, runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.boundSessions == nil {
		d.boundSessions = map[string]string{}
	}
	d.boundSessions[nativeSessionID] = runID
	return nil
}

func (d *recordingDaemon) binding(nativeSessionID string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	runID, ok := d.boundSessions[nativeSessionID]
	return runID, ok
}

// appendTranscript simulates a daemon-side drained provider record (parser catch-up), so the
// terminal-order tests can prove drained records land after PROCESS_EXITED and before RUN_ENDED.
func (d *recordingDaemon) appendTranscript(runID string, role wire.MessagePayloadRole) error {
	now := time.Date(2026, 7, 17, 12, 0, 1, 0, time.UTC)
	c := evidence.Common{
		OccurredAt: now,
		CapturedAt: now,
		Provenance: wire.Provenance{Adapter: "codex-parser", AdapterVersion: "1", ContentPolicy: wire.ProvenanceContentPolicyMETADATAONLY},
		RunContext: &wire.RunContext{RunId: runID, MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY},
	}
	obs, err := evidence.NewMessage(c, evidence.MessageInput{Role: role})
	if err != nil {
		return err
	}
	return d.Append(context.Background(), obs)
}

func (d *recordingDaemon) labels() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.appends))
	for i, a := range d.appends {
		out[i] = a.label
	}
	return out
}

func (d *recordingDaemon) allBytes() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	var buf bytes.Buffer
	for _, a := range d.appends {
		buf.Write(a.bytes)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// runContextRunIDs returns the run_context.run_id stamped on every recorded observation.
func (d *recordingDaemon) runContextRunIDs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, a := range d.appends {
		var p struct {
			RunContext *struct {
				RunID string `json:"run_id"`
			} `json:"run_context"`
		}
		_ = json.Unmarshal(a.bytes, &p)
		if p.RunContext != nil {
			out = append(out, p.RunContext.RunID)
		}
	}
	return out
}

// classify labels a canonical observation by its most specific transition/code, so ordering
// assertions can distinguish RUN_STARTED from RUN_ENDED and REGISTERED from PROCESS_EXITED.
func classify(b []byte) string {
	var p struct {
		Kind        string `json:"kind"`
		RunBoundary *struct {
			Transition string `json:"transition"`
		} `json:"run_boundary"`
		ProcessLifecycle *struct {
			Transition string `json:"transition"`
		} `json:"process_lifecycle"`
		CaptureDiagnostic *struct {
			Code string `json:"code"`
		} `json:"capture_diagnostic"`
	}
	_ = json.Unmarshal(b, &p)
	switch {
	case p.RunBoundary != nil && p.RunBoundary.Transition != "":
		return p.RunBoundary.Transition
	case p.ProcessLifecycle != nil && p.ProcessLifecycle.Transition != "":
		return p.ProcessLifecycle.Transition
	case p.CaptureDiagnostic != nil && p.CaptureDiagnostic.Code != "":
		return "CAPTURE_DIAGNOSTIC:" + p.CaptureDiagnostic.Code
	default:
		return p.Kind
	}
}

// ---- real-spool daemon (exercises the committed E1.3 capacity + reserve API) ----

// spoolDaemon backs the seam with the real spool.Reserves + spool.CapacityModel, so the
// capacity-refusal and reserve-lifecycle tests run against the committed E1.3 contract rather
// than a hand-rolled stub.
type spoolDaemon struct {
	mu       sync.Mutex
	reserves *spool.Reserves
	model    spool.CapacityModel
	used     int64 // injectable used bytes
	seq      int64
	appends  []recordedObs
	drainFn  func(ctx context.Context, runID string) (DrainOutcome, error)
}

func newSpoolDaemon(t *testing.T, cfg spool.CapacityConfig) *spoolDaemon {
	t.Helper()
	model, err := spool.NewCapacityModel(cfg)
	if err != nil {
		t.Fatalf("NewCapacityModel: %v", err)
	}
	res, err := spool.LoadReserves(t.TempDir(), cfg.TerminalReserveBytes)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	return &spoolDaemon{reserves: res, model: model}
}

func (d *spoolDaemon) setUsed(n int64) {
	d.mu.Lock()
	d.used = n
	d.mu.Unlock()
}

func (d *spoolDaemon) ReserveTerminal(_ context.Context, runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.model.Evaluate(d.used, d.reserves.OpenReserveBytes())
	if !st.AdmitNewExplicitRun {
		return fmt.Errorf("%w: pressure=%s", ErrCapacityRefused, st.Pressure)
	}
	return d.reserves.Reserve(runID)
}

func (d *spoolDaemon) Append(_ context.Context, obs evidence.PendingObservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq++
	sealed, err := obs.Seal(d.seq, fmt.Sprintf("obs_%08d", d.seq))
	if err != nil {
		return err
	}
	b, err := wire.CanonicalBytes(sealed)
	if err != nil {
		return err
	}
	d.appends = append(d.appends, recordedObs{label: classify(b), bytes: b, obs: sealed})
	return nil
}

func (d *spoolDaemon) Drain(ctx context.Context, runID string) (DrainOutcome, error) {
	if d.drainFn != nil {
		return d.drainFn(ctx, runID)
	}
	return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
}

func (d *spoolDaemon) ReleaseTerminal(_ context.Context, runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reserves.Release(runID)
}

func (d *spoolDaemon) BindSession(_ context.Context, _, _ string) error { return nil }

func (d *spoolDaemon) isOpen(runID string) bool { return d.reserves.IsOpen(runID) }

func (d *spoolDaemon) openReserveBytes() int64 { return d.reserves.OpenReserveBytes() }

func (d *spoolDaemon) labels() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.appends))
	for i, a := range d.appends {
		out[i] = a.label
	}
	return out
}

// ---- file-backed daemon for the out-of-process wrapper-crash test ----

// fileDaemon durably records sealed observations as fsync'd JSONL and keeps reserve state in a
// real spool.Reserves sidecar, so an external test can inspect run state after SIGKILL-ing the
// wrapper process that drives it.
type fileDaemon struct {
	mu       sync.Mutex
	logFile  *os.File
	reserves *spool.Reserves
	seq      int64
}

func newFileDaemon(logPath, reservesDir string) (*fileDaemon, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	res, err := spool.LoadReserves(reservesDir, 4096)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &fileDaemon{logFile: f, reserves: res}, nil
}

func (d *fileDaemon) ReserveTerminal(_ context.Context, runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reserves.Reserve(runID)
}

func (d *fileDaemon) Append(_ context.Context, obs evidence.PendingObservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq++
	sealed, err := obs.Seal(d.seq, fmt.Sprintf("obs_%08d", d.seq))
	if err != nil {
		return err
	}
	b, err := wire.CanonicalBytes(sealed)
	if err != nil {
		return err
	}
	if _, err := d.logFile.Write(append(b, '\n')); err != nil {
		return err
	}
	return d.logFile.Sync()
}

func (d *fileDaemon) Drain(_ context.Context, _ string) (DrainOutcome, error) {
	return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
}

func (d *fileDaemon) ReleaseTerminal(_ context.Context, runID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reserves.Release(runID)
}

func (d *fileDaemon) BindSession(_ context.Context, _, _ string) error { return nil }

// runWrapperHelper is the "wrapper" re-exec role: it builds a config from the environment and
// runs the full wrapper, then exits with the child's exit code. The crash test SIGKILLs it
// mid-run; the signal-forwarding test signals it and checks the propagated exit code.
func runWrapperHelper() int {
	target := shimTarget() // argv after "--"
	if len(target) == 0 {
		fmt.Fprintln(os.Stderr, "wrapper helper: no target")
		return 97
	}
	cfg := Config{
		Target:         target,
		BeadsProjectID: "btsproj_helper01",
		WorkItemBeadID: "bd-helper",
		Shim:           testShimSpec(),
	}
	var d DaemonClient
	if os.Getenv("RUNWRAP_WRAPPER_UNOBSERVED") == "1" {
		cfg.AllowUnobserved = true
	} else {
		fd, err := newFileDaemon(os.Getenv("RUNWRAP_WRAPPER_LOG"), os.Getenv("RUNWRAP_WRAPPER_RESERVES"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "wrapper helper daemon:", err)
			return 96
		}
		d = fd
	}
	res, err := Run(context.Background(), d, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wrapper helper run error:", err)
		return 98
	}
	return res.ExitCode
}

// ---- shared shell helpers (real child subprocesses) ----

func shPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	return p
}

// readLines reads the RUN log file into classified labels for assertions.
func classifyLogFile(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log %s: %v", path, err)
	}
	defer f.Close()
	var labels []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		labels = append(labels, classify(line))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan log: %v", err)
	}
	return labels
}

// runIDFromLog extracts the RUN_STARTED run id from a durable log file.
func runIDFromLog(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var p struct {
			RunBoundary *struct {
				Transition string `json:"transition"`
				RunID      string `json:"run_id"`
			} `json:"run_boundary"`
		}
		if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
			continue
		}
		if p.RunBoundary != nil && p.RunBoundary.Transition == "RUN_STARTED" {
			return p.RunBoundary.RunID
		}
	}
	return ""
}
