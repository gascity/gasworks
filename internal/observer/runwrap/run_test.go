package runwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

func childExit(t *testing.T, code int) []string {
	return []string{shPath(t), "-c", fmt.Sprintf("exit %d", code)}
}

func childSignalSelf(t *testing.T) []string {
	return []string{shPath(t), "-c", "kill -TERM $$"}
}

func childWriteMarker(t *testing.T, marker string) []string {
	return []string{shPath(t), "-c", `echo ran > "$1"`, "sh", marker}
}

func assertLabels(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("append order mismatch:\n got: %v\nwant: %v", got, want)
	}
}

// TestRunZeroExit proves the happy path: reserve, durable RUN_STARTED, REGISTERED, the child
// runs, then the normative terminal order PROCESS_EXITED -> (COMPLETE drain) -> RUN_ENDED, the
// reserve is released, and the run outcome is never expressed (always UNKNOWN server-side).
func TestRunZeroExit(t *testing.T) {
	d := newRecordingDaemon()
	res, err := Run(context.Background(), d, baseConfig(childExit(t, 0)...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Observed || !res.Launched || res.ExitCode != 0 || res.Signaled {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.DrainStatus != wire.RunEndedBoundaryDrainStatusCOMPLETE {
		t.Fatalf("drain status = %q, want COMPLETE", res.DrainStatus)
	}
	assertLabels(t, d.labels(), []string{"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "RUN_ENDED"})
	if d.events[0] != "RESERVE" || d.events[len(d.events)-1] != "RELEASE" {
		t.Fatalf("reserve/release bookkeeping wrong: %v", d.events)
	}
	if bytes.Contains(d.allBytes(), []byte("outcome")) {
		t.Fatalf("an observation carried a run outcome field:\n%s", d.allBytes())
	}
	// The declared beads reference is persisted on the boundary.
	assertBoundaryHasWorkRef(t, d, "btsproj_0123456789", "bd-42")
}

// TestRunNonzeroExit proves a nonzero child exit is process evidence, not a Run error, and the
// run outcome stays UNKNOWN.
func TestRunNonzeroExit(t *testing.T) {
	d := newRecordingDaemon()
	res, err := Run(context.Background(), d, baseConfig(childExit(t, 7)...))
	if err != nil {
		t.Fatalf("Run returned error for a nonzero child exit: %v", err)
	}
	if res.ExitCode != 7 || res.Signaled {
		t.Fatalf("exit code = %d signaled=%v, want 7/false", res.ExitCode, res.Signaled)
	}
	assertLabels(t, d.labels(), []string{"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "RUN_ENDED"})
	assertProcessExitedCode(t, d, 7)
}

// TestRunSignalExit proves a signal-terminated child is recorded with its signal number (not an
// exit code) and still leaves the run outcome UNKNOWN.
func TestRunSignalExit(t *testing.T) {
	d := newRecordingDaemon()
	res, err := Run(context.Background(), d, baseConfig(childSignalSelf(t)...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Signaled || res.Signal != 15 {
		t.Fatalf("signaled=%v signal=%d, want true/15", res.Signaled, res.Signal)
	}
	assertLabels(t, d.labels(), []string{"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "RUN_ENDED"})
	assertProcessExitedSignal(t, d, 15)
}

// TestRunLaunchFailure proves that a child that cannot be exec'd (after RUN_STARTED) produces
// PROCESS_LAUNCH_FAILED then RUN_ENDED with NO drain and NO PROCESS_EXITED, the reserve is
// released, and Run returns the launch error.
func TestRunLaunchFailure(t *testing.T) {
	d := newRecordingDaemon()
	cfg := baseConfig(filepath.Join(t.TempDir(), "definitely-not-a-real-binary"))
	res, err := Run(context.Background(), d, cfg)
	if err == nil {
		t.Fatal("expected a launch error, got nil")
	}
	if res.Launched {
		t.Fatal("result reports launched for a failed exec")
	}
	assertLabels(t, d.labels(), []string{"RUN_STARTED", "REGISTERED", "PROCESS_LAUNCH_FAILED", "RUN_ENDED"})
	if !d.released {
		t.Fatal("reserve not released after launch failure")
	}
	for _, l := range d.labels() {
		if l == "PROCESS_EXITED" {
			t.Fatal("launch failure must not emit PROCESS_EXITED")
		}
	}
}

// TestRunRefusesWhenBoundaryNotDurable proves the wrapper refuses to start the child when
// RUN_STARTED cannot be durably recorded: no child runs, the reserve is released, and the typed
// ErrBoundaryNotDurable is returned.
func TestRunRefusesWhenBoundaryNotDurable(t *testing.T) {
	d := newRecordingDaemon()
	d.appendErrOn["RUN_STARTED"] = errors.New("wal fsync failed")
	marker := filepath.Join(t.TempDir(), "marker")
	_, err := Run(context.Background(), d, baseConfig(childWriteMarker(t, marker)...))
	if !errors.Is(err, ErrBoundaryNotDurable) {
		t.Fatalf("error = %v, want ErrBoundaryNotDurable", err)
	}
	if len(d.labels()) != 0 {
		t.Fatalf("no observation should be durable, got %v", d.labels())
	}
	if !d.released {
		t.Fatal("reserve not released after a non-durable boundary")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("child ran despite a non-durable boundary")
	}
}

// capacityConfig is a small, valid E1.3 capacity model: ceiling 1000, one 100-byte max segment
// held in reserve, and a 50-byte terminal reserve per run — so hard pressure begins at 900
// committed bytes.
func capacityConfig() spool.CapacityConfig {
	return spool.CapacityConfig{
		CeilingBytes:         1000,
		MaxSegmentBytes:      100,
		ScratchBytes:         0,
		TerminalReserveBytes: 50,
		SafetyMarginRatio:    0.25,
	}
}

// TestRunHardPressureRefusesBeforeStart proves hard byte-ceiling pressure refuses a NEW explicit
// run before RUN_STARTED: no boundary, no child, and the typed ErrCapacityRefused surfaces.
func TestRunHardPressureRefusesBeforeStart(t *testing.T) {
	d := newSpoolDaemon(t, capacityConfig())
	d.setUsed(900) // committed >= hard floor
	marker := filepath.Join(t.TempDir(), "marker")
	_, err := Run(context.Background(), d, baseConfig(childWriteMarker(t, marker)...))
	if !errors.Is(err, ErrCapacityRefused) {
		t.Fatalf("error = %v, want ErrCapacityRefused", err)
	}
	if len(d.labels()) != 0 {
		t.Fatalf("no observation should be written under hard pressure, got %v", d.labels())
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("child ran under hard pressure")
	}
}

// TestRunReserveLifecycle proves the terminal reserve is preallocated on RUN_STARTED, held
// across the whole run (checked mid-drain), and released only after RUN_ENDED — using the real
// spool.Reserves + CapacityModel from E1.3.
func TestRunReserveLifecycle(t *testing.T) {
	d := newSpoolDaemon(t, capacityConfig())
	var heldDuringDrain bool
	var runID string
	d.drainFn = func(_ context.Context, id string) (DrainOutcome, error) {
		heldDuringDrain = d.isOpen(id)
		runID = id
		return DrainOutcome{Status: wire.RunEndedBoundaryDrainStatusCOMPLETE}, nil
	}
	res, err := Run(context.Background(), d, baseConfig(childExit(t, 0)...))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !heldDuringDrain {
		t.Fatal("terminal reserve was not held during the drain")
	}
	if runID != res.RunID {
		t.Fatalf("drain run id %q != result run id %q", runID, res.RunID)
	}
	if d.isOpen(res.RunID) {
		t.Fatal("terminal reserve was not released after RUN_ENDED")
	}
	assertLabels(t, d.labels(), []string{"RUN_STARTED", "REGISTERED", "PROCESS_EXITED", "RUN_ENDED"})
}

// TestReserveContractStartedRunKeepsReserve proves the E1.3 contract the wrapper relies on: a
// run that has already started keeps its preallocated reserve even after pressure turns hard,
// while a brand-new run is refused.
func TestReserveContractStartedRunKeepsReserve(t *testing.T) {
	d := newSpoolDaemon(t, capacityConfig())
	if err := d.ReserveTerminal(context.Background(), "run-1"); err != nil {
		t.Fatalf("reserve run-1: %v", err)
	}
	d.setUsed(900) // now hard pressure
	err := d.ReserveTerminal(context.Background(), "run-2")
	if !errors.Is(err, ErrCapacityRefused) {
		t.Fatalf("run-2 error = %v, want ErrCapacityRefused", err)
	}
	if !d.isOpen("run-1") {
		t.Fatal("already-started run-1 lost its reserve under hard pressure")
	}
}

// TestRunAllowUnobserved proves the emergency bypass: a prominent warning, no run id, no daemon
// contact, and no GASWORKS_RUN_ID exported (an inherited one is stripped).
func TestRunAllowUnobserved(t *testing.T) {
	d := newRecordingDaemon()
	var out, warn bytes.Buffer
	cfg := Config{
		Target:          []string{shPath(t), "-c", `printf '[%s]' "$GASWORKS_RUN_ID"`},
		AllowUnobserved: true,
		Shim:            testShimSpec(),
		Stdout:          &out,
		Warn:            &warn,
		Env:             append(os.Environ(), RunIDEnvVar+"=run_outer_should_be_stripped"),
	}
	res, err := Run(context.Background(), d, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Observed || res.RunID != "" {
		t.Fatalf("unobserved run leaked observation state: %+v", res)
	}
	if len(d.events) != 0 {
		t.Fatalf("unobserved run contacted the daemon: %v", d.events)
	}
	if got := out.String(); got != "[]" {
		t.Fatalf("child saw GASWORKS_RUN_ID %q, want empty", got)
	}
	if !strings.Contains(warn.String(), "UNOBSERVED") {
		t.Fatalf("missing prominent warning, got %q", warn.String())
	}
}

// TestRunNestedWrapperNearestAncestor proves a wrapper started inside another wrapper's run
// mints its OWN authoritative run id, exports that (not the inherited outer id) to the child,
// retains the inherited id only as correlation evidence, and never stamps the outer id as any
// observation's membership.
func TestRunNestedWrapperNearestAncestor(t *testing.T) {
	const outer = "run_outer_abc123"
	d := newRecordingDaemon()
	var out bytes.Buffer
	cfg := baseConfig(shPath(t), "-c", `printf '%s' "$GASWORKS_RUN_ID"`)
	cfg.Stdout = &out
	cfg.Env = append(os.Environ(), RunIDEnvVar+"="+outer)

	res, err := Run(context.Background(), d, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RunID == outer || res.RunID == "" {
		t.Fatalf("inner run id %q must be freshly minted and distinct from the outer id", res.RunID)
	}
	if res.InheritedRunID != outer {
		t.Fatalf("inherited run id = %q, want %q (correlation-only)", res.InheritedRunID, outer)
	}
	if got := out.String(); got != res.RunID {
		t.Fatalf("child saw GASWORKS_RUN_ID %q, want the inner id %q (nearest ancestor authoritative)", got, res.RunID)
	}
	for _, id := range d.runContextRunIDs() {
		if id == outer {
			t.Fatalf("outer run id was stamped as membership on an observation; it must be correlation-only")
		}
		if id != res.RunID {
			t.Fatalf("observation stamped run id %q, want the inner id %q", id, res.RunID)
		}
	}
}

// TestRunArgvEnvExcluded is the sentinel-scan proof (the E1.1 approach) across ALL four vectors
// the wrapper directly handles: planted sentinels in the child's argv, environment key/value,
// executable PATH (Target[0]), and working directory — all of which the child really receives —
// must never appear in any captured observation.
func TestRunArgvEnvExcluded(t *testing.T) {
	const (
		argvSentinel   = "SENTINEL_ARGV_ZZZ"
		envKeySentinel = "SENTINEL_ENV_KEY_ZZZ"
		envValSentinel = "SENTINEL_ENV_VAL_ZZZ"
		pathSentinel   = "SENTINEL_EXECPATH_ZZZ"
		cwdSentinel    = "SENTINEL_CWD_ZZZ"
	)
	// A real executable whose directory AND basename carry a sentinel, used as Target[0].
	execDir := filepath.Join(t.TempDir(), pathSentinel+"_dir")
	if err := os.MkdirAll(execDir, 0o755); err != nil {
		t.Fatalf("mkdir exec dir: %v", err)
	}
	execPath := filepath.Join(execDir, pathSentinel+"_bin")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write exec: %v", err)
	}
	// A working directory whose path carries a sentinel.
	cwd := filepath.Join(t.TempDir(), cwdSentinel+"_dir")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	t.Chdir(cwd)

	d := newRecordingDaemon()
	cfg := baseConfig(execPath, argvSentinel)
	cfg.Env = append(os.Environ(), envKeySentinel+"="+envValSentinel)
	if _, err := Run(context.Background(), d, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	blob := d.allBytes()
	for _, s := range []string{argvSentinel, envKeySentinel, envValSentinel, pathSentinel, cwdSentinel} {
		if bytes.Contains(blob, []byte(s)) {
			t.Fatalf("captured observation leaked %q:\n%s", s, blob)
		}
	}
	// Belt and suspenders: no field name that could carry command/argv/env/path/cwd content.
	for _, k := range []string{
		`"argv"`, `"command"`, `"env"`, `"environment"`, `"exec_path"`, `"cmdline"`,
		`"cwd"`, `"working_directory"`,
	} {
		if bytes.Contains(blob, []byte(k)) {
			t.Fatalf("captured observation carried a forbidden field %s:\n%s", k, blob)
		}
	}
}

func assertBoundaryHasWorkRef(t *testing.T, d *recordingDaemon, project, bead string) {
	t.Helper()
	for _, a := range d.appends {
		if a.label != "RUN_STARTED" {
			continue
		}
		var p struct {
			RunBoundary struct {
				WorkItemRefs []struct {
					TeamServerProjectID string `json:"team_server_project_id"`
					BeadID              string `json:"bead_id"`
					Origin              string `json:"origin"`
				} `json:"work_item_refs"`
			} `json:"run_boundary"`
		}
		if err := json.Unmarshal(a.bytes, &p); err != nil {
			t.Fatalf("unmarshal RUN_STARTED: %v", err)
		}
		refs := p.RunBoundary.WorkItemRefs
		if len(refs) != 1 || refs[0].TeamServerProjectID != project || refs[0].BeadID != bead || refs[0].Origin != "DECLARED" {
			t.Fatalf("RUN_STARTED work ref = %+v, want one DECLARED %s/%s", refs, project, bead)
		}
		return
	}
	t.Fatal("no RUN_STARTED boundary recorded")
}

func assertProcessExitedCode(t *testing.T, d *recordingDaemon, want int32) {
	t.Helper()
	code, sig := processExitEvidence(t, d)
	if sig != nil {
		t.Fatalf("PROCESS_EXITED carried a signal %d, want exit code", *sig)
	}
	if code == nil || *code != want {
		t.Fatalf("PROCESS_EXITED exit code = %v, want %d", code, want)
	}
}

func assertProcessExitedSignal(t *testing.T, d *recordingDaemon, want int32) {
	t.Helper()
	code, sig := processExitEvidence(t, d)
	if code != nil {
		t.Fatalf("PROCESS_EXITED carried an exit code %d, want a signal", *code)
	}
	if sig == nil || *sig != want {
		t.Fatalf("PROCESS_EXITED signal = %v, want %d", sig, want)
	}
}

func processExitEvidence(t *testing.T, d *recordingDaemon) (*int32, *int32) {
	t.Helper()
	for _, a := range d.appends {
		if a.label != "PROCESS_EXITED" {
			continue
		}
		var p struct {
			ProcessLifecycle struct {
				ExitCode *int32 `json:"exit_code"`
				Signal   *int32 `json:"signal"`
			} `json:"process_lifecycle"`
		}
		if err := json.Unmarshal(a.bytes, &p); err != nil {
			t.Fatalf("unmarshal PROCESS_EXITED: %v", err)
		}
		return p.ProcessLifecycle.ExitCode, p.ProcessLifecycle.Signal
	}
	t.Fatal("no PROCESS_EXITED recorded")
	return nil, nil
}
