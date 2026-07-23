package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

const testFixedReserve int64 = 4096

// ---- observation payloads (only the fields reserve reconciliation classifies on) ----

func runStartedPayload(runID string) []byte {
	return []byte(fmt.Sprintf(`{"kind":"RUN_BOUNDARY","run_boundary":{"transition":"RUN_STARTED","run_id":%q}}`, runID))
}

func runEndedPayload(runID string) []byte {
	return []byte(fmt.Sprintf(`{"kind":"RUN_BOUNDARY","run_boundary":{"transition":"RUN_ENDED","run_id":%q}}`, runID))
}

func processExitedPayload(runID string) []byte {
	return []byte(fmt.Sprintf(`{"kind":"PROCESS_LIFECYCLE","process_lifecycle":{"transition":"PROCESS_EXITED"},"run_context":{"membership_evidence":"DECLARED_BOUNDARY","run_id":%q}}`, runID))
}

func processLaunchFailedPayload(runID string) []byte {
	return []byte(fmt.Sprintf(`{"kind":"PROCESS_LIFECYCLE","process_lifecycle":{"transition":"PROCESS_LAUNCH_FAILED"},"run_context":{"membership_evidence":"DECLARED_BOUNDARY","run_id":%q}}`, runID))
}

func passivePayload() []byte {
	return []byte(`{"kind":"SESSION_LIFECYCLE"}`)
}

// buildSegmentPayloads writes a segment [first, first+len(payloads)-1] with caller-supplied
// canonical payloads, through the real writer path.
func buildSegmentPayloads(t *testing.T, walDir string, first int64, payloads ...[]byte) {
	t.Helper()
	seg, err := CreateSegment(walDir, SegmentOptions{FormatVersion: 1, SourceID: testSourceID, FirstSequence: first})
	if err != nil {
		t.Fatalf("CreateSegment(%d): %v", first, err)
	}
	for i, p := range payloads {
		if err := seg.Append(Frame{Sequence: first + int64(i), Payload: p}); err != nil {
			t.Fatalf("Append %d: %v", first+int64(i), err)
		}
	}
	if err := seg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ---- reserves sidecar ----

func TestReservesPreallocateAndReleaseEachTerminal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		release string
	}{
		{"RUN_ENDED", "r-ended"},
		{"PROCESS_EXITED", "r-exited"},
		{"PROCESS_LAUNCH_FAILED", "r-failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := recoverDir(t)
			r, err := LoadReserves(dir, testFixedReserve)
			if err != nil {
				t.Fatalf("LoadReserves: %v", err)
			}
			if err := r.Reserve(tc.release); err != nil {
				t.Fatalf("Reserve: %v", err)
			}
			if !r.IsOpen(tc.release) || r.OpenReserveBytes() != testFixedReserve {
				t.Fatalf("after RUN_STARTED: open=%v bytes=%d, want open/%d", r.IsOpen(tc.release), r.OpenReserveBytes(), testFixedReserve)
			}
			// The terminal event releases the reserve.
			if err := r.Release(tc.release); err != nil {
				t.Fatalf("Release: %v", err)
			}
			if r.IsOpen(tc.release) || r.OpenReserveBytes() != 0 {
				t.Fatalf("after terminal: open=%v bytes=%d, want closed/0", r.IsOpen(tc.release), r.OpenReserveBytes())
			}
			// Durable across reload.
			reloaded, err := LoadReserves(dir, testFixedReserve)
			if err != nil {
				t.Fatalf("reload LoadReserves: %v", err)
			}
			if reloaded.IsOpen(tc.release) {
				t.Fatalf("released reserve reappeared after reload")
			}
		})
	}
}

func TestReservesReserveAndReleaseAreIdempotent(t *testing.T) {
	dir := recoverDir(t)
	r, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := r.Reserve("R1"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := r.Reserve("R1"); err != nil { // duplicate RUN_STARTED replay
		t.Fatalf("idempotent Reserve: %v", err)
	}
	if r.OpenReserveBytes() != testFixedReserve {
		t.Fatalf("double reserve inflated bytes to %d", r.OpenReserveBytes())
	}
	if err := r.Release("R1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := r.Release("R1"); err != nil { // releasing an unknown run is a no-op
		t.Fatalf("idempotent Release: %v", err)
	}
	if err := r.Reserve(""); !errors.Is(err, ErrReserveRunID) {
		t.Fatalf("empty run id: err = %v, want ErrReserveRunID", err)
	}
}

func TestReservesMultipleOpenRunsSumAndSort(t *testing.T) {
	dir := recoverDir(t)
	r, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	for _, id := range []string{"R2", "R1", "R3"} {
		if err := r.Reserve(id); err != nil {
			t.Fatalf("Reserve %s: %v", id, err)
		}
	}
	if r.OpenReserveBytes() != 3*testFixedReserve {
		t.Fatalf("OpenReserveBytes = %d, want %d", r.OpenReserveBytes(), 3*testFixedReserve)
	}
	got := r.OpenRuns()
	want := []string{"R1", "R2", "R3"}
	if len(got) != len(want) {
		t.Fatalf("OpenRuns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OpenRuns[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReservesCorruptSidecarUnhealthyNeverReset(t *testing.T) {
	dir := recoverDir(t)
	r, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := r.Reserve("R1"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := filepath.Join(dir, reservesFilename)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reserves: %v", err)
	}
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 0xFF // flip the CRC
	if err := os.WriteFile(path, corrupt, fileMode); err != nil {
		t.Fatalf("write corrupt reserves: %v", err)
	}
	if _, err := LoadReserves(dir, testFixedReserve); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("corrupt reserves load: err = %v, want ErrChecksumMismatch", err)
	}
	// Held, not reset to empty.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reserves after: %v", err)
	}
	if len(after) != len(corrupt) || after[len(after)-1] != corrupt[len(corrupt)-1] {
		t.Fatalf("corrupt reserves were rewritten/reset instead of held")
	}
}

func TestReservesDecodeRejectsOversizedCount(t *testing.T) {
	// A sidecar claiming an absurd entry count is rejected before allocation.
	data := make([]byte, 12)
	putReservesHeader(data, maxReserveEntries+1)
	if _, err := decodeReserves(data); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("oversized count: err = %v, want ErrChecksumMismatch", err)
	}
}

func putReservesHeader(buf []byte, count uint32) {
	buf[0], buf[1], buf[2], buf[3] = 0x4F, 0x52, 0x53, 0x31 // "ORS1"
	buf[4] = byte(count >> 24)
	buf[5] = byte(count >> 16)
	buf[6] = byte(count >> 8)
	buf[7] = byte(count)
}

// ---- classification + scan ----

func TestClassifyRunFrame(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		kind    RunEventKind
		runID   string
	}{
		{"run_started", runStartedPayload("A"), RunEventStarted, "A"},
		{"run_ended", runEndedPayload("A"), RunEventTerminated, "A"},
		{"process_exited", processExitedPayload("B"), RunEventTerminated, "B"},
		{"process_launch_failed", processLaunchFailedPayload("C"), RunEventTerminated, "C"},
		{"passive", passivePayload(), RunEventOther, ""},
		{"garbage", []byte("{not json"), RunEventOther, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, runID := classifyRunFrame(c.payload)
			if kind != c.kind || runID != c.runID {
				t.Fatalf("classifyRunFrame = (%v, %q), want (%v, %q)", kind, runID, c.kind, c.runID)
			}
		})
	}
}

// evCommon builds a valid, policy-clean observation envelope. A non-empty runID stamps a
// run_context (needed for PROCESS_LIFECYCLE run-id resolution); an empty runID leaves it nil.
func evCommon(runID string) evidence.Common {
	now := time.Unix(1700000000, 0).UTC()
	c := evidence.Common{
		OccurredAt: now,
		CapturedAt: now,
		Provenance: wire.Provenance{
			Adapter:        "codex-hook",
			AdapterVersion: "0.1.0",
			ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		},
	}
	if runID != "" {
		c.RunContext = &wire.RunContext{
			MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY,
			RunId:              runID,
		}
	}
	return c
}

func canonicalBytesOf(t *testing.T, p evidence.PendingObservation, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatalf("construct observation: %v", err)
	}
	obs, err := p.Seal(1, "obs_0000000000000000000000000001")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := wire.CanonicalBytes(obs)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	return b
}

// TestClassifyRunFrameOnCanonicalWireBytes ties classifyRunFrame to the REAL canonical bytes
// production writes (evidence constructor → Seal → wire.CanonicalBytes), not to hand-written
// JSON copied from the parser. A wire-tag drift that renamed/renested run_boundary / run_context
// / transition / run_id would silently reclassify every boundary as RunEventOther and strand or
// leak every reserve; this guard fails the build instead.
func TestClassifyRunFrameOnCanonicalWireBytes(t *testing.T) {
	exit := int32(0)
	runStarted, e1 := evidence.NewRunStarted(evCommon(""), evidence.RunStartedInput{
		RunID:          "R1",
		BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	runEndedDrain, e2 := evidence.NewRunEndedDrain(evCommon(""), evidence.RunEndedDrainInput{
		RunID:            "R1",
		BoundarySource:   wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		DrainStatus:      wire.RunEndedBoundaryDrainStatusCOMPLETE,
		CoveredWatermark: wire.Watermark{ByteOffset: 10},
	})
	runEndedLaunchFail, e3 := evidence.NewRunEndedLaunchFailure(evCommon(""), evidence.RunEndedLaunchFailureInput{
		RunID:          "R2",
		BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	procExited, e4 := evidence.NewProcessLifecycle(evCommon("R3"), evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionPROCESSEXITED,
		Identity:   wire.ProcessIdentity{BootId: "boot-1", Pid: 100, ProcessStartTime: 5},
		ExitCode:   &exit,
	})
	procLaunchFailed, e5 := evidence.NewProcessLifecycle(evCommon("R4"), evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionPROCESSLAUNCHFAILED,
		Identity:   wire.ProcessIdentity{BootId: "boot-1", Pid: 101, ProcessStartTime: 6},
	})
	// A process lifecycle with no stamped run_context cannot resolve a run id → RunEventOther.
	procNoContext, e6 := evidence.NewProcessLifecycle(evCommon(""), evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionPROCESSEXITED,
		Identity:   wire.ProcessIdentity{BootId: "boot-1", Pid: 102, ProcessStartTime: 7},
	})

	cases := []struct {
		name    string
		payload []byte
		kind    RunEventKind
		runID   string
	}{
		{"RUN_STARTED", canonicalBytesOf(t, runStarted, e1), RunEventStarted, "R1"},
		{"RUN_ENDED_drain", canonicalBytesOf(t, runEndedDrain, e2), RunEventTerminated, "R1"},
		{"RUN_ENDED_launch_failure", canonicalBytesOf(t, runEndedLaunchFail, e3), RunEventTerminated, "R2"},
		{"PROCESS_EXITED", canonicalBytesOf(t, procExited, e4), RunEventTerminated, "R3"},
		{"PROCESS_LAUNCH_FAILED", canonicalBytesOf(t, procLaunchFailed, e5), RunEventTerminated, "R4"},
		{"PROCESS_no_run_context", canonicalBytesOf(t, procNoContext, e6), RunEventOther, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, runID := classifyRunFrame(c.payload)
			if kind != c.kind || runID != c.runID {
				t.Fatalf("classifyRunFrame(canonical %s) = (%v, %q), want (%v, %q)\npayload: %s",
					c.name, kind, runID, c.kind, c.runID, c.payload)
			}
		})
	}
}

func TestScanRunEventsInSequenceOrder(t *testing.T) {
	dir := recoverDir(t)
	buildSegmentPayloads(t, walOf(dir), 1,
		runStartedPayload("R1"), passivePayload(), runEndedPayload("R1"))
	buildSegmentPayloads(t, walOf(dir), 4,
		runStartedPayload("R2"), processExitedPayload("R2"))
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	want := []RunEvent{
		{Sequence: 1, RunID: "R1", Kind: RunEventStarted},
		{Sequence: 3, RunID: "R1", Kind: RunEventTerminated},
		{Sequence: 4, RunID: "R2", Kind: RunEventStarted},
		{Sequence: 5, RunID: "R2", Kind: RunEventTerminated},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events[%d] = %v, want %v", i, events[i], want[i])
		}
	}
}

func TestScanRunEventsToleratesInterruptedCreateTail(t *testing.T) {
	// A benign interrupted-create trailing segment (a crash during CreateSegment) is what
	// Recover tolerates as OutcomeInterruptedCreate. ScanRunEvents/ReconcileReserves must
	// tolerate it identically instead of hard-erroring on decodeSegmentHeader.
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	buildSegmentPayloads(t, walOf(dir), 1, runStartedPayload("R1"), passivePayload()) // [1,2]
	slot := filepath.Join(walOf(dir), segmentFilename(3))
	if err := os.WriteFile(slot, nil, fileMode); err != nil {
		t.Fatalf("seed interrupted-create tail: %v", err)
	}

	rec := mustRecover(t, dir)
	if rec.Outcome != OutcomeInterruptedCreate {
		t.Fatalf("recover outcome = %v, want OutcomeInterruptedCreate", rec.Outcome)
	}

	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents hard-failed on interrupted-create tail: %v", err)
	}
	if len(events) != 1 || events[0].RunID != "R1" || events[0].Kind != RunEventStarted {
		t.Fatalf("events = %v, want a single RUN_STARTED(R1)", events)
	}
	// End-to-end reconciliation still succeeds and re-derives R1 as still-open.
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves with interrupted-create tail: %v", err)
	}
	if !r.IsOpen("R1") {
		t.Fatalf("R1 reserve not re-derived past the interrupted-create tail")
	}
}

// ---- recovery reconciliation ----

func TestReconcileCrashAfterRunStartedReAddsReserve(t *testing.T) {
	// RUN_STARTED was durably appended, then a crash hit before the sidecar preallocation.
	dir := recoverDir(t)
	buildSegmentPayloads(t, walOf(dir), 1, runStartedPayload("R1"), passivePayload())
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves: %v", err)
	}
	if !r.IsOpen("R1") || r.OpenReserveBytes() != testFixedReserve {
		t.Fatalf("still-open RUN_STARTED reserve not re-derived: open=%v bytes=%d", r.IsOpen("R1"), r.OpenReserveBytes())
	}
	// The reconciled state was persisted.
	reloaded, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.IsOpen("R1") {
		t.Fatalf("reconciled reserve not persisted")
	}
}

func TestReconcileCrashAfterTerminalReleasesReserve(t *testing.T) {
	// The terminal frame is durable, the sidecar still holds the reserve (crash before release).
	dir := recoverDir(t)
	buildSegmentPayloads(t, walOf(dir), 1, runStartedPayload("R1"), runEndedPayload("R1"))
	seed, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := seed.Reserve("R1"); err != nil {
		t.Fatalf("seed Reserve: %v", err)
	}
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves: %v", err)
	}
	if r.IsOpen("R1") || r.OpenReserveBytes() != 0 {
		t.Fatalf("closed run's reserve not released: open=%v bytes=%d", r.IsOpen("R1"), r.OpenReserveBytes())
	}
}

func TestReconcileTerminalOnlyReleasesStaleSidecarEntry(t *testing.T) {
	// The RUN_STARTED was compacted; only the terminal frame remains, proving the run closed.
	dir := recoverDir(t)
	buildSegmentPayloads(t, walOf(dir), 5, runEndedPayload("R1"))
	seed, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := seed.Reserve("R1"); err != nil {
		t.Fatalf("seed Reserve: %v", err)
	}
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves: %v", err)
	}
	if r.IsOpen("R1") {
		t.Fatalf("terminal frame did not release the stale sidecar reserve")
	}
}

func TestReconcileKeepsSidecarOnlyOpenRun(t *testing.T) {
	// A run whose RUN_STARTED was acknowledged and compacted, still open: no frame contradicts
	// the authoritative sidecar, so the reserve is kept.
	dir := recoverDir(t)
	buildSegmentPayloads(t, walOf(dir), 5, passivePayload()) // no R1 frames survive
	seed, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := seed.Reserve("R1"); err != nil {
		t.Fatalf("seed Reserve: %v", err)
	}
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves: %v", err)
	}
	if !r.IsOpen("R1") || r.OpenReserveBytes() != testFixedReserve {
		t.Fatalf("authoritative sidecar reserve lost: open=%v bytes=%d", r.IsOpen("R1"), r.OpenReserveBytes())
	}
}

// TestFinding10AckCompactStillOpenRunSurvivesRestartUnderHardPressure is the S2.1 finding-10
// case: a still-open run's RUN_STARTED segment is acknowledged and compacted, then the daemon
// restarts under hard pressure. The reserve (authoritative in the sidecar) AND next_sequence
// both survive.
func TestFinding10AckCompactStillOpenRunSurvivesRestartUnderHardPressure(t *testing.T) {
	dir := recoverDir(t)
	if err := writeIdentity(dir, testSourceID, 1); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	// seg0 = [1,3] holds RUN_STARTED(R1); seg1 = [4,5] is the active tail. R1 never ends.
	buildSegmentPayloads(t, walOf(dir), 1, runStartedPayload("R1"), passivePayload(), passivePayload())
	buildSegmentPayloads(t, walOf(dir), 4, passivePayload(), passivePayload())

	// Preallocate R1's reserve (done atomically with RUN_STARTED in production).
	r0, err := LoadReserves(dir, testFixedReserve)
	if err != nil {
		t.Fatalf("LoadReserves: %v", err)
	}
	if err := r0.Reserve("R1"); err != nil {
		t.Fatalf("Reserve R1: %v", err)
	}
	// Acknowledge through 3 (covers seg0) and compact it away — the RUN_STARTED frame is gone.
	if err := writeAck(dir, 3); err != nil {
		t.Fatalf("writeAck: %v", err)
	}
	res, err := Compact(dir, 3)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(res.RemovedSegments) != 1 {
		t.Fatalf("compaction removed %v, want seg0", res.RemovedSegments)
	}

	// --- restart ---
	rec := mustRecover(t, dir)
	if rec.NextSequence != 6 {
		t.Fatalf("NextSequence after ack+compact = %d, want 6", rec.NextSequence)
	}
	events, err := ScanRunEvents(dir)
	if err != nil {
		t.Fatalf("ScanRunEvents: %v", err)
	}
	// No RUN_STARTED/terminal for R1 survives on disk.
	for _, e := range events {
		if e.RunID == "R1" {
			t.Fatalf("unexpected surviving R1 event %v", e)
		}
	}
	r, err := ReconcileReserves(dir, testFixedReserve, events)
	if err != nil {
		t.Fatalf("ReconcileReserves: %v", err)
	}
	if !r.IsOpen("R1") || r.OpenReserveBytes() != testFixedReserve {
		t.Fatalf("finding-10: reserve lost after ack+compact+restart: open=%v bytes=%d", r.IsOpen("R1"), r.OpenReserveBytes())
	}

	// Under hard pressure the reserve is preserved and new explicit runs are rejected, while the
	// still-open run keeps its terminal reserve.
	model, err := NewCapacityModel(CapacityConfig{
		CeilingBytes: 1000, MaxSegmentBytes: 100, ScratchBytes: 50,
		TerminalReserveBytes: testFixedReserve, SoftThresholdBytes: 600,
	})
	if err != nil {
		t.Fatalf("NewCapacityModel: %v", err)
	}
	st := model.Evaluate(870, r.OpenReserveBytes()) // committed well past the hard floor (850)
	if st.Pressure != PressureHard {
		t.Fatalf("pressure = %v, want hard", st.Pressure)
	}
	if st.AdmitNewExplicitRun {
		t.Fatalf("admitted a new explicit run under hard pressure")
	}
	if !r.IsOpen("R1") {
		t.Fatalf("hard pressure evicted the open run's reserve")
	}
}

// ---- byte-ceiling accounting ----

func newModel(t *testing.T) CapacityModel {
	t.Helper()
	m, err := NewCapacityModel(CapacityConfig{
		CeilingBytes: 1000, MaxSegmentBytes: 100, ScratchBytes: 50,
		TerminalReserveBytes: 40, SoftThresholdBytes: 600,
	})
	if err != nil {
		t.Fatalf("NewCapacityModel: %v", err)
	}
	return m
}

func TestCapacityPressureThresholdsNearFullDisk(t *testing.T) {
	m := newModel(t)
	// hardFloor = 1000 - 100 - 50 = 850; soft = 600.
	cases := []struct {
		used, reserve int64
		pressure      Pressure
		passive       bool
		newRun        bool
	}{
		{500, 0, PressureNone, true, true},   // 500+40=540 <= 850
		{599, 0, PressureNone, true, true},   // just below soft
		{600, 0, PressureSoft, false, true},  // at soft; 640 <= 850
		{810, 0, PressureSoft, false, true},  // 850 boundary: 810+40=850 <= 850 admit
		{811, 0, PressureSoft, false, false}, // 811+40=851 > 850 reject new run, still soft
		{849, 0, PressureSoft, false, false},
		{850, 0, PressureHard, false, false}, // at hard floor
		{900, 0, PressureHard, false, false},
		{810, 40, PressureHard, false, false}, // committed 850 via open reserve
	}
	for _, c := range cases {
		st := m.Evaluate(c.used, c.reserve)
		if st.Pressure != c.pressure || st.AdmitPassiveCapture != c.passive || st.AdmitNewExplicitRun != c.newRun {
			t.Fatalf("Evaluate(%d,%d) = {p=%v passive=%v newRun=%v}, want {p=%v passive=%v newRun=%v}",
				c.used, c.reserve, st.Pressure, st.AdmitPassiveCapture, st.AdmitNewExplicitRun,
				c.pressure, c.passive, c.newRun)
		}
	}
}

func TestCapacityRequiredCeilingFormula(t *testing.T) {
	m, err := NewCapacityModel(CapacityConfig{
		CeilingBytes: 100000, MaxSegmentBytes: 100, ScratchBytes: 50,
		OfflineNormalizedBytes: 200, TerminalReserveBytes: 40, SoftThresholdBytes: 600,
	})
	if err != nil {
		t.Fatalf("NewCapacityModel: %v", err)
	}
	// base = 200 + 50 + 150 = 400; +25% margin = 500; + one max segment 100 = 600.
	if got := m.RequiredCeiling(150); got != 600 {
		t.Fatalf("RequiredCeiling(150) = %d, want 600", got)
	}
}

func TestCapacityDefaultSoftThresholdBelowHardFloorSmallCeiling(t *testing.T) {
	// Realistic default-segment ratio: a 128 MiB ceiling with the default 64 MiB max segment.
	// The old ceiling-anchored default (0.75*ceiling = 96 MiB) landed above hardFloor (64 MiB)
	// and refused to construct. The hard-floor-anchored default must construct and place the
	// soft threshold strictly below the floor.
	m, err := NewCapacityModel(CapacityConfig{
		CeilingBytes:         2 * DefaultSegmentCeiling, // 128 MiB
		MaxSegmentBytes:      DefaultSegmentCeiling,     // 64 MiB
		TerminalReserveBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("small-ceiling default soft threshold refused to construct: %v", err)
	}
	// hardFloor = 128 - 64 = 64 MiB; default soft = floor(0.75 * 64 MiB) = 48 MiB.
	const softAt = 48 << 20
	if st := m.Evaluate(softAt, 0); st.Pressure != PressureSoft {
		t.Fatalf("at default soft threshold: pressure = %v, want soft", st.Pressure)
	}
	if st := m.Evaluate(softAt-1, 0); st.Pressure != PressureNone {
		t.Fatalf("just below default soft threshold: pressure = %v, want none", st.Pressure)
	}
	if st := m.Evaluate(64<<20, 0); st.Pressure != PressureHard {
		t.Fatalf("at hard floor: pressure = %v, want hard", st.Pressure)
	}
}

func TestCapacityConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  CapacityConfig
		ok   bool
	}{
		{"zero ceiling", CapacityConfig{CeilingBytes: 0, MaxSegmentBytes: 100}, false},
		{"margin below floor", CapacityConfig{CeilingBytes: 1000, MaxSegmentBytes: 100, SafetyMarginRatio: 0.1}, false},
		{"no room after reserves", CapacityConfig{CeilingBytes: 100, MaxSegmentBytes: 100, ScratchBytes: 50}, false},
		{"soft above hard floor", CapacityConfig{CeilingBytes: 1000, MaxSegmentBytes: 100, ScratchBytes: 50, SoftThresholdBytes: 900}, false},
		{"defaults applied", CapacityConfig{CeilingBytes: 1000, MaxSegmentBytes: 100, ScratchBytes: 50}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewCapacityModel(c.cfg)
			if c.ok && err != nil {
				t.Fatalf("NewCapacityModel: unexpected err %v", err)
			}
			if !c.ok && !errors.Is(err, ErrCapacityConfig) {
				t.Fatalf("NewCapacityModel: err = %v, want ErrCapacityConfig", err)
			}
		})
	}
}

func TestWALBytesTracksSegmentsAndCompaction(t *testing.T) {
	dir := recoverDir(t)
	if empty, err := WALBytes(dir); err != nil || empty != 0 {
		t.Fatalf("WALBytes(empty) = %d, %v, want 0/nil", empty, err)
	}
	buildSegment(t, walOf(dir), 1, 5)
	buildSegment(t, walOf(dir), 6, 5) // active tail
	before, err := WALBytes(dir)
	if err != nil {
		t.Fatalf("WALBytes: %v", err)
	}
	if before <= 0 {
		t.Fatalf("WALBytes = %d, want > 0", before)
	}
	if _, err := Compact(dir, 5); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	after, err := WALBytes(dir)
	if err != nil {
		t.Fatalf("WALBytes after: %v", err)
	}
	if after >= before {
		t.Fatalf("WALBytes after compaction = %d, want < %d", after, before)
	}
}
