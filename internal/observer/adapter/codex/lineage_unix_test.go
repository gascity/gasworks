//go:build unix

package codex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestLineageSleeperHelper is the re-exec'd child used by startSleeperChild. Under the normal
// suite (env unset) it is a no-op; as a spawned child it blocks on stdin so the parent controls
// its lifetime and it stays a live, walkable /proc ancestor.
func TestLineageSleeperHelper(t *testing.T) {
	if os.Getenv("CODEX_LINEAGE_SLEEPER") != "1" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// startSleeperChild spawns a direct child process (whose parent is this test process) and
// returns its pid once it is visible in /proc. The child is a real process with a real ancestry
// chain, so the lineage walk exercises real /proc.
func startSleeperChild(t *testing.T) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLineageSleeperHelper")
	cmd.Env = append(os.Environ(), "CODEX_LINEAGE_SLEEPER=1")
	cmd.Stdin = r
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatalf("start child: %v", err)
	}
	r.Close() // the child holds its own copy of the read end
	t.Cleanup(func() {
		w.Close() // EOF to the child → it returns and exits
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, err := readProcStat(pid); err == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("child pid %d never appeared in /proc", pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestProcessAncestryExcludesSelfNearestFirst proves the /proc walk excludes the starting
// process and orders strict ancestors nearest-first with the supplied boot id.
func TestProcessAncestryExcludesSelfNearestFirst(t *testing.T) {
	self := os.Getpid()
	parent := os.Getppid()
	if parent <= 1 {
		t.Skip("test process has no non-init parent to walk")
	}
	chain := processAncestry(self, "boot-x")
	if len(chain) == 0 {
		t.Fatal("expected at least one ancestor")
	}
	if chain[0].Pid != int64(parent) {
		t.Fatalf("nearest ancestor pid = %d, want parent %d", chain[0].Pid, parent)
	}
	for _, id := range chain {
		if id.Pid == int64(self) {
			t.Fatal("ancestry must exclude the starting process itself")
		}
		if id.BootId != "boot-x" {
			t.Fatalf("boot id = %q, want boot-x", id.BootId)
		}
	}
}

// TestProveLineageNearestAncestorWins proves that when exact lineage reaches multiple registered
// wrappers, the NEAREST registered ancestor wins and farther ones are retained only as
// correlation (Outer).
func TestProveLineageNearestAncestorWins(t *testing.T) {
	child := startSleeperChild(t)
	self := os.Getpid()
	parent := os.Getppid()
	if parent <= 1 {
		t.Skip("test process has no non-init parent for a two-wrapper chain")
	}
	seam := newFakeSeam()
	seam.register(identityForPID(t, self), "gwr_nearest")   // child's parent
	seam.register(identityForPID(t, parent), "gwr_farther") // child's grandparent

	proof, err := proveLineage(context.Background(), seam, child)
	if err != nil {
		t.Fatalf("proveLineage: %v", err)
	}
	if !proof.Attached {
		t.Fatal("expected an attached lineage proof")
	}
	if proof.Nearest.RunID != "gwr_nearest" {
		t.Fatalf("nearest run = %q, want gwr_nearest", proof.Nearest.RunID)
	}
	found := false
	for _, o := range proof.Outer {
		if o.RunID == "gwr_farther" {
			found = true
		}
	}
	if !found {
		t.Fatalf("farther registered ancestor gwr_farther missing from Outer correlation: %+v", proof.Outer)
	}
}

// TestDecideExactLineageAttachesHigh proves a hook that is an exact descendant of a registered
// wrapper, with no inherited run id, attaches HIGH via PROVEN_PROCESS_LINEAGE.
func TestDecideExactLineageAttachesHigh(t *testing.T) {
	child := startSleeperChild(t)
	seam := newFakeSeam()
	seam.register(identityForPID(t, os.Getpid()), "gwr_lineage")

	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		HookPID:         child,
	})
	if d.Disposition != DispositionAttachHigh {
		t.Fatalf("disposition = %v, want AttachHigh", d.Disposition)
	}
	if d.RunID != "gwr_lineage" {
		t.Fatalf("run id = %q, want gwr_lineage", d.RunID)
	}
	if d.Membership != wire.RunContextMembershipEvidencePROVENPROCESSLINEAGE {
		t.Fatalf("membership = %q, want PROVEN_PROCESS_LINEAGE", d.Membership)
	}
}

// TestDecideInheritedConflictsWithLineageQuarantined proves an inherited id that resolves OPEN
// but disagrees with the nearest proven process ancestor is quarantined (conflict precedence).
func TestDecideInheritedConflictsWithLineageQuarantined(t *testing.T) {
	child := startSleeperChild(t)
	seam := newFakeSeam()
	seam.register(identityForPID(t, os.Getpid()), "gwr_lineage")
	seam.resolve("gwr_inherited", InheritedOpenSameScope) // resolvable but a DIFFERENT run

	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		InheritedRunID:  "gwr_inherited",
		HookPID:         child,
	})
	if d.Disposition != DispositionQuarantine {
		t.Fatalf("disposition = %v, want Quarantine", d.Disposition)
	}
	if d.Quarantine != QuarantineLineageConflict {
		t.Fatalf("reason = %v, want QuarantineLineageConflict", d.Quarantine)
	}
}

// TestDecideInheritedAgreesWithLineageAttachesHigh proves that when the inherited id and the
// nearest proven ancestor name the SAME run (the ordinary wrapped session), it attaches HIGH via
// INHERITED_RUN_ID with no conflict.
func TestDecideInheritedAgreesWithLineageAttachesHigh(t *testing.T) {
	child := startSleeperChild(t)
	seam := newFakeSeam()
	seam.register(identityForPID(t, os.Getpid()), "gwr_shared")
	seam.resolve("gwr_shared", InheritedOpenSameScope)

	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		InheritedRunID:  "gwr_shared",
		HookPID:         child,
	})
	if d.Disposition != DispositionAttachHigh {
		t.Fatalf("disposition = %v, want AttachHigh", d.Disposition)
	}
	if d.Membership != wire.RunContextMembershipEvidenceINHERITEDRUNID {
		t.Fatalf("membership = %q, want INHERITED_RUN_ID", d.Membership)
	}
	if d.RunID != "gwr_shared" {
		t.Fatalf("run id = %q, want gwr_shared", d.RunID)
	}
}

// TestProveLineageSeamErrorPropagates proves an ancestry-query transport failure surfaces as an
// error (the caller degrades it to a separate inferred run).
func TestProveLineageSeamErrorPropagates(t *testing.T) {
	seam := newFakeSeam()
	seam.lookupErr = errors.New("boom")
	if _, err := proveLineage(context.Background(), seam, os.Getpid()); err == nil {
		t.Fatal("expected a seam-query error to propagate")
	}
}

// TestDecideLineageQueryErrorDegradesToInferred proves that a lineage-query failure on the
// no-inherited path degrades to a separate inferred run with ProofUnavailable surfaced.
func TestDecideLineageQueryErrorDegradesToInferred(t *testing.T) {
	seam := newFakeSeam()
	seam.lookupErr = errors.New("boom")
	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		HookPID:         os.Getpid(),
	})
	if d.Disposition != DispositionInferred {
		t.Fatalf("disposition = %v, want Inferred", d.Disposition)
	}
	if !d.ProofUnavailable {
		t.Fatal("ProofUnavailable = false, want true")
	}
}

// chainStat builds a statFunc from a fixed pid → (ppid, startTime) table. An unlisted pid is an
// unreadable /proc entry (the walk stops there, as it would for a real vanished process).
func chainStat(table map[int][2]int64) statFunc {
	return func(pid int) (int, int64, error) {
		v, ok := table[pid]
		if !ok {
			return 0, 0, fmt.Errorf("no pid %d", pid)
		}
		return int(v[0]), v[1], nil
	}
}

// TestWalkAncestryStartTimeMonotonicityGate proves the pid-reuse defense (red-team finding 0): an
// ancestor whose process_start_time exceeds the child generation's start_time is a recycled-pid
// impostor and is rejected, stopping the walk; a legitimate chain with non-increasing start_times
// is fully recorded; an equal start_time (fast fork) is accepted.
func TestWalkAncestryStartTimeMonotonicityGate(t *testing.T) {
	// Legitimate, strictly decreasing start_times upward: 1000(500) → 2000(300) → 3000(100).
	legit := walkAncestry(1000, "boot-x", chainStat(map[int][2]int64{
		1000: {2000, 500}, 2000: {3000, 300}, 3000: {1, 100},
	}))
	if len(legit) != 2 || legit[0].Pid != 2000 || legit[1].Pid != 3000 {
		t.Fatalf("legitimate chain = %+v, want [2000, 3000]", legit)
	}

	// Recycled direct parent: pid 2000 started AFTER the child (900 > 500) → rejected, walk stops.
	reuse := walkAncestry(1000, "boot-x", chainStat(map[int][2]int64{
		1000: {2000, 500}, 2000: {1, 900},
	}))
	if len(reuse) != 0 {
		t.Fatalf("recycled parent must be rejected; got %+v", reuse)
	}

	// Reuse mid-chain: parent 2000 ok (300), grandparent 3000 recycled (400 > 300) → keep parent only.
	mid := walkAncestry(1000, "boot-x", chainStat(map[int][2]int64{
		1000: {2000, 500}, 2000: {3000, 300}, 3000: {1, 400},
	}))
	if len(mid) != 1 || mid[0].Pid != 2000 {
		t.Fatalf("mid-chain reuse must keep only the parent; got %+v", mid)
	}

	// Equal start_time (parent and child in the same tick) is a valid parent, not an impostor.
	equal := walkAncestry(1000, "boot-x", chainStat(map[int][2]int64{
		1000: {2000, 500}, 2000: {1, 500},
	}))
	if len(equal) != 1 || equal[0].Pid != 2000 {
		t.Fatalf("equal start_time parent must be accepted; got %+v", equal)
	}
}

// TestDecidePidReuseAncestorFallsThroughToInferred is the live decision-level probe: a registered
// wrapper whose pid was recycled to a later-started process (its OWN full-tuple registration would
// match) must NOT produce a HIGH merge — the monotonicity gate keeps the impostor out of the
// chain and the session falls through to a separate inferred run. The legitimate monotonic
// variant at the same pid still proves HIGH.
func TestDecidePidReuseAncestorFallsThroughToInferred(t *testing.T) {
	boot, err := hostBootID()
	if err != nil {
		t.Skipf("no host boot id: %v", err)
	}
	old := procStatReader
	t.Cleanup(func() { procStatReader = old })

	// Impostor: child 1000 (start 500) → pid 2000 recycled, start 900 (> 500).
	procStatReader = chainStat(map[int][2]int64{1000: {2000, 500}, 2000: {1, 900}})
	impostorSeam := newFakeSeam()
	impostorSeam.register(wire.ProcessIdentity{BootId: boot, Pid: 2000, ProcessStartTime: 900}, "gwr_impostor")
	dImp := Decide(context.Background(), impostorSeam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		HookPID:         1000,
	})
	if dImp.Disposition != DispositionInferred {
		t.Fatalf("impostor: disposition = %v, want Inferred", dImp.Disposition)
	}
	if dImp.RunID == "gwr_impostor" {
		t.Fatal("impostor: attached HIGH to a recycled-pid run — false merge not prevented")
	}

	// Legitimate: same pid, start 300 (<= child 500) → HIGH via proven lineage.
	procStatReader = chainStat(map[int][2]int64{1000: {2000, 500}, 2000: {1, 300}})
	realSeam := newFakeSeam()
	realSeam.register(wire.ProcessIdentity{BootId: boot, Pid: 2000, ProcessStartTime: 300}, "gwr_real")
	dReal := Decide(context.Background(), realSeam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		HookPID:         1000,
	})
	if dReal.Disposition != DispositionAttachHigh || dReal.RunID != "gwr_real" {
		t.Fatalf("legitimate ancestor: got %v run=%q, want AttachHigh gwr_real", dReal.Disposition, dReal.RunID)
	}
	if dReal.Membership != wire.RunContextMembershipEvidencePROVENPROCESSLINEAGE {
		t.Fatalf("legitimate ancestor: membership = %q, want PROVEN_PROCESS_LINEAGE", dReal.Membership)
	}
}
