//go:build linux

package daemon

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestRegistryFoldRegisteredThenBoundaries folds REGISTERED, then RUN_STARTED, then RUN_ENDED and
// asserts Lookup/Resolve reflect each step, including the four ResolveInherited classifications.
func TestRegistryFoldRegisteredThenBoundaries(t *testing.T) {
	reg := NewRegistry("src_test", "ws_main")
	id := wire.ProcessIdentity{BootId: "boot-1", Pid: 4242, ProcessStartTime: 99}

	// REGISTERED maps the process identity to the run it opened.
	if err := reg.Fold(sealObs(t, registeredPending(t, id, "run_1"), 1)); err != nil {
		t.Fatalf("fold REGISTERED: %v", err)
	}
	if got, ok := reg.LookupRegistered(id); !ok || got != "run_1" {
		t.Fatalf("LookupRegistered = (%q, %v), want (run_1, true)", got, ok)
	}
	// Before RUN_STARTED, the boundary is unknown (registration does not open a boundary).
	if s := reg.ResolveInherited("run_1", "ws_main"); s != local.InheritedRunUnknown {
		t.Errorf("resolve before RUN_STARTED = %q, want UNKNOWN", s)
	}

	// RUN_STARTED opens the boundary.
	if err := reg.Fold(sealObs(t, runStartedPending(t, "run_1"), 2)); err != nil {
		t.Fatalf("fold RUN_STARTED: %v", err)
	}
	if s := reg.ResolveInherited("run_1", "ws_main"); s != local.InheritedRunOpenSameScope {
		t.Errorf("resolve same workspace = %q, want OPEN_SAME_SCOPE", s)
	}
	if s := reg.ResolveInherited("run_1", "ws_other"); s != local.InheritedRunCrossWorkspace {
		t.Errorf("resolve other workspace = %q, want CROSS_WORKSPACE", s)
	}

	// RUN_ENDED closes the boundary.
	if err := reg.Fold(sealObs(t, runEndedPending(t, "run_1"), 3)); err != nil {
		t.Fatalf("fold RUN_ENDED: %v", err)
	}
	if s := reg.ResolveInherited("run_1", "ws_main"); s != local.InheritedRunClosed {
		t.Errorf("resolve after RUN_ENDED = %q, want CLOSED", s)
	}

	// An unknown run id (covers cross-source) is UNKNOWN, and an unregistered identity misses.
	if s := reg.ResolveInherited("run_absent", "ws_main"); s != local.InheritedRunUnknown {
		t.Errorf("resolve absent run = %q, want UNKNOWN", s)
	}
	if _, ok := reg.LookupRegistered(wire.ProcessIdentity{BootId: "boot-nope", Pid: 1, ProcessStartTime: 1}); ok {
		t.Errorf("LookupRegistered of an unregistered identity returned found=true")
	}
}

// TestRegistryBootReplayRebuildsFromWAL populates a real WAL through the spool writer while folding
// the same observations live, then rebuilds a fresh registry with ReplayWAL and proves the two are
// byte-for-byte identical projections.
func TestRegistryBootReplayRebuildsFromWAL(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	live := NewRegistry("src_test", "ws_main")

	id := wire.ProcessIdentity{BootId: "boot-xyz", Pid: 5150, ProcessStartTime: 424242}
	steps := []func(*testing.T) wire.Observation{
		func(t *testing.T) wire.Observation {
			return sealObs(t, registeredPending(t, id, "run_open"), wire.SequenceMin)
		},
		func(t *testing.T) wire.Observation {
			return sealObs(t, runStartedPending(t, "run_open"), wire.SequenceMin)
		},
		func(t *testing.T) wire.Observation {
			return sealObs(t, runStartedPending(t, "run_closed"), wire.SequenceMin)
		},
		func(t *testing.T) wire.Observation {
			return sealObs(t, runEndedPending(t, "run_closed"), wire.SequenceMin)
		},
	}
	for _, step := range steps {
		obs := step(t)
		// Append restamps the sequence into the WAL; the live fold sees the pre-restamp value, which
		// the registry ignores — proving the append-path and replay-path projections converge.
		if _, err := w.AppendObservation(obs); err != nil {
			t.Fatalf("AppendObservation: %v", err)
		}
		if err := live.Fold(obs); err != nil {
			t.Fatalf("live fold: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	replayed := NewRegistry("src_test", "ws_main")
	if err := ReplayWAL(dir, replayed); err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}

	if !reflect.DeepEqual(live.registered, replayed.registered) {
		t.Errorf("registered index diverged:\n live=%v\n replay=%v", live.registered, replayed.registered)
	}
	if !reflect.DeepEqual(live.boundaries, replayed.boundaries) {
		t.Errorf("boundary index diverged:\n live=%v\n replay=%v", live.boundaries, replayed.boundaries)
	}
	// Spot-check the rebuilt projection answers queries identically.
	if got, ok := replayed.LookupRegistered(id); !ok || got != "run_open" {
		t.Errorf("replayed LookupRegistered = (%q,%v), want (run_open,true)", got, ok)
	}
	if s := replayed.ResolveInherited("run_open", "ws_main"); s != local.InheritedRunOpenSameScope {
		t.Errorf("replayed resolve run_open = %q, want OPEN_SAME_SCOPE", s)
	}
	if s := replayed.ResolveInherited("run_closed", "ws_main"); s != local.InheritedRunClosed {
		t.Errorf("replayed resolve run_closed = %q, want CLOSED", s)
	}
}

// TestRegistryClosureIsTerminalOnReopen is the BLOCKER regression: a RUN_STARTED that arrives after
// a run's RUN_ENDED must NOT reopen it. A WAL of [RUN_STARTED, RUN_ENDED, RUN_STARTED(same id)] must
// resolve CLOSED on BOTH the live fold and the boot replay, so codex.Decide quarantines the inherited
// id instead of attaching HIGH to a run the spec says is permanently closed.
func TestRegistryClosureIsTerminalOnReopen(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	live := NewRegistry("src_test", "ws_main")

	// RUN_STARTED opens.
	openObs := sealObs(t, runStartedPending(t, "run_x"), wire.SequenceMin)
	appendToWriter(t, w, openObs)
	if err := live.Fold(openObs); err != nil {
		t.Fatalf("fold RUN_STARTED: %v", err)
	}
	if s := live.ResolveInherited("run_x", "ws_main"); s != local.InheritedRunOpenSameScope {
		t.Fatalf("after RUN_STARTED = %q, want OPEN_SAME_SCOPE", s)
	}

	// RUN_ENDED closes — a normal [RUN_STARTED, RUN_ENDED] resolves CLOSED.
	endObs := sealObs(t, runEndedPending(t, "run_x"), wire.SequenceMin)
	appendToWriter(t, w, endObs)
	if err := live.Fold(endObs); err != nil {
		t.Fatalf("fold RUN_ENDED: %v", err)
	}
	if s := live.ResolveInherited("run_x", "ws_main"); s != local.InheritedRunClosed {
		t.Fatalf("after RUN_ENDED = %q, want CLOSED", s)
	}

	// A later RUN_STARTED must NOT reopen — closure is terminal.
	reopenObs := sealObs(t, runStartedPending(t, "run_x"), wire.SequenceMin)
	appendToWriter(t, w, reopenObs)
	if err := live.Fold(reopenObs); err != nil {
		t.Fatalf("fold reopen RUN_STARTED: %v", err)
	}
	if s := live.ResolveInherited("run_x", "ws_main"); s != local.InheritedRunClosed {
		t.Errorf("live fold after reopen = %q, want CLOSED (closure is terminal)", s)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// The boot replay converges on the same terminal-CLOSED state.
	replayed := NewRegistry("src_test", "ws_main")
	if err := ReplayWAL(dir, replayed); err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if s := replayed.ResolveInherited("run_x", "ws_main"); s != local.InheritedRunClosed {
		t.Errorf("replay after reopen = %q, want CLOSED", s)
	}
	if !reflect.DeepEqual(live.boundaries, replayed.boundaries) {
		t.Errorf("live vs replay boundaries diverged:\n live=%v\n replay=%v", live.boundaries, replayed.boundaries)
	}
}

// TestRegistryPreEndDuplicateStartCloses proves an idempotent pre-END duplicate RUN_STARTED does not
// break the close: [RUN_STARTED, RUN_STARTED, RUN_ENDED] resolves CLOSED (the second start folds to
// open, then RUN_ENDED closes it).
func TestRegistryPreEndDuplicateStartCloses(t *testing.T) {
	reg := NewRegistry("src_test", "ws_main")
	if err := reg.Fold(sealObs(t, runStartedPending(t, "run_y"), 1)); err != nil {
		t.Fatalf("fold start 1: %v", err)
	}
	if err := reg.Fold(sealObs(t, runStartedPending(t, "run_y"), 2)); err != nil {
		t.Fatalf("fold start 2: %v", err)
	}
	// Still open after the duplicate start.
	if s := reg.ResolveInherited("run_y", "ws_main"); s != local.InheritedRunOpenSameScope {
		t.Fatalf("after duplicate RUN_STARTED = %q, want OPEN_SAME_SCOPE", s)
	}
	if err := reg.Fold(sealObs(t, runEndedPending(t, "run_y"), 3)); err != nil {
		t.Fatalf("fold end: %v", err)
	}
	if s := reg.ResolveInherited("run_y", "ws_main"); s != local.InheritedRunClosed {
		t.Errorf("[START,START,END] = %q, want CLOSED", s)
	}
}

// TestReplayWALEmptyIsNoError proves a daemon booting with no WAL yet gets an empty projection, not
// an error.
func TestReplayWALEmptyIsNoError(t *testing.T) {
	reg := NewRegistry("src_test", "ws_main")
	if err := ReplayWAL(t.TempDir(), reg); err != nil {
		t.Fatalf("ReplayWAL on empty dir: %v", err)
	}
	if s := reg.ResolveInherited("run_any", "ws_main"); s != local.InheritedRunUnknown {
		t.Errorf("empty registry resolve = %q, want UNKNOWN", s)
	}
}

// TestRegistryConcurrentFoldAndQuery runs folds and queries from many goroutines under -race to
// prove the projection is concurrency-safe. Observations are pre-sealed on the test goroutine so
// no helper calls t.Fatal off the main goroutine.
func TestRegistryConcurrentFoldAndQuery(t *testing.T) {
	const workers = 8
	reg := NewRegistry("src_test", "ws_main")

	type unit struct {
		id   wire.ProcessIdentity
		run  string
		reg  wire.Observation
		strt wire.Observation
		end  wire.Observation
	}
	units := make([]unit, workers)
	for i := 0; i < workers; i++ {
		id := wire.ProcessIdentity{BootId: fmt.Sprintf("boot-%d", i), Pid: int64(1000 + i), ProcessStartTime: int64(10 * i)}
		run := fmt.Sprintf("run_%d", i)
		units[i] = unit{
			id:   id,
			run:  run,
			reg:  sealObs(t, registeredPending(t, id, run), int64(3*i+1)),
			strt: sealObs(t, runStartedPending(t, run), int64(3*i+2)),
			end:  sealObs(t, runEndedPending(t, run), int64(3*i+3)),
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		u := units[i]
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = reg.Fold(u.reg)
			_ = reg.Fold(u.strt)
			_ = reg.Fold(u.end)
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = reg.LookupRegistered(u.id)
				_ = reg.ResolveInherited(u.run, "ws_main")
			}
		}()
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		u := units[i]
		if got, ok := reg.LookupRegistered(u.id); !ok || got != u.run {
			t.Errorf("worker %d LookupRegistered = (%q,%v), want (%q,true)", i, got, ok, u.run)
		}
		if s := reg.ResolveInherited(u.run, "ws_main"); s != local.InheritedRunClosed {
			t.Errorf("worker %d resolve = %q, want CLOSED", i, s)
		}
	}
}
