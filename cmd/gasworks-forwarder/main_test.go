package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRun_NoArgsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	if code := run([]string{"bogus"}); code != 2 {
		t.Fatalf("run(bogus) = %d, want 2", code)
	}
}

func TestRun_EventsIdleExitsZero(t *testing.T) {
	// No GASWORKS_EVENTS_* config => the events axis is idle. It must return 0 without
	// dialing (the egress gate keeps it from building a client). t.Setenv clears any
	// inherited config for the test.
	t.Setenv("GASWORKS_EVENTS_INGEST_URL", "")
	t.Setenv("GASWORKS_EVENTS_CITIES", "")
	t.Setenv("GASWORKS_EVENTS_TOKEN", "")
	t.Setenv("GASWORKS_EVENTS_TOKEN_FILE", "")
	if code := run([]string{"events"}); code != 0 {
		t.Fatalf("idle events = %d, want 0", code)
	}
}

func TestRun_EventsPlainHTTPRejected(t *testing.T) {
	// A non-loopback plain-http ingest URL must fail loudly, not silently idle.
	t.Setenv("GASWORKS_EVENTS_INGEST_URL", "http://events.example.com")
	t.Setenv("GASWORKS_EVENTS_CITIES", "c1")
	t.Setenv("GASWORKS_EVENTS_TOKEN", "tok")
	t.Setenv("GASWORKS_EVENTS_TOKEN_FILE", "")
	if code := run([]string{"events"}); code != 1 {
		t.Fatalf("plain-http events = %d, want 1", code)
	}
}

func TestRun_EventsRejectsUnknownFlag(t *testing.T) {
	if code := run([]string{"events", "--bogus"}); code != 2 {
		t.Fatalf("events --bogus = %d, want 2", code)
	}
}

func TestRun_AllRejectsOnce(t *testing.T) {
	// --once is recall-only; "all" is a daemon and must reject it rather than half-honor.
	if code := run([]string{"all", "--once"}); code != 2 {
		t.Fatalf("all --once = %d, want 2", code)
	}
}

// TestSuperviseAxis_IsolatesPanics proves the core "all"-isolation contract: one
// axis panicking (and crash-looping) NEVER stops its peer. We run two supervised
// axes concurrently — one panics forever, the other ticks steadily — and assert the
// healthy axis keeps making progress while its neighbour thrashes, then both stop
// cleanly on ctx cancel.
func TestSuperviseAxis_IsolatesPanics(t *testing.T) {
	old := axisBaseBackoff
	axisBaseBackoff = 5 * time.Millisecond // keep the restart loop fast for the test
	defer func() { axisBaseBackoff = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var panics, ticks int64
	var wg sync.WaitGroup

	// "bad" axis: panics every time it is (re)started.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = superviseAxis(ctx, "bad", func() int {
			atomic.AddInt64(&panics, 1)
			panic("axis boom")
		})
	}()

	// "good" axis: a long-lived loop that ticks until ctx is cancelled, like a real
	// daemon. It must never be interrupted by the bad axis's crashes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = superviseAxis(ctx, "good", func() int {
			for ctx.Err() == nil {
				atomic.AddInt64(&ticks, 1)
				time.Sleep(2 * time.Millisecond)
			}
			return 0
		})
	}()

	// Let both run: the bad axis should have crash-looped several times and the good
	// axis should have ticked many times, fully decoupled.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&panics) >= 3 && atomic.LoadInt64(&ticks) >= 10 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	gotPanics := atomic.LoadInt64(&panics)
	gotTicks := atomic.LoadInt64(&ticks)
	if gotPanics < 3 {
		t.Fatalf("bad axis only restarted %d times (recover()+backoff loop not working)", gotPanics)
	}
	if gotTicks < 10 {
		t.Fatalf("good axis only ticked %d times while its peer crash-looped (isolation broken)", gotTicks)
	}

	cancel()
	wg.Wait() // both axes must return on ctx cancel (no goroutine leak / hang)
}

// TestRunGuarded_RecoversAndReportsPanic proves runGuarded converts a panic into a
// (1, true) result instead of unwinding the process, and reports a clean return
// verbatim.
func TestRunGuarded_RecoversAndReportsPanic(t *testing.T) {
	if code, panicked := runGuarded("x", func() int { panic("nope") }); !panicked || code != 1 {
		t.Fatalf("panic case = (%d,%v), want (1,true)", code, panicked)
	}
	if code, panicked := runGuarded("x", func() int { return 7 }); panicked || code != 7 {
		t.Fatalf("clean case = (%d,%v), want (7,false)", code, panicked)
	}
}

func TestRun_RecallIdleOnceExitsZero(t *testing.T) {
	// No RECALL_FORWARDER_URL / _SOURCE_ID / token => the axis is idle. With --once it
	// must exit 0 without dialing anything (the egress gate keeps it from constructing a
	// client). t.Setenv clears any inherited config for the duration of the test.
	t.Setenv("RECALL_FORWARDER_URL", "")
	t.Setenv("RECALL_FORWARDER_SOURCE_ID", "")
	t.Setenv("RECALL_FORWARDER_TOKEN", "")
	t.Setenv("RECALL_FORWARDER_TOKEN_FILE", "")
	if code := run([]string{"recall", "--once"}); code != 0 {
		t.Fatalf("idle recall --once = %d, want 0", code)
	}
}

func TestRun_RecallRejectsUnknownFlag(t *testing.T) {
	if code := run([]string{"recall", "--bogus"}); code != 2 {
		t.Fatalf("recall --bogus = %d, want 2", code)
	}
}

func TestRun_RecallPlainHTTPRejected(t *testing.T) {
	// A non-loopback plain-http URL must fail loudly, not silently idle.
	t.Setenv("RECALL_FORWARDER_URL", "http://recall.example.com")
	t.Setenv("RECALL_FORWARDER_SOURCE_ID", "src")
	t.Setenv("RECALL_FORWARDER_TOKEN", "tok")
	t.Setenv("RECALL_FORWARDER_TOKEN_FILE", "")
	if code := run([]string{"recall", "--once"}); code != 1 {
		t.Fatalf("plain-http recall --once = %d, want 1", code)
	}
}

func TestRun_AllBothIdleExitsZero(t *testing.T) {
	// With neither axis configured, "all" runs both as idle (each returns immediately
	// without dialing) and exits 0. Both axes' egress gates keep them from dialing.
	t.Setenv("RECALL_FORWARDER_URL", "")
	t.Setenv("RECALL_FORWARDER_SOURCE_ID", "")
	t.Setenv("RECALL_FORWARDER_TOKEN", "")
	t.Setenv("RECALL_FORWARDER_TOKEN_FILE", "")
	t.Setenv("GASWORKS_EVENTS_INGEST_URL", "")
	t.Setenv("GASWORKS_EVENTS_CITIES", "")
	t.Setenv("GASWORKS_EVENTS_TOKEN", "")
	t.Setenv("GASWORKS_EVENTS_TOKEN_FILE", "")
	if code := run([]string{"all"}); code != 0 {
		t.Fatalf("all with both axes idle = %d, want 0", code)
	}
}
