package runwrap

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// testNativeID extracts the trailing native-session UUID of a transcript filename (the Codex
// rollout and Claude shapes both end in <uuid>.jsonl), mirroring the `run` adapter's extractor.
var testNativeIDRe = regexp.MustCompile(`([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$`)

func testNativeID(path string) (string, bool) {
	m := testNativeIDRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// TestRunBindsChildNativeSession proves the explicit-run usage binding is native and automatic: a
// wrapped child that creates a new transcript file (as codex/claude do) has its native session id
// discovered from the file name and bound to THIS run via the daemon seam — no manual attach step.
// The binding is what lets the daemon's sink stamp run_context onto the session's usage, so the
// run's bead carries the real cost.
func TestRunBindsChildNativeSession(t *testing.T) {
	root := t.TempDir()
	const native = "019f8229-42ff-72c1-8c28-45f6936bf0d2"
	sessionFile := filepath.Join(root, "rollout-2026-07-21T00-00-00-"+native+".jsonl")

	// The child sleeps briefly, then creates its session file (as a live agent does after startup),
	// then lingers so the discovery poll observes the new file before the child exits.
	cfg := baseConfig("bash", "-c", "sleep 0.05; : > '"+sessionFile+"'; sleep 0.4")
	cfg.SessionRoots = []string{root}
	cfg.NativeSessionID = testNativeID
	cfg.bindPoll = 20 * time.Millisecond

	d := newRecordingDaemon()
	res, err := Run(context.Background(), d, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Launched {
		t.Fatalf("child did not launch")
	}
	runID, ok := d.binding(native)
	if !ok {
		t.Fatalf("child native session %q was never bound to the run", native)
	}
	if runID != res.RunID {
		t.Fatalf("session bound to run %q, want the wrapper's run %q", runID, res.RunID)
	}
}

// TestRunIgnoresPreexistingSessions proves the discovery binds ONLY the child's new transcript, not
// a co-resident session that already existed before launch — so a wrapped run never steals an
// unrelated live session's usage.
func TestRunIgnoresPreexistingSessions(t *testing.T) {
	root := t.TempDir()
	const preexisting = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	// A session file that exists BEFORE the run starts.
	if err := os.WriteFile(filepath.Join(root, "rollout-2026-07-20T00-00-00-"+preexisting+".jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("seed preexisting session: %v", err)
	}
	const child = "019f8229-1111-72c1-8c28-45f6936bf0d2"
	sessionFile := filepath.Join(root, "rollout-2026-07-21T00-00-00-"+child+".jsonl")

	cfg := baseConfig("bash", "-c", "sleep 0.05; : > '"+sessionFile+"'; sleep 0.4")
	cfg.SessionRoots = []string{root}
	cfg.NativeSessionID = testNativeID
	cfg.bindPoll = 20 * time.Millisecond

	d := newRecordingDaemon()
	if _, err := Run(context.Background(), d, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := d.binding(preexisting); ok {
		t.Fatalf("pre-existing session %q was bound; discovery must only bind the child's new file", preexisting)
	}
	if _, ok := d.binding(child); !ok {
		t.Fatalf("child session %q was not bound", child)
	}
}

// TestRunDrainSettleDelaysRunEnded proves the post-exit settle inserts a wait AFTER PROCESS_EXITED
// and BEFORE RUN_ENDED, giving the async watcher time to sequence the session's USAGE ahead of the
// closing boundary (otherwise the platform quarantines the usage as "association after RUN_ENDED").
func TestRunDrainSettleDelaysRunEnded(t *testing.T) {
	cfg := baseConfig("bash", "-c", "true")
	cfg.DrainSettle = 300 * time.Millisecond

	d := newRecordingDaemon()
	start := time.Now()
	if _, err := Run(context.Background(), d, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < cfg.DrainSettle {
		t.Fatalf("run took %v, want >= the %v drain settle (settle must delay RUN_ENDED)", elapsed, cfg.DrainSettle)
	}
	// The settle sits between PROCESS_EXITED and RUN_ENDED in the terminal order.
	exitedIdx, endedIdx := indexOf(d.events, "APPEND:PROCESS_EXITED"), indexOf(d.events, "APPEND:RUN_ENDED")
	if exitedIdx < 0 || endedIdx < 0 || exitedIdx > endedIdx {
		t.Fatalf("terminal order wrong: PROCESS_EXITED@%d, RUN_ENDED@%d in %v", exitedIdx, endedIdx, d.events)
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
