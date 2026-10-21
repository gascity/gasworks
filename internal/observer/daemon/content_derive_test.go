//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
)

const (
	derivedCodexUUID  = "019a2f3e-4b5c-7d6e-8f90-a1b2c3d4e5f6"
	derivedClaudeUUID = "3f2b8c1a-9d4e-4f6a-8b7c-1d2e3f4a5b6c"
)

func TestDeriveSessionFromName(t *testing.T) {
	cases := []struct {
		path             string
		native, provider string
		ok               bool
	}{
		{"/r/2026/10/17/rollout-2026-10-17T12-34-56-" + derivedCodexUUID + ".jsonl", derivedCodexUUID, "codex", true},
		{"/r/-work-p/" + derivedClaudeUUID + ".jsonl", derivedClaudeUUID, "claude", true},
		// A subagent transcript carries its parent's session id: keying it by that id would replace
		// the parent's snapshot in the content store, so it is never derived.
		{"/r/-work-p/" + derivedClaudeUUID + "/subagents/agent-a1b2c3.jsonl", "", "", false},
		{"/r/rollout-2026-06.jsonl", "", "", false},                                     // no uuid
		{"/r/rollout-" + derivedCodexUUID + ".jsonl", "", "", false},                    // no timestamp before the uuid
		{"/r/rollout-2026-10-17T12-34-56" + derivedCodexUUID + ".jsonl", "", "", false}, // no dash before the uuid
		{"/r/3F2B8C1A-9D4E-4F6A-8B7C-1D2E3F4A5B6C.jsonl", "", "", false},                // not the providers' lowercase shape
		{"/r/" + derivedClaudeUUID + ".json", "", "", false},
		{"/r/history.jsonl", "", "", false},
	}
	for _, c := range cases {
		native, provider, ok := deriveSessionFromName(c.path)
		if native != c.native || provider != c.provider || ok != c.ok {
			t.Errorf("deriveSessionFromName(%q) = (%q, %q, %v), want (%q, %q, %v)", c.path, native, provider, ok, c.native, c.provider, c.ok)
		}
	}
}

// TestContentUploadRestartHoleMarkerlessFinishedTranscriptUploaded is the regression for the restart
// hole: a previous run parsed two finished transcripts to EOF (its uploads of them were never
// accepted, so it left no marker and no pending record), and the daemon restarted. The restarted
// watcher's cursor is at EOF, so its sink never threads either session again. Before the name
// derivation both were skipped on every tick for good; now both upload once, keyed by the id their
// name carries, and their markers make the upload survive the next restart.
func TestContentUploadRestartHoleMarkerlessFinishedTranscriptUploaded(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	rolloutDir := filepath.Join(root, "2026", "10", "17")
	claudeDir := filepath.Join(root, "-work-p")
	for _, d := range []string{rolloutDir, claudeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rollout := filepath.Join(rolloutDir, "rollout-2026-10-17T12-34-56-"+derivedCodexUUID+".jsonl")
	claude := filepath.Join(claudeDir, derivedClaudeUUID+".jsonl")
	bodies := map[string]string{rollout: "rollout-line-1\nrollout-line-2\n", claude: "claude-line-1\n"}
	for p, b := range bodies {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The previous run: it parsed both transcripts to EOF and persisted its cursors, and never had
	// their content accepted (no marker, no pending record).
	prev, err := codex.NewWatcher(codex.WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: noopCandidateSink{}})
	if err != nil {
		t.Fatalf("NewWatcher (previous run): %v", err)
	}
	if err := prev.Poll(context.Background()); err != nil {
		t.Fatalf("poll (previous run): %v", err)
	}

	// The restart: a fresh uploader whose sink threading is empty, over the same state dir.
	clock := newClock()
	sender := &fakeContentSender{}
	newRun := func(sender *fakeContentSender) *contentUploader {
		cu, err := newContentUploader(contentUploaderConfig{
			sender:   sender,
			sessions: newSessions(),
			stateDir: state,
			read:     codex.ReadValidatedTranscript,
			now:      clock.now,
			debounce: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("newContentUploader: %v", err)
		}
		w, err := codex.NewWatcher(codex.WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: noopCandidateSink{}, ContentObserver: cu})
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		if err := w.Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
		return cu
	}
	cu := newRun(sender)
	clock.advance(31 * time.Second)
	cu.tick(context.Background())

	if sender.count() != 2 {
		t.Fatalf("uploads after restart = %d, want both marker-less finished transcripts", sender.count())
	}
	want := map[string][2]string{rollout: {derivedCodexUUID, "codex"}, claude: {derivedClaudeUUID, "claude"}}
	for i := 0; i < sender.count(); i++ {
		req := sender.at(i)
		w, ok := want[req.SourcePath]
		if !ok {
			t.Fatalf("uploaded unexpected path %q", req.SourcePath)
		}
		if req.NativeSessionID != w[0] || req.Provider != w[1] {
			t.Fatalf("%s keyed (%q, %q), want (%q, %q)", req.SourcePath, req.NativeSessionID, req.Provider, w[0], w[1])
		}
		if string(req.Body) != bodies[req.SourcePath] {
			t.Fatalf("%s body is not the whole file", req.SourcePath)
		}
		delete(want, req.SourcePath)
	}
	markers, _ := filepath.Glob(filepath.Join(state, "content-marker-*.json"))
	if len(markers) != 2 {
		t.Fatalf("markers = %d, want 2", len(markers))
	}

	// A second restart re-ships nothing: the markers now carry the uploads.
	sender2 := &fakeContentSender{}
	cu2 := newRun(sender2)
	clock.advance(31 * time.Second)
	cu2.tick(context.Background())
	if sender2.count() != 0 {
		t.Fatalf("re-shipped %d transcripts after a second restart", sender2.count())
	}
}

// The derived identity is the last resort: a threaded session, a pending record or a marker keeps
// keying the transcript exactly as before, even when the name carries a different id.
func TestContentUploadDerivedSessionIsTheLastResort(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	const dev, ino = 51, 52
	path := "/root/rollout-2026-10-17T12-34-56-" + derivedCodexUUID + ".jsonl"
	h.sessions.set(dev, ino, "threaded-id", "codex")
	h.reader.set(dev, ino, "body-v1", 1)
	h.observe(dev, ino, path, 7, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if h.sender.count() != 1 || h.sender.at(0).NativeSessionID != "threaded-id" {
		t.Fatalf("threaded session not preferred: count=%d", h.sender.count())
	}

	// After a restart with empty threading, the marker's id still wins over the name.
	sender2 := &fakeContentSender{}
	u2 := h.restartedUploader(t, sender2)
	h.reader.set(dev, ino, "body-v1-grown", 2)
	u2.ObserveContent(context.Background(), codex.ContentObservation{
		Root: "/root", Locator: "s.jsonl", Path: path, Device: dev, Inode: ino, Size: 13, ModNanos: 2,
	})
	h.clock.advance(31 * time.Second)
	u2.tick(context.Background())
	if sender2.count() != 1 || sender2.at(0).NativeSessionID != "threaded-id" {
		t.Fatalf("marker session not preferred over the derived one: count=%d", sender2.count())
	}
}
