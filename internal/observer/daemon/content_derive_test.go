//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
)

const (
	derivedCodexUUID  = "019a2f3e-4b5c-7d6e-8f90-a1b2c3d4e5f6"
	derivedClaudeUUID = "3f2b8c1a-9d4e-4f6a-8b7c-1d2e3f4a5b6c"
)

func TestDeriveSessionFromName(t *testing.T) {
	cases := []struct {
		locator          string
		native, provider string
		ok               bool
	}{
		{"2026/10/17/rollout-2026-10-17T12-34-56-" + derivedCodexUUID + ".jsonl", derivedCodexUUID, "codex", true},
		{"rollout-2026-10-17T12-34-56-" + derivedCodexUUID + ".jsonl", derivedCodexUUID, "codex", true},
		{"-work-p/" + derivedClaudeUUID + ".jsonl", derivedClaudeUUID, "claude", true},
		// A Claude transcript names its session only at <project>/<uuid>.jsonl: at the root itself
		// or any deeper it is some other layout.
		{derivedClaudeUUID + ".jsonl", "", "", false},
		{"-work-p/" + derivedClaudeUUID + "/" + derivedClaudeUUID + ".jsonl", "", "", false},
		{"-work-p/" + derivedClaudeUUID + "/subagents/" + derivedClaudeUUID + ".jsonl", "", "", false},
		// A subagent transcript carries its parent's session id: keying it by that id would replace
		// the parent's snapshot in the content store, so it is never derived.
		{"-work-p/" + derivedClaudeUUID + "/subagents/agent-a1b2c3.jsonl", "", "", false},
		{"-work-p/agent-a1b2c3.jsonl", "", "", false},
		{"../-work-p/" + derivedClaudeUUID + ".jsonl", "", "", false},                // escapes the root
		{"rollout-2026-06.jsonl", "", "", false},                                     // no uuid
		{"rollout-" + derivedCodexUUID + ".jsonl", "", "", false},                    // no timestamp before the uuid
		{"rollout-2026-10-17T12-34-56" + derivedCodexUUID + ".jsonl", "", "", false}, // no dash before the uuid
		{"-work-p/3F2B8C1A-9D4E-4F6A-8B7C-1D2E3F4A5B6C.jsonl", "", "", false},        // not the providers' lowercase shape
		{"-work-p/" + derivedClaudeUUID + ".json", "", "", false},
		{"-work-p/journal.jsonl", "", "", false},
		{"history.jsonl", "", "", false},
	}
	for _, c := range cases {
		native, provider, ok := deriveSessionFromName(c.locator)
		if native != c.native || provider != c.provider || ok != c.ok {
			t.Errorf("deriveSessionFromName(%q) = (%q, %q, %v), want (%q, %q, %v)", c.locator, native, provider, ok, c.native, c.provider, c.ok)
		}
	}
}

// claudeTranscriptLines is a minimal Claude Code transcript of one finished response whose records
// carry sessionID: what both a session's own transcript and its subagents' transcripts look like.
func claudeTranscriptLines(sessionID string) string {
	const rec = `{"type":%q,"uuid":%q,"parentUuid":%s,"sessionId":%q,"timestamp":"2026-10-17T10:00:0%dZ","message":%s}` + "\n"
	return fmt.Sprintf(rec, "user", "u1", "null", sessionID, 1, `{"role":"user","content":"hi"}`) +
		fmt.Sprintf(rec, "assistant", "a1", `"u1"`, sessionID, 2, `{"role":"assistant","id":"msg_1","model":"claude-opus-5-5","stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":3},"content":[{"type":"text"}]}`)
}

// TestContentUploadRestartHoleMarkerlessFinishedTranscriptUploaded is the regression for the restart
// hole: a previous run parsed two finished transcripts to EOF (its uploads of them were never
// accepted, so it left no marker and no pending record), and the daemon restarted. The restarted
// watcher's cursor is at EOF, so its sink never threads either session again. Before the name
// derivation both were skipped on every tick for good; now both upload once, keyed by the id their
// name carries, and their markers make the upload survive the next restart.
//
// Both runs use the production sink (the uploader's SessionFor is the same sink the watcher feeds),
// so the test proves the restarted sink really never threads the EOF transcripts. A Claude subagent
// transcript, whose records carry its parent's session id, sits beside them and is never uploaded.
func TestContentUploadRestartHoleMarkerlessFinishedTranscriptUploaded(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	rolloutDir := filepath.Join(root, "2026", "10", "17")
	claudeDir := filepath.Join(root, "-work-p")
	subagentDir := filepath.Join(claudeDir, derivedClaudeUUID, "subagents")
	for _, d := range []string{rolloutDir, claudeDir, subagentDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rollout := filepath.Join(rolloutDir, "rollout-2026-10-17T12-34-56-"+derivedCodexUUID+".jsonl")
	claude := filepath.Join(claudeDir, derivedClaudeUUID+".jsonl")
	subagent := filepath.Join(subagentDir, "agent-a1b2c3d4.jsonl")
	bodies := map[string]string{
		rollout:  rolloutLines(derivedCodexUUID, 2),
		claude:   claudeTranscriptLines(derivedClaudeUUID),
		subagent: claudeTranscriptLines(derivedClaudeUUID),
	}
	idOf := map[string]transcriptIdentity{}
	for p, b := range bodies {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		idOf[p] = transcriptIdentity{device: uint64(st.Dev), inode: st.Ino}
	}

	spoolDir := t.TempDir()
	srv := startDaemonServer(t, spoolDir, newSpoolWriter(t, spoolDir), NewRegistry("src_test", "ws_main"))
	watcher := func(sink *CandidateSinkAdapter, obs codex.ContentObserver) *codex.Watcher {
		cfg := codex.WatchConfig{
			ApprovedRoots: []string{root},
			StateDir:      state,
			Sink:          NewPartialCandidateSinkAdapter(sink),
			References:    codex.ReferenceConfig{Resolver: evidence.ProjectResolver{DefaultProjectID: "proj_test"}},
		}
		if obs != nil {
			cfg.ContentObserver = obs
		}
		w, err := codex.NewWatcher(cfg)
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		return w
	}

	// The previous run: it parsed all three transcripts to EOF and persisted its cursors, and never
	// had their content accepted (no marker, no pending record). Its sink threaded every session,
	// the subagent's under its parent's id.
	prevSink := newSink(t, local.NewClient(srv.SocketPath()))
	if err := watcher(prevSink, nil).Poll(context.Background()); err != nil {
		t.Fatalf("poll (previous run): %v", err)
	}
	for p, want := range map[string]string{rollout: derivedCodexUUID, claude: derivedClaudeUUID, subagent: derivedClaudeUUID} {
		if got, _, ok := prevSink.SessionFor(idOf[p].device, idOf[p].inode); !ok || got != want {
			t.Fatalf("previous run threaded %s as (%q, %v), want %q", filepath.Base(p), got, ok, want)
		}
	}

	// The restart: a fresh production sink and uploader over the same state dir.
	clock := newClock()
	newRun := func(sender *fakeContentSender) (*contentUploader, *CandidateSinkAdapter) {
		sink := newSink(t, local.NewClient(srv.SocketPath()))
		cu, err := newContentUploader(contentUploaderConfig{
			sender:   sender,
			sessions: sink,
			stateDir: state,
			read:     codex.ReadValidatedTranscript,
			now:      clock.now,
			debounce: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("newContentUploader: %v", err)
		}
		if err := watcher(sink, cu).Poll(context.Background()); err != nil {
			t.Fatalf("poll: %v", err)
		}
		return cu, sink
	}
	sender := &fakeContentSender{}
	cu, sink := newRun(sender)
	for p := range bodies {
		if _, _, ok := sink.SessionFor(idOf[p].device, idOf[p].inode); ok {
			t.Fatalf("the restarted sink threaded %s from an EOF cursor; the test no longer covers the hole", filepath.Base(p))
		}
	}
	clock.advance(31 * time.Second)
	cu.tick(context.Background())

	if sender.count() != 2 {
		t.Fatalf("uploads after restart = %d, want the two marker-less finished session transcripts", sender.count())
	}
	want := map[string][2]string{rollout: {derivedCodexUUID, "codex"}, claude: {derivedClaudeUUID, "claude"}}
	for i := 0; i < sender.count(); i++ {
		req := sender.at(i)
		if req.SourcePath == subagent {
			t.Fatal("uploaded the subagent transcript under its parent's session id")
		}
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

	// A second restart re-ships nothing: the markers now carry the uploads, and the subagent is
	// still never derived.
	sender2 := &fakeContentSender{}
	cu2, _ := newRun(sender2)
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

func TestIsClaudeSubagentTranscript(t *testing.T) {
	cases := []struct {
		locator string
		want    bool
	}{
		{"-work-p/" + derivedClaudeUUID + "/subagents/agent-a1b2c3.jsonl", true},
		{"/home/u/.claude/projects/-work-p/" + derivedClaudeUUID + "/subagents/agent-0123456789abcdef.jsonl", true},
		{"-work-p/agent-a1b2c3.jsonl", true}, // the older layout, beside the session's transcript
		{"-work-p/agent-A1B2C3.jsonl", true},
		{"-work-p/" + derivedClaudeUUID + ".jsonl", false},
		{"-work-p/agent-.jsonl", false},
		{"-work-p/agent-xyz.jsonl", false},
		{"-work-p/agent-a1b2c3.json", false},
		{"2026/10/17/rollout-2026-10-17T12-34-56-" + derivedCodexUUID + ".jsonl", false},
	}
	for _, c := range cases {
		if got := isClaudeSubagentTranscript(c.locator); got != c.want {
			t.Errorf("isClaudeSubagentTranscript(%q) = %v, want %v", c.locator, got, c.want)
		}
	}
}

// TestContentUploadLiveSubagentTranscriptNeverUploaded is the regression for bts-xpw.204.9.10. On the
// LIVE path (no restart) the production sink threads a Claude subagent transcript to its parent's
// native session id, because every subagent record carries the parent's sessionId. Uploaded under that
// id, the subagent's bytes replaced the parent session's snapshot in the content store. Now the
// subagent transcript is never read, keyed, queued or uploaded; the parent's transcript is, and the
// subagent's usage still threads under the parent's session on the metadata lane.
func TestContentUploadLiveSubagentTranscriptNeverUploaded(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	claudeDir := filepath.Join(root, "-work-p")
	subagentDir := filepath.Join(claudeDir, derivedClaudeUUID, "subagents")
	if err := os.MkdirAll(subagentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(claudeDir, derivedClaudeUUID+".jsonl")
	subagent := filepath.Join(subagentDir, "agent-a1b2c3d4.jsonl")
	second := filepath.Join(subagentDir, "agent-e5f6a7b8.jsonl")
	bodies := map[string]string{
		parent:   claudeTranscriptLines(derivedClaudeUUID),
		subagent: claudeTranscriptLines(derivedClaudeUUID),
		second:   claudeTranscriptLines(derivedClaudeUUID),
	}
	idOf := map[string]transcriptIdentity{}
	for p, b := range bodies {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		idOf[p] = transcriptIdentity{device: uint64(st.Dev), inode: st.Ino}
	}

	spoolDir := t.TempDir()
	srv := startDaemonServer(t, spoolDir, newSpoolWriter(t, spoolDir), NewRegistry("src_test", "ws_main"))
	sink := newSink(t, local.NewClient(srv.SocketPath()))
	clock := newClock()
	sender := &fakeContentSender{}
	var logMu sync.Mutex
	var logs []string
	cu, err := newContentUploader(contentUploaderConfig{
		sender:   sender,
		sessions: sink,
		stateDir: state,
		read:     codex.ReadValidatedTranscript,
		now:      clock.now,
		debounce: 30 * time.Second,
		log: func(s string) {
			logMu.Lock()
			defer logMu.Unlock()
			logs = append(logs, s)
		},
	})
	if err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	w, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            NewPartialCandidateSinkAdapter(sink),
		References:      codex.ReferenceConfig{Resolver: evidence.ProjectResolver{DefaultProjectID: "proj_test"}},
		ContentObserver: cu,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	// The precondition of the bug: the live sink threads each subagent under its parent's id.
	for _, p := range []string{subagent, second} {
		if got, _, ok := sink.SessionFor(idOf[p].device, idOf[p].inode); !ok || got != derivedClaudeUUID {
			t.Fatalf("live sink threaded the subagent %s as (%q, %v), want its parent's %q; the test no longer covers the bug", filepath.Base(p), got, ok, derivedClaudeUUID)
		}
	}
	clock.advance(31 * time.Second)
	cu.tick(context.Background())

	if sender.count() != 1 || sender.at(0).SourcePath != parent || sender.at(0).NativeSessionID != derivedClaudeUUID {
		for i := 0; i < sender.count(); i++ {
			t.Logf("upload %d: %s as %q", i, sender.at(i).SourcePath, sender.at(i).NativeSessionID)
		}
		t.Fatalf("uploads = %d, want only the parent's transcript under its own id", sender.count())
	}
	for _, p := range []string{subagent, second} {
		if _, err := os.Stat(filepath.Join(state, contentPendingName(idOf[p].device, idOf[p].inode))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a pending record was written for the subagent transcript %s (stat err %v)", filepath.Base(p), err)
		}
	}

	// It grows: still never uploaded. Each subagent transcript is counted once, and only the run's
	// first skip is logged.
	if err := os.WriteFile(subagent, []byte(bodies[subagent]+claudeTranscriptLines(derivedClaudeUUID)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	clock.advance(31 * time.Second)
	cu.tick(context.Background())
	if sender.count() != 1 {
		t.Fatalf("uploads after the subagent grew = %d, want still 1", sender.count())
	}
	cu.mu.Lock()
	skips := cu.subagentSkips
	cu.mu.Unlock()
	logMu.Lock()
	defer logMu.Unlock()
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "subagent transcript") {
			n++
		}
	}
	if skips != 2 || n != 1 {
		t.Fatalf("subagent skips counted %d, logged %d; want 2 counted, 1 logged (logs %q)", skips, n, logs)
	}
}

// A pending record an earlier release wrote for a Claude subagent transcript (under its parent's id)
// is not owed: the uploader discards it at startup instead of ever keying the subagent by it, and logs
// it apart from content discarded because the consent it was queued under no longer applies.
func TestContentUploadDiscardsPendingRecordOfASubagentTranscript(t *testing.T) {
	state := t.TempDir()
	write := func(ino uint64, locator, consentRoot string) string {
		t.Helper()
		data, _ := json.Marshal(contentPending{Version: contentPendingVersion, Device: 7, Inode: ino, NativeSessionID: derivedClaudeUUID, Provider: "claude", ConsentRoot: consentRoot, Locator: locator, Size: 1, ModNanos: 1})
		name := contentPendingName(7, ino)
		if err := writeStateFile(state, name, contentPendingTempPrefix, data); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(state, name)
	}
	sub := write(1, "-work-p/"+derivedClaudeUUID+"/subagents/agent-a1b2c3d4.jsonl", "")
	own := write(2, "-work-p/"+derivedClaudeUUID+".jsonl", "")
	// Queued under a live consent policy, which this static-configuration uploader cannot honour.
	withdrawn := write(3, "-work-q/"+derivedClaudeUUID+".jsonl", "/work-q")
	var discarded []string
	log := func(s string) {
		if strings.Contains(s, "discarded") {
			discarded = append(discarded, s)
		}
	}
	if _, err := newContentUploader(contentUploaderConfig{sender: &fakeContentSender{}, sessions: newSessions(), stateDir: state, log: log}); err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	if _, err := os.Stat(sub); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the subagent's pending record survived startup (stat err %v)", err)
	}
	if _, err := os.Stat(withdrawn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the pending record queued under withdrawn consent survived startup (stat err %v)", err)
	}
	if _, err := os.Stat(own); err != nil {
		t.Fatalf("the parent's pending record was discarded: %v", err)
	}
	want := []string{
		"content upload: discarded the queued content of 1 Claude subagent transcripts an earlier release queued: the content lane never uploads a subagent transcript",
		"content upload: discarded the queued content of 1 transcripts: the consent it was queued under no longer applies",
	}
	if !slices.Equal(discarded, want) {
		t.Fatalf("startup discard lines = %q, want %q", discarded, want)
	}
}
