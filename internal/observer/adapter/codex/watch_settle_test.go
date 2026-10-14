//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWatcherSettlesOpenClaudeUsageOnceTheTranscriptGoesQuiet is the watcher wiring of the settle: a
// Claude message whose final record never arrives (the session ended mid-response) is counted once
// the transcript has been unwritten for openUsageSettle — not before, not twice — and a late record
// of it after that is not counted again.
func TestWatcherSettlesOpenClaudeUsageOnceTheTranscriptGoesQuiet(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 4, 675, 128077}, "thinking"))
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	now := info.ModTime()
	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, Now: func() time.Time { return now }})

	poll := func(label string) []*Candidate {
		t.Helper()
		before := len(sink.all())
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("%s: Poll: %v", label, err)
		}
		return sink.all()[before:]
	}
	if got := usageCands(poll("first read")); len(got) != 0 {
		t.Fatalf("open message counted on first read: %s", describeUsages(got))
	}
	now = info.ModTime().Add(openUsageSettle - time.Second)
	if got := usageCands(poll("not yet quiet")); len(got) != 0 {
		t.Fatalf("open message settled before the transcript was quiet for %v: %s", openUsageSettle, describeUsages(got))
	}
	now = info.ModTime().Add(openUsageSettle)
	settled := poll("quiet")
	assertClaudeUsages(t, "settled", settled, []claudeUsageWant{{"msg_A", 2, 4, 675, 128077}})
	if s := usageCands(settled)[0].Session; s == nil || s.NativeID != claudeTestSession {
		t.Fatalf("settled usage carries session %+v", s)
	}
	if got := usageCands(poll("after settle")); len(got) != 0 {
		t.Fatalf("settled message counted again: %s", describeUsages(got))
	}

	appendString(t, p, claudeAssistant(claudeTestSession, at(2*time.Hour), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 900, 675, 128077}, "tool_use:toolu_A"))
	if got := usageCands(poll("late record")); len(got) != 0 {
		t.Fatalf("a late record of a settled message was counted again: %s", describeUsages(got))
	}
}
