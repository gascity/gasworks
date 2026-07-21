//go:build linux

package main

import (
	"testing"
	"time"
)

// TestTranscriptNameMatch pins the transcript filename filter to the real session transcripts of
// both providers while rejecting every non-transcript sidecar the approved roots also hold. A
// regression here is the flood the soak surfaced: a 72KB tool-results *.txt tracked as a transcript
// yields ~962 "malformed transcript line" diagnostics and trips has_partial_capture on real runs.
func TestTranscriptNameMatch(t *testing.T) {
	tracked := []string{
		"48bc659f-6656-4f39-b424-864992f96c2c.jsonl",                            // Claude session
		"rollout-2026-07-14T23-46-58-019f6306-cdf3-7813-ae8e-a90bb1799c99.jsonl", // Codex rollout
	}
	for _, name := range tracked {
		if !transcriptNameMatch(name) {
			t.Errorf("transcriptNameMatch(%q) = false, want true (real transcript)", name)
		}
	}

	rejected := []string{
		"a1b2c3d4.meta.json",    // Claude per-message metadata sidecar
		"sessions-index.json",   // Claude session index
		"tool-result-0007.txt",  // Claude tool-results payload (the flood source)
		"bundle.js",             // source artifact under a project root
		"README.md",             // markdown under a project root
		"report.pdf",            // binary sidecar
		"session.jsonl.tmp",     // an in-progress rename, not yet a transcript
		"session.jsonl.bak",     // a backup, not the live transcript
	}
	for _, name := range rejected {
		if transcriptNameMatch(name) {
			t.Errorf("transcriptNameMatch(%q) = true, want false (non-transcript)", name)
		}
	}
}

// TestNewWatchLoopConfigInstallsTranscriptFilter guards the wiring: the daemon must hand the
// watcher the transcript filter, not leave Match nil (which parses every file under the roots), and
// must pass the poll cadence through.
func TestNewWatchLoopConfigInstallsTranscriptFilter(t *testing.T) {
	cfg := newWatchLoopConfig([]string{"/home/u/.claude/projects"}, "/tmp/cursors", 2*time.Second)
	if cfg.Match == nil {
		t.Fatal("newWatchLoopConfig left Match nil; the watcher would parse all ~60k files under the roots")
	}
	if !cfg.Match("session.jsonl") {
		t.Error("wired filter must admit a real .jsonl transcript")
	}
	if cfg.Match("tool-result.txt") {
		t.Error("wired filter must refuse a non-transcript .txt sidecar")
	}
	if cfg.Interval != 2*time.Second {
		t.Errorf("poll interval = %v, want 2s (must be wired through)", cfg.Interval)
	}
}
