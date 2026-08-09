//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// TestTranscriptNameMatch pins the transcript filename filter to the real session transcripts of
// both providers while rejecting every non-transcript sidecar the approved roots also hold. A
// regression here is the flood the soak surfaced: a 72KB tool-results *.txt tracked as a transcript
// yields ~962 "malformed transcript line" diagnostics and trips has_partial_capture on real runs.
func TestTranscriptNameMatch(t *testing.T) {
	tracked := []string{
		"48bc659f-6656-4f39-b424-864992f96c2c.jsonl",                             // Claude session
		"rollout-2026-07-14T23-46-58-019f6306-cdf3-7813-ae8e-a90bb1799c99.jsonl", // Codex rollout
	}
	for _, name := range tracked {
		if !transcriptNameMatch(name) {
			t.Errorf("transcriptNameMatch(%q) = false, want true (real transcript)", name)
		}
	}

	rejected := []string{
		"a1b2c3d4.meta.json",   // Claude per-message metadata sidecar
		"sessions-index.json",  // Claude session index
		"tool-result-0007.txt", // Claude tool-results payload (the flood source)
		"bundle.js",            // source artifact under a project root
		"README.md",            // markdown under a project root
		"report.pdf",           // binary sidecar
		"session.jsonl.tmp",    // an in-progress rename, not yet a transcript
		"session.jsonl.bak",    // a backup, not the live transcript
	}
	for _, name := range rejected {
		if transcriptNameMatch(name) {
			t.Errorf("transcriptNameMatch(%q) = true, want false (non-transcript)", name)
		}
	}
}

func TestNewPolicyWatchLoopConfigPreservesExplicitPerRootConsent(t *testing.T) {
	records := []rootpolicy.Record{
		{Path: "/explicit/claude", Generation: 4, Active: true, Mode: rootpolicy.ForwardOnly},
		{Path: "/explicit/codex", Generation: 9, Active: false},
	}
	cfg := newPolicyWatchLoopConfig(records, "/tmp/cursors", 2*time.Second)
	if len(cfg.ApprovedRoots) != 0 || len(cfg.RootPolicies) != len(records) {
		t.Fatalf("watch config roots = legacy %v policy %v, want only policy records", cfg.ApprovedRoots, cfg.RootPolicies)
	}
	if cfg.RootPolicies[0] != records[0] || cfg.RootPolicies[1] != records[1] {
		t.Fatalf("root policies = %+v, want %+v", cfg.RootPolicies, records)
	}
}

// TestCapturableRootsHoldsProjectRootsBackFromTheWatcher pins the C2-prime gate: a kind=project
// root is a valid registration the daemon must carry, but its path is a project folder, not a
// transcript directory, so it must never reach the watcher until session membership ships.
func TestCapturableRootsHoldsProjectRootsBackFromTheWatcher(t *testing.T) {
	records := []rootpolicy.Record{
		{Path: "/explicit/claude", Generation: 4, Active: true, Mode: rootpolicy.ForwardOnly},
		{Path: "/home/u/work/app", Generation: 5, Active: true, Mode: rootpolicy.ForwardOnly, Kind: rootpolicy.Project},
		{Path: "/explicit/codex", Generation: 9, Active: true, Mode: rootpolicy.Backfill, Kind: rootpolicy.Transcripts},
		{Path: "/home/u/work/old", Generation: 10, Kind: rootpolicy.Project},
	}
	got := capturableRoots(records)
	want := []rootpolicy.Record{records[0], records[2]}
	if len(got) != len(want) {
		t.Fatalf("capturable roots = %+v, want only the transcript roots %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("capturable root %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestPolicyWiringAcceptsV2AndIgnoresProjectRoots drives the daemon's real load-and-wire path over
// on-disk policy files: a v2 document with only transcript roots must wire the watcher exactly like
// the equivalent v1 document, and a v2 document with a project root must wire only its transcript
// root while still carrying the project root and the recorded stores.
func TestPolicyWiringAcceptsV2AndIgnoresProjectRoots(t *testing.T) {
	transcriptRoot := t.TempDir()
	project := t.TempDir()
	store := t.TempDir()
	cursorDir := t.TempDir()

	v1Path := writePolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v1","roots":[`+
		`{"path":"`+transcriptRoot+`","generation":7,"active":true,"mode":"forward-only"}]}`)
	v2Path := writePolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v2","roots":[`+
		`{"path":"`+transcriptRoot+`","generation":7,"active":true,"mode":"forward-only"}]}`)
	v1Policy, err := rootpolicy.LoadPolicy(v1Path)
	if err != nil {
		t.Fatalf("LoadPolicy(v1): %v", err)
	}
	v2Policy, err := rootpolicy.LoadPolicy(v2Path)
	if err != nil {
		t.Fatalf("LoadPolicy(v2 transcripts only): %v", err)
	}
	v1Cfg := newPolicyWatchLoopConfig(capturableRoots(v1Policy.Roots), cursorDir, 0)
	v2Cfg := newPolicyWatchLoopConfig(capturableRoots(v2Policy.Roots), cursorDir, 0)
	if len(v2Cfg.RootPolicies) != 1 || v2Cfg.RootPolicies[0] != v1Cfg.RootPolicies[0] {
		t.Fatalf("v2 transcripts-only policy = %+v, want the v1 wiring %+v", v2Cfg.RootPolicies, v1Cfg.RootPolicies)
	}

	mixedPath := writePolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v2","roots":[`+
		`{"path":"`+transcriptRoot+`","generation":7,"active":true,"mode":"forward-only","kind":"transcripts"},`+
		`{"path":"`+project+`","generation":8,"active":true,"mode":"forward-only","kind":"project"}],`+
		`"stores":["`+store+`"]}`)
	mixed, err := rootpolicy.LoadPolicy(mixedPath)
	if err != nil {
		t.Fatalf("LoadPolicy(v2 with a project root): %v", err)
	}
	if len(mixed.Roots) != 2 || len(mixed.Stores) != 1 || mixed.Stores[0] != store {
		t.Fatalf("loaded policy = %+v, want both roots plus the recorded store %q", mixed, store)
	}
	cfg := newPolicyWatchLoopConfig(capturableRoots(mixed.Roots), cursorDir, 0)
	if len(cfg.RootPolicies) != 1 || cfg.RootPolicies[0].Path != transcriptRoot {
		t.Fatalf("watched roots = %+v, want only the transcript root %q", cfg.RootPolicies, transcriptRoot)
	}
}

func writePolicyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root-policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
