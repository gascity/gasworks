//go:build linux

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
	"github.com/gascity/gasworks/internal/observer/wire"
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

// TestConsentPolicyPreservesExplicitPerRootConsent: the live consent policy hands the watcher the
// owner's records exactly — generation, active, mode, tombstones — and the watch configuration it is
// paired with carries no roots of its own.
func TestConsentPolicyPreservesExplicitPerRootConsent(t *testing.T) {
	claude := t.TempDir()
	codexRoot := filepath.Join(t.TempDir(), "codex-removed")
	path := writePolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v1","roots":[`+
		`{"path":"`+claude+`","generation":4,"active":true,"mode":"forward-only"},`+
		`{"path":"`+codexRoot+`","generation":9,"active":false,"mode":""}]}`)
	src, err := openConsentPolicy(path, false, func(string) {})
	if err != nil {
		t.Fatalf("openConsentPolicy: %v", err)
	}
	want := []rootpolicy.Record{
		{Path: claude, Generation: 4, Active: true, Mode: rootpolicy.ForwardOnly},
		{Path: codexRoot, Generation: 9, Active: false},
	}
	got := src.Latest().Roots
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("policy roots = %+v, want %+v", got, want)
	}
	cfg := newConsentWatchLoopConfig("/tmp/cursors", 2*time.Second, codex.ReferenceConfig{})
	if len(cfg.ApprovedRoots) != 0 || len(cfg.RootPolicies) != 0 {
		t.Fatalf("watch config roots = legacy %v policy %v, want none: they come from the live policy", cfg.ApprovedRoots, cfg.RootPolicies)
	}
	if cfg.Match == nil || cfg.Interval != 2*time.Second || cfg.StateDir != "/tmp/cursors" {
		t.Fatalf("watch config = %+v, want the transcript filter, the cadence, and the cursor dir", cfg)
	}
}

// TestCapturableRecordHoldsProjectRootsBackFromTheWatcher pins the C2-prime gate: a kind=project
// root is a valid registration the daemon must carry, but its path is a project folder, not a
// transcript directory, so it must never reach the watcher until session membership ships.
func TestCapturableRecordHoldsProjectRootsBackFromTheWatcher(t *testing.T) {
	for _, tc := range []struct {
		record rootpolicy.Record
		want   bool
	}{
		{rootpolicy.Record{Path: "/explicit/claude", Generation: 4, Active: true, Mode: rootpolicy.ForwardOnly}, true},
		{rootpolicy.Record{Path: "/home/u/work/app", Generation: 5, Active: true, Mode: rootpolicy.ForwardOnly, Kind: rootpolicy.Project}, false},
		{rootpolicy.Record{Path: "/explicit/codex", Generation: 9, Active: true, Mode: rootpolicy.Backfill, Kind: rootpolicy.Transcripts}, true},
		{rootpolicy.Record{Path: "/home/u/work/old", Generation: 10, Kind: rootpolicy.Project}, false},
	} {
		if got := capturableRecord(tc.record); got != tc.want {
			t.Errorf("capturableRecord(%+v) = %t, want %t", tc.record, got, tc.want)
		}
	}
}

// TestPolicyWiringAcceptsV2AndIgnoresProjectRoots drives the daemon's real load-and-wire path over
// on-disk policy files: a v2 document with only transcript roots must wire the watcher exactly like
// the equivalent v1 document, and a v2 document with a project root must wire only its transcript
// root while the document itself still carries the project root and the recorded stores.
func TestPolicyWiringAcceptsV2AndIgnoresProjectRoots(t *testing.T) {
	transcriptRoot := t.TempDir()
	project := t.TempDir()
	store := t.TempDir()

	open := func(body string) []rootpolicy.Record {
		t.Helper()
		src, err := openConsentPolicy(writePolicyFile(t, body), false, func(string) {})
		if err != nil {
			t.Fatalf("openConsentPolicy: %v", err)
		}
		return src.Latest().Roots
	}
	v1 := open(`{"schema_version":"gasworks.companion.root-policy/v1","roots":[` +
		`{"path":"` + transcriptRoot + `","generation":7,"active":true,"mode":"forward-only"}]}`)
	v2 := open(`{"schema_version":"gasworks.companion.root-policy/v2","roots":[` +
		`{"path":"` + transcriptRoot + `","generation":7,"active":true,"mode":"forward-only"}]}`)
	if len(v2) != 1 || len(v1) != 1 || v2[0] != v1[0] {
		t.Fatalf("v2 transcripts-only policy = %+v, want the v1 wiring %+v", v2, v1)
	}

	mixedBody := `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` +
		`{"path":"` + transcriptRoot + `","generation":7,"active":true,"mode":"forward-only","kind":"transcripts"},` +
		`{"path":"` + project + `","generation":8,"active":true,"mode":"forward-only","kind":"project"}],` +
		`"stores":["` + store + `"]}`
	mixed, err := rootpolicy.LoadPolicy(writePolicyFile(t, mixedBody))
	if err != nil {
		t.Fatalf("LoadPolicy(v2 with a project root): %v", err)
	}
	if len(mixed.Roots) != 2 || len(mixed.Stores) != 1 || mixed.Stores[0] != store {
		t.Fatalf("loaded policy = %+v, want both roots plus the recorded store %q", mixed, store)
	}
	if watched := open(mixedBody); len(watched) != 1 || watched[0].Path != transcriptRoot {
		t.Fatalf("watched roots = %+v, want only the transcript root %q", watched, transcriptRoot)
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
	cfg := newWatchLoopConfig([]string{"/home/u/.claude/projects"}, "/tmp/cursors", 2*time.Second, codex.ReferenceConfig{})
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

// TestNewReferenceConfigWiresPassiveExtraction is the load-bearing guard for the passive linkage:
// the -bead-prefix/-beads-project flags must map onto the ReferenceConfig the codex watcher consumes,
// both watcher constructors must carry it into References (nil there = the dead extractor this wiring
// fixes), and the wired config must actually fire — a bd tool call carrying a prefixed bead id yields
// exactly one work reference resolved to the configured project, while an empty prefix set stays off.
func TestNewReferenceConfigWiresPassiveExtraction(t *testing.T) {
	const (
		prefix  = "bd-"
		project = "lego_pilot"
		beadID  = "bd-abc123"
	)
	refs := newReferenceConfig([]string{prefix}, project)

	if len(refs.BeadPrefixes) != 1 || refs.BeadPrefixes[0] != prefix {
		t.Fatalf("BeadPrefixes = %v, want [%q]", refs.BeadPrefixes, prefix)
	}
	if refs.Resolver.DefaultProjectID != project {
		t.Fatalf("Resolver.DefaultProjectID = %q, want %q", refs.Resolver.DefaultProjectID, project)
	}

	// Both watcher constructors must thread the same config into References; before this wiring both
	// omitted it, leaving BeadPrefixes nil so extractBeads always returned nil.
	if got := newWatchLoopConfig([]string{"/root"}, "/cursors", 0, refs).References; !reflect.DeepEqual(got, refs) {
		t.Errorf("newWatchLoopConfig References = %+v, want %+v", got, refs)
	}
	if got := newConsentWatchLoopConfig("/cursors", 0, refs).References; !reflect.DeepEqual(got, refs) {
		t.Errorf("newConsentWatchLoopConfig References = %+v, want %+v", got, refs)
	}

	// The extractor fires with the prefix set: a bd TOOL_CALL carrying the bead id yields exactly one
	// work reference that resolves to the configured project — the passive run→bead link in one step.
	surface := codex.SurfaceText{Tool: "bd", Text: "bd update " + beadID + " --status in_progress"}
	got, _ := codex.ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL, surface, refs)
	var work []codex.ExtractedReference
	for _, r := range got {
		if r.Kind == codex.RefKindBead {
			work = append(work, r)
		}
	}
	if len(work) != 1 {
		t.Fatalf("extracted %d bead references, want exactly 1: %+v", len(work), got)
	}
	if work[0].Work.BeadID != beadID {
		t.Errorf("extracted bead id = %q, want %q", work[0].Work.BeadID, beadID)
	}
	if work[0].Work.Resolver.DefaultProjectID != project {
		t.Errorf("extracted reference resolves to project %q, want %q", work[0].Work.Resolver.DefaultProjectID, project)
	}

	// With no prefixes the extractor stays off — the daemon is metadata-only for beads, as before.
	off := newReferenceConfig(nil, "")
	none, _ := codex.ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL, surface, off)
	for _, r := range none {
		if r.Kind == codex.RefKindBead {
			t.Fatalf("empty prefix set still extracted a bead reference: %+v", r)
		}
	}
}
