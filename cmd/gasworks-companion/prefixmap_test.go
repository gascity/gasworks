//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestDaemonPrefixMapFlagValidation: the multi-project map is mutually exclusive with the
// single-project flags, and a present-but-invalid map fails startup (exit 2) rather than silently
// capturing nothing.
func TestDaemonPrefixMapFlagValidation(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`[{"prefix":"acme-","project_id":"p"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`[{"prefix":"acme","project_id":"p"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-dir", filepath.Join(dir, "state"), "-source-id", e2eSourceID}
	for name, extra := range map[string][]string{
		"with_bead_prefix":   {"-bead-prefix-map-file", good, "-bead-prefix", "acme-"},
		"with_beads_project": {"-bead-prefix-map-file", good, "-beads-project", "p"},
		"invalid_map":        {"-bead-prefix-map-file", bad},
	} {
		if code := runDaemon(append(append([]string{}, base...), extra...)); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// durableWorkRefs returns bead id -> team_server_project_id for every durable EXTRACTED
// WORK_REFERENCE frame under dir.
func durableWorkRefs(dir string) (map[string]string, error) {
	recs, err := upload.SpoolFrameStore{Dir: dir}.ReadRange(wire.SequenceMin, 1<<40)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i := range recs {
		var p struct {
			Kind          string `json:"kind"`
			WorkReference *struct {
				BeadID    string `json:"bead_id"`
				ProjectID string `json:"team_server_project_id"`
				Origin    string `json:"origin"`
			} `json:"work_reference"`
		}
		if json.Unmarshal(recs[i].Payload, &p) != nil || p.WorkReference == nil {
			continue
		}
		if p.WorkReference.Origin == string(wire.WorkReferenceOriginEXTRACTED) {
			out[p.WorkReference.BeadID] = p.WorkReference.ProjectID
		}
	}
	return out, nil
}

// TestDaemonPrefixMapMultiProjectHotReloadEndToEnd is the bead acceptance through a REAL assembled
// daemon (watcher -> extractor -> policy -> durable WAL) wired exactly as -bead-prefix-map-file
// wires it: a session referencing beads of two projects yields durable EXTRACTED references to
// both, each under its own project; then the map file is rewritten with a new project and, with the
// daemon still running, the new project's bead is captured and resolved.
func TestDaemonPrefixMapMultiProjectHotReloadEndToEnd(t *testing.T) {
	stateDir := t.TempDir()
	root := t.TempDir()
	cursorDir := t.TempDir()
	mapFile := filepath.Join(t.TempDir(), "bead-prefixes.json")
	if err := os.WriteFile(mapFile, []byte(`[{"prefix":"acme-","project_id":"btsproj_acme"},{"prefix":"beta-","project_id":"btsproj_beta"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	const poll = 15 * time.Millisecond
	refs := newReferenceConfig(nil, "")
	pm, err := openPrefixMap(mapFile, poll, func(string) {})
	if err != nil {
		t.Fatalf("openPrefixMap: %v", err)
	}
	refs.PrefixMap = pm
	watch := newWatchLoopConfig([]string{root}, cursorDir, poll, refs)
	watch.Policy = e2eWatchPolicy()

	svc, err := daemon.NewService(daemon.ServiceConfig{
		Dir:               stateDir,
		SourceID:          e2eSourceID,
		Capacity:          permissiveCap(),
		RegistrySource:    e2eSourceID,
		RegistryWorkspace: "ws-e2e",
		Watch:             watch,
		PeerUID:           euidPeerE2E,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})

	transcript := filepath.Join(root, "session.jsonl")
	line := func(cmd string) string {
		return `{"type":"tool_call","tool":"bd","category":"SHELL","command":"` + cmd + `","ts":"2026-07-17T10:00:01Z"}` + "\n"
	}
	writeFile(t, transcript, line("bd dep add acme-12 beta-7")+line("bd show gamma-3"))

	want := map[string]string{"acme-12": "btsproj_acme", "beta-7": "btsproj_beta"}
	if !waitUntil(8*time.Second, func() bool {
		got, err := durableWorkRefs(stateDir)
		return err == nil && got["acme-12"] == want["acme-12"] && got["beta-7"] == want["beta-7"]
	}) {
		got, _ := durableWorkRefs(stateDir)
		t.Fatalf("cross-project refs = %v, want %v", got, want)
	}
	if got, _ := durableWorkRefs(stateDir); got["gamma-3"] != "" {
		t.Fatalf("unmapped prefix was captured before the reload: %v", got)
	}

	// A new project lands in the map while the daemon runs (bd's refresh rewrites the file).
	tmp := mapFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(`[{"prefix":"acme-","project_id":"btsproj_acme"},{"prefix":"beta-","project_id":"btsproj_beta"},{"prefix":"gamma-","project_id":"btsproj_gamma"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(tmp, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, mapFile); err != nil {
		t.Fatal(err)
	}
	if !waitUntil(2*time.Second, func() bool { _, ok := pm.Current().Lookup("gamma-1"); return ok }) {
		t.Fatal("prefix map file change not observed")
	}
	f, err := os.OpenFile(transcript, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line("bd close gamma-4")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if !waitUntil(8*time.Second, func() bool {
		got, err := durableWorkRefs(stateDir)
		return err == nil && got["gamma-4"] == "btsproj_gamma"
	}) {
		got, _ := durableWorkRefs(stateDir)
		t.Fatalf("new project not picked up without restart: %v", got)
	}
}
