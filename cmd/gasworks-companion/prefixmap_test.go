//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/prefixmap"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestDaemonPrefixMapFlagValidation: the multi-project map is mutually exclusive with the
// single-project flags and its path must be absolute (a static misconfiguration fails startup with
// exit 2; the file's content never does).
func TestDaemonPrefixMapFlagValidation(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`[{"prefix":"acme-","project_id":"p"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"-dir", filepath.Join(dir, "state"), "-source-id", e2eSourceID}
	for name, extra := range map[string][]string{
		"with_single_project_pair": {"-bead-prefix-map-file", good, "-bead-prefix", "acme-", "-beads-project", "p"},
		"with_beads_project":       {"-bead-prefix-map-file", good, "-beads-project", "p"},
		"relative_path":            {"-bead-prefix-map-file", "bead-prefixes.json"},
	} {
		if code := runDaemon(append(append([]string{}, base...), extra...)); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// TestOpenPrefixMapNeverFailsOnTheFile: the map file is written by bd from team-server data, so its
// content must never stop the daemon — an exit here crash-loops under launchd/systemd and stops ALL
// transcript capture. An invalid file is logged and leaves bead capture idle.
func TestOpenPrefixMapNeverFailsOnTheFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`[{"prefix":"acme-","project_id":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs []string
	pm, err := openPrefixMap(bad, 0, func(s string) { logs = append(logs, s) })
	if err != nil {
		t.Fatalf("openPrefixMap failed on an invalid file: %v", err)
	}
	if pm.Current().Len() != 0 {
		t.Fatal("invalid file served prefixes")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "bead capture idle until a valid map is written") {
		t.Fatalf("logs = %q", logs)
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

// prefixMapDaemon starts a REAL assembled daemon (watcher -> extractor -> policy -> durable WAL)
// wired exactly as -bead-prefix-map-file wires it, tailing one transcript root.
func prefixMapDaemon(t *testing.T, mapFile string) (stateDir, root string, pm *prefixmap.File) {
	t.Helper()
	stateDir, root = t.TempDir(), t.TempDir()
	const poll = 15 * time.Millisecond
	refs := newReferenceConfig(nil, "")
	pm, err := openPrefixMap(mapFile, poll, func(string) {})
	if err != nil {
		t.Fatalf("openPrefixMap: %v", err)
	}
	refs.PrefixMap = pm
	watch := newWatchLoopConfig([]string{root}, t.TempDir(), poll, refs)
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
	return stateDir, root, pm
}

func bdToolLine(cmd string) string {
	return `{"type":"tool_call","tool":"bd","category":"SHELL","command":"` + cmd + `","ts":"2026-07-17T10:00:01Z"}` + "\n"
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

// replaceMapFile atomically replaces the map file, as bd's refresh does.
func replaceMapFile(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestDaemonPrefixMapMultiProjectHotReloadEndToEnd is the bead acceptance through a REAL assembled
// daemon: a session referencing beads of two projects yields durable EXTRACTED references to both,
// each under its own project, while a malformed declaration and a prefix two projects share (both
// possible in the team server's project list) neither block the map nor mis-link; then the map file
// is rewritten with a new project and, with the daemon still running, the new project's bead is
// captured and resolved.
func TestDaemonPrefixMapMultiProjectHotReloadEndToEnd(t *testing.T) {
	mapFile := filepath.Join(t.TempDir(), "bead-prefixes.json")
	if err := os.WriteFile(mapFile, []byte(`[{"prefix":"acme-","project_id":"btsproj_acme"},{"prefix":"beta-","project_id":"btsproj_beta"},`+
		`{"prefix":"my_app-","project_id":"btsproj_mine"},{"prefix":"fe-","project_id":"btsproj_fe1"},{"prefix":"fe-","project_id":"btsproj_fe2"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir, root, pm := prefixMapDaemon(t, mapFile)

	transcript := filepath.Join(root, "session.jsonl")
	writeFile(t, transcript, bdToolLine("bd dep add acme-12 beta-7")+bdToolLine("bd show gamma-3 fe-5"))

	want := map[string]string{"acme-12": "btsproj_acme", "beta-7": "btsproj_beta"}
	if !waitUntil(8*time.Second, func() bool {
		got, err := durableWorkRefs(stateDir)
		return err == nil && got["acme-12"] == want["acme-12"] && got["beta-7"] == want["beta-7"]
	}) {
		got, _ := durableWorkRefs(stateDir)
		t.Fatalf("cross-project refs = %v, want %v", got, want)
	}
	got, _ := durableWorkRefs(stateDir)
	if _, ok := got["gamma-3"]; ok {
		t.Fatalf("unmapped prefix was captured before the reload: %v", got)
	}
	if _, ok := got["fe-5"]; ok {
		t.Fatalf("a prefix declared for two projects linked: %v", got)
	}

	// A new project lands in the map while the daemon runs (bd's refresh rewrites the file).
	replaceMapFile(t, mapFile, `[{"prefix":"acme-","project_id":"btsproj_acme"},{"prefix":"beta-","project_id":"btsproj_beta"},{"prefix":"gamma-","project_id":"btsproj_gamma"}]`)
	if !waitUntil(2*time.Second, func() bool { _, ok := pm.Current().Lookup("gamma-1"); return ok }) {
		t.Fatal("prefix map file change not observed")
	}
	appendLine(t, transcript, bdToolLine("bd close gamma-4"))

	if !waitUntil(8*time.Second, func() bool {
		got, err := durableWorkRefs(stateDir)
		return err == nil && got["gamma-4"] == "btsproj_gamma"
	}) {
		got, _ := durableWorkRefs(stateDir)
		t.Fatalf("new project not picked up without restart: %v", got)
	}
}

// TestDaemonPrefixMapInvalidAtStartupRecovers: a daemon whose map file is invalid when it starts
// keeps running (transcript capture is never held hostage by the enrichment map) and links beads as
// soon as bd writes a valid map — no restart.
func TestDaemonPrefixMapInvalidAtStartupRecovers(t *testing.T) {
	mapFile := filepath.Join(t.TempDir(), "bead-prefixes.json")
	if err := os.WriteFile(mapFile, []byte(`[{"prefix":"acme-","project_id":"btsproj_acme"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir, root, pm := prefixMapDaemon(t, mapFile)

	transcript := filepath.Join(root, "session.jsonl")
	writeFile(t, transcript, bdToolLine("bd show acme-1"))
	// The daemon is up and tailing: the session's own metadata becomes durable even though the
	// map is invalid, and no bead is linked yet.
	if !waitUntil(8*time.Second, func() bool {
		recs, err := upload.SpoolFrameStore{Dir: stateDir}.ReadRange(wire.SequenceMin, 1<<40)
		return err == nil && len(recs) > 0
	}) {
		t.Fatal("daemon with an invalid map captured nothing")
	}
	if got, _ := durableWorkRefs(stateDir); len(got) != 0 {
		t.Fatalf("refs linked from an invalid map: %v", got)
	}

	replaceMapFile(t, mapFile, `[{"prefix":"acme-","project_id":"btsproj_acme"}]`)
	if !waitUntil(2*time.Second, func() bool { _, ok := pm.Current().Lookup("acme-2"); return ok }) {
		t.Fatal("valid map not picked up")
	}
	appendLine(t, transcript, bdToolLine("bd close acme-2"))
	if !waitUntil(8*time.Second, func() bool {
		got, err := durableWorkRefs(stateDir)
		return err == nil && got["acme-2"] == "btsproj_acme"
	}) {
		got, _ := durableWorkRefs(stateDir)
		t.Fatalf("bead not linked after the map was fixed: %v", got)
	}
}
