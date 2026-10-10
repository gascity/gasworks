package prefixmap

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) Log(s string) { l.mu.Lock(); defer l.mu.Unlock(); l.lines = append(l.lines, s) }
func (l *logSink) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// writeMap writes the file and bumps its mtime forward so every rewrite is a distinct state even
// on a filesystem with coarse timestamps.
func writeMap(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// replaceMap atomically replaces path (temp file + rename, as bd writes it) with body and the given
// mtime.
func replaceMap(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	tmp := path + ".tmp"
	writeMap(t, tmp, body, mtime)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func lookup(t *testing.T, f *File, bead string) string {
	t.Helper()
	p, _ := f.Current().Lookup(bead)
	return p
}

func TestParse(t *testing.T) {
	m, err := Parse([]byte(`[{"prefix":"acme-","project_id":"p_acme","issue_prefix_note":"ignored"},{"prefix":"beta-","project_id":"p_beta"}]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Len() != 2 || m.Problems() != "" {
		t.Fatalf("Len = %d problems = %q, want 2 and none", m.Len(), m.Problems())
	}
	if m, err := Parse([]byte("[]\n")); err != nil || m.Len() != 0 {
		t.Fatalf("empty array: m=%v err=%v", m, err)
	}
	// A malformed document is rejected whole: it is not the file bd writes (or it is truncated).
	for _, bad := range []string{
		``, `   `, `null`, `{}`, `[1]`, `["acme-"]`, `[] []`, `[]]`, `[] }`, `[{"prefix":"acme-","project_id":"p"}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) accepted, want error", bad)
		}
	}
	// A well-formed document applies every declaration it can; the rest are reported.
	m, err = Parse([]byte(`[{"prefix":"acme","project_id":"p"},{"prefix":"beta-","project_id":"p_beta"},null,` +
		`{"prefix":"fe-","project_id":"a"},{"prefix":"fe-","project_id":"b"}]`))
	if err != nil {
		t.Fatalf("per-entry problems failed the document: %v", err)
	}
	if got, ok := m.Lookup("beta-1"); !ok || got != "p_beta" {
		t.Fatalf("valid declaration not applied: %q,%v", got, ok)
	}
	if _, ok := m.Lookup("fe-1"); ok {
		t.Fatal("ambiguous prefix resolved")
	}
	if p := m.Problems(); !strings.Contains(p, "skipped 2 malformed entries") || !strings.Contains(p, "fe-") {
		t.Fatalf("problems = %q", p)
	}
}

// TestOpenNeverFailsOnTheFile: the map is enrichment, so the file's state never fails startup (a
// daemon that exits there crash-loops under launchd/systemd and stops ALL capture). An invalid,
// oversized, non-regular or missing file leaves capture idle with one log line; only a missing path
// (a configuration error) fails.
func TestOpenNeverFailsOnTheFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeMap(t, bad, `[{"prefix":"acme-","project_id":"p"}`, time.Now())
	big := filepath.Join(dir, "big.json")
	writeMap(t, big, "["+strings.Repeat(" ", MaxFileBytes)+"]", time.Now())
	for name, path := range map[string]string{
		"invalid":   bad,
		"oversized": big,
		"directory": dir,
		"missing":   filepath.Join(dir, "absent.json"),
	} {
		logs := &logSink{}
		f, err := Open(Config{Path: path, Log: logs.Log})
		if err != nil {
			t.Errorf("%s: Open failed: %v", name, err)
			continue
		}
		if f.Current().Len() != 0 {
			t.Errorf("%s: served prefixes", name)
		}
		f.Current()
		f.Current()
		if len(logs.lines) != 1 {
			t.Errorf("%s: want exactly one log line, got %q", name, logs.lines)
		}
	}
	for _, p := range []string{"", "bead-prefixes.json", "./x/bead-prefixes.json"} {
		if _, err := Open(Config{Path: p}); err == nil {
			t.Errorf("Open(%q) accepted a missing or relative path", p)
		}
	}
}

// TestInvalidAtStartupThenFixed: a file that is invalid when the daemon starts is picked up as soon
// as it becomes valid, with no restart.
func TestInvalidAtStartupThenFixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bead-prefixes.json")
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	logs := &logSink{}
	mt := time.Unix(1_700_000_000, 0)
	writeMap(t, path, `not json`, mt)
	f, err := Open(Config{Path: path, CheckInterval: time.Second, Now: clk.Now, Log: logs.Log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if logs.count("bead capture idle until a valid map is written") != 1 {
		t.Fatalf("startup failure not logged: %v", logs.lines)
	}
	replaceMap(t, path, `[{"prefix":"acme-","project_id":"p_acme"}]`, mt.Add(time.Second))
	clk.Advance(time.Second)
	if got := lookup(t, f, "acme-1"); got != "p_acme" {
		t.Fatalf("fixed map not picked up: acme-1 -> %q", got)
	}
	if logs.count("loaded: 1 prefixes") != 1 {
		t.Fatalf("load not logged: %v", logs.lines)
	}
}

// TestHotReload is the no-restart guarantee: a rewritten map is picked up on the first check after
// the interval, a new project's prefix resolves, an invalid rewrite keeps the last good map (logged
// once), the corrected file then loads, a removed file keeps the last good map, and a file that
// appears after startup is picked up.
func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bead-prefixes.json")
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	logs := &logSink{}
	mt := time.Unix(1_700_000_000, 0)
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p_acme"}]`, mt)

	f, err := Open(Config{Path: path, CheckInterval: time.Second, Now: clk.Now, Log: logs.Log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := lookup(t, f, "acme-1"); got != "p_acme" {
		t.Fatalf("acme-1 -> %q", got)
	}
	if logs.count("loaded: 1 prefixes") != 1 {
		t.Fatalf("initial load not logged: %v", logs.lines)
	}

	// A new project is added. Within the interval the old snapshot still serves (no stat storm).
	mt = mt.Add(time.Second)
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p_acme"},{"prefix":"beta-","project_id":"p_beta"}]`, mt)
	if got := lookup(t, f, "beta-1"); got != "" {
		t.Fatalf("reloaded before the check interval elapsed: beta-1 -> %q", got)
	}
	clk.Advance(time.Second)
	if got := lookup(t, f, "beta-1"); got != "p_beta" {
		t.Fatalf("new project not picked up without restart: beta-1 -> %q", got)
	}
	if logs.count("loaded: 2 prefixes") != 1 {
		t.Fatalf("reload not logged: %v", logs.lines)
	}

	// An invalid (e.g. half-written) rewrite never replaces the last good map and logs once.
	mt = mt.Add(time.Second)
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p_acme"},{"pre`, mt)
	for i := 0; i < 3; i++ {
		clk.Advance(time.Second)
		if got := lookup(t, f, "beta-1"); got != "p_beta" {
			t.Fatalf("invalid rewrite displaced the last good map: beta-1 -> %q", got)
		}
	}
	if n := logs.count("keeping the last loaded map (2 prefixes)"); n != 1 {
		t.Fatalf("invalid file logged %d times, want once: %v", n, logs.lines)
	}

	// The completed write loads.
	mt = mt.Add(time.Second)
	writeMap(t, path, `[{"prefix":"gamma-","project_id":"p_gamma"}]`, mt)
	clk.Advance(time.Second)
	if got := lookup(t, f, "gamma-1"); got != "p_gamma" {
		t.Fatalf("corrected file not loaded: gamma-1 -> %q", got)
	}
	if got := lookup(t, f, "acme-1"); got != "" {
		t.Fatalf("removed prefix still resolves: acme-1 -> %q", got)
	}

	// Removal keeps the last good map.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	if got := lookup(t, f, "gamma-1"); got != "p_gamma" {
		t.Fatalf("removed file dropped the last good map: gamma-1 -> %q", got)
	}
	if logs.count("file removed; keeping the last loaded map (1 prefixes)") != 1 {
		t.Fatalf("removal not logged: %v", logs.lines)
	}

	// A file that appears after startup is picked up.
	late := filepath.Join(dir, "late.json")
	g, err := Open(Config{Path: late, CheckInterval: time.Second, Now: clk.Now, Log: logs.Log})
	if err != nil {
		t.Fatalf("Open(missing): %v", err)
	}
	if g.Current().Len() != 0 {
		t.Fatal("missing file served prefixes")
	}
	writeMap(t, late, `[{"prefix":"late-","project_id":"p_late"}]`, mt)
	clk.Advance(time.Second)
	if got := lookup(t, g, "late-1"); got != "p_late" {
		t.Fatalf("late file not picked up: late-1 -> %q", got)
	}
}

// TestAtomicReplaceDetectedWithinOneTimestampTick: bd replaces the file by rename. A replacement
// with the same size and the same mtime (two writes inside one filesystem timestamp tick) is still a
// different file and must be re-read.
func TestAtomicReplaceDetectedWithinOneTimestampTick(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bead-prefixes.json")
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	mt := time.Unix(1_700_000_000, 0)
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p_aaaa"}]`, mt)
	f, err := Open(Config{Path: path, CheckInterval: time.Second, Now: clk.Now})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := lookup(t, f, "acme-1"); got != "p_aaaa" {
		t.Fatalf("acme-1 -> %q", got)
	}
	replaceMap(t, path, `[{"prefix":"acme-","project_id":"p_bbbb"}]`, mt) // same size, same mtime
	clk.Advance(time.Second)
	if got := lookup(t, f, "acme-1"); got != "p_bbbb" {
		t.Fatalf("same-size same-mtime replacement not detected: acme-1 -> %q", got)
	}
}

// TestIdenticalRewriteKeepsSnapshot: bd's periodic refresh rewrites unchanged content. The daemon
// keeps the same snapshot (so the extractor's compiled pattern stays cached) and logs nothing.
func TestIdenticalRewriteKeepsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bead-prefixes.json")
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	logs := &logSink{}
	mt := time.Unix(1_700_000_000, 0)
	body := `[{"prefix":"acme-","project_id":"p_acme"},{"prefix":"beta-","project_id":"p_beta"}]`
	writeMap(t, path, body, mt)
	f, err := Open(Config{Path: path, CheckInterval: time.Second, Now: clk.Now, Log: logs.Log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := f.Current()
	for i := 1; i <= 3; i++ {
		replaceMap(t, path, `[{"prefix":"beta-","project_id":"p_beta"},{"prefix":"acme-","project_id":"p_acme"}]`, mt.Add(time.Duration(i)*time.Hour))
		clk.Advance(time.Second)
		if f.Current() != first {
			t.Fatalf("identical rewrite %d swapped the snapshot", i)
		}
	}
	if n := len(logs.lines); n != 1 {
		t.Fatalf("identical rewrites logged: %v", logs.lines)
	}
}

// TestLoadReportsPerEntryProblems: a file with a malformed and an ambiguous declaration still
// applies the rest, and the load line names the problems (bounded, no project ids).
func TestLoadReportsPerEntryProblems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bead-prefixes.json")
	logs := &logSink{}
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p_acme"},{"prefix":"my_app-","project_id":"p_mine"},`+
		`{"prefix":"FE-","project_id":"p_fe1"},{"prefix":"FE-","project_id":"p_fe2"}]`, time.Now())
	f, err := Open(Config{Path: path, Log: logs.Log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := lookup(t, f, "acme-1"); got != "p_acme" {
		t.Fatalf("acme-1 -> %q", got)
	}
	if got := lookup(t, f, "FE-1"); got != "" {
		t.Fatalf("ambiguous FE-1 -> %q", got)
	}
	want := `loaded: 2 prefixes; skipped 1 malformed entry (first: entry 1: prefix "my_app-" is not dash-joined alphanumerics ending in '-'); 1 prefix declared for more than one project resolves to no project: FE-`
	if logs.count(want) != 1 {
		t.Fatalf("load line = %v, want it to contain %q", logs.lines, want)
	}
	if logs.count("p_fe") != 0 || logs.count("p_mine") != 0 {
		t.Fatalf("project ids leaked into the log: %v", logs.lines)
	}
}

// TestCurrentIsConcurrencySafe exercises Current from several goroutines while the file changes
// (run under -race).
func TestCurrentIsConcurrencySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	mt := time.Unix(1_700_000_000, 0)
	writeMap(t, path, `[{"prefix":"acme-","project_id":"p"}]`, mt)
	f, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = f.Current().Len()
			}
		}()
	}
	for j := 0; j < 20; j++ {
		mt = mt.Add(time.Second)
		replaceMap(t, path, `[{"prefix":"acme-","project_id":"p"},{"prefix":"beta-","project_id":"q"}]`, mt)
	}
	wg.Wait()
}
