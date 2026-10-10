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
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	if m, err := Parse([]byte(`[]`)); err != nil || m.Len() != 0 {
		t.Fatalf("empty array: m=%v err=%v", m, err)
	}
	for _, bad := range []string{
		``, `   `, `null`, `{}`, `[{"prefix":"acme","project_id":"p"}]`,
		`[{"prefix":"acme-"}]`, `[] []`, `[{"prefix":"acme-","project_id":"p"}`,
		`[{"prefix":"acme-","project_id":"a"},{"prefix":"acme-","project_id":"b"}]`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) accepted, want error", bad)
		}
	}
}

func TestOpenFailsLoudOnInvalidFileButToleratesMissing(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeMap(t, bad, `[{"prefix":"nope","project_id":"p"}]`, time.Now())
	if _, err := Open(Config{Path: bad}); err == nil {
		t.Fatal("Open accepted an invalid map")
	}
	if _, err := Open(Config{Path: dir}); err == nil {
		t.Fatal("Open accepted a directory")
	}
	big := filepath.Join(dir, "big.json")
	writeMap(t, big, "["+strings.Repeat(" ", MaxFileBytes)+"]", time.Now())
	if _, err := Open(Config{Path: big}); err == nil {
		t.Fatal("Open accepted an oversized file")
	}
	f, err := Open(Config{Path: filepath.Join(dir, "absent.json")})
	if err != nil {
		t.Fatalf("missing file must be tolerated: %v", err)
	}
	if f.Current().Len() != 0 {
		t.Fatal("missing file must yield an empty map")
	}
	if _, err := Open(Config{}); err == nil {
		t.Fatal("Open without a path accepted")
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
	if logs.count("reloaded: 2 prefixes") != 1 {
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
	if n := logs.count("not reloaded"); n != 1 {
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
		writeMap(t, path, `[{"prefix":"acme-","project_id":"p"},{"prefix":"beta-","project_id":"q"}]`, mt)
	}
	wg.Wait()
}
