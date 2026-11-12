package operatorfile

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	userID = "usr_01a19b2a-9bbb-79e6-b877-0f48ad23f928"
	spID   = "sp_019f0000-0000-7000-8000-00000000000c"
)

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) log(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }
func (l *logSink) all() string  { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.lines, "\n") }

func write(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil { // atomic replace, as bd writes it
		t.Fatal(err)
	}
}

func userFile(principal, class, since string) string {
	return `{"schema":"bd.operator/v1","org_id":"org_a","principal_id":"` + principal + `","principal_class":"` + class +
		`","principal_since":"` + since + `","written_at":"` + since + `"}`
}

// TestOperatorFileHotReload: a missing file is no report; a valid file is read; a rewrite is picked
// up after the check interval; a logout reads as LoggedOut; removal drops the report at once.
func TestOperatorFileHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "org_a.json")
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var logs logSink
	f, err := Open(Config{Path: path, CheckInterval: 2 * time.Second, Log: logs.log, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Current(); ok {
		t.Fatal("a missing file reported an operator")
	}

	write(t, path, userFile(userID, "USER", "2026-11-12T08:00:00Z"))
	now = now.Add(3 * time.Second)
	snap, ok := f.Current()
	if !ok || snap.PrincipalID != userID || snap.PrincipalClass != ClassUser || !snap.PrincipalSince.Equal(time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("snapshot = %+v, %v", snap, ok)
	}

	// Within the check interval a rewrite is not seen yet; after it, it is.
	write(t, path, `{"schema":"bd.operator/v1","org_id":"org_a","principal_id":"","written_at":"2026-11-12T09:00:04Z","logged_out_at":"2026-11-12T09:00:04Z"}`)
	now = now.Add(time.Second)
	if snap, _ := f.Current(); snap.PrincipalID != userID {
		t.Fatal("re-read before the check interval elapsed")
	}
	now = now.Add(2 * time.Second)
	if snap, ok := f.Current(); !ok || !snap.LoggedOut() {
		t.Fatalf("logout = %+v, %v", snap, ok)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Second)
	if _, ok := f.Current(); ok {
		t.Fatal("a removed file kept reporting")
	}
	if strings.Contains(logs.all(), "usr_") {
		t.Fatalf("a log line carries the principal: %s", logs.all())
	}
}

// TestOperatorFileRejectsMalformed: every malformed file reads as no report and is logged once
// without any of its content; fixing it is picked up.
func TestOperatorFileRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "org_a.json")
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	for name, body := range map[string]string{
		"not json":       `secret-token-value`,
		"wrong schema":   `{"schema":"bd.operator/v9","principal_id":"` + userID + `"}`,
		"email":          userFile("ada@example.com", "USER", "2026-11-12T08:00:00Z"),
		"name":           userFile("Ada Lovelace", "USER", "2026-11-12T08:00:00Z"),
		"class mismatch": userFile(spID, "USER", "2026-11-12T08:00:00Z"),
		"no since":       userFile(userID, "USER", "yesterday"),
		"class, no id":   `{"schema":"bd.operator/v1","principal_id":"","principal_class":"USER"}`,
		"too long":       userFile("usr_"+strings.Repeat("a", 61), "USER", "2026-11-12T08:00:00Z"),
		"oversized":      `{"schema":"bd.operator/v1","pad":"` + strings.Repeat("x", MaxFileBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			write(t, path, body)
			var logs logSink
			f, err := Open(Config{Path: path, Log: logs.log, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := f.Current(); ok {
				t.Fatal("a malformed file reported an operator")
			}
			f.Current()
			got := logs.all()
			if strings.Count(got, "not loaded") != 1 {
				t.Fatalf("want one content-free failure line, got %q", got)
			}
			for _, leak := range []string{"usr_", "sp_", "@", "Ada", "secret", "yesterday"} {
				if strings.Contains(got, leak) {
					t.Fatalf("log carries file content %q: %s", leak, got)
				}
			}
			write(t, path, userFile(spID, "SERVICE", "2026-11-12T08:00:00Z"))
			if snap, ok := f.Current(); !ok || snap.PrincipalID != spID || snap.PrincipalClass != ClassService {
				t.Fatalf("fixed file = %+v, %v", snap, ok)
			}
		})
	}
}

func TestOpenRequiresAnAbsolutePath(t *testing.T) {
	for _, p := range []string{"", "relative/org_a.json"} {
		if _, err := Open(Config{Path: p}); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}
