package consent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// logRecorder collects a Source's log lines.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRecorder) log(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}

func (l *logRecorder) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// policyFile is an owner-only root policy file the test rewrites the way bd does: a temporary file
// renamed over the policy.
type policyFile struct {
	t    *testing.T
	path string
}

func newPolicyFile(t *testing.T, body string) *policyFile {
	t.Helper()
	f := &policyFile{t: t, path: filepath.Join(t.TempDir(), "root-policy.json")}
	f.replace(body)
	return f
}

func (f *policyFile) replace(body string) {
	f.t.Helper()
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		f.t.Fatal(err)
	}
}

func record(path string, generation uint64, active bool) string {
	mode := `""`
	if active {
		mode = `"backfill"`
	}
	return `{"path":"` + path + `","generation":` + strconv.FormatUint(generation, 10) + `,"active":` + boolString(active) + `,"mode":` + mode + `}`
}

func v3(content bool, records ...string) string {
	return `{"schema_version":"gasworks.companion.root-policy/v3","content_upload":` + boolString(content) + `,"roots":[` + strings.Join(records, ",") + `]}`
}

func v2(records ...string) string {
	return `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` + strings.Join(records, ",") + `]}`
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func open(t *testing.T, cfg Config) *Source {
	t.Helper()
	src, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return src
}

func TestOpenRefusesAnUnusablePolicy(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(t.TempDir(), "absent.json")
	malformed := newPolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v3","roots":[`)
	unstated := newPolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v3","roots":[`+record(root, 1, true)+`]}`)
	for name, path := range map[string]string{
		"relative path":             "root-policy.json",
		"missing file":              missing,
		"malformed document":        malformed.path,
		"v3 without content_upload": unstated.path,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(Config{Path: path}); err == nil {
				t.Fatal("Open succeeded, want error")
			}
		})
	}
}

// TestContentWithdrawalAppliesWithoutRestart is the core promise: a v3 document turning content
// upload off takes effect at the next check, with one log line naming the change.
func TestContentWithdrawalAppliesWithoutRestart(t *testing.T) {
	root := t.TempDir()
	logs := &logRecorder{}
	f := newPolicyFile(t, v3(true, record(root, 1, true)))
	src := open(t, Config{Path: f.path, Log: logs.log})

	first := src.Current()
	if !first.ContentUpload || !first.Valid() || first.Version != 1 {
		t.Fatalf("initial policy = %+v, want content on, valid, version 1", first)
	}

	f.replace(v3(false, record(root, 1, true)))
	got := src.Current()
	if got.ContentUpload {
		t.Fatal("content upload still on after the policy withdrew it")
	}
	if got.Version != 2 || !got.Allows(root, 1) {
		t.Fatalf("policy after withdrawal = %+v, want version 2 still consenting %s", got, root)
	}
	if src.Latest().Version != 2 {
		t.Fatalf("Latest version = %d, want 2", src.Latest().Version)
	}
	lines := logs.all()
	if len(lines) != 2 || !strings.Contains(lines[1], "content upload off (stated by the policy)") {
		t.Fatalf("logs = %q, want a load line and one change line naming content upload off", lines)
	}

	// Re-granting is applied the same way.
	f.replace(v3(true, record(root, 1, true)))
	if got := src.Current(); !got.ContentUpload || got.Version != 3 {
		t.Fatalf("policy after re-grant = %+v, want content on at version 3", got)
	}
}

// TestPreV3DocumentKeepsTheFlagDefault: v1/v2 documents state no content decision, so the
// -content-upload flag (OBSERVER_CONTENT_UPLOAD) decides; a v3 document always overrides it.
func TestPreV3DocumentKeepsTheFlagDefault(t *testing.T) {
	root := t.TempDir()
	for _, def := range []bool{true, false} {
		f := newPolicyFile(t, v2(record(root, 1, true)))
		src := open(t, Config{Path: f.path, ContentDefault: def})
		if got := src.Current().ContentUpload; got != def {
			t.Fatalf("v2 document with flag default %t: content upload = %t", def, got)
		}
		f.replace(v3(!def, record(root, 1, true)))
		if got := src.Current().ContentUpload; got != !def {
			t.Fatalf("v3 document stating %t with flag default %t: content upload = %t", !def, def, got)
		}
	}
}

// TestRootWithdrawalAndReRegistrationFenceGenerations: Allows is exact on (path, generation), so a
// tombstoned root and an earlier generation of a re-registered root are both outside consent.
func TestRootWithdrawalAndReRegistrationFenceGenerations(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	logs := &logRecorder{}
	f := newPolicyFile(t, v3(true, record(a, 1, true), record(b, 1, true)))
	src := open(t, Config{Path: f.path, Log: logs.log})
	if p := src.Current(); !p.Allows(a, 1) || !p.Allows(b, 1) {
		t.Fatalf("initial policy = %+v, want both roots consented at generation 1", p)
	}

	f.replace(v3(true, record(a, 2, false), record(b, 1, true)))
	p := src.Current()
	if p.Allows(a, 1) || p.Allows(a, 2) || !p.Allows(b, 1) {
		t.Fatalf("after withdrawing %s: %+v", a, p)
	}
	if last := logs.all()[len(logs.all())-1]; !strings.Contains(last, "withdrew "+a+" (generation 1)") {
		t.Fatalf("change line %q does not name the withdrawn root", last)
	}

	f.replace(v3(true, record(a, 2, false), record(b, 3, true)))
	p = src.Current()
	if p.Allows(b, 1) || !p.Allows(b, 3) {
		t.Fatalf("after re-registering %s at generation 3: %+v", b, p)
	}
	if last := logs.all()[len(logs.all())-1]; !strings.Contains(last, "re-registered "+b+" (generation 1 -> 3, backfill)") {
		t.Fatalf("change line %q does not name the re-registration", last)
	}

	c := t.TempDir()
	f.replace(v3(true, record(a, 2, false), record(b, 3, true), record(c, 1, true)))
	if p := src.Current(); !p.Allows(c, 1) {
		t.Fatalf("widening to %s not applied: %+v", c, p)
	}
	if last := logs.all()[len(logs.all())-1]; !strings.Contains(last, "consented "+c+" (generation 1, backfill)") {
		t.Fatalf("change line %q does not name the added root", last)
	}
}

// TestUnusablePolicyFailsClosed: a malformed, removed, or no-longer-owner-only file withdraws
// content upload at once and keeps metadata capture on the last valid roots; the failure is logged
// once per distinct problem, and a valid file restores the policy.
func TestUnusablePolicyFailsClosed(t *testing.T) {
	root := t.TempDir()
	valid := v3(true, record(root, 1, true))
	for name, breakIt := range map[string]func(f *policyFile){
		"malformed": func(f *policyFile) {
			f.replace(`{"schema_version":"gasworks.companion.root-policy/v3","content_upload":true,"roots":[`)
		},
		"removed": func(f *policyFile) {
			if err := os.Remove(f.path); err != nil {
				t.Fatal(err)
			}
		},
		"world readable": func(f *policyFile) {
			if err := os.Chmod(f.path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			logs := &logRecorder{}
			f := newPolicyFile(t, valid)
			src := open(t, Config{Path: f.path, Log: logs.log})
			src.Current()

			breakIt(f)
			p := src.Current()
			if p.ContentUpload || p.Valid() {
				t.Fatalf("unusable file yielded %+v, want content withdrawn and the problem reported", p)
			}
			if !p.Allows(root, 1) {
				t.Fatalf("unusable file dropped the last valid roots: %+v", p)
			}
			// A second check of the same broken file neither re-logs nor bumps the version.
			if again := src.Current(); again.Version != p.Version {
				t.Fatalf("version moved from %d to %d on an unchanged broken file", p.Version, again.Version)
			}
			lines := logs.all()
			if len(lines) != 2 || !strings.Contains(lines[1], "content upload is withdrawn (fail closed)") {
				t.Fatalf("logs = %q, want exactly one loud fail-closed line after the load line", lines)
			}

			f.replace(valid)
			if err := os.Chmod(f.path, 0o600); err != nil {
				t.Fatal(err)
			}
			restored := src.Current()
			if !restored.ContentUpload || !restored.Valid() || restored.Version != p.Version+1 {
				t.Fatalf("restored policy = %+v, want content on and valid at version %d", restored, p.Version+1)
			}
			if last := logs.all()[len(logs.all())-1]; !strings.Contains(last, "the policy file is valid again") {
				t.Fatalf("recovery line %q does not say the file is valid again", last)
			}
		})
	}
}

// TestUnchangedFileIsNotReread: the per-call cost of an unchanged file is one lstat. Here the
// policy file is untouched while an active root's directory is deleted — which a re-read would
// refuse — so the policy stays exactly as loaded until the file itself changes.
func TestUnchangedFileIsNotReread(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	body := v3(true, record(root, 1, true))
	f := newPolicyFile(t, body)
	src := open(t, Config{Path: f.path})
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if p := src.Current(); !p.Valid() || !p.ContentUpload || p.Version != 1 {
			t.Fatalf("an unchanged policy file was re-read: %+v", p)
		}
	}
	f.replace(body) // the same document, newly written: re-read, and now refused
	if p := src.Current(); p.Valid() || p.ContentUpload {
		t.Fatalf("a rewritten policy naming a missing root was accepted: %+v", p)
	}
}

// TestUnusableDocumentNarrowsButNeverGrants: a document that fails validation (here because an
// active root's directory is gone) still withdraws what it no longer consents to — a root it
// tombstones or drops — while nothing it newly lists is granted, and content upload stays off.
func TestUnusableDocumentNarrowsButNeverGrants(t *testing.T) {
	parent := t.TempDir()
	gone := filepath.Join(parent, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	kept, withdrawn, added := t.TempDir(), t.TempDir(), t.TempDir()
	logs := &logRecorder{}
	f := newPolicyFile(t, v3(true, record(gone, 1, true), record(kept, 1, true), record(withdrawn, 1, true)))
	src := open(t, Config{Path: f.path, Log: logs.log})
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	f.replace(v3(true, record(gone, 1, true), record(kept, 1, true), record(withdrawn, 2, false), record(added, 1, true)))
	p := src.Current()
	if p.Valid() || p.ContentUpload {
		t.Fatalf("an unusable document yielded %+v, want it reported and content withdrawn", p)
	}
	if p.Allows(withdrawn, 1) {
		t.Fatal("a root the unusable document tombstoned is still consented")
	}
	if !p.Allows(kept, 1) || !p.Allows(gone, 1) {
		t.Fatalf("roots the document still consents to were dropped: %+v", p.Roots)
	}
	if p.Allows(added, 1) {
		t.Fatal("an unusable document granted a new root")
	}
	if last := logs.all()[len(logs.all())-1]; !strings.Contains(last, "the unusable document still withdrew "+withdrawn+" (generation 1)") {
		t.Fatalf("the narrowing was not logged: %q", last)
	}

	// An unreadable document narrows nothing: there is no consent statement to read.
	f.replace(`{"schema_version":"gasworks.companion.root-policy/v3",`)
	if p := src.Current(); !p.Allows(kept, 1) || p.Allows(withdrawn, 1) {
		t.Fatalf("a malformed document changed the roots: %+v", p.Roots)
	}
}

// TestConcurrentChecksAreSafe exercises the Source the way the daemon does — checks from several
// loops, hot-path reads, and a subscriber — while the file changes, under the race detector.
func TestConcurrentChecksAreSafe(t *testing.T) {
	root := t.TempDir()
	f := newPolicyFile(t, v3(true, record(root, 1, true)))
	src := open(t, Config{Path: f.path})
	var notified sync.WaitGroup
	notified.Add(1)
	var once sync.Once
	src.Subscribe(func() {
		_ = src.Latest()
		once.Do(notified.Done)
	})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				src.Current()
				_ = src.Latest().Allows(root, 1)
			}
		}()
	}
	for i := range 20 {
		f.replace(v3(i%2 == 0, record(root, 1, true)))
	}
	wg.Wait()
	f.replace(v3(false, record(root, 2, true)))
	if p := src.Current(); p.ContentUpload || !p.Allows(root, 2) {
		t.Fatalf("final policy = %+v", p)
	}
	notified.Wait()
}

// TestIdenticalRewriteIsNotAChange: bd may rewrite the policy with identical consent; that is not a
// change, so nothing is logged and subscribers are not woken.
func TestIdenticalRewriteIsNotAChange(t *testing.T) {
	root := t.TempDir()
	body := v3(true, record(root, 1, true))
	logs := &logRecorder{}
	f := newPolicyFile(t, body)
	src := open(t, Config{Path: f.path, Log: logs.log})
	woken := 0
	src.Subscribe(func() { woken++ })

	f.replace(body)
	if p := src.Current(); p.Version != 1 {
		t.Fatalf("identical rewrite bumped the version to %d", p.Version)
	}
	if woken != 0 || len(logs.all()) != 1 {
		t.Fatalf("identical rewrite woke %d subscribers and logged %q", woken, logs.all())
	}

	f.replace(v3(false, record(root, 1, true)))
	src.Current()
	src.Current()
	if woken != 1 {
		t.Fatalf("one change woke subscribers %d times, want once", woken)
	}
}

// TestCapturableFiltersRecords: records the daemon cannot act on never reach a Policy.
func TestCapturableFiltersRecords(t *testing.T) {
	transcripts, project, store := t.TempDir(), t.TempDir(), t.TempDir()
	f := newPolicyFile(t, `{"schema_version":"gasworks.companion.root-policy/v3","content_upload":true,"roots":[`+
		`{"path":"`+transcripts+`","generation":1,"active":true,"mode":"backfill","kind":"transcripts"},`+
		`{"path":"`+project+`","generation":2,"active":true,"mode":"forward-only","kind":"project"}],"stores":["`+store+`"]}`)
	src := open(t, Config{Path: f.path, Capturable: func(r rootpolicy.Record) bool { return !r.IsProject() }})
	p := src.Current()
	if len(p.Roots) != 1 || p.Roots[0].Path != transcripts || p.Allows(project, 2) {
		t.Fatalf("roots = %+v, want only the transcripts root", p.Roots)
	}
}
