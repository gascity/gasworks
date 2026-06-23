package recallaxis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/saauth"
)

// --- BLAKE3 known-answer vector (official empty-input test vector) ---

func TestBlake3EmptyVector(t *testing.T) {
	const want = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	got := blake3Hex([]byte{})
	if got != want {
		t.Fatalf("blake3(\"\") = %s, want official vector %s", got, want)
	}
}

func TestBlake3KnownAbcVector(t *testing.T) {
	// Official BLAKE3 vector for the 3-byte input "abc".
	const want = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
	if got := blake3Hex([]byte("abc")); got != want {
		t.Fatalf("blake3(\"abc\") = %s, want %s", got, want)
	}
}

// --- fnmatch equivalence (M16) ---

func TestFnmatchEquivalence(t *testing.T) {
	cases := []struct {
		name, pat string
		want      bool
	}{
		{"mcp.json", "*mcp*.json", true},
		{"foo-mcp-bar.json", "*mcp*.json", true},
		{"mcp.jsonl", "*mcp*.json", false}, // suffix differs
		{"settings.json", "settings*.json", true},
		{"settings-local.json", "settings*.json", true},
		{"my.env", "*.env", true},
		{"a/b.env", "*.env", true}, // fnmatch "*" spans "/", unlike filepath.Match
		{"x-token-y.json", "*token*.json", true},
		{"secret.json", "*secret*.json", true},
		{"apikey.json", "*key*.json", true},
		{"transcript.jsonl", "*mcp*.json", false},
		{"abc", "a?c", true},
		{"ac", "a?c", false},
		{"d", "[a-f]", true},
		{"z", "[a-f]", false},
		{"z", "[!a-f]", true},
		{"[", "[", true},   // unterminated class => literal "["
		{"[]", "[]", true}, // "[]" has no real class close => literal match
	}
	for _, c := range cases {
		if got := fnmatch(c.name, c.pat); got != c.want {
			t.Errorf("fnmatch(%q,%q)=%v want %v", c.name, c.pat, got, c.want)
		}
	}
}

// --- denylist runs before the suffix check ---

func TestDeniedBasenames(t *testing.T) {
	deny := []string{
		".hidden.jsonl", "credentials.json", ".credentials.json", "auth.json",
		".claude.json", "settings.json", "config.json", "mcp.json", "history.jsonl",
		"foo-mcp.json", "settings-x.json", "my.env", "a-token-b.json", "x-secret.json", "z-key.json",
		"CREDENTIALS.JSON", // case-insensitive
	}
	for _, n := range deny {
		if !denied(n) {
			t.Errorf("denied(%q)=false, want true", n)
		}
	}
	allow := []string{
		"01234567-89ab-cdef-0123-456789abcdef.jsonl",
		"rollout-2026.jsonl",
		"transcript.json",
	}
	for _, n := range allow {
		if denied(n) {
			t.Errorf("denied(%q)=true, want false", n)
		}
	}
}

// --- allowlist shapes (M16) ---

func TestAllowlistShapes(t *testing.T) {
	root := "/home/u/.claude/projects"
	if !allowed("claude", root, root+"/01234567-89ab-cdef-0123-456789abcdef.jsonl") {
		t.Error("claude uuid.jsonl should be allowed")
	}
	// agent-<hex>.jsonl subagent transcripts are the majority shape — must pass strict.
	if !allowed("claude", root, root+"/agent-deadbeef00.jsonl") {
		t.Error("claude agent-<hex>.jsonl should be allowed")
	}
	if allowed("claude", root, root+"/notauuid.jsonl") {
		t.Error("claude non-uuid/non-agent .jsonl should be rejected")
	}
	if allowed("claude", root, root+"/agent-.jsonl") {
		t.Error("claude agent- with empty hex should be rejected")
	}
	if allowed("claude", root, root+"/agent-xyz.jsonl") {
		t.Error("claude agent-<non-hex> should be rejected")
	}
	cxroot := "/home/u/.codex/sessions"
	if !allowed("codex", cxroot, cxroot+"/rollout-2026-06.jsonl") {
		t.Error("codex rollout-*.jsonl should be allowed")
	}
	if allowed("codex", cxroot, cxroot+"/other.jsonl") {
		t.Error("codex non-rollout should be rejected")
	}
	gmroot := "/home/u/.gemini/tmp"
	if !allowed("gemini", gmroot, gmroot+"/sess1/log.json") {
		t.Error("gemini *.json under tmp/<id>/ should be allowed")
	}
	if allowed("gemini", gmroot, gmroot+"/top.json") {
		t.Error("gemini *.json directly in tmp should be rejected (needs an id subdir)")
	}
}

// --- PEM content sniff (M16) ---

func TestLooksLikePEM(t *testing.T) {
	if !looksLikePEM([]byte("-----BEGIN PRIVATE KEY-----\n...")) {
		t.Error("PEM header should be detected")
	}
	if !looksLikePEM([]byte("\n  -----BEGIN RSA PRIVATE KEY-----")) {
		t.Error("leading-whitespace PEM should be detected")
	}
	// (M4) A leading UTF-8 BOM must NOT smuggle a PEM key past the sniff.
	if !looksLikePEM([]byte("\xEF\xBB\xBF-----BEGIN PRIVATE KEY-----\n")) {
		t.Error("BOM-prefixed PEM should be detected")
	}
	// (M4) Other leading control bytes (vertical tab, form feed, NUL) must be trimmed too.
	if !looksLikePEM([]byte("\xEF\xBB\xBF\v\f\x00 -----BEGIN EC PRIVATE KEY-----")) {
		t.Error("BOM + control-byte-prefixed PEM should be detected")
	}
	if looksLikePEM([]byte(`{"type":"user","content":"hi"}`)) {
		t.Error("JSON transcript should not look like PEM")
	}
	// A BOM-led real transcript is still not PEM.
	if looksLikePEM([]byte("\xEF\xBB\xBF{\"type\":\"user\"}")) {
		t.Error("BOM-led JSON transcript should not look like PEM")
	}
}

// --- NonProviderRoots startup advisory ---

func TestNonProviderRoots(t *testing.T) {
	roots := []string{
		"/home/u/.claude/projects", // under a provider home -> OK
		"/home/u/.codex/sessions",  // OK
		"/home/u/.gemini/tmp",      // OK
		"/home/u/.gemini",          // the provider home itself -> OK
		"/tmp/random",              // NOT under a provider home -> flagged
		"/home/u/Documents",        // flagged
	}
	bad := NonProviderRoots(roots)
	want := map[string]bool{"/tmp/random": true, "/home/u/Documents": true}
	if len(bad) != len(want) {
		t.Fatalf("NonProviderRoots = %v, want exactly %v", bad, want)
	}
	for _, b := range bad {
		if !want[b] {
			t.Errorf("unexpected non-provider root %q", b)
		}
	}
}

// --- URLOK https-only (M14) ---

func TestURLOK(t *testing.T) {
	cases := []struct {
		url       string
		allowHTTP bool
		want      bool
	}{
		{"https://recall.example.com", false, true},
		{"http://recall.example.com", false, false},
		{"http://recall.example.com", true, false}, // http allowed only for loopback
		{"http://localhost:8080", true, true},
		{"http://127.0.0.1:8080", true, true},
		{"http://localhost:8080", false, false},
		{"ftp://x", true, false},
		{"https://", false, false}, // no host
	}
	for _, c := range cases {
		if got := URLOK(c.url, c.allowHTTP); got != c.want {
			t.Errorf("URLOK(%q,%v)=%v want %v", c.url, c.allowHTTP, got, c.want)
		}
	}
}

// --- size-race guard + distinct length headers (M15) ---

func TestReadCappedSizeCapAndGuard(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.jsonl")
	if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cap below the file size: drop.
	if _, ok := readCapped(p, 5); ok {
		t.Error("file over cap must be dropped")
	}
	// Cap at exactly the size: keep.
	rr, ok := readCapped(p, 10)
	if !ok || len(rr.data) != 10 || rr.size != 10 {
		t.Fatalf("readCapped at cap: ok=%v len=%d size=%d", ok, len(rr.data), rr.size)
	}
}

// --- containment (M15) ---

func TestContainedIn(t *testing.T) {
	root := "/home/u/.claude/projects"
	if !containedIn(root, root+"/a/b.jsonl") {
		t.Error("a file under root should be contained")
	}
	if containedIn(root, "/home/u/.claude/elsewhere.jsonl") {
		t.Error("a sibling outside root must not be contained")
	}
	if containedIn(root, "/etc/passwd") {
		t.Error("an unrelated path must not be contained")
	}
}

// --- (M18) egress gate: a disabled axis makes NO request ---

func TestDisabledAxisMakesNoRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(201)
	}))
	defer srv.Close()

	// Missing token => not Enabled.
	cfg := Config{URL: srv.URL, SourceID: "src", Token: saauth.Provider{}}
	if cfg.Enabled() {
		t.Fatal("axis with no token must not be Enabled")
	}
	r := NewRunner(cfg, nil)
	if r.client != nil {
		t.Fatal("disabled axis must NOT construct an http client")
	}
	st := NewState()
	stats := r.ScanOnce(context.Background(), st)
	if stats != (ScanStats{}) {
		t.Fatalf("disabled axis must do nothing, got %+v", stats)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("disabled axis dialed the server %d times, want 0", got)
	}
}

func TestEnabledRequiresAllThree(t *testing.T) {
	tok := saauth.EnvProvider("t")
	cases := []struct {
		cfg  Config
		want bool
	}{
		{Config{URL: "https://x", SourceID: "s", Token: tok}, true},
		{Config{URL: "", SourceID: "s", Token: tok}, false},
		{Config{URL: "https://x", SourceID: "", Token: tok}, false},
		{Config{URL: "https://x", SourceID: "s", Token: saauth.Provider{}}, false},
	}
	for i, c := range cases {
		if got := c.cfg.Enabled(); got != c.want {
			t.Errorf("case %d Enabled()=%v want %v", i, got, c.want)
		}
	}
}

// --- end-to-end scan + post against an httptest server ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setupClaudeRoot builds a fake ~/.claude/projects tree with several transcript-shaped
// files (a uuid, an agent-<hex> subagent transcript, and a weird-named one) plus files
// that MUST be filtered out by the always-on guards (deny-list / PEM / dotfile), and
// returns the resolved root.
func setupClaudeRoot(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".claude", "projects")
	// Valid claude transcript (uuid.jsonl).
	writeFile(t, filepath.Join(root, "proj", "01234567-89ab-cdef-0123-456789abcdef.jsonl"), `{"type":"user","text":"hello"}`+"\n")
	// Subagent transcript (agent-<hex>.jsonl) — the dominant real shape.
	writeFile(t, filepath.Join(root, "proj", "agent-deadbeef00.jsonl"), `{"type":"user","text":"sub"}`+"\n")
	// A weird-named transcript: dropped by the strict allowlist but FORWARDED by default
	// (proves there is no silent allowlist when strict is off).
	writeFile(t, filepath.Join(root, "proj", "weird-name.jsonl"), `{"x":1}`)
	// Denylisted config files that share the extension (dropped in BOTH modes).
	writeFile(t, filepath.Join(root, "proj", "settings.json"), `{"secret":"x"}`)
	writeFile(t, filepath.Join(root, "proj", "foo-mcp.json"), `{"servers":{}}`)
	writeFile(t, filepath.Join(root, "proj", "history.jsonl"), `{"h":1}`)
	// PEM key that sneaked a .json name (dropped in BOTH modes by the content sniff).
	writeFile(t, filepath.Join(root, "proj", "leaked.json"), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	// Dotfile.
	writeFile(t, filepath.Join(root, "proj", ".hidden.jsonl"), `{"x":1}`)
	return root
}

// setupSingleTranscriptRoot builds a claude root with exactly ONE forwardable transcript
// (a uuid.jsonl) plus only always-dropped noise (deny-list / PEM / dotfile). It is for the
// upload/state-mechanics e2e tests that assert a single send regardless of allowlist mode.
func setupSingleTranscriptRoot(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, ".claude", "projects")
	writeFile(t, filepath.Join(root, "proj", "01234567-89ab-cdef-0123-456789abcdef.jsonl"), `{"type":"user","text":"hello"}`+"\n")
	writeFile(t, filepath.Join(root, "proj", "settings.json"), `{"secret":"x"}`)
	writeFile(t, filepath.Join(root, "proj", "foo-mcp.json"), `{"servers":{}}`)
	writeFile(t, filepath.Join(root, "proj", "history.jsonl"), `{"h":1}`)
	writeFile(t, filepath.Join(root, "proj", "leaked.json"), "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	writeFile(t, filepath.Join(root, "proj", ".hidden.jsonl"), `{"x":1}`)
	return root
}

func candNames(cands []candidate) []string {
	var names []string
	for _, c := range cands {
		names = append(names, baseName(c.path))
	}
	return names
}

func hasCand(cands []candidate, base string) bool {
	for _, n := range candNames(cands) {
		if n == base {
			return true
		}
	}
	return false
}

// By DEFAULT (strict OFF = faithful to the live Python forwarder) every transcript-shaped
// .jsonl is forwarded: the uuid, the agent-<hex> subagent transcript, AND the weird-named
// one. Only the always-on guards (deny-list, PEM sniff, dotfile) filter anything.
func TestScanDefaultForwardsAllTranscriptShapes(t *testing.T) {
	root := setupClaudeRoot(t)
	cfg := Config{Roots: []string{root}, MaxBytes: defaultMaxBytes}
	cands := scanRoots(cfg, nil)

	for _, want := range []string{
		"01234567-89ab-cdef-0123-456789abcdef.jsonl",
		"agent-deadbeef00.jsonl",
		"weird-name.jsonl",
	} {
		if !hasCand(cands, want) {
			t.Errorf("default scan must forward %q (faithful = no allowlist); got %v", want, candNames(cands))
		}
	}
	// Always-on guards still drop these in default mode.
	for _, dropped := range []string{"settings.json", "foo-mcp.json", "history.jsonl", "leaked.json", ".hidden.jsonl"} {
		if hasCand(cands, dropped) {
			t.Errorf("default scan must still drop %q (deny/PEM/dotfile guard); got %v", dropped, candNames(cands))
		}
	}
	for _, c := range cands {
		if c.provider != "claude" {
			t.Errorf("provider = %q, want claude", c.provider)
		}
	}
}

// With StrictAllowlist ON the positive per-provider shape gate applies: <uuid>.jsonl,
// agent-<hex>.jsonl, and codex rollout-*.jsonl all pass but the weird-named one is dropped
// — and the drop is logged (not silent).
func TestScanStrictAllowlistDropsNonShapedAndLogs(t *testing.T) {
	root := setupClaudeRoot(t)
	// A sibling codex root with a valid rollout-*.jsonl transcript.
	codexHome := t.TempDir()
	codexRoot := filepath.Join(codexHome, ".codex", "sessions")
	writeFile(t, filepath.Join(codexRoot, "rollout-2026-06.jsonl"), `{"type":"user"}`+"\n")

	var logs []string
	log := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	cfg := Config{Roots: []string{root, codexRoot}, MaxBytes: defaultMaxBytes, StrictAllowlist: true}
	cands := scanRoots(cfg, log)

	for _, want := range []string{
		"01234567-89ab-cdef-0123-456789abcdef.jsonl",
		"agent-deadbeef00.jsonl",
		"rollout-2026-06.jsonl",
	} {
		if !hasCand(cands, want) {
			t.Errorf("strict scan must keep %q; got %v", want, candNames(cands))
		}
	}
	if hasCand(cands, "weird-name.jsonl") {
		t.Errorf("strict scan must drop weird-name.jsonl; got %v", candNames(cands))
	}
	// Always-on guards still drop these in strict mode too.
	for _, dropped := range []string{"settings.json", "foo-mcp.json", "history.jsonl", "leaked.json", ".hidden.jsonl"} {
		if hasCand(cands, dropped) {
			t.Errorf("strict scan must still drop %q; got %v", dropped, candNames(cands))
		}
	}
	// The drop must be surfaced (not silent).
	var logged bool
	for _, l := range logs {
		if strings.Contains(l, "strict allowlist dropped") {
			logged = true
		}
	}
	if !logged {
		t.Errorf("strict allowlist drop must be logged; logs=%v", logs)
	}
}

// The deny-list + PEM content sniff drop credentials.json / -----BEGIN files in BOTH the
// default and strict modes (requirement 4d).
func TestDenyAndPEMDropInBothModes(t *testing.T) {
	for _, strict := range []bool{false, true} {
		home := t.TempDir()
		root := filepath.Join(home, ".claude", "projects")
		writeFile(t, filepath.Join(root, "proj", "01234567-89ab-cdef-0123-456789abcdef.jsonl"), `{"ok":1}`)
		writeFile(t, filepath.Join(root, "proj", "credentials.json"), `{"token":"sekret"}`)
		writeFile(t, filepath.Join(root, "proj", "pem.json"), "-----BEGIN PRIVATE KEY-----\nAAAA\n")
		cfg := Config{Roots: []string{root}, MaxBytes: defaultMaxBytes, StrictAllowlist: strict}
		cands := scanRoots(cfg, nil)
		if hasCand(cands, "credentials.json") {
			t.Errorf("strict=%v: deny-list must drop credentials.json; got %v", strict, candNames(cands))
		}
		if hasCand(cands, "pem.json") {
			t.Errorf("strict=%v: PEM sniff must drop -----BEGIN content; got %v", strict, candNames(cands))
		}
		if !hasCand(cands, "01234567-89ab-cdef-0123-456789abcdef.jsonl") {
			t.Errorf("strict=%v: the real transcript must survive; got %v", strict, candNames(cands))
		}
	}
}

func TestSymlinkedSubdirEscapeBlocked(t *testing.T) {
	root := setupClaudeRoot(t)
	// Create a secret outside the root and a symlinked subdir pointing at its parent.
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "01234567-89ab-cdef-0123-456789abcdee.jsonl"), `{"leak":1}`)
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	cfg := Config{Roots: []string{root}, MaxBytes: defaultMaxBytes}
	for _, c := range scanRoots(cfg, nil) {
		if strings.Contains(c.path, outside) {
			t.Fatalf("symlinked subdir escaped containment: %s", c.path)
		}
	}
}

func runWithServer(t *testing.T, root string, handler http.HandlerFunc) (ScanStats, *State, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{
		URL:       srv.URL,
		SourceID:  "src-1",
		Token:     saauth.EnvProvider("bearer-xyz"),
		Roots:     []string{root},
		MaxBytes:  defaultMaxBytes,
		AllowHTTP: true,
	}
	if !cfg.Enabled() {
		t.Fatal("test cfg should be Enabled")
	}
	r := NewRunner(cfg, nil)
	st := NewState()
	stats := r.ScanOnce(context.Background(), st)
	return stats, st, &hits
}

func TestEndToEndUploadSendsCorrectHeaders(t *testing.T) {
	root := setupSingleTranscriptRoot(t)
	var gotHeaders http.Header
	stats, st, hits := runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		// Server requires X-Cass-Observation-Id (422 if absent) — assert it's present.
		body := make([]byte, 1<<16)
		n, _ := r.Body.Read(body)
		_ = n
		w.WriteHeader(201)
	})
	if *hits != 1 {
		t.Fatalf("server hit %d times, want 1 (only the transcript)", *hits)
	}
	if stats.Sent != 1 {
		t.Fatalf("stats=%+v, want Sent=1", stats)
	}
	for _, h := range []string{
		"X-Cass-Source-Id", "X-Cass-Provider", "X-Cass-Source-Path", "X-Cass-Provider-Session-Id",
		"X-Cass-Content-Length", "X-Cass-Observation-Id", "X-Cass-Blake3", "X-Cass-Sha256",
		"X-Cass-Source-Mtime-Ns", "X-Cass-Source-Size",
	} {
		if gotHeaders.Get(h) == "" {
			t.Errorf("missing required header %s", h)
		}
	}
	if gotHeaders.Get("Authorization") != "Bearer bearer-xyz" {
		t.Errorf("Authorization = %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("Content-Type = %q", gotHeaders.Get("Content-Type"))
	}
	// Observation-Id must equal the Blake3 hex.
	if gotHeaders.Get("X-Cass-Observation-Id") != gotHeaders.Get("X-Cass-Blake3") {
		t.Errorf("Observation-Id %q != Blake3 %q", gotHeaders.Get("X-Cass-Observation-Id"), gotHeaders.Get("X-Cass-Blake3"))
	}
	// Source-Path must be provider-relative (no abs path / home leak).
	if sp := gotHeaders.Get("X-Cass-Source-Path"); !strings.HasPrefix(sp, "claude/") || strings.Contains(sp, root) {
		t.Errorf("Source-Path leaks abs path: %q", sp)
	}
	// State recorded the send.
	for path, fs := range st.files {
		if fs.Status != StatusSent {
			t.Errorf("%s status=%q want sent", path, fs.Status)
		}
	}
}

func TestTerminalCodeMarkedRejectedNoRetry(t *testing.T) {
	root := setupSingleTranscriptRoot(t)
	// First pass: server returns 422 (terminal) -> mark rejected.
	stats, st, hits := runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
	})
	if *hits != 1 {
		t.Fatalf("first pass hits=%d want 1", *hits)
	}
	if stats.Sent != 0 {
		t.Fatalf("422 must not count as sent: %+v", stats)
	}
	var rejected int
	for _, fs := range st.files {
		if fs.Status == StatusRejected && fs.Code == 422 {
			rejected++
		}
	}
	if rejected != 1 {
		t.Fatalf("expected 1 rejected record, got %d", rejected)
	}

	// Touch the file's mtime so the cheap metadata short-circuit does NOT fire — this
	// forces the second pass through the blake3 comparison, which is where a terminally
	// rejected file (same content) is recognized and counted as skipped, mirroring the
	// Python _scan_once. The HTTP request must still never be made.
	var transcript string
	for p := range st.files {
		transcript = p
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(transcript, future, future); err != nil {
		t.Fatal(err)
	}

	// Second pass against a server that would 201: the already-rejected content (same
	// blake3) must NOT be re-sent even though its mtime changed.
	var hits2 int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits2, 1)
		w.WriteHeader(201)
	}))
	defer srv2.Close()
	cfg := Config{URL: srv2.URL, SourceID: "src-1", Token: saauth.EnvProvider("bearer-xyz"), Roots: []string{root}, MaxBytes: defaultMaxBytes, AllowHTTP: true}
	r2 := NewRunner(cfg, nil)
	stats2 := r2.ScanOnce(context.Background(), st)
	if atomic.LoadInt32(&hits2) != 0 {
		t.Fatalf("a terminally-rejected file was retried %d times, want 0", hits2)
	}
	if stats2.Skipped != 1 {
		t.Fatalf("rejected file should count as skipped, got %+v", stats2)
	}
}

func TestUnchangedContentNotResent(t *testing.T) {
	root := setupSingleTranscriptRoot(t)
	stats, st, _ := runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	if stats.Sent != 1 {
		t.Fatalf("first pass Sent=%d want 1", stats.Sent)
	}
	// Second pass: same state, same content => no send.
	var hits2 int32
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits2, 1)
		w.WriteHeader(201)
	}))
	defer srv2.Close()
	cfg := Config{URL: srv2.URL, SourceID: "src-1", Token: saauth.EnvProvider("bearer-xyz"), Roots: []string{root}, MaxBytes: defaultMaxBytes, AllowHTTP: true}
	r2 := NewRunner(cfg, nil)
	stats2 := r2.ScanOnce(context.Background(), st)
	if atomic.LoadInt32(&hits2) != 0 || stats2.Sent != 0 {
		t.Fatalf("unchanged content re-sent: hits=%d stats=%+v", hits2, stats2)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "state.json")
	st := NewState()
	st.Put("/a/b.jsonl", FileState{Status: StatusSent, Blake3: "abc", MtimeNS: 5, Size: 9})
	st.Put("/a/c.jsonl", FileState{Status: StatusRejected, Blake3: "def", Code: 422})
	if err := SaveState(p, st); err != nil {
		t.Fatal(err)
	}
	// Saved file must be owner-only.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v, want 0600", fi.Mode().Perm())
	}
	loaded, err := LoadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("loaded %d records, want 2", loaded.Len())
	}
	if fs, _ := loaded.Get("/a/c.jsonl"); fs.Status != StatusRejected || fs.Code != 422 {
		t.Errorf("rejected record lost: %+v", fs)
	}
}
