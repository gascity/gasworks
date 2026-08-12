package contentguard

import "testing"

// These tests are carried over from internal/recallaxis (recallaxis_test.go), the source of
// truth for the guard semantics, so the re-implementation is provably identical rather than a
// paraphrase. The recall forwarder's gemini allowlist shape is not carried (gemini is not a
// content-lane provider); the gemini cases are replaced by a fail-closed default-deny check.

// --- fnmatch equivalence (verbatim from recallaxis) ---

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

// --- denylist runs before the shape check (verbatim from recallaxis) ---

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

// --- allowlist shapes (claude + codex carried verbatim; gemini replaced by default-deny) ---

func TestAllowlistShapes(t *testing.T) {
	if !allowed("claude", "01234567-89ab-cdef-0123-456789abcdef.jsonl") {
		t.Error("claude uuid.jsonl should be allowed")
	}
	// agent-<hex>.jsonl subagent transcripts are the majority shape — must pass.
	if !allowed("claude", "agent-deadbeef00.jsonl") {
		t.Error("claude agent-<hex>.jsonl should be allowed")
	}
	if allowed("claude", "notauuid.jsonl") {
		t.Error("claude non-uuid/non-agent .jsonl should be rejected")
	}
	if allowed("claude", "agent-.jsonl") {
		t.Error("claude agent- with empty hex should be rejected")
	}
	if allowed("claude", "agent-xyz.jsonl") {
		t.Error("claude agent-<non-hex> should be rejected")
	}
	if !allowed("codex", "rollout-2026-06.jsonl") {
		t.Error("codex rollout-*.jsonl should be allowed")
	}
	if allowed("codex", "other.jsonl") {
		t.Error("codex non-rollout should be rejected")
	}
	// Non-content-lane providers are refused by default (fail-closed). gemini content never
	// reaches this lane, so its recallaxis shape is intentionally not carried.
	if allowed("gemini", "log.json") {
		t.Error("gemini is not a content-lane provider and must be refused")
	}
	if allowed("", "01234567-89ab-cdef-0123-456789abcdef.jsonl") {
		t.Error("empty provider must be refused")
	}
}

// --- PEM content sniff (verbatim from recallaxis) ---

func TestLooksLikePEM(t *testing.T) {
	if !looksLikePEM([]byte("-----BEGIN PRIVATE KEY-----\n...")) {
		t.Error("PEM header should be detected")
	}
	if !looksLikePEM([]byte("\n  -----BEGIN RSA PRIVATE KEY-----")) {
		t.Error("leading-whitespace PEM should be detected")
	}
	// A leading UTF-8 BOM must NOT smuggle a PEM key past the sniff.
	if !looksLikePEM([]byte("\xEF\xBB\xBF-----BEGIN PRIVATE KEY-----\n")) {
		t.Error("BOM-prefixed PEM should be detected")
	}
	// Other leading control bytes (vertical tab, form feed, NUL) must be trimmed too.
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

// --- public API: ScreenName ---

func TestScreenName(t *testing.T) {
	cases := []struct {
		provider, path string
		wantReason     Reason
		wantRefused    bool
	}{
		// Denylist wins first, regardless of provider/shape.
		{"claude", "/root/proj/credentials.json", ReasonDenylistedName, true},
		{"codex", "/root/sessions/settings.json", ReasonDenylistedName, true},
		{"claude", "/root/proj/foo-mcp.json", ReasonDenylistedName, true},
		{"claude", "/root/proj/x.env", ReasonDenylistedName, true},         // deny-glob *.env
		{"claude", "/root/proj/.hidden.jsonl", ReasonDenylistedName, true}, // dotfile
		{"codex", "/root/sessions/history.jsonl", ReasonDenylistedName, true},
		// Passes denylist but wrong shape → not-allowlisted.
		{"claude", "/root/proj/notes.jsonl", ReasonNotAllowlisted, true},
		{"codex", "/root/sessions/notes.jsonl", ReasonNotAllowlisted, true},
		{"gemini", "/root/tmp/id/log.json", ReasonNotAllowlisted, true}, // off-lane provider
		// Real transcripts pass both filename guards.
		{"claude", "/root/proj/01234567-89ab-cdef-0123-456789abcdef.jsonl", "", false},
		{"claude", "/root/proj/agent-deadbeef00.jsonl", "", false},
		{"codex", "/root/sessions/rollout-2026-06.jsonl", "", false},
	}
	for _, c := range cases {
		reason, refused := ScreenName(c.provider, c.path)
		if refused != c.wantRefused || reason != c.wantReason {
			t.Errorf("ScreenName(%q,%q) = (%q,%v), want (%q,%v)",
				c.provider, c.path, reason, refused, c.wantReason, c.wantRefused)
		}
	}
}

// --- public API: ScreenContent ---

func TestScreenContent(t *testing.T) {
	if reason, refused := ScreenContent([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n")); !refused || reason != ReasonPEMContent {
		t.Errorf("PEM body: got (%q,%v), want (%q,true)", reason, refused, ReasonPEMContent)
	}
	if _, refused := ScreenContent([]byte(`{"type":"user","text":"hello"}` + "\n")); refused {
		t.Error("a JSON transcript body must pass ScreenContent")
	}
	if _, refused := ScreenContent(nil); refused {
		t.Error("empty content must pass ScreenContent")
	}
	// Only the first SniffBytes are inspected: a PEM marker pushed past the window is not
	// caught by the head sniff (matches the recall forwarder's fixed 64-byte window).
	pad := make([]byte, SniffBytes)
	for i := range pad {
		pad[i] = ' '
	}
	if _, refused := ScreenContent(append(pad, []byte("-----BEGIN KEY-----")...)); refused {
		t.Error("a PEM marker beyond the sniff window must not be caught by the head sniff")
	}
}
