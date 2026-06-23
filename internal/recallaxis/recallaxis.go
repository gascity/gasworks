// Package recallaxis is the recall forwarder axis: it scans the NARROW per-provider
// coding-agent transcript directories for new/changed transcript files and POSTs each
// as a snapshot to recall's ingest API. It is a faithful Go port of the gasworks pack's
// recall_forwarder.py with the additional hardening called for in Phase 3.
//
// (M17) RAW-TRANSCRIPT EGRESS — NO CONTENT REDACTION BY DESIGN.
// Recall ships the FULL transcript bytes. The transcript IS the payload, and it may
// contain anything a user pasted into a coding-agent session — secrets, code, PII.
// There is intentionally NO content redaction: redacting the transcript would defeat
// recall's purpose (a faithful corpus of the session). This is an operator-acknowledged
// raw-egress channel, gated hard so it only ever runs when explicitly opted in:
//
//   - SAFE BY DEFAULT: the axis is disabled (Enabled()==false) and never constructs an
//     http client or dials unless a URL AND a token source AND a source_id are all set
//     (M18 egress gate);
//   - SCOPED BY DEFAULT: only files under the narrow per-provider transcript subdirs are
//     considered — never the whole agent home, which holds credentials with the same
//     extensions — and a denylist + allowlist + a PEM content-sniff drop config/secret
//     files up front (M16);
//   - CONTAINED: symlinks are never followed and every file must resolve inside its root
//     (M15), with a size-race guard so a file that grows past the cap mid-read is dropped;
//   - TLS-ONLY: the endpoint must be https (or an explicit localhost dev opt-in), all
//     redirects are refused, and the bearer never crosses a non-TLS / cross-host hop (M14);
//   - NO STORM: a permanently-rejected snapshot is not re-sent until its content changes;
//   - it only reads + hashes + uploads transcript content, never executes it, and never
//     logs the bearer credential.
package recallaxis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/blake3"

	"github.com/gascity/gasworks/internal/saauth"
)

// providerDirs maps a known agent-home directory name to its provider label. A
// transcript is only forwarded if it lives under one of these (never an invented
// "generic" provider).
var providerDirs = map[string]string{
	".claude": "claude",
	".codex":  "codex",
	".gemini": "gemini",
}

var transcriptSuffixes = map[string]bool{".jsonl": true, ".json": true}

// denyBasenames drops credential/config files BEFORE the suffix check (exact,
// case-insensitive basename match — see denied). Mirrors the Python set; includes
// history.jsonl, which has a transcript extension but is never a transcript.
var denyBasenames = map[string]bool{
	"credentials.json":          true,
	".credentials.json":         true,
	"auth.json":                 true,
	".claude.json":              true,
	"google_accounts.json":      true,
	"settings.json":             true,
	"config.json":               true,
	"mcp.json":                  true,
	"mcp_config.json":           true,
	"mcp-needs-auth-cache.json": true,
	"stats-cache.json":          true,
	"history.jsonl":             true,
}

// denyGlobs drop config/secret files by fnmatch pattern (also BEFORE the suffix check).
// These are matched with fnmatch semantics, not filepath.Match — see fnmatchEqual.
var denyGlobs = []string{"*mcp*.json", "settings*.json", "*.env", "*token*.json", "*secret*.json", "*key*.json"}

// terminalCodes are server terminal/client-error responses: the same content is never
// re-sent on any of these (no retry storm). Mirrors the Python TERMINAL_CODES.
var terminalCodes = map[int]bool{400: true, 401: true, 403: true, 404: true, 409: true, 413: true, 415: true, 422: true}

const (
	defaultInterval = 60 * time.Second
	minInterval     = 5 * time.Second
	// defaultMaxBytes mirrors the Python 100 MiB cap.
	defaultMaxBytes int64 = 100 * 1024 * 1024
)

// Config is the resolved recall-axis configuration. Build it with ConfigFromEnv.
type Config struct {
	URL       string          // destination base (trailing slash trimmed); "" => idle
	SourceID  string          // X-Cass-Source-Id; "" => idle
	Token     saauth.Provider // bearer source (file or env); unconfigured => idle
	Roots     []string        // transcript roots to scan
	StatePath string          // dedup state file
	Interval  time.Duration   // daemon scan interval
	MaxBytes  int64           // per-file byte cap
	AllowHTTP bool            // localhost http opt-in
	// StrictAllowlist OPTS IN to the positive per-provider allowlist gate (M16). It is
	// DEFAULT OFF to stay faithful to the live Python forwarder, which has no allowlist —
	// turning it on would SILENTLY narrow coverage (e.g. drop agent-<hex>.jsonl subagent
	// transcripts). The deny-list, suffix check, containment, and PEM sniff are always on.
	// Set via RECALL_FORWARDER_STRICT_ALLOWLIST=1 to enable it.
	StrictAllowlist bool
}

// Enabled is the (M18) egress gate: the axis may construct an http client and dial
// ONLY when a destination URL AND a token source AND a source_id are all configured.
// When this is false the axis must never build a client or send a request.
func (c Config) Enabled() bool {
	return c.URL != "" && c.SourceID != "" && c.Token.Configured()
}

// defaultRoots returns the narrow per-provider transcript subdirs under HOME. NOT the
// agent home: ~/.claude, ~/.codex, ~/.gemini hold .credentials.json / auth.json /
// *mcp*.json etc. with the same extensions as transcripts.
func defaultRoots(home string) []string {
	return []string{
		filepath.Join(home, ".claude", "projects"),
		filepath.Join(home, ".codex", "sessions"),
		filepath.Join(home, ".gemini", "tmp"),
	}
}

// ConfigFromEnv builds a Config from RECALL_FORWARDER_* env vars, mirroring the
// Python _config(). The token Provider prefers RECALL_FORWARDER_TOKEN_FILE (a
// hardened, rotation-ready file) and falls back to RECALL_FORWARDER_TOKEN, which is
// popped from the environment and flagged dev-only (visible in /proc/<pid>/environ).
// It returns a non-fatal warning string (e.g. for the env-token case) for the caller
// to log, never the token value.
func ConfigFromEnv() (Config, string) {
	home, _ := os.UserHomeDir()
	var warn string

	roots := defaultRoots(home)
	if rv := strings.TrimSpace(os.Getenv("RECALL_FORWARDER_ROOTS")); rv != "" {
		roots = nil
		for _, r := range strings.Split(rv, string(os.PathListSeparator)) {
			if r != "" {
				roots = append(roots, r)
			}
		}
	}

	state := strings.TrimSpace(os.Getenv("RECALL_FORWARDER_STATE"))
	if state == "" {
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			stateHome = filepath.Join(home, ".local", "state")
		}
		state = filepath.Join(stateHome, "recall-forwarder", "state.json")
	}

	tokenProvider := func() saauth.Provider {
		if fp := strings.TrimSpace(os.Getenv("RECALL_FORWARDER_TOKEN_FILE")); fp != "" {
			return saauth.FileProvider(fp)
		}
		if tok, ok := saauth.TokenFromEnv("RECALL_FORWARDER_TOKEN"); ok {
			warn = saauth.EnvWarning
			return saauth.EnvProvider(tok)
		}
		return saauth.Provider{}
	}()

	return Config{
		URL:             strings.TrimRight(strings.TrimSpace(os.Getenv("RECALL_FORWARDER_URL")), "/"),
		SourceID:        strings.TrimSpace(os.Getenv("RECALL_FORWARDER_SOURCE_ID")),
		Token:           tokenProvider,
		Roots:           roots,
		StatePath:       state,
		Interval:        envInterval("RECALL_FORWARDER_INTERVAL", defaultInterval),
		MaxBytes:        envBytes("RECALL_FORWARDER_MAX_BYTES", defaultMaxBytes),
		AllowHTTP:       os.Getenv("RECALL_FORWARDER_ALLOW_HTTP") == "1",
		StrictAllowlist: envTrue("RECALL_FORWARDER_STRICT_ALLOWLIST"),
	}, warn
}

// NonProviderRoots returns the configured roots that do NOT live under a known per-provider
// agent home (.claude/.codex/.gemini). A custom RECALL_FORWARDER_ROOTS entry pointing
// somewhere else bypasses the narrow per-provider scoping guarantee — scanRoots will still
// refuse to attach a provider to files it finds there (providerFor returns ""), so nothing
// is forwarded, but the operator should be told their override is inert/unscoped. The caller
// logs these as a startup warning. A root that resolves under a provider dir is fine.
func NonProviderRoots(roots []string) []string {
	var bad []string
	for _, r := range roots {
		if !rootUnderProviderHome(r) {
			bad = append(bad, r)
		}
	}
	return bad
}

// rootUnderProviderHome reports whether path is, or lives under, a known provider agent
// home (.claude/.codex/.gemini). It walks the cleaned path's ancestors; symlinks are not
// resolved here (a best-effort startup advisory, not a security boundary — the real
// containment + provider gate happen per-file in scanRoots).
func rootUnderProviderHome(path string) bool {
	dir := filepath.Clean(path)
	for {
		if _, ok := providerDirs[filepath.Base(dir)]; ok {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// envTrue reports whether an env var opts in: "1" or "true" (case-insensitive). Empty
// or any other value is false (the safe/faithful default).
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true":
		return true
	default:
		return false
	}
}

func envInterval(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	d := time.Duration(n) * time.Second
	if d < minInterval {
		return minInterval
	}
	return d
}

func envBytes(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return def
	}
	return n
}

// URLOK enforces the (M14) https-only rule: https with a host is always allowed; plain
// http is allowed ONLY with AllowHTTP and a loopback host. Mirrors the Python _url_ok.
func URLOK(rawURL string, allowHTTP bool) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && u.Host != "" {
		return true
	}
	return u.Scheme == "http" && allowHTTP && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}

// blake3Hex returns the lowercase blake3 hex digest of data.
func blake3Hex(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sha256Hex returns the lowercase sha256 hex digest of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// pemBOM is the UTF-8 byte-order mark. A file may legitimately lead with it, and an
// attacker could prepend it to slip a PEM key past a naive "-----BEGIN" prefix check, so we
// strip it before sniffing.
var pemBOM = []byte{0xEF, 0xBB, 0xBF}

// looksLikePEM reports whether the leading bytes look like a PEM/PKCS key block
// (M16 content sniff). A transcript never starts with "-----BEGIN". It first strips a
// leading UTF-8 BOM, then trims a WIDER set of leading whitespace/control bytes (space,
// tab, CR, LF, vertical tab, form feed, NUL) so a "\xEF\xBB\xBF" / "\v" / "\f" / NUL before
// the marker can't smuggle a key file through.
func looksLikePEM(head []byte) bool {
	head = bytes.TrimPrefix(head, pemBOM)
	return bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n\v\f\x00"), []byte("-----BEGIN"))
}
