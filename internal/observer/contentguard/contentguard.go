// Package contentguard is the observer content lane's always-on refusal gate. It re-implements
// the recall forwarder's M16 content guards — a secrets/config filename denylist, a strict
// per-provider transcript-shape allowlist, and a PEM key-block content sniff — so a
// credential, config, or key file can never be shipped through the whole-transcript content
// upload side channel, even if it slips past the watcher's upstream filters.
//
// WHY A RE-IMPLEMENTATION, NOT AN IMPORT. The semantics here are lifted verbatim from
// internal/recallaxis (the source of truth), but the observer endpoint is FORBIDDEN from
// importing that package: it is a banned legacy telemetry axis in the endpoint's dependency
// allow-list (cmd/gasworks-observer/boundary_test.go). So the deny-list, the hand-rolled
// Python-fnmatch glob engine (fnmatch.go), the allowlist shapes, and the PEM sniff are
// carried over as an observer-closure package, with recallaxis's tests ported alongside.
//
// UNCONDITIONAL ON THE CONTENT LANE. recallaxis applies its positive allowlist only in an
// opt-in strict mode (default OFF, to stay faithful to the live Python forwarder). The
// content lane is the opposite posture: bd-63vj1 requires ALL client guards ON, so the
// allowlist here is always enforced. The lane already runs, upstream of this package, a
// provider allow-set ({claude,codex}), a consent forward-only seal, a .jsonl suffix filter,
// and root containment; this package is the defense-in-depth refusal that a secret file
// authored under an approved root with a transcript extension is still never uploaded.
//
// The guards are pure functions over a filename + a small content head — no I/O, no state —
// so the daemon can apply the filename guards before it ever reads a file and the content
// sniff on bytes it already holds, and refuse before any request is constructed. Refusals
// are surfaced (counted + logged) by the caller, never silent.
package contentguard

import (
	"bytes"
	"path/filepath"
	"strings"
)

// Reason names why a transcript was refused. It is a stable, log- and metric-safe label.
type Reason string

const (
	// ReasonDenylistedName is a basename on the secrets/config denylist (a dotfile, an exact
	// credential/config basename, or a deny-glob match) — refused before its bytes are read.
	ReasonDenylistedName Reason = "denylisted-name"
	// ReasonNotAllowlisted is a basename that does not match its provider's transcript shape
	// (claude <uuid>.jsonl / agent-<hex>.jsonl, codex rollout-*.jsonl) — refused before read.
	ReasonNotAllowlisted Reason = "not-allowlisted"
	// ReasonPEMContent is content whose leading bytes look like a PEM/PKCS key block —
	// refused after the read, before any upload request is constructed.
	ReasonPEMContent Reason = "pem-content"
)

// SniffBytes is how many leading bytes the PEM content sniff inspects. It mirrors the recall
// forwarder's 64-byte sniff window exactly, so a key block is detected identically here.
const SniffBytes = 64

// denyBasenames drops credential/config files by exact, case-insensitive basename match,
// BEFORE any suffix/shape check. Ported verbatim from recallaxis.denyBasenames; includes
// history.jsonl, which carries a transcript extension but is never a transcript.
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

// denyGlobs drop config/secret files by fnmatch pattern (also BEFORE the suffix/shape check).
// Ported verbatim from recallaxis.denyGlobs. Matched with Python-fnmatch semantics (fnmatch.go),
// NOT filepath.Match — "*" spans separators, so filepath.Match would silently weaken them.
var denyGlobs = []string{"*mcp*.json", "settings*.json", "*.env", "*token*.json", "*secret*.json", "*key*.json"}

// ScreenName applies the always-on filename guards to one transcript path for its resolved
// provider, in the recall forwarder's order: the secrets/config denylist (dotfile → exact
// basename → deny-glob) first, then the strict per-provider transcript-shape allowlist. It
// returns a non-empty Reason and true when the file must be refused BEFORE its bytes are read
// (so a denylisted secret is never even loaded into memory), or ("", false) when the filename
// passes and the caller should proceed to read and content-sniff it.
func ScreenName(provider, path string) (Reason, bool) {
	base := filepath.Base(path)
	if denied(base) {
		return ReasonDenylistedName, true
	}
	if !allowed(provider, base) {
		return ReasonNotAllowlisted, true
	}
	return "", false
}

// ScreenContent applies the PEM key-block content sniff to a transcript's leading bytes. Pass
// the whole content or at least the first SniffBytes bytes; only the first SniffBytes are
// inspected, matching the recall forwarder's fixed sniff window. It returns ReasonPEMContent
// and true when the head looks like a PEM/PKCS key block and the file must be refused before
// any upload request is constructed. This is applied LAST in the chain, after ScreenName.
func ScreenContent(content []byte) (Reason, bool) {
	head := content
	if len(head) > SniffBytes {
		head = head[:SniffBytes]
	}
	if looksLikePEM(head) {
		return ReasonPEMContent, true
	}
	return "", false
}

// denied drops a basename via the secrets/config denylist. Any dotfile is denied; then the
// exact deny-list; then the fnmatch deny-globs. The basename is lowercased so the match is
// case-insensitive (mirrors the recall forwarder's normcase + "lowercase literal basename").
// Ported verbatim from recallaxis.denied.
func denied(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(name, ".") {
		return true
	}
	if denyBasenames[lower] {
		return true
	}
	for _, g := range denyGlobs {
		if fnmatch(lower, g) {
			return true
		}
	}
	return false
}

// allowed is the strict per-provider transcript-shape gate. The basename must match a known
// transcript shape for its provider; anything else is refused. Ported from recallaxis.allowed,
// scoped to the content lane's providers ({claude,codex}) — the only providers the content
// endpoint accepts (cmd/gasworks-observer/../daemon/content.go validContentHeaders). Any other
// provider label is refused by default (fail-closed); the recall forwarder's gemini shape is
// intentionally not carried here because gemini content is never on this lane.
//
// Shapes:
//
//	claude: <uuid>.jsonl  OR  agent-<hex>.jsonl (subagent transcript)
//	codex:  rollout-*.jsonl
func allowed(provider, base string) bool {
	base = strings.ToLower(base)
	switch provider {
	case "claude":
		if !strings.HasSuffix(base, ".jsonl") {
			return false
		}
		stem := strings.TrimSuffix(base, ".jsonl")
		return isUUIDStem(stem) || isAgentHexStem(stem)
	case "codex":
		return strings.HasSuffix(base, ".jsonl") && strings.HasPrefix(base, "rollout-")
	default:
		return false
	}
}

// isUUIDStem reports whether s looks like a (lowercased) UUID: 8-4-4-4-12 hex with dashes.
// Claude transcript files are named <session-uuid>.jsonl. Ported verbatim from recallaxis.
func isUUIDStem(s string) bool {
	const layout = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	if len(s) != len(layout) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if layout[i] == '-' {
			if s[i] != '-' {
				return false
			}
			continue
		}
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return false
		}
	}
	return true
}

// isAgentHexStem reports whether s (a lowercased basename minus ".jsonl") is the
// subagent-transcript shape "agent-<hex>": the literal prefix "agent-" followed by a
// non-empty run of lowercase hex. These are the majority of real Claude transcripts and must
// pass so they are not silently dropped. Ported verbatim from recallaxis.
func isAgentHexStem(s string) bool {
	const prefix = "agent-"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hex := s[len(prefix):]
	if hex == "" {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// pemBOM is the UTF-8 byte-order mark. A file may legitimately lead with it, and an attacker
// could prepend it to slip a PEM key past a naive "-----BEGIN" prefix check, so it is stripped
// before sniffing. Ported verbatim from recallaxis.
var pemBOM = []byte{0xEF, 0xBB, 0xBF}

// looksLikePEM reports whether the leading bytes look like a PEM/PKCS key block. A transcript
// never starts with "-----BEGIN". It first strips a leading UTF-8 BOM, then trims a WIDER set
// of leading whitespace/control bytes (space, tab, CR, LF, vertical tab, form feed, NUL) so a
// "\xEF\xBB\xBF" / "\v" / "\f" / NUL before the marker can't smuggle a key file through.
// Ported verbatim from recallaxis.looksLikePEM.
func looksLikePEM(head []byte) bool {
	head = bytes.TrimPrefix(head, pemBOM)
	return bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n\v\f\x00"), []byte("-----BEGIN"))
}
