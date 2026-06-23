// Package saauth is the ONE hardened service-account bearer reader shared by the
// forwarder axes. It loads a bearer token from a file (rotation-ready, re-read on
// each call) or, as a documented dev-only fallback, from an environment variable.
//
// The file reader (M13) mirrors recall_forwarder.py:124-147: it opens with
// O_NOFOLLOW (a symlink at the path is refused), fstats the open FD rather than the
// path (no TOCTOU between the path check and the read), requires a regular file
// owned by the current uid with no group/world access bits (mode & 0o077 == 0), caps
// the read at 64 KiB, and trims surrounding whitespace.
//
// SECURITY: the token value is NEVER logged. Callers receive the secret and an error
// (or warning signal) only; warnings describe the source, never the value.
package saauth

import (
	"os"
	"strings"
)

// maxTokenBytes caps a token-file read. A bearer is a few KiB at most; 64 KiB is a
// generous ceiling that still bounds a hostile/garbage file.
const maxTokenBytes = 1 << 16

// Source identifies where a Provider reads its token from.
type Source int

const (
	// SourceNone means no token is configured; the axis must stay idle.
	SourceNone Source = iota
	// SourceFile reads the token file on every Token() call (rotation-ready).
	SourceFile
	// SourceEnv captured a token from the environment once and popped it from the
	// process environment. Dev-only — see EnvWarning.
	SourceEnv
)

// EnvWarning is the operator-facing signal returned alongside an env-sourced token.
// Env tokens are visible in /proc/<pid>/environ to anything that can read the
// process; a token FILE (mode 0600) is the production path.
const EnvWarning = "token came from an environment variable (visible in /proc/<pid>/environ); dev-only — prefer a token file"

// Provider yields a bearer token for one forwarder axis. Construct it per-axis so a
// recall token is never shared with the events axis (axis isolation). A SourceFile
// provider re-reads (and re-validates) its file on every Token() call so a rotated
// credential is picked up without a restart.
type Provider struct {
	source Source
	path   string // SourceFile only
	token  string // SourceEnv only (captured once)
}

// FileProvider returns a Provider that re-reads path on every Token() call.
func FileProvider(path string) Provider {
	return Provider{source: SourceFile, path: path}
}

// EnvProvider captures the token already read from the environment. Use TokenFromEnv
// to read+pop the variable first, then pass the value here.
func EnvProvider(token string) Provider {
	return Provider{source: SourceEnv, token: token}
}

// Configured reports whether the Provider has any token source at all. A
// zero-value Provider (SourceNone) is not configured and the axis must stay idle.
func (p Provider) Configured() bool { return p.source != SourceNone }

// Source returns the provider's token source.
func (p Provider) Source() Source { return p.source }

// Token returns the current bearer token. For a file provider this opens, validates,
// and reads the file fresh (rotation). For an env provider it returns the value
// captured at construction. An empty token with a nil error means "configured but
// unreadable this cycle" (e.g. the file disappeared) — the caller should skip the
// cycle, exactly like the Python which returns "" and idles.
func (p Provider) Token() (string, error) {
	switch p.source {
	case SourceFile:
		return TokenFromFile(p.path)
	case SourceEnv:
		return p.token, nil
	default:
		return "", nil
	}
}

// TokenFromEnv reads varname; if it is set it is POPPED from the process environment
// (os.Unsetenv) so a child process or a later /proc/<pid>/environ read cannot recover
// it, and (token, true) is returned. The token is dev-only — env values are visible
// in /proc/<pid>/environ for the lifetime they remain set; prefer a token file. When
// the variable is unset/empty, ("", false) is returned.
func TokenFromEnv(varname string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(varname))
	if v == "" {
		// Pop even an empty value so a later read can't observe it; harmless if unset.
		_ = os.Unsetenv(varname)
		return "", false
	}
	_ = os.Unsetenv(varname)
	return v, true
}

// trimToken trims surrounding whitespace from a raw token-file read. Mirrors the
// Python .strip(). It is in the cross-platform file so both build tags share it.
func trimToken(raw []byte) string {
	return strings.TrimSpace(string(raw))
}
