// Package eventsaxis is the events forwarder axis: it tails one or more cities'
// supervisor SSE event streams, projects each event down to a redacted,
// envelope-only shell via the published pkg/eventexport projection, batches the
// envelopes, and POSTs each per-city Batch to the configured events-ingest URL
// with the events bearer.
//
// REDACTION BOUNDARY — ENVELOPE ONLY, BY DESIGN.
// The supervisor records every event with free-form, untrusted content (bead
// titles/descriptions, mail bodies, paths). This axis NEVER copies that content:
// the SSE source maps ONLY the closed set of typed primitive fields
// (city/seq/type/ts/actor/subject) into an eventexport.TaggedEvent — Message and
// Payload are never read into any field — and pkg/eventexport reduces that to a
// fixed envelope (type, time, salted actor hash, id-gated ref). An unknown or
// non-allowlisted type is dropped, and the envelope is a closed struct so a newly
// added source field can never escape. run_id/session_id ship EMPTY in v0
// (EmitCorrelation stays off inside the pkg until a typed-at-record-site source
// lands), so this axis does NOT parse them off the SSE payload.
//
// AXIS ISOLATION.
// The events bearer + config is SEPARATE from recall's: its own env set
// (GASWORKS_EVENTS_*), its own saauth.Provider. A recall raw-content token is
// never usable here and vice versa.
//
// (M18) EGRESS GATE — SAFE BY DEFAULT.
// The axis is disabled (Enabled()==false) and never constructs an HTTP client or
// dials unless a destination URL AND a token source AND at least one city are all
// configured. pkg/eventexport's Exporter additionally requires a non-empty
// Endpoint to do anything; we never run it without one.
package eventsaxis

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/saauth"
)

const (
	defaultSupervisor   = "http://127.0.0.1:8372"
	defaultBatchMax     = 1000
	defaultBatchEvery   = 5 * time.Second
	minBatchEvery       = time.Second
	defaultReconnect    = 3 * time.Second
	maxReconnect        = 30 * time.Second
	defaultStreamPath   = "/v0/city/%s/events/stream"
	defaultStateSubpath = "events-forwarder"
)

// Config is the resolved events-axis configuration. Build it with ConfigFromEnv.
type Config struct {
	// URL is the events-ingest destination (trailing slash trimmed); "" => idle.
	URL string
	// Supervisor is the loopback supervisor base whose SSE stream we tail. It must
	// be a loopback host: the SSE read API is unauthenticated, so only OS-user
	// trust is acceptable.
	Supervisor string
	// Cities is the set of city names to tail; empty => idle.
	Cities []string
	// Token is the events bearer source (file or env). Its OWN provider — never a
	// recall token. Unconfigured => idle.
	Token saauth.Provider
	// Salt is the actor-hash salt handed to the projection; pkg/eventexport fails
	// closed (drops events) when it is shorter than 16 bytes.
	Salt []byte
	// ExportRef includes the id-gated ref (opaque bead/convoy ids only).
	ExportRef bool
	// EmitContent opts in to lifting free-form content (bead title, run formula)
	// plus the opaque gc.step_id off the SSE payload. It REVERSES the envelope-only
	// default and also turns on the opaque correlation ids (run_id/session_id/
	// step_id), since step_id is the join key those content fields exist for. Set
	// ONLY under an explicit operator/org content opt-in; default false.
	EmitContent bool
	// StatePath is the per-city cursor file (resume point).
	StatePath string
	// BatchMax is the max events per POST.
	BatchMax int
	// BatchInterval is the max time between POSTs.
	BatchInterval time.Duration
	// AllowHTTP opts in to a plain-http (loopback only) ingest URL for dev.
	AllowHTTP bool
}

// Enabled is the (M18) egress gate: the axis may construct an HTTP client and dial
// ONLY when a destination URL AND a token source AND at least one city are all
// configured. When false the axis never builds a client or sends a request.
func (c Config) Enabled() bool {
	return c.URL != "" && len(c.Cities) > 0 && c.Token.Configured()
}

// ConfigFromEnv builds a Config from GASWORKS_EVENTS_* env vars. The token Provider
// prefers GASWORKS_EVENTS_TOKEN_FILE (a hardened, rotation-ready file) and falls
// back to GASWORKS_EVENTS_TOKEN, which is popped from the environment and flagged
// dev-only. It returns a non-fatal warning string (e.g. for the env-token case) for
// the caller to log — never the token value.
//
// Env vars (all under the events namespace — SEPARATE from RECALL_FORWARDER_*):
//
//	GASWORKS_EVENTS_INGEST_URL    events-ingest destination (https; "" => idle)
//	GASWORKS_EVENTS_SUPERVISOR    loopback supervisor base (default 127.0.0.1:8372)
//	GASWORKS_EVENTS_CITIES        comma/space-separated city names ("" => idle)
//	GASWORKS_EVENTS_TOKEN_FILE    bearer token file (preferred)
//	GASWORKS_EVENTS_TOKEN         bearer token (dev-only, popped from env)
//	GASWORKS_EVENTS_SALT          actor-hash salt (>= 16 bytes or events are dropped)
//	GASWORKS_EVENTS_EXPORT_REF    include the id-gated ref (default on)
//	GASWORKS_EVENTS_EMIT_CONTENT  "1" to lift bead title + run formula + gc.step_id
//	                              off the payload (default off; REVERSES envelope-only)
//	GASWORKS_EVENTS_STATE         cursor file (default XDG state dir)
//	GASWORKS_EVENTS_BATCH_MAX     max events per POST (default 1000)
//	GASWORKS_EVENTS_BATCH_INTERVAL flush interval seconds (default 5)
//	GASWORKS_EVENTS_ALLOW_HTTP    "1" to allow loopback plain-http ingest (dev)
func ConfigFromEnv() (Config, string) {
	home, _ := os.UserHomeDir()
	var warn string

	tokenProvider := func() saauth.Provider {
		if fp := strings.TrimSpace(os.Getenv("GASWORKS_EVENTS_TOKEN_FILE")); fp != "" {
			return saauth.FileProvider(fp)
		}
		if tok, ok := saauth.TokenFromEnv("GASWORKS_EVENTS_TOKEN"); ok {
			warn = saauth.EnvWarning
			return saauth.EnvProvider(tok)
		}
		return saauth.Provider{}
	}()

	supervisor := strings.TrimSpace(os.Getenv("GASWORKS_EVENTS_SUPERVISOR"))
	if supervisor == "" {
		supervisor = defaultSupervisor
	}

	state := strings.TrimSpace(os.Getenv("GASWORKS_EVENTS_STATE"))
	if state == "" {
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			stateHome = filepath.Join(home, ".local", "state")
		}
		state = filepath.Join(stateHome, defaultStateSubpath, "cursors.json")
	}

	return Config{
		URL:           strings.TrimRight(strings.TrimSpace(os.Getenv("GASWORKS_EVENTS_INGEST_URL")), "/"),
		Supervisor:    strings.TrimRight(supervisor, "/"),
		Cities:        splitCities(os.Getenv("GASWORKS_EVENTS_CITIES")),
		Token:         tokenProvider,
		Salt:          []byte(os.Getenv("GASWORKS_EVENTS_SALT")),
		ExportRef:     envBool("GASWORKS_EVENTS_EXPORT_REF", true),
		EmitContent:   envBool("GASWORKS_EVENTS_EMIT_CONTENT", false),
		StatePath:     state,
		BatchMax:      envInt("GASWORKS_EVENTS_BATCH_MAX", defaultBatchMax),
		BatchInterval: envInterval("GASWORKS_EVENTS_BATCH_INTERVAL", defaultBatchEvery),
		AllowHTTP:     os.Getenv("GASWORKS_EVENTS_ALLOW_HTTP") == "1",
	}, warn
}

// splitCities parses a comma/space/newline-separated city list, dropping blanks
// and de-duplicating while preserving order.
func splitCities(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// URLOK enforces the https-only rule for the ingest destination: https with a host
// is always allowed; plain http is allowed ONLY with AllowHTTP and a loopback host.
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

// supervisorLoopback reports whether the supervisor base is a loopback host. The
// SSE read API is unauthenticated, so a non-loopback supervisor would let any peer
// observe (and the events stream is the one place free-form content lives), and we
// refuse to tail it.
func supervisorLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return isLoopbackHost(strings.ToLower(u.Hostname()))
}

func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "":
		return true
	default:
		return false
	}
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true":
		return true
	case "0", "false":
		return false
	default:
		return def
	}
}

func envInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	return n
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
	if d < minBatchEvery {
		return minBatchEvery
	}
	return d
}
