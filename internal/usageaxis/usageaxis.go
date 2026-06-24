// Package usageaxis is the usage forwarder axis: it tails a Gas City's local
// usage-fact ledger (.gc/usage.jsonl, written by gc's usage Sink), assigns each
// fact a per-source monotonic seq, batches them, and POSTs each Batch to the
// configured usage-ingest URL with the usage bearer. usage-ingest re-validates and
// projects each fact into a manifold.spend row tagged source='estimated'.
//
// WHAT LEAVES THE BOX. Unlike the events axis (envelope-only, payload-stripped),
// usage facts ARE numbers: tokens and a list-price cost estimate, plus the opaque
// {run_id, session_id, step_id} correlation tuple and the model/provider labels.
// There is no free text — no prompt, response, title, or path. This axis maps only
// the closed set of usage.Fact fields into the wire Fact; anything gc adds that is
// not one of them is dropped.
//
// AXIS ISOLATION. The usage bearer + config is SEPARATE from events' and recall's:
// its own env set (GASWORKS_USAGE_*), its own saauth.Provider. One axis's token is
// never usable by another.
//
// EGRESS GATE — SAFE BY DEFAULT. The axis is disabled (Enabled()==false) and never
// constructs an HTTP client or dials unless a destination URL AND a token source AND
// a source id AND a ledger path are all configured.
package usageaxis

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
	defaultBatchMax     = 1000
	defaultBatchEvery   = 5 * time.Second
	minBatchEvery       = time.Second
	defaultStateSubpath = "usage-forwarder"
	defaultLedgerName   = "usage.jsonl"
	// SchemaVersion is stamped on every Batch; usage-ingest rejects a mismatch. It
	// is the usage wire contract version, independent of the events one.
	SchemaVersion = 1
	// KindModel is the only kind this axis forwards. Compute facts (wall-seconds, no
	// model/tokens) are dropped at the source — usage-ingest would reject them, and
	// shipping them wastes a round trip.
	KindModel = "model"
)

// Fact is one usage fact on the wire: the gc usage.Fact JSON shape plus the
// forwarder-assigned per-source Seq. Only the fields usage-ingest reads are mapped;
// gc may carry others (idempotency_key, city, runtime, …) which are dropped.
type Fact struct {
	Seq uint64 `json:"seq"`

	RunID     string `json:"run_id"`
	SessionID string `json:"session_id"`
	StepID    string `json:"step_id"`
	Worker    string `json:"worker"`

	Kind     string `json:"kind"`
	Model    string `json:"model"`
	Provider string `json:"provider"`

	InputTokens         int `json:"input_tokens"`
	OutputTokens        int `json:"output_tokens"`
	CacheReadTokens     int `json:"cache_read_tokens"`
	CacheCreationTokens int `json:"cache_creation_tokens"`

	CostUSDEstimate float64 `json:"cost_usd_estimate"`
	Unpriced        bool    `json:"unpriced"`

	UpstreamReqID string `json:"upstream_req_id"`
	At            int64  `json:"at"`
}

// Batch is one POST body to usage-ingest.
type Batch struct {
	SourceID      string `json:"source_id"`
	SchemaVersion int    `json:"schema_version"`
	Facts         []Fact `json:"facts"`
}

// Config is the resolved usage-axis configuration. Build it with ConfigFromEnv.
type Config struct {
	// URL is the usage-ingest destination (trailing slash trimmed); "" => idle.
	URL string
	// SourceID is the opaque per-deployment id stamped on every Batch and used by
	// usage-ingest as the dedup namespace. "" => idle.
	SourceID string
	// Ledger is the path to the gc usage.jsonl this axis tails.
	Ledger string
	// Token is the usage bearer source (file or env). Its OWN provider — never an
	// events/recall token. Unconfigured => idle.
	Token saauth.Provider
	// StatePath is the resume-cursor file.
	StatePath string
	// BatchMax is the max facts per POST.
	BatchMax int
	// BatchInterval is the max time between POSTs.
	BatchInterval time.Duration
	// AllowHTTP opts in to a plain-http (loopback only) ingest URL for dev.
	AllowHTTP bool
}

// Enabled is the egress gate: the axis may construct an HTTP client and dial ONLY
// when a destination URL AND a source id AND a ledger path AND a token source are
// all configured. When false the axis never builds a client or sends a request.
func (c Config) Enabled() bool {
	return c.URL != "" && c.SourceID != "" && c.Ledger != "" && c.Token.Configured()
}

// ConfigFromEnv builds a Config from GASWORKS_USAGE_* env. The token Provider prefers
// GASWORKS_USAGE_TOKEN_FILE and falls back to GASWORKS_USAGE_TOKEN (popped from env,
// dev-only). Returns a non-fatal warning string for the caller to log (never the
// token value).
//
//	GASWORKS_USAGE_INGEST_URL     usage-ingest destination (https; "" => idle)
//	GASWORKS_USAGE_SOURCE_ID      opaque per-deployment id ("" => idle)
//	GASWORKS_USAGE_LEDGER         usage.jsonl path (default ~/.gc/usage.jsonl)
//	GASWORKS_USAGE_TOKEN_FILE     bearer token file (preferred)
//	GASWORKS_USAGE_TOKEN          bearer token (dev-only, popped from env)
//	GASWORKS_USAGE_STATE          resume-cursor file (default XDG state dir)
//	GASWORKS_USAGE_BATCH_MAX      max facts per POST (default 1000)
//	GASWORKS_USAGE_BATCH_INTERVAL flush interval seconds (default 5)
//	GASWORKS_USAGE_ALLOW_HTTP     "1" to allow loopback plain-http ingest (dev)
func ConfigFromEnv() (Config, string) {
	home, _ := os.UserHomeDir()
	var warn string

	token := func() saauth.Provider {
		if fp := strings.TrimSpace(os.Getenv("GASWORKS_USAGE_TOKEN_FILE")); fp != "" {
			return saauth.FileProvider(fp)
		}
		if tok, ok := saauth.TokenFromEnv("GASWORKS_USAGE_TOKEN"); ok {
			warn = saauth.EnvWarning
			return saauth.EnvProvider(tok)
		}
		return saauth.Provider{}
	}()

	ledger := strings.TrimSpace(os.Getenv("GASWORKS_USAGE_LEDGER"))
	if ledger == "" {
		ledger = filepath.Join(home, ".gc", defaultLedgerName)
	}

	state := strings.TrimSpace(os.Getenv("GASWORKS_USAGE_STATE"))
	if state == "" {
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			stateHome = filepath.Join(home, ".local", "state")
		}
		state = filepath.Join(stateHome, defaultStateSubpath, "cursors.json")
	}

	return Config{
		URL:           strings.TrimRight(strings.TrimSpace(os.Getenv("GASWORKS_USAGE_INGEST_URL")), "/"),
		SourceID:      strings.TrimSpace(os.Getenv("GASWORKS_USAGE_SOURCE_ID")),
		Ledger:        ledger,
		Token:         token,
		StatePath:     state,
		BatchMax:      envInt("GASWORKS_USAGE_BATCH_MAX", defaultBatchMax),
		BatchInterval: envInterval("GASWORKS_USAGE_BATCH_INTERVAL", defaultBatchEvery),
		AllowHTTP:     os.Getenv("GASWORKS_USAGE_ALLOW_HTTP") == "1",
	}, warn
}

// URLOK enforces the https-only rule for the ingest destination: https with a host
// is always allowed; plain http only with AllowHTTP and a loopback host.
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
