package eventsaxis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/gastownhall/gascity/pkg/eventexport"
)

// Logf is an injectable structured logger; it MUST NOT be called with the token
// value. The axis upholds that contract.
type Logf func(format string, args ...any)

// cursorSaveEvery bounds how often the resume cursors are persisted while running.
// The exporter advances a city's cursor only on a confirmed POST, so persisting on
// a timer (plus once on shutdown) loses at most this window of progress on a hard
// crash — every event is re-fetched and re-projected idempotently, never dropped.
const cursorSaveEvery = 10 * time.Second

// Runner owns the events axis: it builds the SSE source + the pkg/eventexport
// Exporter (only when Enabled) and runs the export loop, persisting per-city
// resume cursors. Construct it with NewRunner.
//
// The two HTTP paths use DISTINCT clients on purpose: client is the long-lived SSE
// tail (no read timeout — the stream stays open for hours), while postClient backs the
// exporter's ingest POST and carries a bounded timeout so a hung ingest endpoint can't
// wedge a POST forever (the SSE client's no-timeout property must NOT leak onto the POST).
type Runner struct {
	cfg        Config
	log        Logf
	client     *http.Client
	postClient *http.Client

	// seams for tests
	newSource func(ctx context.Context, cfg Config, client *http.Client, cursors map[string]uint64, logf func(string, ...any)) eventexport.Source
	loadCur   func(path string) map[string]uint64
	saveCur   func(path string, cursors map[string]uint64) error
}

// NewRunner constructs a Runner. The HTTP client is built ONLY when the axis is
// Enabled() — a disabled axis never constructs a client or dials (M18). log may be
// nil (defaults to a no-op).
func NewRunner(cfg Config, log Logf) *Runner {
	if log == nil {
		log = func(string, ...any) {}
	}
	r := &Runner{
		cfg: cfg,
		log: log,
		newSource: func(ctx context.Context, cfg Config, client *http.Client, cursors map[string]uint64, logf func(string, ...any)) eventexport.Source {
			return newSSESource(ctx, cfg, client, cursors, logf)
		},
		loadCur: eventexport.LoadCursors,
		saveCur: eventexport.SaveCursors,
	}
	if cfg.Enabled() {
		r.client = newClient()
		r.postClient = newPostClient()
	}
	return r
}

// newClient builds the HTTP client for the long-lived SSE tail. It refuses ALL redirects
// so the bearer can't bounce to another host, and pins a TLS 1.2 floor (TLS verification
// stays on). The SSE tail needs no read timeout (the stream is long-lived), so Timeout is
// left unset; per-request cancellation rides on the context.
func newClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postClientTimeout bounds the exporter's ingest POST (matches the recall axis). It is a
// per-request ceiling — the POST is short-lived, unlike the SSE tail — so a hung ingest
// endpoint can't wedge the export loop.
const postClientTimeout = 30 * time.Second

// newPostClient builds the bounded-timeout client for the ingest POST. Same redirect +
// TLS hardening as newClient, but WITH a timeout (the SSE client deliberately has none).
func newPostClient() *http.Client {
	c := newClient()
	c.Timeout = postClientTimeout
	return c
}

// Run builds the source + exporter and runs the export loop until ctx is cancelled.
// A disabled axis returns immediately with a clear idle log (it never dials). The
// ingest URL is validated up front so a plain-http misconfig fails loudly instead
// of silently idling.
func (r *Runner) Run(ctx context.Context) error {
	if !r.cfg.Enabled() {
		r.log("events: idle — GASWORKS_EVENTS_INGEST_URL / _CITIES / token not all set (opt in to enable)")
		return nil
	}
	if !URLOK(r.cfg.URL, r.cfg.AllowHTTP) {
		return fmt.Errorf("events: GASWORKS_EVENTS_INGEST_URL must be https:// (or localhost http with GASWORKS_EVENTS_ALLOW_HTTP=1)")
	}
	if !supervisorLoopback(r.cfg.Supervisor) {
		return fmt.Errorf("events: refusing non-loopback supervisor %q (the SSE API is unauthenticated; only loopback/OS-user trust is allowed)", r.cfg.Supervisor)
	}
	if len(r.cfg.Salt) < 16 {
		// pkg/eventexport drops every event under a short salt (fail-closed actor
		// hash). Surfacing it here turns a silent "ships nothing" into a loud config
		// error the operator can act on.
		return fmt.Errorf("events: GASWORKS_EVENTS_SALT must be >= 16 bytes (the actor hash is brute-forceable below that; events would be silently dropped)")
	}

	cursors := r.loadCur(r.cfg.StatePath)

	exp := eventexport.New(eventexport.Config{
		Endpoint:      r.cfg.URL,
		TokenProvider: r.cfg.Token.Token,
		Salt:          r.cfg.Salt,
		ExportRef:     r.cfg.ExportRef,
		// Correlation ids (opaque run_id/session_id/step_id) ride the envelope and are
		// independent of the free-form content opt-in — they have their own gate.
		EmitContent:     r.cfg.EmitContent,
		EmitCorrelation: r.cfg.EmitCorrelation,
		BatchMax:        r.cfg.BatchMax,
		BatchInterval:   r.cfg.BatchInterval,
		// The ingest POST uses its OWN bounded-timeout client, NOT the no-timeout SSE
		// client, so a hung endpoint can't stall the export loop (L3).
		Client: r.postClient,
		Logf:   func(f string, a ...any) { r.log("events: "+f, a...) },
	})
	exp.SetCursors(cursors)

	src := r.newSource(ctx, r.cfg, r.client, cursors, func(f string, a ...any) { r.log(f, a...) })

	r.log("events: start cities=%v supervisor=%s interval=%s", r.cfg.Cities, r.cfg.Supervisor, r.cfg.BatchInterval)

	// Persist cursors periodically so progress survives a crash; the exporter's
	// final drain on ctx cancel happens inside Run, so we snapshot once more after
	// it returns.
	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		t := time.NewTicker(cursorSaveEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.persist(exp)
			}
		}
	}()

	runErr := exp.Run(ctx, src)
	<-saveDone
	r.persist(exp) // final snapshot after the exporter's drain
	r.log("events: stopped")

	// A context cancellation is a clean shutdown, not a failure.
	if runErr == context.Canceled || runErr == context.DeadlineExceeded {
		return nil
	}
	return runErr
}

// persist writes the exporter's current resume cursors, logging (never failing) on
// a write error so a transient disk problem never crashes the axis.
func (r *Runner) persist(exp *eventexport.Exporter) {
	if err := r.saveCur(r.cfg.StatePath, exp.Cursors()); err != nil {
		r.log("events: cursor save failed: %v", err)
	}
}
