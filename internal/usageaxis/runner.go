package usageaxis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Logf is an injectable structured logger; it MUST NOT be called with the token
// value. The axis upholds that contract.
type Logf func(format string, args ...any)

const postTimeout = 30 * time.Second

// postResult is the outcome of one batch POST.
type postResult struct {
	advance   bool // 2xx: commit the cursor
	retryable bool // back off and retry (the cursor is NOT advanced)
}

// Runner owns the usage axis: it tails the ledger, batches, and POSTs to
// usage-ingest, persisting the per-source resume cursor only on a confirmed POST.
// Construct it with NewRunner.
type Runner struct {
	cfg        Config
	log        Logf
	postClient *http.Client

	// seams for tests
	tail func(path string, cur Cursor, max int) ([]Fact, Cursor, bool, error)
	post func(ctx context.Context, b Batch) postResult
}

// NewRunner constructs a Runner. The HTTP client is built ONLY when the axis is
// Enabled() — a disabled axis never constructs a client or dials. log may be nil.
func NewRunner(cfg Config, log Logf) *Runner {
	if log == nil {
		log = func(string, ...any) {}
	}
	r := &Runner{cfg: cfg, log: log, tail: Tail}
	if cfg.Enabled() {
		r.postClient = newPostClient()
	}
	r.post = r.httpPost
	return r
}

// newPostClient builds the bounded-timeout POST client: refuses ALL redirects so the
// bearer can't bounce to another host, pins a TLS 1.2 floor (verification stays on),
// and carries a timeout so a hung ingest endpoint can't wedge the loop.
func newPostClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		Timeout:   postTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Run drains the ledger to usage-ingest on each BatchInterval tick until ctx is
// cancelled, persisting the resume cursor after every confirmed POST. A disabled
// axis returns immediately (it never dials). With once=true it does a single drain
// pass and returns (cron / test mode).
func (r *Runner) Run(ctx context.Context) error { return r.run(ctx, false) }

// RunOnce does a single drain pass (catch up to EOF) and returns.
func (r *Runner) RunOnce(ctx context.Context) error { return r.run(ctx, true) }

func (r *Runner) run(ctx context.Context, once bool) error {
	if !r.cfg.Enabled() {
		r.log("usage: idle — GASWORKS_USAGE_INGEST_URL / _SOURCE_ID / _LEDGER / token not all set (opt in to enable)")
		return nil
	}
	if !URLOK(r.cfg.URL, r.cfg.AllowHTTP) {
		return fmt.Errorf("usage: GASWORKS_USAGE_INGEST_URL must be https:// (or localhost http with GASWORKS_USAGE_ALLOW_HTTP=1)")
	}

	st, _ := LoadState(r.cfg.StatePath)
	cur, ok := st.Get(r.cfg.SourceID)
	if !ok || cur.NextSeq == 0 {
		cur = Cursor{Offset: cur.Offset, NextSeq: 1} // 1-based seq for a fresh source
	}

	r.log("usage: start source=%s ledger=%s interval=%s", r.cfg.SourceID, r.cfg.Ledger, r.cfg.BatchInterval)

	drain := func() {
		cur = r.drain(ctx, cur, st)
	}

	drain() // catch up immediately on start
	if once {
		return nil
	}

	t := time.NewTicker(r.cfg.BatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.log("usage: stopped")
			return nil
		case <-t.C:
			drain()
		}
	}
}

// drain tails+POSTs repeated batches until caught up (no new facts) or a POST asks to
// back off, persisting the cursor after each confirmed batch. It returns the latest
// committed cursor. Bounded by maxBatchesPerDrain so one tick can't hog forever.
const maxBatchesPerDrain = 50

func (r *Runner) drain(ctx context.Context, cur Cursor, st *State) Cursor {
	for i := 0; i < maxBatchesPerDrain; i++ {
		if ctx.Err() != nil {
			return cur
		}
		facts, next, rotated, err := r.tail(r.cfg.Ledger, cur, r.cfg.BatchMax)
		if err != nil {
			r.log("usage: tail error: %v", err)
			return cur
		}
		if rotated {
			r.log("usage: ledger rotated/truncated; resuming from the top (seq stays monotonic)")
		}
		if len(facts) == 0 {
			// No facts, but the offset may have advanced past skipped lines — commit it
			// so we don't re-scan them forever.
			if next.Offset != cur.Offset {
				r.commit(st, next)
				cur = next
			}
			return cur
		}
		res := r.post(ctx, Batch{SourceID: r.cfg.SourceID, SchemaVersion: SchemaVersion, Facts: facts})
		if !res.advance {
			if res.retryable {
				r.log("usage: POST not accepted (%d facts held; cursor unchanged, will retry)", len(facts))
			}
			return cur // do NOT advance: the same facts/seqs re-POST next time (idempotent)
		}
		r.commit(st, next)
		cur = next
	}
	return cur
}

// commit persists the cursor for this source, logging (never failing) on a write
// error so a transient disk problem never crashes the axis.
func (r *Runner) commit(st *State, cur Cursor) {
	st.Put(r.cfg.SourceID, cur)
	if err := SaveState(r.cfg.StatePath, st); err != nil {
		r.log("usage: cursor save failed: %v", err)
	}
}

// httpPost POSTs one batch to usage-ingest with the usage bearer and classifies the
// response into advance / retryable.
func (r *Runner) httpPost(ctx context.Context, b Batch) postResult {
	token, err := r.cfg.Token.Token()
	if err != nil {
		r.log("usage: token unavailable: %v", err)
		return postResult{retryable: true}
	}
	if token == "" {
		// An empty token (e.g. a not-yet-populated token file) would POST a bare
		// "Authorization: Bearer " and 401. Idle this cycle instead and hold the
		// cursor, so a later credential rotation enables the axis without data loss.
		r.log("usage: token empty; idling this cycle (cursor held)")
		return postResult{retryable: true}
	}
	body, err := json.Marshal(b)
	if err != nil {
		r.log("usage: batch marshal failed: %v", err) // not retryable, but should never happen
		return postResult{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return postResult{retryable: true}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.postClient.Do(req)
	if err != nil {
		r.log("usage: POST error: %v", err)
		return postResult{retryable: true}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode/100 == 2:
		return postResult{advance: true}
	case resp.StatusCode == 429 || resp.StatusCode/100 == 5:
		return postResult{retryable: true} // transient: hold the cursor, retry
	default:
		// 4xx (schema mismatch, auth, conflict): the batch won't succeed as-is. Hold
		// the cursor and back off rather than skip — losing data is worse than a loud
		// retry the operator can see and fix (e.g. a deploy-skew SchemaVersion).
		r.log("usage: POST rejected %d (holding cursor; check token/schema/edge)", resp.StatusCode)
		return postResult{retryable: true}
	}
}
