package recallaxis

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// readResult is the capped read of a transcript file plus its stat metadata.
type readResult struct {
	data    []byte
	size    int64 // stat size at read time
	mtimeNS int64
}

// readCapped opens path (no symlink follow), fstats it, and reads up to MaxBytes. It
// returns (nil, false) — DROP the file — when it is not a regular file, when its stat
// size already exceeds MaxBytes, or when it GREW past MaxBytes between stat and read
// (the size-race guard, M15): we read MaxBytes+1 and drop if the result is longer than
// MaxBytes. X-Cass-Content-Length is len(data); X-Cass-Source-Size is the stat size —
// kept DISTINCT so the server sees both the bytes we sent and the file's size.
func readCapped(path string, maxBytes int64) (readResult, bool) {
	return readCappedOS(path, maxBytes)
}

// postSnapshot builds and sends ONE ingest request. seam: client is injected so tests
// drive an httptest server; in production it is the hardened client from newClient.
// Returns the HTTP status code, or an error for a transport-level failure (no response).
func postSnapshot(ctx context.Context, client *http.Client, cfg Config, token string, c candidate, rr readResult) (int, error) {
	b3 := blake3Hex(rr.data)
	s2 := sha256Hex(rr.data)
	rel := srcRel(c)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL+"/api/v1/ingest/snapshots", bytes.NewReader(rr.data))
	if err != nil {
		return 0, err
	}
	h := req.Header
	h.Set("Authorization", "Bearer "+token)
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Cass-Source-Id", cfg.SourceID)
	h.Set("X-Cass-Provider", c.provider)
	h.Set("X-Cass-Source-Path", rel)
	h.Set("X-Cass-Provider-Session-Id", rel) // root-relative => no cross-dir collision
	h.Set("X-Cass-Content-Length", strconv.Itoa(len(rr.data)))
	h.Set("X-Cass-Observation-Id", b3) // server requires this (422 if absent)
	h.Set("X-Cass-Blake3", b3)
	h.Set("X-Cass-Sha256", s2)
	h.Set("X-Cass-Source-Mtime-Ns", strconv.FormatInt(rr.mtimeNS, 10))
	h.Set("X-Cass-Source-Size", strconv.FormatInt(rr.size, 10))

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; ignore the body content.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// srcRel returns "provider/<path-relative-to-root>" so no absolute / home / username
// leaks into the wire. Falls back to "provider/<basename>" if Rel fails.
func srcRel(c candidate) string {
	rel, err := relUnder(c.rootReal, c.path)
	if err != nil {
		return c.provider + "/" + baseName(c.path)
	}
	return c.provider + "/" + rel
}

// newClient builds the hardened http.Client for the axis (M14): it refuses ALL
// redirects (http.ErrUseLastResponse) so the bearer + transcript can't bounce to
// another host, and pins a TLS 1.2 floor (TLS verification stays on; InsecureSkipVerify
// is never set) so a MITM can't negotiate a downgrade to TLS 1.0/1.1. https-only is
// enforced separately by URLOK at startup.
func newClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ScanStats summarizes one scan pass.
type ScanStats struct {
	Sent    int
	Failed  int
	Skipped int
}

// Logf is an injectable structured logger; it MUST NOT be called with the token value.
type Logf func(format string, args ...any)

// Runner owns the scan + post seams so tests can substitute a temp roots dir + an
// httptest server. Build it with NewRunner.
type Runner struct {
	cfg    Config
	client *http.Client
	scan   func(Config, Logf) []candidate
	read   func(path string, maxBytes int64) (readResult, bool)
	post   func(ctx context.Context, client *http.Client, cfg Config, token string, c candidate, rr readResult) (int, error)
	log    Logf
}

// NewRunner constructs a Runner. The http client is built lazily and ONLY when the axis
// is Enabled() — a disabled axis never constructs a client or dials (M18). log may be
// nil (defaults to a no-op).
func NewRunner(cfg Config, log Logf) *Runner {
	if log == nil {
		log = func(string, ...any) {}
	}
	r := &Runner{
		cfg:  cfg,
		scan: scanRoots,
		read: readCapped,
		post: postSnapshot,
		log:  log,
	}
	if cfg.Enabled() {
		r.client = newClient()
	}
	return r
}

// ScanOnce performs one scan-and-upload pass against the current state, mirroring the
// Python _scan_once: unchanged files (by mtime+size) are skipped; a file whose blake3
// is unchanged is not re-sent (and a prior terminal rejection stays rejected); 200/201
// marks sent; a terminal HTTP code marks rejected (never retried until content changes);
// anything else counts as a transient failure. It returns updated stats; state is
// mutated in place. ScanOnce is a no-op on a disabled axis.
func (r *Runner) ScanOnce(ctx context.Context, st *State) ScanStats {
	var stats ScanStats
	if !r.cfg.Enabled() || r.client == nil {
		return stats
	}
	token, err := r.cfg.Token.Token()
	if err != nil {
		r.log("recall: token unreadable this cycle: %v", err)
		return stats
	}
	if token == "" {
		return stats // configured but unreadable (e.g. file rotated away): skip cycle
	}

	for _, c := range r.scan(r.cfg, r.log) {
		fi, serr := os.Stat(c.path)
		if serr != nil {
			continue
		}
		prior, hadPrior := st.Get(c.path)
		if hadPrior && prior.MtimeNS == fi.ModTime().UnixNano() && prior.Size == fi.Size() {
			continue // unchanged by cheap metadata check
		}
		rr, ok := r.read(c.path, r.cfg.MaxBytes)
		if !ok {
			continue // too big / grew mid-read / not regular
		}
		b3 := blake3Hex(rr.data)
		if hadPrior && prior.Blake3 == b3 {
			if prior.Status == StatusRejected {
				stats.Skipped++
			}
			// Same content (already sent or terminally rejected): just refresh metadata.
			prior.MtimeNS = rr.mtimeNS
			prior.Size = rr.size
			st.Put(c.path, prior)
			continue
		}

		status, perr := r.post(ctx, r.client, r.cfg, token, c, rr)
		if perr != nil {
			stats.Failed++
			r.log("recall: ingest %s/%s: %v (retryable)", c.provider, baseName(c.path), perr)
			time.Sleep(time.Second) // avoid busy-spin on a transport wave
			continue
		}
		switch {
		case status == http.StatusOK || status == http.StatusCreated:
			st.Put(c.path, FileState{Status: StatusSent, Blake3: b3, MtimeNS: rr.mtimeNS, Size: rr.size})
			stats.Sent++
		case terminalCodes[status]:
			st.Put(c.path, FileState{Status: StatusRejected, Blake3: b3, MtimeNS: rr.mtimeNS, Size: rr.size, Code: status})
			r.log("recall: ingest %s/%s: http %d (terminal — not retried until content changes)", c.provider, baseName(c.path), status)
		default:
			stats.Failed++
			r.log("recall: ingest %s/%s: http %d (retryable)", c.provider, baseName(c.path), status)
			time.Sleep(time.Second)
		}
	}
	return stats
}

// Run loops ScanOnce every Interval until ctx is cancelled, persisting state after any
// pass that did work. It is the daemon entry point. A disabled axis returns immediately
// with a clear idle log (it never dials).
func (r *Runner) Run(ctx context.Context) error {
	if !r.cfg.Enabled() {
		r.log("recall: idle — RECALL_FORWARDER_URL / _SOURCE_ID / token not all set (opt in to enable)")
		return nil
	}
	if !URLOK(r.cfg.URL, r.cfg.AllowHTTP) {
		return fmt.Errorf("recall: RECALL_FORWARDER_URL must be https:// (or localhost http with RECALL_FORWARDER_ALLOW_HTTP=1)")
	}
	st, _ := LoadState(r.cfg.StatePath)
	r.log("recall: start roots=%v interval=%s", r.cfg.Roots, r.cfg.Interval)
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		stats := r.ScanOnce(ctx, st)
		if stats.Sent != 0 || stats.Failed != 0 || stats.Skipped != 0 {
			if err := SaveState(r.cfg.StatePath, st); err != nil {
				r.log("recall: state save failed: %v", err)
			}
			r.log("recall: scan sent=%d failed=%d skipped=%d", stats.Sent, stats.Failed, stats.Skipped)
		}
		select {
		case <-ctx.Done():
			r.log("recall: stopped")
			return nil
		case <-ticker.C:
		}
	}
}
