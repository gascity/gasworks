package eventsaxis

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gastownhall/gascity/pkg/eventexport"
)

// flatBeadPayload is the minimal slice of a bead.* event payload as RECORDED in
// the city's events.jsonl (and its rotated archives): there the payload IS the
// bead, flat. The supervisor SSE stream wraps the same bead under a "bead" key
// (see beadPayload/liftContent) — the two shapes differ, so the backfill has its
// own lift.
type flatBeadPayload struct {
	Title    string            `json:"title"`
	Metadata map[string]string `json:"metadata"`
}

// liftContentFlat is liftContent for the flat, file-recorded payload shape. Field
// semantics are identical: bead title, gc.step_id, gc.root_bead_id (run_id
// fallback), and the formula from gc.formula_name else the gc.step_ref prefix.
// Best-effort: malformed or absent payloads yield empties, never an error.
func liftContentFlat(payload json.RawMessage) (title, stepID, runID, formula string) {
	if len(payload) == 0 {
		return "", "", "", ""
	}
	var bp flatBeadPayload
	if err := json.Unmarshal(payload, &bp); err != nil {
		return "", "", "", ""
	}
	title = bp.Title
	if m := bp.Metadata; m != nil {
		stepID = m["gc.step_id"]
		runID = m["gc.root_bead_id"]
		if formula = m["gc.formula_name"]; formula == "" {
			formula = formulaFromStepRef(m["gc.step_ref"])
		}
	}
	return title, stepID, runID, formula
}

// BackfillResult summarizes one Backfill run.
type BackfillResult struct {
	Read      int    // raw lines read within the seq window
	Projected int    // envelopes that survived projection (allowlist + validation)
	Posted    int    // envelopes acked by the ingest
	Dupes     int    // envelopes the ingest reported as already-accepted
	Rejected  int    // envelopes the ingest rejected row-wise
	LastSeq   uint64 // last acked source seq (0 when nothing posted)
}

// ingestResponse is the ingest's per-POST summary body.
type ingestResponse struct {
	AcceptedThroughSeq uint64 `json:"accepted_through_seq"`
	Accepted           int    `json:"accepted"`
	Rejected           int    `json:"rejected"`
	Dupes              int    `json:"dupes"`
}

// Backfill replays a city's recorded event history — the events.jsonl file and
// its rotated .gz archives — through the SAME projection the live axis uses, and
// POSTs the resulting envelopes to cfg.URL in chunks of at most cfg.BatchMax.
// Files must be given in ascending seq order; lines outside (fromSeq, toSeq] or
// not strictly ascending are skipped. A 429 or 5xx response retries the same
// chunk with backoff, so a per-org ingest rate limit paces the drain instead of
// wedging it. dryRun projects and counts without dialing.
func Backfill(ctx context.Context, cfg Config, city string, files []string, fromSeq, toSeq uint64, dryRun bool, logf Logf) (BackfillResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var res BackfillResult
	if !dryRun {
		if !cfg.Token.Configured() {
			return res, fmt.Errorf("backfill: no events token configured")
		}
		if !URLOK(cfg.URL, cfg.AllowHTTP) {
			return res, fmt.Errorf("backfill: ingest URL must be https:// (or loopback http with GASWORKS_EVENTS_ALLOW_HTTP=1)")
		}
	}
	if len(cfg.Salt) < 16 {
		return res, fmt.Errorf("backfill: GASWORKS_EVENTS_SALT must be >= 16 bytes")
	}
	batchMax := cfg.BatchMax
	if batchMax <= 0 {
		batchMax = defaultBatchMax
	}

	opt := eventexport.Options{
		Salt:            cfg.Salt,
		ExportRef:       cfg.ExportRef,
		EmitCorrelation: cfg.EmitCorrelation,
		EmitContent:     cfg.EmitContent,
	}
	client := &http.Client{Timeout: 30 * time.Second}

	var chunk []eventexport.Envelope
	lastRead := fromSeq
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		if dryRun {
			res.Posted += len(chunk)
			res.LastSeq = chunk[len(chunk)-1].Seq
			chunk = chunk[:0]
			return nil
		}
		ir, err := postChunk(ctx, client, cfg, city, chunk)
		if err != nil {
			return err
		}
		res.Posted += ir.Accepted
		res.Dupes += ir.Dupes
		res.Rejected += ir.Rejected
		res.LastSeq = chunk[len(chunk)-1].Seq
		logf("backfill: %s acked through seq %d (accepted=%d dupes=%d rejected=%d)",
			city, res.LastSeq, ir.Accepted, ir.Dupes, ir.Rejected)
		chunk = chunk[:0]
		// Pace successive chunks under the per-org ingest budget (5k rows/s)
		// so the drain converges without leaning on 429 retries.
		if !sleep(ctx, 300*time.Millisecond) {
			return ctx.Err()
		}
		return nil
	}

	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		err := scanEventFile(path, func(line []byte) error {
			var r rawEvent
			if err := json.Unmarshal(line, &r); err != nil {
				return nil // malformed line; skip, keep scanning
			}
			if r.Seq <= lastRead || (toSeq > 0 && r.Seq > toSeq) {
				return nil
			}
			lastRead = r.Seq
			res.Read++
			te := eventexport.TaggedEvent{
				City:      city,
				Seq:       r.Seq,
				Type:      r.Type,
				Ts:        parseTS(r.TS),
				Actor:     r.Actor,
				Subject:   r.Subject,
				RunID:     r.RunID,
				SessionID: r.SessionID,
				StepID:    r.StepID,
			}
			if cfg.EmitContent {
				title, stepID, runID, formula := liftContentFlat(r.Payload)
				te.Title, te.Formula = title, formula
				if te.RunID == "" {
					te.RunID = runID
				}
				if te.StepID == "" {
					te.StepID = stepID
				}
			}
			env, ok := eventexport.ProjectEvent(te, opt)
			if !ok {
				return nil // not allowlisted / invalid ts — dropped, as live
			}
			if err := eventexport.Validate(env, opt); err != nil {
				logf("backfill: dropped envelope failing self-validation (seq=%d type=%s): %v", te.Seq, te.Type, err)
				return nil
			}
			res.Projected++
			chunk = append(chunk, env)
			if len(chunk) >= batchMax {
				return flush()
			}
			return nil
		})
		if err != nil {
			return res, fmt.Errorf("backfill: %s: %w", path, err)
		}
	}
	if err := flush(); err != nil {
		return res, err
	}
	return res, nil
}

// postChunk POSTs one batch, retrying 429/5xx with backoff until ctx cancels.
// The per-org ingest rate limit rejects an entire over-budget request, so the
// retry (with the SAME bounded chunk) is what converges a large backlog.
func postChunk(ctx context.Context, client *http.Client, cfg Config, city string, chunk []eventexport.Envelope) (ingestResponse, error) {
	body, err := json.Marshal(eventexport.Batch{CityID: city, SchemaVersion: eventexport.SchemaVersion, Events: chunk})
	if err != nil {
		return ingestResponse{}, err
	}
	backoff := 2 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return ingestResponse{}, err
		}
		token, err := cfg.Token.Token()
		if err != nil {
			return ingestResponse{}, fmt.Errorf("resolve token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, strings.NewReader(string(body)))
		if err != nil {
			return ingestResponse{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil {
			rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			switch {
			case resp.StatusCode/100 == 2:
				var ir ingestResponse
				_ = json.Unmarshal(rb, &ir)
				return ir, nil
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5:
				// retryable — fall through to backoff
			default:
				return ingestResponse{}, fmt.Errorf("ingest returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
			}
		}
		if !sleep(ctx, backoff) {
			return ingestResponse{}, ctx.Err()
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// archiveSeqRange extracts the (first, last) seq range encoded in a rotated
// archive name of the form events.jsonl.archive-<ts>-seq-<first>-<last>.gz.
var archiveSeqRange = regexp.MustCompile(`-seq-(\d+)-(\d+)\.gz$`)

// DiscoverEventFiles collects a city's recorded event history relevant to the
// (fromSeq, toSeq] window, in ascending seq order: rotated archives from
// .gc/events-archive-cold/ and .gc/ (their names encode their seq range), then
// the live .gc/events.jsonl. toSeq==0 means unbounded.
func DiscoverEventFiles(cityDir string, fromSeq, toSeq uint64) ([]string, error) {
	type ranged struct {
		path  string
		first uint64
	}
	var archives []ranged
	for _, dir := range []string{
		filepath.Join(cityDir, ".gc", "events-archive-cold"),
		filepath.Join(cityDir, ".gc"),
	} {
		names, err := filepath.Glob(filepath.Join(dir, "events.jsonl.archive-*.gz"))
		if err != nil {
			return nil, err
		}
		for _, p := range names {
			m := archiveSeqRange.FindStringSubmatch(p)
			if m == nil {
				continue
			}
			first, err1 := strconv.ParseUint(m[1], 10, 64)
			last, err2 := strconv.ParseUint(m[2], 10, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			if last <= fromSeq || (toSeq > 0 && first > toSeq) {
				continue // entirely outside the window
			}
			archives = append(archives, ranged{path: p, first: first})
		}
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].first < archives[j].first })
	files := make([]string, 0, len(archives)+1)
	for _, a := range archives {
		files = append(files, a.path)
	}
	live := filepath.Join(cityDir, ".gc", "events.jsonl")
	if _, err := os.Stat(live); err == nil {
		files = append(files, live)
	}
	return files, nil
}

// scanEventFile streams one recorded event file (gzip when the name ends in
// .gz), invoking fn per line. Lines up to 8 MiB are supported, matching the SSE
// scanner budget.
func scanEventFile(path string, fn func(line []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}
