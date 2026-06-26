package eventsaxis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gastownhall/gascity/pkg/eventexport"
)

// rawEvent is the slice of a supervisor SSE event we decode. seq/type/ts/actor/
// subject are always read. Payload is decoded ONLY when content emission is opted
// in (Config.EmitContent): liftContent then extracts the bead title + the opaque
// gc.step_id / run-formula metadata from it. With the opt-in OFF (the default) the
// payload is ignored and no free-form content is lifted — the envelope-only
// contract holds. (run_id/session_id ship empty in v0; we do not decode them.)
type rawEvent struct {
	Seq     uint64          `json:"seq"`
	Type    string          `json:"type"`
	TS      string          `json:"ts"`
	Actor   string          `json:"actor"`
	Subject string          `json:"subject"`
	Payload json.RawMessage `json:"payload"`
}

// beadPayload is the minimal slice of a bead.* event payload read under the
// content opt-in: the human title and the gc.* step/formula metadata.
type beadPayload struct {
	Bead struct {
		Title    string            `json:"title"`
		Metadata map[string]string `json:"metadata"`
	} `json:"bead"`
}

// liftContent extracts the opt-in content/correlation fields from a bead.* event
// payload: the bead title, the opaque gc.step_id, and the run formula name
// (gc.formula_name, else derived from the gc.step_ref "mol-<formula>.<step>"
// prefix). Best-effort: a malformed or absent payload yields empties, never an
// error — a bad payload must never wedge the stream. This is the ONLY place the
// axis reads the SSE payload, reached solely when Config.EmitContent is set.
func liftContent(payload json.RawMessage) (title, stepID, runID, formula string) {
	if len(payload) == 0 {
		return "", "", "", ""
	}
	var bp beadPayload
	if err := json.Unmarshal(payload, &bp); err != nil {
		return "", "", "", ""
	}
	title = bp.Bead.Title
	if m := bp.Bead.Metadata; m != nil {
		// step_id = the work bead's OWN gc.step_id (the logical formula-step). The
		// session's gc.active_work_bead (= manifold.spend.step_id) is the same step
		// for the active bead, so the step->spend join is exact. Work beads carry
		// gc.step_id, never gc.active_work_bead (that lives on the session).
		stepID = m["gc.step_id"]
		// run_id = the run-root bead id (gc.root_bead_id) = beadmeta.ResolveRunID with
		// no workflow_id, so it equals the run_id the spend plane stamps for the run.
		// Without this the events plane has no run key and no run can open.
		runID = m["gc.root_bead_id"]
		// formula = the run's recipe name. Prefer the canonical gc.formula_name (the
		// producer stamps it on the run-root); fall back to deriving it from the
		// step bead's gc.step_ref "mol-<formula>.<step>" prefix until that lands.
		if formula = m["gc.formula_name"]; formula == "" {
			formula = formulaFromStepRef(m["gc.step_ref"])
		}
	}
	return title, stepID, runID, formula
}

// formulaFromStepRef derives the run formula name from a gc.step_ref of the form
// "mol-<formula>.<step>" (e.g. "mol-randy-triage-patrol.apply" -> "randy-triage-patrol").
// Returns "" when the ref is not in that shape.
func formulaFromStepRef(ref string) string {
	const pfx = "mol-"
	if !strings.HasPrefix(ref, pfx) {
		return ""
	}
	rest := ref[len(pfx):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// sseSource implements eventexport.Source. It tails one supervisor SSE stream per
// configured city, multiplexes the decoded TaggedEvents onto a single channel, and
// hands them to the exporter in arrival order. Each city's connection reconnects
// independently with capped backoff and resumes from its last-acked cursor via the
// after_seq query param + Last-Event-ID header.
type sseSource struct {
	supervisor  string
	cities      []string
	client      *http.Client
	cursors     map[string]uint64 // city -> resume seq (last acked)
	logf        func(format string, args ...any)
	emitContent bool // when true, lift bead title + gc.* step/formula off the payload

	events chan eventexport.TaggedEvent
}

// newSSESource starts one tail goroutine per city. cursors seeds each city's
// resume point (after_seq). The source stops when ctx is cancelled; Next then
// returns the channel-closed signal once every tail has exited.
func newSSESource(ctx context.Context, cfg Config, client *http.Client, cursors map[string]uint64, logf func(string, ...any)) *sseSource {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &sseSource{
		supervisor:  cfg.Supervisor,
		cities:      append([]string(nil), cfg.Cities...),
		client:      client,
		cursors:     cursors,
		logf:        logf,
		emitContent: cfg.EmitContent,
		events:      make(chan eventexport.TaggedEvent, 256),
	}
	go s.run(ctx)
	return s
}

// run fans out one tail goroutine per city and closes the events channel only once
// they have all exited (so Next observes a clean end-of-stream on shutdown).
func (s *sseSource) run(ctx context.Context) {
	defer close(s.events)
	done := make(chan struct{}, len(s.cities))
	for _, city := range s.cities {
		go func(city string) {
			defer func() { done <- struct{}{} }()
			s.tailCity(ctx, city)
		}(city)
	}
	for range s.cities {
		<-done
	}
}

// tailCity keeps one city's SSE connection alive, reconnecting with capped backoff
// until ctx is cancelled. A dropped or erroring connection for ONE city never tears
// down the others.
func (s *sseSource) tailCity(ctx context.Context, city string) {
	backoff := defaultReconnect
	for ctx.Err() == nil {
		err := s.streamOnce(ctx, city)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.logf("events: city %s stream error (reconnecting in %s): %v", city, backoff, err)
		}
		if !sleep(ctx, backoff) {
			return
		}
		backoff *= 2
		if backoff > maxReconnect {
			backoff = maxReconnect
		}
	}
}

// streamOnce opens one SSE connection for a city and pumps decoded events onto the
// channel until the connection drops or ctx is cancelled. A successful read resets
// the caller's backoff implicitly (it returns nil on a clean EOF).
func (s *sseSource) streamOnce(ctx context.Context, city string) error {
	cur := s.cursors[city]
	u := fmt.Sprintf("%s%s?after_seq=%d",
		s.supervisor, fmt.Sprintf(defaultStreamPath, url.PathEscape(city)), cur)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if cur > 0 {
		req.Header.Set("Last-Event-ID", strconv.FormatUint(cur, 10))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("stream status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var dataLine string
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Text()
		switch {
		case line == "": // blank line dispatches the buffered event
			if dataLine != "" {
				if !s.dispatch(ctx, city, []byte(dataLine)) {
					return ctx.Err()
				}
				dataLine = ""
			}
		case strings.HasPrefix(line, "data:"):
			dataLine = strings.TrimSpace(line[len("data:"):])
		case strings.HasPrefix(line, ":"):
			// heartbeat / comment — ignore
		default:
			// other SSE fields (id:, event:, retry:) — we resume by query param +
			// Last-Event-ID, so they carry no extra signal we act on.
		}
	}
	return sc.Err()
}

// dispatch decodes one SSE `data:` payload into a TaggedEvent — mapping the typed
// primitive fields, plus (only under the EmitContent opt-in) the bead title +
// gc.step_id/run-formula lifted from the payload via liftContent — and hands it to
// the exporter. It returns false only when ctx is cancelled (shutting down). A
// payload that fails to parse, or whose ts is unparseable, is dropped quietly: the
// projector would reject it anyway, and a malformed line must not kill the stream.
func (s *sseSource) dispatch(ctx context.Context, city string, data []byte) bool {
	var r rawEvent
	if err := json.Unmarshal(data, &r); err != nil {
		return true // malformed line; skip, keep streaming
	}
	te := eventexport.TaggedEvent{
		City:    city,
		Seq:     r.Seq,
		Type:    r.Type,
		Ts:      parseTS(r.TS),
		Actor:   r.Actor,
		Subject: r.Subject,
		// RunID/SessionID intentionally left empty in v0.
	}
	if s.emitContent {
		// The ONLY place this axis reads the SSE payload, reached solely under the
		// content opt-in: lift the bead title + opaque run_id/step_id + run-formula.
		te.Title, te.StepID, te.RunID, te.Formula = liftContent(r.Payload)
	}
	select {
	case s.events <- te:
		return true
	case <-ctx.Done():
		return false
	}
}

// Next yields the next decoded event, blocking until one is available or ctx is
// cancelled. When every city tail has exited and the channel is drained it returns
// io.EOF, which the exporter treats as a clean end-of-stream.
func (s *sseSource) Next(ctx context.Context) (eventexport.TaggedEvent, error) {
	select {
	case <-ctx.Done():
		return eventexport.TaggedEvent{}, ctx.Err()
	case te, ok := <-s.events:
		if !ok {
			return eventexport.TaggedEvent{}, io.EOF
		}
		return te, nil
	}
}

// parseTS parses an RFC3339(Nano) timestamp; an unparseable/empty value yields the
// zero time, which makes ProjectEvent drop the event (it requires a non-zero ts).
func parseTS(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	return time.Time{}
}

// sleep waits d or until ctx is cancelled. It returns false if ctx was cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
