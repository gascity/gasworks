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

// rawEvent is the MINIMAL slice of a supervisor SSE event we ever decode. These
// are the ONLY fields that may cross into a projectable TaggedEvent. Message,
// Payload, and every other field on the wire are deliberately absent here — the
// JSON decoder discards them, so free-form content can never be lifted into the
// envelope. (The supervisor ships run_id/session_id empty in v0; we do not decode
// them — that is the deferred typed-field follow-up.)
type rawEvent struct {
	Seq     uint64 `json:"seq"`
	Type    string `json:"type"`
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Subject string `json:"subject"`
}

// sseSource implements eventexport.Source. It tails one supervisor SSE stream per
// configured city, multiplexes the decoded TaggedEvents onto a single channel, and
// hands them to the exporter in arrival order. Each city's connection reconnects
// independently with capped backoff and resumes from its last-acked cursor via the
// after_seq query param + Last-Event-ID header.
type sseSource struct {
	supervisor string
	cities     []string
	client     *http.Client
	cursors    map[string]uint64 // city -> resume seq (last acked)
	logf       func(format string, args ...any)

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
		supervisor: cfg.Supervisor,
		cities:     append([]string(nil), cfg.Cities...),
		client:     client,
		cursors:    cursors,
		logf:       logf,
		events:     make(chan eventexport.TaggedEvent, 256),
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

// dispatch decodes one SSE `data:` payload into a TaggedEvent — mapping ONLY the
// typed primitive fields, never Message/Payload — and hands it to the exporter. It
// returns false only when ctx is cancelled (the source is shutting down). A
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
