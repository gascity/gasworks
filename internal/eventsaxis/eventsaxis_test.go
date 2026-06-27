package eventsaxis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/saauth"
	"github.com/gastownhall/gascity/pkg/eventexport"
)

// testSalt is a >=16-byte salt so ProjectEvent does not fail closed.
var testSalt = []byte("events-axis-test-salt-0123456789")

// --- config / egress gate -------------------------------------------------

func TestEnabled_GateRequiresAllThree(t *testing.T) {
	tok := saauth.EnvProvider("t")
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"all set", Config{URL: "https://x/ingest", Cities: []string{"c1"}, Token: tok}, true},
		{"no url", Config{Cities: []string{"c1"}, Token: tok}, false},
		{"no cities", Config{URL: "https://x/ingest", Token: tok}, false},
		{"no token", Config{URL: "https://x/ingest", Cities: []string{"c1"}}, false},
		{"zero value", Config{}, false},
	}
	for _, c := range cases {
		if got := c.cfg.Enabled(); got != c.want {
			t.Errorf("%s: Enabled()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestURLOK(t *testing.T) {
	cases := []struct {
		url       string
		allowHTTP bool
		want      bool
	}{
		{"https://ingest.gasworks.dev/v0/events", false, true},
		{"http://ingest.gasworks.dev/v0/events", false, false},
		{"http://localhost:9000/ingest", true, true},
		{"http://127.0.0.1:9000/ingest", true, true},
		{"http://evil.example.com/ingest", true, false}, // non-loopback http rejected even with allow
		{"ftp://x/y", false, false},
		{"://bad", false, false},
	}
	for _, c := range cases {
		if got := URLOK(c.url, c.allowHTTP); got != c.want {
			t.Errorf("URLOK(%q,%v)=%v want %v", c.url, c.allowHTTP, got, c.want)
		}
	}
}

func TestSupervisorLoopback(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8372", "http://localhost:8372", "http://[::1]:8372"} {
		if !supervisorLoopback(ok) {
			t.Errorf("supervisorLoopback(%q)=false, want true", ok)
		}
	}
	for _, bad := range []string{"http://cherry.tail3127c0.ts.net:8372", "https://supervisor.example.com"} {
		if supervisorLoopback(bad) {
			t.Errorf("supervisorLoopback(%q)=true, want false", bad)
		}
	}
}

func TestSplitCities_DedupAndOrder(t *testing.T) {
	got := splitCities("maintainer-city, paxel maintainer-city\nfoo,, paxel")
	want := []string{"maintainer-city", "paxel", "foo"}
	if len(got) != len(want) {
		t.Fatalf("splitCities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCities = %v, want %v", got, want)
		}
	}
}

// TestRunner_DisabledNeverDials proves the (M18) egress gate: with no endpoint the
// axis returns idle and never constructs a client or dials. We back the would-be
// client with a RoundTripper that fails the test if it is ever invoked.
func TestRunner_DisabledNeverDials(t *testing.T) {
	var dialed int32
	r := NewRunner(Config{ /* no URL, no cities, no token => disabled */ }, nil)
	if r.client != nil {
		t.Fatal("disabled axis constructed an http client (must stay nil until Enabled)")
	}
	// Force a client with a tripwire transport; Run must still not use it because the
	// axis is disabled and returns before building the source.
	r.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&dialed, 1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("disabled Run returned error: %v", err)
	}
	if n := atomic.LoadInt32(&dialed); n != 0 {
		t.Fatalf("disabled axis dialed %d times (must never dial)", n)
	}
}

// --- end-to-end SSE -> redacted batch ------------------------------------

// sseEvent is the supervisor's on-the-wire event shape (a superset; the source must
// only ever read the typed primitive fields). Message/Payload carry free-form
// content that must NEVER reach the exported batch.
type sseEvent struct {
	Seq       uint64 `json:"seq"`
	Type      string `json:"type"`
	TS        string `json:"ts"`
	Actor     string `json:"actor"`
	Subject   string `json:"subject"`
	RunID     string `json:"run_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`
	Message   string `json:"message,omitempty"`
	Payload   string `json:"payload,omitempty"`
}

// sseServer streams a fixed slice of events as SSE for one city, honoring after_seq,
// then holds the connection open (heartbeats) so the exporter keeps a live stream
// until the test cancels it.
func sseServer(t *testing.T, events []sseEvent) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, ": connected\n\n") // heartbeat comment (must be ignored)
		fl.Flush()
		for _, ev := range events {
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.Seq, b)
			fl.Flush()
		}
		// keep the stream open until the client disconnects
		<-r.Context().Done()
	}))
}

// ingestCapture is the events-ingest stand-in: it records every Batch it receives
// plus the Authorization header.
type ingestCapture struct {
	mu      sync.Mutex
	batches []eventexport.Batch
	auth    string
	bodies  []string
}

func (c *ingestCapture) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var b eventexport.Batch
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auth = r.Header.Get("Authorization")
	c.bodies = append(c.bodies, string(body))
	if json.Unmarshal(body, &b) == nil {
		c.batches = append(c.batches, b)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ingestCapture) snapshot() ([]eventexport.Batch, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]eventexport.Batch(nil), c.batches...), c.auth, strings.Join(c.bodies, "")
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// TestRunner_ProjectsRedactsAndAdvancesCursor is the core e2e: an SSE stream of
// events (some non-allowlisted, all carrying free-form Message/Payload) flows
// through the real source + the pkg exporter to the ingest capture. It asserts:
//   - the batch SchemaVersion == eventexport.SchemaVersion;
//   - only allowlisted types appear; bead.updated is dropped;
//   - the actor cleartext is replaced by a hash;
//   - NO Message/Payload substring reaches the wire (the leak test);
//   - the cursor advances PAST the dropped event;
//   - the bearer is sent.
func TestRunner_ProjectsRedactsAndAdvancesCursor(t *testing.T) {
	const (
		secretMsg     = "DELETE FROM users -- free form bead title"
		secretPayload = "api_key=sk-live-supersecret-7f39"
	)
	events := []sseEvent{
		{Seq: 1, Type: "bead.closed", TS: "2026-06-21T10:00:00Z", Actor: "alice@corp.example", Subject: "mc-wisp-i6vz0e", Message: secretMsg, Payload: secretPayload},
		{Seq: 2, Type: "bead.updated", TS: "2026-06-21T10:00:01Z", Actor: "bob", Subject: "mc-2", Message: secretMsg, Payload: secretPayload}, // DROPPED (not allowlisted)
		{Seq: 3, Type: "order.completed", TS: "2026-06-21T10:00:02Z", Actor: "carol", Subject: "nightly-sweep-slug", Message: secretMsg, Payload: secretPayload},
		{Seq: 4, Type: "mail.sent", TS: "2026-06-21T10:00:03Z", Actor: "dave@x", Subject: "re: secret thread", Message: secretMsg}, // reduced to {seq,type,ts}
	}
	sse := sseServer(t, events)
	defer sse.Close()
	ing := &ingestCapture{}
	ingest := httptest.NewServer(http.HandlerFunc(ing.handler))
	defer ingest.Close()

	cfg := Config{
		URL:           ingest.URL,
		Supervisor:    sse.URL,
		Cities:        []string{"c1"},
		Token:         saauth.EnvProvider("events-bearer-xyz"),
		Salt:          testSalt,
		ExportRef:     true,
		StatePath:     t.TempDir() + "/cursors.json",
		BatchMax:      100,
		BatchInterval: 15 * time.Millisecond,
		AllowHTTP:     true, // httptest ingest is plain http on loopback
	}
	r := NewRunner(cfg, func(string, ...any) {})
	r.client = sse.Client()        // SSE tail client (no timeout)
	r.postClient = ingest.Client() // ingest POST client (distinct, bounded) reaches the capture server

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()

	// cursor must reach 4 (advancing PAST the dropped seq 2).
	waitFor(t, 3*time.Second, func() bool {
		bs, _, _ := ing.snapshot()
		var maxSeq uint64
		for _, b := range bs {
			for _, e := range b.Events {
				if e.Seq > maxSeq {
					maxSeq = e.Seq
				}
			}
		}
		return maxSeq >= 4
	})
	cancel()
	<-done

	batches, auth, blob := ing.snapshot()
	if auth != "Bearer events-bearer-xyz" {
		t.Fatalf("auth header = %q, want the events bearer", auth)
	}

	var types []string
	var sawSeq2 bool
	for _, b := range batches {
		if b.CityID != "c1" {
			t.Fatalf("batch city_id = %q, want c1", b.CityID)
		}
		if b.SchemaVersion != eventexport.SchemaVersion {
			t.Fatalf("batch schema_version = %d, want %d", b.SchemaVersion, eventexport.SchemaVersion)
		}
		for _, e := range b.Events {
			types = append(types, e.Type)
			if e.Seq == 2 {
				sawSeq2 = true
			}
		}
	}
	if sawSeq2 {
		t.Fatal("seq 2 (bead.updated) must be dropped, not exported")
	}
	if strings.Contains(strings.Join(types, ","), "bead.updated") {
		t.Fatalf("non-allowlisted type exported: %v", types)
	}

	// THE LEAK TEST: no free-form content (Message/Payload, raw actor cleartext,
	// non-opaque subject) may appear anywhere in the bytes that crossed the wire.
	for _, forbidden := range []string{
		secretMsg, secretPayload,
		"DELETE FROM", "sk-live", "api_key",
		"alice@corp.example", "bob", "carol", "dave@x", // raw actor cleartext
		"nightly-sweep-slug",     // non-opaque subject for order.completed (no ref)
		"re: secret thread",      // mail subject
		`"message"`, `"payload"`, // the field names must not even appear
	} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("LEAK: forbidden substring %q reached the wire:\n%s", forbidden, blob)
		}
	}

	// A bead.closed with ExportRef MUST carry its opaque ref (proves ref path works
	// while non-opaque subjects above are still dropped).
	var sawRef bool
	for _, b := range batches {
		for _, e := range b.Events {
			if e.Type == "bead.closed" && e.Ref == "mc-wisp-i6vz0e" {
				sawRef = true
			}
			// actor must be hashed (16 hex) or empty, never cleartext.
			if e.ActorHash != "" && len(e.ActorHash) != 16 {
				t.Fatalf("actor_hash %q is not 16 hex (cleartext leak?)", e.ActorHash)
			}
		}
	}
	if !sawRef {
		t.Fatal("bead.closed opaque ref mc-wisp-i6vz0e was not exported (ExportRef path broken)")
	}

	// Every received batch must pass the receiver-side validation (defense in depth).
	for _, b := range batches {
		if err := eventexport.ValidateBatch(b); err != nil {
			t.Fatalf("ValidateBatch rejected an exported batch: %v", err)
		}
	}

	// The cursor file must persist progress to 4.
	cur := eventexport.LoadCursors(cfg.StatePath)
	if cur["c1"] != 4 {
		t.Fatalf("persisted cursor for c1 = %d, want 4", cur["c1"])
	}
}

// TestSource_HeartbeatAndMalformedTolerated proves the SSE source ignores heartbeat
// comments and skips a malformed data line without killing the stream.
func TestSource_HeartbeatAndMalformedTolerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, ": heartbeat\n\n")
		fmt.Fprint(w, "data: {not json}\n\n") // malformed; must be skipped
		fmt.Fprint(w, "retry: 1000\n\n")      // non-data field; ignored
		fmt.Fprintf(w, "data: %s\n\n", `{"seq":7,"type":"session.woke","ts":"2026-06-21T10:00:00Z","actor":"sys"}`)
		fl.Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := newSSESource(ctx, Config{Supervisor: srv.URL, Cities: []string{"c1"}}, srv.Client(), map[string]uint64{}, nil)

	te, err := src.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if te.Seq != 7 || te.Type != "session.woke" || te.City != "c1" {
		t.Fatalf("decoded event = %+v, want seq7 session.woke c1", te)
	}
	if !te.Ts.Equal(mustTime("2026-06-21T10:00:00Z")) {
		t.Fatalf("ts = %v, want parsed RFC3339", te.Ts)
	}
	// This envelope carries no correlation ids and there is no content opt-in, so the
	// projected event stays empty (the producer simply didn't stamp them).
	if te.RunID != "" || te.SessionID != "" || te.StepID != "" {
		t.Fatalf("correlation ids must be empty when the envelope omits them, got %q/%q/%q", te.RunID, te.SessionID, te.StepID)
	}
}

// TestDispatch_EnvelopeCorrelation proves run_id/session_id/step_id are read off the
// envelope with no content opt-in, that the payload metadata is only a fallback for
// producers that omit them, and that the envelope value always wins.
func TestDispatch_EnvelopeCorrelation(t *testing.T) {
	cases := []struct {
		name                           string
		data                           string
		emitContent                    bool
		wantRun, wantSession, wantStep string
	}{
		{
			name:    "envelope ids, no content opt-in",
			data:    `{"seq":1,"type":"bead.created","ts":"2026-06-27T00:00:00Z","actor":"a","run_id":"mc-root","session_id":"mc-sess","step_id":"synthesize"}`,
			wantRun: "mc-root", wantSession: "mc-sess", wantStep: "synthesize",
		},
		{
			name:        "no envelope ids + content opt-in -> payload fallback for run/step, session empty",
			data:        `{"seq":2,"type":"bead.created","ts":"2026-06-27T00:00:00Z","actor":"a","payload":{"bead":{"title":"T","metadata":{"gc.root_bead_id":"mc-fallback","gc.step_id":"apply"}}}}`,
			emitContent: true,
			wantRun:     "mc-fallback", wantStep: "apply",
		},
		{
			name:        "envelope wins over payload metadata",
			data:        `{"seq":3,"type":"bead.created","ts":"2026-06-27T00:00:00Z","actor":"a","run_id":"mc-env","step_id":"env-step","payload":{"bead":{"metadata":{"gc.root_bead_id":"mc-payload","gc.step_id":"payload-step"}}}}`,
			emitContent: true,
			wantRun:     "mc-env", wantStep: "env-step",
		},
		{
			name: "no envelope ids, no content opt-in -> empty",
			data: `{"seq":4,"type":"session.woke","ts":"2026-06-27T00:00:00Z","actor":"a"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sseSource{events: make(chan eventexport.TaggedEvent, 1), emitContent: tc.emitContent}
			if !s.dispatch(context.Background(), "c1", []byte(tc.data)) {
				t.Fatal("dispatch returned false without a ctx cancel")
			}
			te := <-s.events
			if te.RunID != tc.wantRun {
				t.Errorf("RunID = %q, want %q", te.RunID, tc.wantRun)
			}
			if te.SessionID != tc.wantSession {
				t.Errorf("SessionID = %q, want %q", te.SessionID, tc.wantSession)
			}
			if te.StepID != tc.wantStep {
				t.Errorf("StepID = %q, want %q", te.StepID, tc.wantStep)
			}
		})
	}
}

// TestRunner_EmitsEnvelopeCorrelation proves the opaque envelope correlation ids flow
// end-to-end through the projection under EmitCorrelation — WITHOUT the content opt-in —
// and are withheld when EmitCorrelation is off.
func TestRunner_EmitsEnvelopeCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name            string
		emitCorrelation bool
		wantRun         string
	}{
		{"correlation on -> run_id flows", true, "mc-root-bead"},
		{"correlation off -> envelope-minimal", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []sseEvent{{
				Seq: 1, Type: "bead.closed", TS: "2026-06-27T10:00:00Z", Actor: "alice", Subject: "mc-wisp-1",
				RunID: "mc-root-bead", SessionID: "mc-sess-bead", StepID: "synthesize",
			}}
			sse := sseServer(t, events)
			defer sse.Close()
			ing := &ingestCapture{}
			ingest := httptest.NewServer(http.HandlerFunc(ing.handler))
			defer ingest.Close()

			cfg := Config{
				URL: ingest.URL, Supervisor: sse.URL, Cities: []string{"c1"},
				Token: saauth.EnvProvider("b"), Salt: testSalt,
				ExportRef:       true,
				EmitCorrelation: tc.emitCorrelation, // EmitContent stays OFF
				StatePath:       t.TempDir() + "/cursors.json",
				BatchMax:        100, BatchInterval: 15 * time.Millisecond, AllowHTTP: true,
			}
			r := NewRunner(cfg, func(string, ...any) {})
			r.client = sse.Client()
			r.postClient = ingest.Client()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { _ = r.Run(ctx); close(done) }()
			waitFor(t, 3*time.Second, func() bool {
				bs, _, _ := ing.snapshot()
				for _, b := range bs {
					for _, e := range b.Events {
						if e.Seq == 1 {
							return true
						}
					}
				}
				return false
			})
			cancel()
			<-done

			batches, _, blob := ing.snapshot()
			var gotRun, gotSession, gotStep string
			for _, b := range batches {
				for _, e := range b.Events {
					if e.Seq == 1 {
						gotRun, gotSession, gotStep = e.RunID, e.SessionID, e.StepID
					}
				}
			}
			if gotRun != tc.wantRun {
				t.Fatalf("exported run_id = %q, want %q", gotRun, tc.wantRun)
			}
			if tc.emitCorrelation {
				if gotSession != "mc-sess-bead" || gotStep != "synthesize" {
					t.Fatalf("exported session/step = %q/%q, want mc-sess-bead/synthesize", gotSession, gotStep)
				}
			} else if gotSession != "" || gotStep != "" {
				t.Fatalf("correlation off: session/step must be empty, got %q/%q", gotSession, gotStep)
			}
			// EmitContent is OFF, so no free-form content rides along even with correlation on.
			if strings.Contains(blob, `"title"`) || strings.Contains(blob, `"formula"`) {
				t.Fatalf("content leaked with EmitContent off:\n%s", blob)
			}
		})
	}
}

func mustTime(s string) time.Time {
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return tm
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
