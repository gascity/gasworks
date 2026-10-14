//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// attributionFixture is one real-shaped transcript and where it lives under the approved root. The
// codex adapter's testdata holds them: real Claude Code and Codex transcripts with every piece of
// content stripped (prompts, thinking, text, tool inputs and outputs, paths) and only their shape
// kept — record types and order, record lineage, models, stop reasons and usage — with every id
// remapped and every timestamp shifted to a fixed base, gaps preserved.
type attributionFixture struct {
	file, locator, provider string
}

var attributionFixtures = []attributionFixture{
	// A main Claude Code session: model-less records first, the model only ~19s in, every response's
	// final usage repeated on each of its records, a <synthetic> placeholder mid-session.
	{"claude_main_session.jsonl", "projects/p/session-main.jsonl", "claude"},
	// A subagent that streams partial usage, writes responses without a stop_reason, and rewrites its
	// whole history into the file when it is resumed.
	{"claude_subagent_replay.jsonl", "projects/p/subagents/agent-replay.jsonl", "claude"},
	// A subagent excerpt (tail-only, as a mid-file resume sees it) with concurrent responses.
	{"claude_subagent_concurrent.jsonl", "projects/p/subagents/agent-concurrent.jsonl", "claude"},
	// A Codex 0.153 rollout: the model on turn_context after session_meta, cached input on records.
	{"codex_rollout_session.jsonl", "sessions/rollout-own.jsonl", "codex"},
	// A forked Codex 0.154 rollout carrying its parent's session_meta after its own.
	{"codex_forked_rollout.jsonl", "sessions/rollout-fork.jsonl", "codex"},
}

// expectedAttribution is what pricing needs from one transcript, computed straight from its bytes
// in one batch pass — independent of the streaming parser, its cursor state and the sink.
type expectedAttribution struct {
	session string
	model   string
	startAt time.Time
	usage   map[string][4]int64 // message id -> input, output, cache write, cache read
}

// expectAttribution computes a fixture's expected attribution the way a batch reader would: the
// transcript's own session, the first real model, the session's earliest record time up to that
// model, and one usage per message id — Claude's from the message's LAST record, Codex's from each
// token_usage_record with input made fresh (input - cached).
func expectAttribution(t *testing.T, data []byte, provider string) expectedAttribution {
	t.Helper()
	exp := expectedAttribution{usage: map[string][4]int64{}}
	type usage struct {
		Input      int64 `json:"input_tokens"`
		Cached     int64 `json:"cached_input_tokens"`
		Output     int64 `json:"output_tokens"`
		CacheWrite int64 `json:"cache_creation_input_tokens"`
		CacheRead  int64 `json:"cache_read_input_tokens"`
	}
	var rec struct {
		Type      string     `json:"type"`
		SessionID string     `json:"sessionId"`
		Timestamp *time.Time `json:"timestamp"`
		Message   *struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Usage *usage `json:"usage"`
		} `json:"message"`
		Payload *struct {
			ID         string `json:"id"`
			Model      string `json:"model"`
			ResponseID string `json:"response_id"`
			Usage      *usage `json:"usage"`
		} `json:"payload"`
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rec.Type, rec.SessionID, rec.Timestamp, rec.Message, rec.Payload = "", "", nil, nil, nil
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("fixture line: %v", err)
		}
		switch provider {
		case "claude":
			if exp.session == "" && rec.SessionID != "" {
				exp.session = rec.SessionID
			}
			if exp.model == "" && rec.Timestamp != nil && (exp.startAt.IsZero() || rec.Timestamp.Before(exp.startAt)) {
				exp.startAt = *rec.Timestamp
			}
			if rec.Type != "assistant" || rec.Message == nil {
				continue
			}
			if exp.model == "" && rec.Message.Model != "" && rec.Message.Model != "<synthetic>" {
				exp.model = rec.Message.Model
			}
			if u := rec.Message.Usage; u != nil && u.Input+u.Output+u.CacheWrite+u.CacheRead > 0 {
				exp.usage[rec.Message.ID] = [4]int64{u.Input, u.Output, u.CacheWrite, u.CacheRead}
			}
		case "codex":
			switch {
			case rec.Type == "session_meta" && exp.session == "":
				exp.session, exp.startAt = rec.Payload.ID, *rec.Timestamp
			case rec.Type == "turn_context" && exp.model == "":
				exp.model = rec.Payload.Model
			case rec.Type == "token_usage_record":
				u := rec.Payload.Usage
				exp.usage[rec.Payload.ResponseID] = [4]int64{max(u.Input-u.Cached, 0), u.Output, 0, u.Cached}
			}
		}
	}
	if exp.session == "" || exp.model == "" || len(exp.usage) == 0 {
		t.Fatalf("fixture yields no expectation: %+v", exp)
	}
	return exp
}

// TestTranscriptUsageAttributionEndToEnd is the composition proof for pricing-grade capture: real
// watcher, real cursor state, the production partial sink, and a real daemon spool, fed
// real-shaped transcripts as they grow — in small reads that split records, with a daemon restart
// (fresh watcher and sink over the same cursor and spool directories) part way — then quiet long
// enough for the settle. Every transcript must land as exactly one start that carries its model and
// its original start time, delivered before its usage; one usage per message id equal to the batch
// computation; and every one of those observations attributed to the transcript's session and
// stamped with the parser version (which the hook's start never carries).
func TestTranscriptUsageAttributionEndToEnd(t *testing.T) {
	spoolDir, root, cursors := t.TempDir(), t.TempDir(), t.TempDir()
	srv := startDaemonServer(t, spoolDir, newSpoolWriter(t, spoolDir), NewRegistry("src_test", "ws_main"))
	clock := time.Now()
	const readChunk = 1024
	newWatcher := func() *codex.Watcher {
		w, err := codex.NewWatcher(codex.WatchConfig{
			ApprovedRoots: []string{root},
			StateDir:      cursors,
			Sink:          NewPartialCandidateSinkAdapter(newSink(t, local.NewClient(srv.SocketPath()))),
			References:    codex.ReferenceConfig{Resolver: evidence.ProjectResolver{DefaultProjectID: "proj_test"}},
			MaxReadChunk:  readChunk,
			Now:           func() time.Time { return clock },
		})
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		return w
	}

	contents := map[string][]byte{}
	expected := map[string]expectedAttribution{}
	largest := 0
	for _, f := range attributionFixtures {
		data, err := os.ReadFile(filepath.Join("..", "adapter", "codex", "testdata", f.file))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		contents[f.locator] = data
		expected[f.locator] = expectAttribution(t, data, f.provider)
		largest = max(largest, len(data))
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f.locator)), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	// Every transcript grows in three appends cut at arbitrary byte offsets (mid-record), and the
	// daemon restarts after the first. Each phase polls enough times to read every byte.
	ctx := context.Background()
	watcher := newWatcher()
	pollAll := func() {
		t.Helper()
		for range largest/readChunk + 3 {
			if err := watcher.Poll(ctx); err != nil {
				t.Fatalf("Poll: %v", err)
			}
		}
	}
	for phase, cut := range [][2]float64{{0, 0.37}, {0.37, 0.71}, {0.71, 1}} {
		for _, f := range attributionFixtures {
			data := contents[f.locator]
			chunk := data[int(cut[0]*float64(len(data))):int(cut[1]*float64(len(data)))]
			fh, err := os.OpenFile(filepath.Join(root, f.locator), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if _, err := fh.Write(chunk); err != nil {
				t.Fatalf("append: %v", err)
			}
			_ = fh.Close()
		}
		pollAll()
		if phase == 0 {
			watcher = newWatcher()
		}
	}
	// The transcripts go quiet: a response still waiting for its final record settles.
	clock = clock.Add(24 * time.Hour)
	pollAll()

	type started struct {
		seq   int64
		obs   wire.SessionLifecycleObservation
		count int
	}
	starts := map[string]*started{}
	usages := map[string][]wire.UsageObservation{}
	for _, fr := range readWAL(t, spoolDir) {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		kind, err := obs.Discriminator()
		if err != nil {
			t.Fatalf("discriminator: %v", err)
		}
		switch kind {
		case string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE):
			s, err := obs.AsSessionLifecycleObservation()
			if err != nil {
				t.Fatalf("AsSessionLifecycleObservation: %v", err)
			}
			loc := derefStr(s.Provenance.SourceLocator)
			if starts[loc] == nil {
				starts[loc] = &started{seq: s.Sequence, obs: s}
			}
			starts[loc].count++
		case string(wire.ObservationEnvelopeKindUSAGE):
			u, err := obs.AsUsageObservation()
			if err != nil {
				t.Fatalf("AsUsageObservation: %v", err)
			}
			usages[derefStr(u.Provenance.SourceLocator)] = append(usages[derefStr(u.Provenance.SourceLocator)], u)
		case string(wire.ObservationEnvelopeKindCAPTUREDIAGNOSTIC):
			t.Fatalf("real-shaped transcripts produced a capture diagnostic: %s", fr.Payload)
		}
	}

	for _, f := range attributionFixtures {
		exp := expected[f.locator]
		s := starts[f.locator]
		if s == nil || s.count != 1 {
			t.Fatalf("%s: %v session starts, want exactly 1", f.file, s)
		}
		p := s.obs.SessionLifecycle
		if p.NativeSessionId != exp.session || p.Provider != f.provider || p.Model == nil || *p.Model != exp.model {
			t.Fatalf("%s: start = %s/%s/%v, want %s/%s/%s", f.file, p.NativeSessionId, p.Provider, p.Model, exp.session, f.provider, exp.model)
		}
		if !s.obs.OccurredAt.Equal(exp.startAt) {
			t.Fatalf("%s: start occurred_at = %v, want the transcript's start %v", f.file, s.obs.OccurredAt, exp.startAt)
		}
		if derefStr(s.obs.Provenance.ParserVersion) != codex.ParserVersion {
			t.Fatalf("%s: start parser_version = %q, want %q", f.file, derefStr(s.obs.Provenance.ParserVersion), codex.ParserVersion)
		}

		got := map[string][4]int64{}
		for _, u := range usages[f.locator] {
			id := derefStr(u.Usage.MessageId)
			if _, dup := got[id]; dup {
				t.Fatalf("%s: message %q counted twice", f.file, id)
			}
			got[id] = [4]int64{derefInt(u.Usage.InputTokens), derefInt(u.Usage.OutputTokens), derefInt(u.Usage.CacheCreationTokens), derefInt(u.Usage.CacheReadTokens)}
			if nativeOf(u) != exp.session || derefStr(u.Provenance.Provider) != f.provider {
				t.Fatalf("%s: usage %q attributed to %q/%q, want %s/%s", f.file, id, nativeOf(u), derefStr(u.Provenance.Provider), exp.session, f.provider)
			}
			if derefStr(u.Provenance.ParserVersion) != codex.ParserVersion {
				t.Fatalf("%s: usage %q parser_version = %q", f.file, id, derefStr(u.Provenance.ParserVersion))
			}
			if u.Sequence <= s.seq {
				t.Fatalf("%s: usage %q at sequence %d precedes the start at %d", f.file, id, u.Sequence, s.seq)
			}
		}
		if len(got) != len(exp.usage) {
			t.Fatalf("%s: %d usage atoms, want %d", f.file, len(got), len(exp.usage))
		}
		for id, want := range exp.usage {
			if got[id] != want {
				t.Fatalf("%s: usage %q = %v, want %v (input, output, cache write, cache read)", f.file, id, got[id], want)
			}
		}
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// TestTranscriptUsageExactAcrossAPartialDeliveryFailure drives the watcher's partial-commit retry
// through the production sink: one transcript line counts two Claude responses (the next request
// closes the previous response, which never got a stop_reason, and finishes itself), and the
// daemon fails the second append. The retry re-reads that whole line; each response must still be
// durable exactly once.
func TestTranscriptUsageExactAcrossAPartialDeliveryFailure(t *testing.T) {
	spoolDir, root, cursors := t.TempDir(), t.TempDir(), t.TempDir()
	spool := &failOnNthSpool{inner: newSpoolWriter(t, spoolDir), n: 3} // start, msg_A, then msg_B fails
	srv := startDaemonServer(t, spoolDir, spool, NewRegistry("src_test", "ws_main"))
	w, err := codex.NewWatcher(codex.WatchConfig{
		ApprovedRoots: []string{root},
		StateDir:      cursors,
		Sink:          NewPartialCandidateSinkAdapter(newSink(t, local.NewClient(srv.SocketPath()))),
		References:    codex.ReferenceConfig{Resolver: evidence.ProjectResolver{DefaultProjectID: "proj_test"}},
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	const rec = `{"type":%q,"uuid":%q,"parentUuid":%s,"sessionId":"s-partial","timestamp":"2026-09-01T10:00:0%dZ","message":%s}` + "\n"
	assistant := func(id, stop string, out int) string {
		return fmt.Sprintf(`{"role":"assistant","id":%q,"model":"claude-opus-5-5","stop_reason":%s,"usage":{"input_tokens":2,"output_tokens":%d},"content":[{"type":"text"}]}`, id, stop, out)
	}
	transcript := fmt.Sprintf(rec, "assistant", "a1", "null", 1, assistant("msg_A", "null", 5)) +
		fmt.Sprintf(rec, "user", "a2", `"a1"`, 2, `{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}`) +
		fmt.Sprintf(rec, "assistant", "b1", `"a2"`, 3, assistant("msg_B", `"end_turn"`, 9))
	if err := os.WriteFile(filepath.Join(root, "s.jsonl"), []byte(transcript), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx := context.Background()
	if err := w.Poll(ctx); err == nil {
		t.Fatal("the injected append failure was not reported")
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("retry: %v", err)
	}
	starts, usages := 0, map[string]int64{}
	for _, fr := range readWAL(t, spoolDir) {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		switch kind, _ := obs.Discriminator(); kind {
		case string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE):
			starts++
		case string(wire.ObservationEnvelopeKindUSAGE):
			u, _ := obs.AsUsageObservation()
			id := derefStr(u.Usage.MessageId)
			if _, dup := usages[id]; dup {
				t.Fatalf("usage %s appended twice", id)
			}
			usages[id] = derefInt(u.Usage.OutputTokens)
		}
	}
	if starts != 1 || len(usages) != 2 || usages["msg_A"] != 5 || usages["msg_B"] != 9 {
		t.Fatalf("durable: %d starts, usages %v; want 1 start, msg_A=5 and msg_B=9", starts, usages)
	}
}
