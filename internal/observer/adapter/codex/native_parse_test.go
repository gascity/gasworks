package codex

import (
	"testing"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

func firstSession(t *testing.T, cands []*Candidate) *evidence.SessionLifecycleCandidate {
	t.Helper()
	for _, c := range cands {
		if c.Kind == KindSessionLifecycle {
			return c.SessionLifecycle
		}
	}
	t.Fatalf("no SESSION_LIFECYCLE candidate")
	return nil
}

func firstUsage(t *testing.T, cands []*Candidate) *evidence.UsageCandidate {
	t.Helper()
	for _, c := range cands {
		if c.Kind == KindUsage {
			return c.Usage
		}
	}
	t.Fatalf("no USAGE candidate")
	return nil
}

func assertToken(t *testing.T, field string, got *int64, want int64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is absent, want %d", field, want)
	}
	if *got != want {
		t.Fatalf("%s = %d, want %d", field, *got, want)
	}
}

// TestParseRealCodexRollout proves the daemon parses a REAL Codex rollout-*.jsonl natively — no
// external rollout->normalized translate step. The fixture is a real rollout (session id, model,
// and every token_count delta verbatim; only the system-prompt blobs the parser ignores are
// trimmed). It must yield one STARTED SESSION_LIFECYCLE carrying the native session id and the
// model (which lives on a separate turn_context record) plus one PROVIDER_REPORTED USAGE per
// token_count turn with the real token deltas — the shape that regressed to a lone
// CAPTURE_DIAGNOSTIC before native rollout support.
func TestParseRealCodexRollout(t *testing.T) {
	res := Parse(readFixture(t, "rollout_real.jsonl"), defaultRefConfig())

	counts := kindCounts(res.Candidates)
	if counts[KindDiagnostic] != 0 {
		t.Fatalf("real rollout produced %d diagnostics; native parse must recognize the format", counts[KindDiagnostic])
	}
	if counts[KindSessionLifecycle] != 1 {
		t.Fatalf("SESSION_LIFECYCLE count = %d, want 1", counts[KindSessionLifecycle])
	}
	if counts[KindUsage] != 3 {
		t.Fatalf("USAGE count = %d, want 3 (one per token_count turn)", counts[KindUsage])
	}

	sess := firstSession(t, res.Candidates)
	if got, want := sess.NativeSessionID, "019cfdea-e7bc-73a1-9871-aae32d212349"; got != want {
		t.Fatalf("native_session_id = %q, want %q", got, want)
	}
	if got, want := sess.Provider, "codex"; got != want {
		t.Fatalf("provider = %q, want %q", got, want)
	}
	if got, want := sess.Model, "gpt-5.4"; got != want {
		t.Fatalf("model = %q, want %q (threaded from turn_context)", got, want)
	}
	if sess.Transition != wire.SessionLifecyclePayloadTransitionSTARTED {
		t.Fatalf("transition = %q, want STARTED", sess.Transition)
	}

	// The first token_count turn's real per-turn delta.
	u := firstUsage(t, res.Candidates)
	if u.Quality != wire.UsagePayloadQualityPROVIDERREPORTED {
		t.Fatalf("usage quality = %q, want PROVIDER_REPORTED", u.Quality)
	}
	assertToken(t, "input_tokens", u.InputTokens, 14003)
	assertToken(t, "output_tokens", u.OutputTokens, 451)
	assertToken(t, "cache_read_tokens", u.CacheReadTokens, 5504)
}

// TestParseRealClaudeTranscript proves the daemon captures a REAL Claude Code transcript natively:
// each assistant envelope's message.usage becomes a USAGE, and the parser synthesizes one
// SESSION_LIFECYCLE (Claude writes no dedicated session record) from the camelCase sessionId with
// the model peeked off the first assistant record. This is the primary interactive-session lane.
func TestParseRealClaudeTranscript(t *testing.T) {
	res := Parse(readFixture(t, "claude_real.jsonl"), defaultRefConfig())

	counts := kindCounts(res.Candidates)
	if counts[KindDiagnostic] != 0 {
		t.Fatalf("real claude transcript produced %d diagnostics; native parse must recognize the format", counts[KindDiagnostic])
	}
	if counts[KindSessionLifecycle] != 1 {
		t.Fatalf("SESSION_LIFECYCLE count = %d, want 1 (synthesized once)", counts[KindSessionLifecycle])
	}
	if counts[KindUsage] != 2 {
		t.Fatalf("USAGE count = %d, want 2 (one per assistant message)", counts[KindUsage])
	}

	sess := firstSession(t, res.Candidates)
	if got, want := sess.NativeSessionID, "4f28bfcc-d5ea-485a-97e0-dfde6662febe"; got != want {
		t.Fatalf("native_session_id = %q, want %q", got, want)
	}
	if got, want := sess.Provider, "claude"; got != want {
		t.Fatalf("provider = %q, want %q", got, want)
	}
	if got, want := sess.Model, "claude-opus-4-8"; got != want {
		t.Fatalf("model = %q, want %q", got, want)
	}

	u := firstUsage(t, res.Candidates)
	assertToken(t, "input_tokens", u.InputTokens, 7985)
	assertToken(t, "output_tokens", u.OutputTokens, 543)
	assertToken(t, "cache_creation_tokens", u.CacheCreationTokens, 56613)
	assertToken(t, "cache_read_tokens", u.CacheReadTokens, 0)
}

// TestParseClaudeCapturesMessageID proves the assistant record's provider message.id (msg_…) is
// carried through onto the USAGE candidate as the exact-lane spend-join key. This is the primary
// enabler for promoting a captured atom to metering-grade at read time.
func TestParseClaudeCapturesMessageID(t *testing.T) {
	res := Parse(readFixture(t, "claude_real.jsonl"), defaultRefConfig())
	u := firstUsage(t, res.Candidates)
	if got, want := u.MessageID, "msg_011Ccrx5emXPdkC9TA2qi7eP"; got != want {
		t.Fatalf("usage message_id = %q, want %q (from the assistant message.id)", got, want)
	}
}

// TestParseClaudeUsageWithoutMessageIDStaysAbsent proves an assistant record that omits message.id
// yields a USAGE with no message_id — the id is never fabricated, so the atom is exact-lane-ineligible
// and falls back to the heuristic lane.
func TestParseClaudeUsageWithoutMessageIDStaysAbsent(t *testing.T) {
	line := `{"type":"assistant","sessionId":"s-1","timestamp":"2026-07-17T10:00:00Z","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":5}}}`
	res := Parse([]byte(line+"\n"), defaultRefConfig())
	u := firstUsage(t, res.Candidates)
	if u.MessageID != "" {
		t.Fatalf("usage message_id = %q, want empty when the record has no id", u.MessageID)
	}
}

// TestParseRolloutThreadsResponseIDToUsage proves an assistant response_item's provider response id
// (resp_…) is latched and attached to the NEXT token_count USAGE, and consumed so it is never fanned
// across multiple usage atoms. A token_count with no preceding assistant id stays absent.
func TestParseRolloutThreadsResponseIDToUsage(t *testing.T) {
	buf := "" +
		`{"type":"session_meta","timestamp":"2026-07-17T10:00:00Z","payload":{"id":"019cfdea-e7bc-73a1-9871-aae32d212349"}}` + "\n" +
		`{"type":"response_item","timestamp":"2026-07-17T10:00:01Z","payload":{"type":"message","role":"assistant","id":"resp_abc123"}}` + "\n" +
		`{"type":"event_msg","timestamp":"2026-07-17T10:00:02Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}}` + "\n" +
		`{"type":"event_msg","timestamp":"2026-07-17T10:00:03Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":50,"output_tokens":10,"total_tokens":60}}}}` + "\n"
	res := Parse([]byte(buf), defaultRefConfig())

	var usages []*evidence.UsageCandidate
	for _, c := range res.Candidates {
		if c.Kind == KindUsage {
			usages = append(usages, c.Usage)
		}
	}
	if len(usages) != 2 {
		t.Fatalf("USAGE count = %d, want 2", len(usages))
	}
	if got, want := usages[0].MessageID, "resp_abc123"; got != want {
		t.Fatalf("first usage message_id = %q, want %q (latched from the assistant response_item)", got, want)
	}
	if usages[1].MessageID != "" {
		t.Fatalf("second usage message_id = %q, want empty (the id is consumed, never fanned out)", usages[1].MessageID)
	}
}

// TestParseRealRolloutHasNoMessageID pins the honest default: the real rollout fixture records no
// per-turn response id, so every USAGE stays exact-lane-ineligible (heuristic fallback), unchanged
// from the pre-join behaviour.
func TestParseRealRolloutHasNoMessageID(t *testing.T) {
	res := Parse(readFixture(t, "rollout_real.jsonl"), defaultRefConfig())
	for _, c := range res.Candidates {
		if c.Kind == KindUsage && c.Usage.MessageID != "" {
			t.Fatalf("real rollout usage carried message_id %q; the fixture has no ids", c.Usage.MessageID)
		}
	}
}

// TestParseSessionEmittedBeforeUsage guards the ordering the sink depends on: within any buffer the
// SESSION_LIFECYCLE (which carries the native session id) is delivered before the USAGE records
// that must inherit it, for BOTH native dialects. A usage that preceded its session would be
// stamped with an empty native_session_id and orphaned from the run.
func TestParseSessionEmittedBeforeUsage(t *testing.T) {
	for _, f := range []string{"rollout_real.jsonl", "claude_real.jsonl"} {
		res := Parse(readFixture(t, f), defaultRefConfig())
		sessionIdx, usageIdx := -1, -1
		for i, c := range res.Candidates {
			if c.Kind == KindSessionLifecycle && sessionIdx < 0 {
				sessionIdx = i
			}
			if c.Kind == KindUsage && usageIdx < 0 {
				usageIdx = i
			}
		}
		if sessionIdx < 0 || usageIdx < 0 {
			t.Fatalf("%s: missing session (%d) or usage (%d)", f, sessionIdx, usageIdx)
		}
		if sessionIdx > usageIdx {
			t.Fatalf("%s: SESSION_LIFECYCLE at %d must precede first USAGE at %d", f, sessionIdx, usageIdx)
		}
	}
}
