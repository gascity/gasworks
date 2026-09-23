package codex

import (
	"strconv"
	"strings"
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

// rolloutUsages returns the USAGE candidates of a parse, in transcript order.
func rolloutUsages(cands []*Candidate) []*evidence.UsageCandidate {
	var usages []*evidence.UsageCandidate
	for _, c := range cands {
		if c.Kind == KindUsage {
			usages = append(usages, c.Usage)
		}
	}
	return usages
}

// TestParseRolloutUsageRecordResponseIDIsJoinKey proves the Codex >= 0.153 join-key contract: each
// token_count USAGE carries the resp_… id of the token_usage_record written just before it (the id
// Manifold stores as spend.message_id), never the assistant output ITEM id (msg_…), including a
// tool-call-only response with no assistant message. A rate-limit-only token_count that repeats
// the previous usage carries no id, so one response id is never fanned across two atoms.
func TestParseRolloutUsageRecordResponseIDIsJoinKey(t *testing.T) {
	res := Parse(readFixture(t, "rollout_usage_record.jsonl"), defaultRefConfig())
	if n := len(res.Diagnostics()); n != 0 {
		t.Fatalf("fixture produced %d diagnostics, want 0", n)
	}
	usages := rolloutUsages(res.Candidates)
	want := []struct {
		messageID string
		input     int64
	}{
		{"resp_fixture1", 1000},
		{"", 1000}, // rate-limit-only token_count repeating response 1's usage
		{"resp_fixture2", 1300},
		{"resp_fixture3", 1400},
	}
	if len(usages) != len(want) {
		t.Fatalf("USAGE count = %d, want %d", len(usages), len(want))
	}
	for i, w := range want {
		if got := usages[i].MessageID; got != w.messageID {
			t.Errorf("usage[%d].message_id = %q, want %q", i, got, w.messageID)
		}
		if usages[i].InputTokens == nil || *usages[i].InputTokens != w.input {
			t.Errorf("usage[%d].input_tokens = %v, want %d", i, usages[i].InputTokens, w.input)
		}
		if strings.HasPrefix(usages[i].MessageID, "msg_") {
			t.Errorf("usage[%d] carries the output item id %q; the join key is the response id", i, usages[i].MessageID)
		}
	}
}

// TestParseRolloutAssistantItemIDIsNotJoinKey pins that an assistant response_item id (the output
// item id, msg_…) is never promoted to message_id when no token_usage_record precedes the usage —
// the shape of Codex 0.153 rollouts whose record was lost and of any pre-0.153 rollout that did
// record item ids. The usage itself is still emitted.
func TestParseRolloutAssistantItemIDIsNotJoinKey(t *testing.T) {
	buf := "" +
		`{"type":"session_meta","timestamp":"2026-07-17T10:00:00Z","payload":{"id":"019cfdea-e7bc-73a1-9871-aae32d212349"}}` + "\n" +
		`{"type":"response_item","timestamp":"2026-07-17T10:00:01Z","payload":{"type":"message","role":"assistant","id":"msg_item123"}}` + "\n" +
		`{"type":"event_msg","timestamp":"2026-07-17T10:00:02Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}}` + "\n"
	usages := rolloutUsages(Parse([]byte(buf), defaultRefConfig()).Candidates)
	if len(usages) != 1 {
		t.Fatalf("USAGE count = %d, want 1", len(usages))
	}
	if usages[0].MessageID != "" {
		t.Fatalf("usage message_id = %q, want empty (an output item id never equals the metered response id)", usages[0].MessageID)
	}
}

// TestParseRolloutUsageRecordDegradesGracefully covers the id-less and hostile record shapes: a
// record without response_id clears a stale latched id, and an over-long or whitespace-bearing id is
// dropped rather than failing the whole USAGE observation's validation. Tokens are always kept.
func TestParseRolloutUsageRecordDegradesGracefully(t *testing.T) {
	long := "resp_" + strings.Repeat("x", maxJoinKeyID)
	tc := `{"type":"event_msg","timestamp":"2026-07-17T10:00:02Z","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}}` + "\n"
	record := func(rid string) string {
		return `{"type":"token_usage_record","timestamp":"2026-07-17T10:00:01Z","payload":{"response_id":` + strconv.Quote(rid) + `}}` + "\n"
	}
	cases := map[string]string{
		"record without response_id clears stale id": record("resp_stale") + `{"type":"token_usage_record","timestamp":"2026-07-17T10:00:01Z","payload":{"turn_id":"t"}}` + "\n" + tc,
		"over-long id":     record(long) + tc,
		"whitespace in id": record("resp_a b") + tc,
		"malformed record": `{"type":"token_usage_record","timestamp":"2026-07-17T10:00:01Z","payload":{"response_id":7}}` + "\n" + tc,
		"empty id":         record("") + tc,
	}
	for name, buf := range cases {
		t.Run(name, func(t *testing.T) {
			res := Parse([]byte(buf), defaultRefConfig())
			if n := len(res.Diagnostics()); n != 0 {
				t.Fatalf("%d diagnostics, want 0", n)
			}
			usages := rolloutUsages(res.Candidates)
			if len(usages) != 1 {
				t.Fatalf("USAGE count = %d, want 1 (the tokens must survive a bad id)", len(usages))
			}
			if usages[0].MessageID != "" {
				t.Fatalf("usage message_id = %q, want empty", usages[0].MessageID)
			}
		})
	}
}

// TestParseRolloutUsageRecordSplitAcrossBuffers pins the documented degradation when a poll lands
// between a token_usage_record and its token_count: parse state is per buffer, so the second buffer's
// USAGE carries no id (heuristic lane) but its tokens are neither lost nor double counted.
func TestParseRolloutUsageRecordSplitAcrossBuffers(t *testing.T) {
	data := readFixture(t, "rollout_usage_record.jsonl")
	lines := strings.SplitAfter(string(data), "\n")
	split := -1
	for i, l := range lines {
		if strings.Contains(l, `"response_id":"resp_fixture2"`) {
			split = i + 1
			break
		}
	}
	if split < 0 {
		t.Fatal("fixture lacks the resp_fixture2 token_usage_record")
	}
	first := rolloutUsages(Parse([]byte(strings.Join(lines[:split], "")), defaultRefConfig()).Candidates)
	second := rolloutUsages(Parse([]byte(strings.Join(lines[split:], "")), defaultRefConfig()).Candidates)
	whole := rolloutUsages(Parse(data, defaultRefConfig()).Candidates)
	if len(first)+len(second) != len(whole) {
		t.Fatalf("split USAGE count = %d+%d, want %d", len(first), len(second), len(whole))
	}
	if got := second[0].MessageID; got != "" {
		t.Fatalf("usage after the split carries %q, want empty (record was in the previous buffer)", got)
	}
	if got := second[1].MessageID; got != "resp_fixture3" {
		t.Fatalf("next response's usage message_id = %q, want resp_fixture3", got)
	}
}

// TestParseRealRolloutHasNoMessageID pins the pre-0.153 default: the real rollout fixture (Codex
// 0.115) writes no token_usage_record, so every USAGE stays exact-lane-ineligible (heuristic
// fallback), unchanged from the pre-join behaviour.
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
