package codex

import (
	"fmt"
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

// rolloutUsageWant is the expected projection of one Codex USAGE atom.
type rolloutUsageWant struct {
	messageID             string
	input, cached, output int64
}

func assertRolloutUsages(t *testing.T, usages []*evidence.UsageCandidate, want []rolloutUsageWant) {
	t.Helper()
	if len(usages) != len(want) {
		t.Fatalf("USAGE count = %d, want %d", len(usages), len(want))
	}
	for i, w := range want {
		u := usages[i]
		if u.MessageID != w.messageID {
			t.Errorf("usage[%d].message_id = %q, want %q", i, u.MessageID, w.messageID)
		}
		assertToken(t, "input_tokens", u.InputTokens, w.input)
		assertToken(t, "cache_read_tokens", u.CacheReadTokens, w.cached)
		assertToken(t, "output_tokens", u.OutputTokens, w.output)
		if u.CacheCreationTokens != nil {
			t.Errorf("usage[%d].cache_creation_tokens = %d, want absent", i, *u.CacheCreationTokens)
		}
		if strings.HasPrefix(u.MessageID, "msg_") {
			t.Errorf("usage[%d] carries the output item id %q; the join key is the response id", i, u.MessageID)
		}
	}
}

// usageSum totals input/cached/output over atoms, for exactly-once comparisons.
func usageSum(usages []*evidence.UsageCandidate) (in, cached, out int64) {
	for _, u := range usages {
		if u.InputTokens != nil {
			in += *u.InputTokens
		}
		if u.CacheReadTokens != nil {
			cached += *u.CacheReadTokens
		}
		if u.OutputTokens != nil {
			out += *u.OutputTokens
		}
	}
	return in, cached, out
}

// fixtureRolloutWant is rollout_usage_record.jsonl's per-response usage: one atom per
// token_usage_record, keyed on its resp_… id, with cached input mapped to cache_read and
// reasoning (already inside output_tokens) not added again.
var fixtureRolloutWant = []rolloutUsageWant{
	{"resp_fixture1", 1000, 200, 50},
	{"resp_fixture2", 1300, 1000, 20},
	{"resp_fixture3", 1400, 1300, 10},
}

// TestParseRolloutUsageFromUsageRecords proves the Codex >= 0.153 contract: usage atoms come from
// token_usage_record (one per completed response, message_id = its response id), never from
// token_count. The fixture's rate-limit-only token_count that repeats response 1's usage at the
// start of turn 2 must not become a second atom (the pre-fix over-count), and each response's own
// token_count is a second view of its record, not another atom.
func TestParseRolloutUsageFromUsageRecords(t *testing.T) {
	res := Parse(readFixture(t, "rollout_usage_record.jsonl"), defaultRefConfig())
	if n := len(res.Diagnostics()); n != 0 {
		t.Fatalf("fixture produced %d diagnostics, want 0", n)
	}
	usages := rolloutUsages(res.Candidates)
	assertRolloutUsages(t, usages, fixtureRolloutWant)
	for i, u := range usages {
		if u.Quality != wire.UsagePayloadQualityPROVIDERREPORTED || u.ProviderSource != "codex" {
			t.Errorf("usage[%d] quality/provider = %q/%q, want PROVIDER_REPORTED/codex", i, u.Quality, u.ProviderSource)
		}
	}
	if !res.carry.RecordMode {
		t.Fatal("carry.RecordMode = false after a record-bearing buffer")
	}
}

// Synthetic Codex >= 0.153 rollout lines for the reset/compaction and repeat cases.
const (
	synthMeta153 = `{"timestamp":"2026-09-23T08:00:00.000Z","type":"session_meta","payload":{"id":"01a0cd49-0000-7000-8000-00000000c0de","cli_version":"0.153.4"}}` + "\n"
	synthMetaOld = `{"timestamp":"2026-09-23T08:00:00.000Z","type":"session_meta","payload":{"id":"01a0cd49-0000-7000-8000-00000000c0de","cli_version":"0.152.1"}}` + "\n"
)

func synthRecord(rid string, in, cached, out int64) string {
	return fmt.Sprintf(`{"timestamp":"2026-09-23T08:00:01.000Z","type":"token_usage_record","payload":{"response_id":%q,"usage":{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":0,"output_tokens":%d,"reasoning_output_tokens":1,"total_tokens":%d}}}`+"\n", rid, in, cached, out, in+out)
}

// synthTokenCount builds a token_count event. total* is the cumulative total_token_usage (omitted
// when totIn < 0); last is last_token_usage with an explicit total_tokens (which Codex sets to a
// context-size estimate, with zero input/output, after a context reset).
func synthTokenCount(totIn, totOut, lastIn, lastOut, lastTotal int64) string {
	total := ""
	if totIn >= 0 {
		total = fmt.Sprintf(`"total_token_usage":{"input_tokens":%d,"cached_input_tokens":0,"output_tokens":%d,"reasoning_output_tokens":0,"total_tokens":%d},`, totIn, totOut, totIn+totOut)
	}
	return fmt.Sprintf(`{"timestamp":"2026-09-23T08:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{%s"last_token_usage":{"input_tokens":%d,"cached_input_tokens":0,"output_tokens":%d,"reasoning_output_tokens":0,"total_tokens":%d}},"rate_limits":{"limit_id":"codex"}}}`+"\n", total, lastIn, lastOut, lastTotal)
}

// TestParseRolloutZeroUsageTokenCountAfterReset pins the under-count fix: after a context reset
// (compaction) Codex records the compaction response's billed usage in a token_usage_record but its
// token_count reports zero input/output with an estimated total. The atom must carry the record's
// real usage, exactly once.
func TestParseRolloutZeroUsageTokenCountAfterReset(t *testing.T) {
	buf := synthMeta153 +
		synthRecord("resp_turn", 5000, 4000, 100) +
		synthTokenCount(5000, 100, 5000, 100, 5100) +
		synthRecord("resp_compact", 90000, 80000, 2500) +
		synthTokenCount(5000, 100, 0, 0, 12345) + // reset: zeroed last usage, estimated total
		synthTokenCount(5000, 100, 0, 0, 12345) // rate-limit refresh repeating it
	usages := rolloutUsages(Parse([]byte(buf), defaultRefConfig()).Candidates)
	assertRolloutUsages(t, usages, []rolloutUsageWant{
		{"resp_turn", 5000, 4000, 100},
		{"resp_compact", 90000, 80000, 2500},
	})
}

// TestParseRolloutRecordModeFromSessionMeta proves a >= 0.153 session_meta alone selects record
// mode, so a token_count ahead of the first record in the file is not counted; and that only the
// FIRST session_meta decides (a forked rollout copies its parent's session_meta after its own).
func TestParseRolloutRecordModeFromSessionMeta(t *testing.T) {
	tc := synthTokenCount(10, 2, 10, 2, 12)
	if got := rolloutUsages(Parse([]byte(synthMeta153+tc), defaultRefConfig()).Candidates); len(got) != 0 {
		t.Fatalf("0.153 rollout: token_count produced %d atoms, want 0", len(got))
	}
	if got := rolloutUsages(Parse([]byte(synthMetaOld+tc), defaultRefConfig()).Candidates); len(got) != 1 {
		t.Fatalf("0.152 rollout: token_count produced %d atoms, want 1", len(got))
	}
	if got := rolloutUsages(Parse([]byte(synthMetaOld+synthMeta153+tc), defaultRefConfig()).Candidates); len(got) != 1 {
		t.Fatalf("0.152 rollout with a copied 0.153 session_meta: %d atoms, want 1", len(got))
	}
	for v, want := range map[string]bool{
		"0.153.0": true, "0.153.4": true, "0.154.0-alpha.2": true, "1.0.0": true,
		"0.152.1": false, "0.115.0": false, "": false, "dev": false, "0.153": false,
	} {
		if got := writesUsageRecords(v); got != want {
			t.Errorf("writesUsageRecords(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestParseLegacyRolloutDedupesRepeats covers a legacy (< 0.153, record-less) rollout: token_count
// stays the usage source, but a rate-limit-only repeat and a context-reset recount (both leave the
// cumulative total unchanged) are dropped. A token_count without a cumulative total cannot be
// classified and is kept, as before.
func TestParseLegacyRolloutDedupesRepeats(t *testing.T) {
	buf := synthMetaOld +
		synthTokenCount(100, 10, 100, 10, 110) +
		synthTokenCount(100, 10, 100, 10, 110) + // rate-limit-only repeat
		synthTokenCount(250, 30, 150, 20, 170) +
		synthTokenCount(250, 30, 0, 0, 999) + // context reset: zeroed usage, same total
		synthTokenCount(-1, 0, 7, 1, 8) // no cumulative total
	usages := rolloutUsages(Parse([]byte(buf), defaultRefConfig()).Candidates)
	if len(usages) != 3 {
		t.Fatalf("USAGE count = %d, want 3", len(usages))
	}
	if in, _, out := usageSum(usages); in != 257 || out != 31 {
		t.Fatalf("legacy totals = %d in / %d out, want 257 / 31", in, out)
	}
	for i, u := range usages {
		if u.MessageID != "" {
			t.Errorf("legacy usage[%d] message_id = %q, want empty", i, u.MessageID)
		}
	}
}

// TestParseRolloutResumedLegacyThenRecords covers a pre-0.153 rollout resumed by a newer Codex: the
// legacy prefix is counted from token_count, and from the first record on only records count.
func TestParseRolloutResumedLegacyThenRecords(t *testing.T) {
	buf := synthMetaOld +
		synthTokenCount(100, 10, 100, 10, 110) +
		synthRecord("resp_new", 300, 100, 30) +
		synthTokenCount(400, 40, 300, 30, 330)
	usages := rolloutUsages(Parse([]byte(buf), defaultRefConfig()).Candidates)
	if len(usages) != 2 || usages[0].MessageID != "" || usages[1].MessageID != "resp_new" {
		t.Fatalf("usages = %d (%v), want legacy atom then resp_new", len(usages), usages)
	}
	if in, _, out := usageSum(usages); in != 400 || out != 40 {
		t.Fatalf("totals = %d / %d, want 400 / 40", in, out)
	}
}

// TestParseRolloutAssistantItemIDIsNotJoinKey pins that an assistant response_item id (the output
// item id, msg_…) is never promoted to message_id. The usage itself is still emitted.
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
// missing, mistyped, over-long or whitespace-bearing id is dropped rather than failing the USAGE
// observation's validation, and the record's tokens are always kept (exactly once — the following
// token_count never substitutes for them).
func TestParseRolloutUsageRecordDegradesGracefully(t *testing.T) {
	long := "resp_" + strings.Repeat("x", maxJoinKeyID)
	tc := synthTokenCount(10, 2, 10, 2, 12)
	usage := `"usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":2,"total_tokens":12}`
	record := func(idField string) string {
		return `{"type":"token_usage_record","timestamp":"2026-07-17T10:00:01Z","payload":{` + idField + usage + `}}` + "\n"
	}
	cases := map[string]string{
		"record without response_id": record(``) + tc,
		"over-long id":               record(`"response_id":`+strconv.Quote(long)+`,`) + tc,
		"whitespace in id":           record(`"response_id":"resp_a b",`) + tc,
		"mistyped id":                record(`"response_id":7,`) + tc,
		"empty id":                   record(`"response_id":"",`) + tc,
	}
	for name, buf := range cases {
		t.Run(name, func(t *testing.T) {
			res := Parse([]byte(buf), defaultRefConfig())
			if n := len(res.Diagnostics()); n != 0 {
				t.Fatalf("%d diagnostics, want 0", n)
			}
			assertRolloutUsages(t, rolloutUsages(res.Candidates), []rolloutUsageWant{{"", 10, 4, 2}})
		})
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
