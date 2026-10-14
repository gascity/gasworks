//go:build unix

package codex

import (
	"fmt"
	"testing"
	"time"
)

// synthTurnContext is the turn_context record that names the rollout's model.
func synthTurnContext(model string) string {
	return fmt.Sprintf(`{"timestamp":"2026-09-23T08:00:00.700Z","type":"turn_context","payload":{"model":%q,"effort":"high"}}`, model) + "\n"
}

// synthMetaFor is a Codex >= 0.153 session_meta for id at the given second past 08:00:00.
func synthMetaFor(id string, sec int) string {
	return fmt.Sprintf(`{"timestamp":"2026-09-23T08:00:%02d.000Z","type":"session_meta","payload":{"id":%q,"cli_version":"0.153.4"}}`, sec, id) + "\n"
}

const synthRolloutID = "01a0cd49-0000-7000-8000-00000000c0de"

var synthMetaTime = time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)

// TestRolloutStartWaitsForTheTurnContextModel is the Codex half of the model-less start fix: a
// rollout's model rides its turn_context, written after session_meta, so the start is emitted at
// the first turn_context that names a model — stamped with session_meta's time — however the two
// records are split across polls and restarts.
func TestRolloutStartWaitsForTheTurnContextModel(t *testing.T) {
	data := synthMeta153 + synthTurnContext("gpt-5.4") + synthRecord("resp_1", 1000, 600, 40)
	for _, restart := range []bool{false, true} {
		for _, polls := range everySplit(data) {
			label := fmt.Sprintf("split at %d (restart=%v)", len(polls[0]), restart)
			cands := ingestPolls(t, polls, restart)
			starts := sessionStarts(cands)
			if len(starts) != 1 {
				t.Fatalf("%s: %d starts, want 1", label, len(starts))
			}
			s := starts[0].SessionLifecycle
			if s.NativeSessionID != synthRolloutID || s.Provider != rolloutProvider || s.Model != "gpt-5.4" {
				t.Fatalf("%s: start = %+v", label, s)
			}
			if !starts[0].OccurredAt.Equal(synthMetaTime) {
				t.Fatalf("%s: start occurred_at = %v, want session_meta's %v", label, starts[0].OccurredAt, synthMetaTime)
			}
			assertStartBeforeUsage(t, label, cands)
			for _, u := range usageCands(cands) {
				if u.Session == nil || u.Session.NativeID != synthRolloutID || u.Session.Provider != rolloutProvider {
					t.Fatalf("%s: usage carries session %+v", label, u.Session)
				}
			}
		}
	}
}

// TestRolloutCopiedParentMetaIsNotASecondSession pins that a forked rollout's copy of its parent's
// session_meta, even when it opens a later poll, neither starts a second session nor re-attributes
// the rollout's usage to the parent, and does not decide the usage source.
func TestRolloutCopiedParentMetaIsNotASecondSession(t *testing.T) {
	const parent = "01a0cd49-0000-7000-8000-0000000fa7e1"
	own := synthMetaOld
	rest := synthMetaFor(parent, 0) + synthTurnContext("gpt-5.4") + synthTokenCount(100, 10, 100, 10, 110)
	for _, restart := range []bool{false, true} {
		cands := ingestPolls(t, []string{own, rest}, restart)
		starts := sessionStarts(cands)
		if len(starts) != 1 || starts[0].SessionLifecycle.NativeSessionID != synthRolloutID {
			t.Fatalf("restart=%v: starts = %+v, want the rollout's own session only", restart, starts)
		}
		usages := usageCands(cands)
		if len(usages) != 1 || usages[0].Session.NativeID != synthRolloutID {
			t.Fatalf("restart=%v: usages = %s, want the legacy token_count on the rollout's own session", restart, describeUsages(usages))
		}
	}
}

// TestRolloutUsageBeforeAnyModelStillStartsTheSession covers a rollout whose usage arrives before
// any turn_context named a model: the session still starts, without a model, right before that
// usage, so the usage is attributable; the platform withholds a price for a model-less start.
func TestRolloutUsageBeforeAnyModelStillStartsTheSession(t *testing.T) {
	cands := Parse([]byte(synthMeta153+synthRecord("resp_1", 50, 0, 5)+synthTurnContext("gpt-5.4")), defaultRefConfig()).Candidates
	starts := sessionStarts(cands)
	if len(starts) != 1 || starts[0].SessionLifecycle.Model != "" {
		t.Fatalf("starts = %+v, want exactly one, model-less", starts)
	}
	assertStartBeforeUsage(t, "usage first", cands)
}

// TestRolloutWithoutUsageOrModelEmitsNoStart pins that a rollout which never named a model and never
// reported usage (a session opened and abandoned) starts nothing.
func TestRolloutWithoutUsageOrModelEmitsNoStart(t *testing.T) {
	if cands := Parse([]byte(synthMeta153), defaultRefConfig()).Candidates; len(cands) != 0 {
		t.Fatalf("bare session_meta produced %v", kindCounts(cands))
	}
}

// TestRolloutUsageRecordsFreshInput is the fix for gascity/gasworks#95: Codex reports input_tokens
// including its cached input, while USAGE input_tokens is fresh input for every provider (Claude's
// already is), so the cached part is subtracted — clamped at zero — and kept in cache_read_tokens.
func TestRolloutUsageRecordsFreshInput(t *testing.T) {
	buf := synthMeta153 + synthTurnContext("gpt-5.4") +
		synthRecord("resp_cached", 24088, 23552, 33) +
		synthRecord("resp_uncached", 23773, 0, 259) +
		synthRecord("resp_overcached", 10, 15, 2)
	usages := rolloutUsages(Parse([]byte(buf), defaultRefConfig()).Candidates)
	assertRolloutUsages(t, usages, []rolloutUsageWant{
		{"resp_cached", 536, 23552, 33},
		{"resp_uncached", 23773, 0, 259},
		{"resp_overcached", 0, 15, 2},
	})
	legacy := synthMetaOld + `{"timestamp":"2026-09-23T08:00:02.000Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":700,"cached_input_tokens":500,"output_tokens":9,"total_tokens":709},"last_token_usage":{"input_tokens":700,"cached_input_tokens":500,"output_tokens":9,"total_tokens":709}}}}` + "\n"
	assertRolloutUsages(t, rolloutUsages(Parse([]byte(legacy), defaultRefConfig()).Candidates), []rolloutUsageWant{{"", 200, 500, 9}})
}
