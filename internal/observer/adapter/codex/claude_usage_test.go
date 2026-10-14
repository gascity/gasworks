//go:build unix

package codex

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Synthetic Claude Code records, shaped like the transcripts Claude Code 2.1 writes: one record per
// content block, every block of one API response sharing its message.id and repeating its usage.
const claudeTestSession = "5e551011-0000-4000-8000-0000000000aa"

var claudeT0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

// at renders claudeT0 plus d as a Claude record timestamp.
func at(d time.Duration) string { return claudeT0.Add(d).Format("2006-01-02T15:04:05.000Z") }

// claudeUsageJSON renders one message.usage block.
type claudeUsageJSON struct{ in, out, cacheWrite, cacheRead int64 }

func (u claudeUsageJSON) String() string {
	return fmt.Sprintf(`{"input_tokens":%d,"cache_creation_input_tokens":%d,"cache_read_input_tokens":%d,"output_tokens":%d}`, u.in, u.cacheWrite, u.cacheRead, u.out)
}

// claudeAssistant is one assistant record. stop is the stop_reason, "" for null; block is the
// content block type, and a "tool_use:<id>" block carries a tool_use with that id.
func claudeAssistant(session, ts, id, model, stop string, u claudeUsageJSON, block string) string {
	stopJSON := "null"
	if stop != "" {
		stopJSON = fmt.Sprintf("%q", stop)
	}
	content := fmt.Sprintf(`{"type":%q}`, block)
	if tool, ok := strings.CutPrefix(block, "tool_use:"); ok {
		content = fmt.Sprintf(`{"type":"tool_use","id":%q,"name":"Bash","input":{}}`, tool)
	}
	return fmt.Sprintf(`{"type":"assistant","sessionId":%q,"timestamp":%q,"message":{"role":"assistant","id":%q,"model":%q,"stop_reason":%s,"usage":%s,"content":[%s]}}`+"\n",
		session, ts, id, model, stopJSON, u, content)
}

// claudeToolResult is the user record answering tool_use ids.
func claudeToolResult(session, ts string, toolUseIDs ...string) string {
	blocks := make([]string, len(toolUseIDs))
	for i, id := range toolUseIDs {
		blocks[i] = fmt.Sprintf(`{"type":"tool_result","tool_use_id":%q,"content":"ok"}`, id)
	}
	return fmt.Sprintf(`{"type":"user","sessionId":%q,"timestamp":%q,"message":{"role":"user","content":[%s]}}`+"\n", session, ts, strings.Join(blocks, ","))
}

// claudePrompt is a user turn; meta marks a record Claude Code injects (a skill body, a hook
// message) rather than a turn the user took.
func claudePrompt(session, ts string, meta bool) string {
	metaField := ""
	if meta {
		metaField = `"isMeta":true,`
	}
	return fmt.Sprintf(`{"type":"user",%s"sessionId":%q,"timestamp":%q,"message":{"role":"user","content":"do the thing"}}`+"\n", metaField, session, ts)
}

// claudeAux is a non-message record carrying the session (queue-operation, attachment, mode...).
// An empty ts omits the timestamp, as Claude Code does for its mode and last-prompt records.
func claudeAux(session, typ, ts string) string {
	if ts == "" {
		return fmt.Sprintf(`{"type":%q,"sessionId":%q}`+"\n", typ, session)
	}
	return fmt.Sprintf(`{"type":%q,"sessionId":%q,"timestamp":%q}`+"\n", typ, session, ts)
}

// linked gives one record its place in the transcript's record tree: its uuid and the uuid of the
// record it follows ("" for a conversation's first record).
func linked(line, uuid, parent string) string {
	parentJSON := "null"
	if parent != "" {
		parentJSON = fmt.Sprintf("%q", parent)
	}
	return fmt.Sprintf(`{"uuid":%q,"parentUuid":%s,`, uuid, parentJSON) + line[1:]
}

// chained links records into one branch, each following the one before, with uuids prefix1,
// prefix2, ...; the first follows parent.
func chained(prefix, parent string, lines ...string) string {
	var b strings.Builder
	for i, line := range lines {
		uuid := fmt.Sprintf("%s%d", prefix, i+1)
		b.WriteString(linked(line, uuid, parent))
		parent = uuid
	}
	return b.String()
}

// ingestPolls feeds polls to one cursor, persisting and reloading it after every poll when restart
// is set (a daemon restart, which also drops the in-memory remainder), and returns every candidate in
// delivery order.
func ingestPolls(t *testing.T, polls []string, restart bool) []*Candidate {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 11, 11, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	data := []byte(strings.Join(polls, ""))
	var out []*Candidate
	off := 0
	for _, p := range polls {
		end := off + len(p)
		cands, commit := c.Ingest(data[c.ReadOffset():end], cfg)
		commit()
		out = append(out, cands...)
		if restart {
			if err := c.Save(); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if c, err = LoadCursor(dir, 11, 11, testBigSize, testBigMtime, 0); err != nil {
				t.Fatalf("reload LoadCursor: %v", err)
			}
		}
		off = end
	}
	return out
}

// everySplit returns data cut into two polls at every byte offset worth testing: both sides of each
// line boundary and the middle of each line.
func everySplit(data string) [][]string {
	cuts := []int{0, len(data)}
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			cuts = append(cuts, i, i+1, start+(i-start)/2)
			start = i + 1
		}
	}
	out := make([][]string, 0, len(cuts))
	for _, at := range cuts {
		out = append(out, []string{data[:at], data[at:]})
	}
	return out
}

// sessionStarts returns the SESSION_LIFECYCLE candidates in delivery order.
func sessionStarts(cands []*Candidate) []*Candidate {
	var out []*Candidate
	for _, c := range cands {
		if c.Kind == KindSessionLifecycle {
			out = append(out, c)
		}
	}
	return out
}

// usageCands returns the USAGE candidates in delivery order.
func usageCands(cands []*Candidate) []*Candidate {
	var out []*Candidate
	for _, c := range cands {
		if c.Kind == KindUsage {
			out = append(out, c)
		}
	}
	return out
}

// claudeUsageWant is the expected projection of one Claude USAGE atom.
type claudeUsageWant struct {
	messageID                      string
	in, out, cacheWrite, cacheRead int64
}

func assertClaudeUsages(t *testing.T, label string, cands []*Candidate, want []claudeUsageWant) {
	t.Helper()
	got := usageCands(cands)
	if len(got) != len(want) {
		t.Fatalf("%s: %d USAGE atoms, want %d (%s)", label, len(got), len(want), describeUsages(got))
	}
	for i, w := range want {
		u := got[i].Usage
		if u.MessageID != w.messageID {
			t.Fatalf("%s: usage[%d].message_id = %q, want %q", label, i, u.MessageID, w.messageID)
		}
		for _, f := range []struct {
			name string
			got  *int64
			want int64
		}{
			{"input_tokens", u.InputTokens, w.in},
			{"output_tokens", u.OutputTokens, w.out},
			{"cache_creation_tokens", u.CacheCreationTokens, w.cacheWrite},
			{"cache_read_tokens", u.CacheReadTokens, w.cacheRead},
		} {
			if f.got == nil || *f.got != f.want {
				t.Fatalf("%s: usage[%d] (%s).%s = %v, want %d", label, i, w.messageID, f.name, deref(f.got), f.want)
			}
		}
	}
}

func deref(p *int64) any {
	if p == nil {
		return "absent"
	}
	return *p
}

func describeUsages(cands []*Candidate) string {
	parts := make([]string, len(cands))
	for i, c := range cands {
		parts[i] = fmt.Sprintf("%s:%v/%v", c.Usage.MessageID, deref(c.Usage.InputTokens), deref(c.Usage.OutputTokens))
	}
	return strings.Join(parts, ", ")
}

// assertStartBeforeUsage pins the ordering the platform needs: the transcript's start is delivered
// before any of its usage.
func assertStartBeforeUsage(t *testing.T, label string, cands []*Candidate) {
	t.Helper()
	started := false
	for _, c := range cands {
		switch c.Kind {
		case KindSessionLifecycle:
			started = true
		case KindUsage:
			if !started {
				t.Fatalf("%s: USAGE %q delivered before the session start", label, c.Usage.MessageID)
			}
		}
	}
}

// A Claude session as Claude Code writes it: records without a timestamp, a queued prompt, the
// user turn, and only some seconds later the first assistant record naming the model. Its first
// response streams three blocks: the first two carry the partial usage Claude Code knew when it
// wrote them, the last (with stop_reason) the response's final usage.
func claudeStreamedSession() string {
	return "" +
		claudeAux(claudeTestSession, "last-prompt", "") +
		claudeAux(claudeTestSession, "mode", "") +
		claudeAux(claudeTestSession, "queue-operation", at(0)) +
		claudePrompt(claudeTestSession, at(100*time.Millisecond), false) +
		claudeAux(claudeTestSession, "attachment", at(200*time.Millisecond)) +
		claudeAssistant(claudeTestSession, at(17*time.Second), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 8, 20544, 0}, "thinking") +
		claudeAssistant(claudeTestSession, at(17*time.Second+300*time.Millisecond), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 8, 20544, 0}, "text") +
		claudeAssistant(claudeTestSession, at(19*time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 437, 20544, 0}, "tool_use:toolu_A1") +
		claudeToolResult(claudeTestSession, at(20*time.Second), "toolu_A1") +
		claudeAssistant(claudeTestSession, at(22*time.Second), "msg_B", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 61, 900, 20544}, "text")
}

var claudeStreamedWant = []claudeUsageWant{
	{"msg_A", 2, 437, 20544, 0},
	{"msg_B", 2, 61, 900, 20544},
}

// TestClaudeStartWaitsForTheFirstModelRecord is the fix for model-less Claude starts: the start is
// emitted with the first assistant record that names the model — never earlier, from a record that
// cannot know it — and is stamped with the transcript's original start time (the earliest record
// time of the session), however the bytes are split across polls and restarts.
func TestClaudeStartWaitsForTheFirstModelRecord(t *testing.T) {
	data := claudeStreamedSession()
	for _, restart := range []bool{false, true} {
		for _, polls := range everySplit(data) {
			label := fmt.Sprintf("split at %d (restart=%v)", len(polls[0]), restart)
			cands := ingestPolls(t, polls, restart)
			starts := sessionStarts(cands)
			if len(starts) != 1 {
				t.Fatalf("%s: %d session starts, want 1", label, len(starts))
			}
			s := starts[0]
			if s.SessionLifecycle.NativeSessionID != claudeTestSession || s.SessionLifecycle.Provider != claudeProvider {
				t.Fatalf("%s: start = %s/%s", label, s.SessionLifecycle.NativeSessionID, s.SessionLifecycle.Provider)
			}
			if s.SessionLifecycle.Model != "claude-opus-5-5" {
				t.Fatalf("%s: start model = %q, want claude-opus-5-5", label, s.SessionLifecycle.Model)
			}
			if !s.OccurredAt.Equal(claudeT0) {
				t.Fatalf("%s: start occurred_at = %v, want the session's first record time %v", label, s.OccurredAt, claudeT0)
			}
			assertStartBeforeUsage(t, label, cands)
			assertClaudeUsages(t, label, cands, claudeStreamedWant)
		}
	}
}

// TestClaudeTranscriptWithoutAModelEmitsNoStart pins that a transcript Claude never answered (a
// prompt, then nothing) emits no start at all — a start without a model is exactly what makes the
// platform withhold a run's cost — and that its earliest time survives a restart, so the start the
// first model record later emits still carries it.
func TestClaudeTranscriptWithoutAModelEmitsNoStart(t *testing.T) {
	head := claudeAux(claudeTestSession, "queue-operation", at(0)) + claudePrompt(claudeTestSession, at(time.Second), false)
	if cands := ingestPolls(t, []string{head}, true); len(cands) != 0 {
		t.Fatalf("model-less transcript produced %v, want nothing", kindCounts(cands))
	}
	tail := claudeAssistant(claudeTestSession, at(40*time.Second), "msg_A", "claude-opus-5-5", "end_turn", claudeUsageJSON{3, 9, 100, 0}, "text")
	cands := ingestPolls(t, []string{head, tail}, true)
	starts := sessionStarts(cands)
	if len(starts) != 1 || !starts[0].OccurredAt.Equal(claudeT0) || starts[0].SessionLifecycle.Model != "claude-opus-5-5" {
		t.Fatalf("starts = %v, want one at %v with the model", starts, claudeT0)
	}
}

// TestClaudeSyntheticRecordIsNotTheSessionModel pins that Claude Code's own placeholder record
// (model "<synthetic>": an API error or an interrupted turn, written without any model response)
// never stands in for the model, even when it is the transcript's first assistant record.
func TestClaudeSyntheticRecordIsNotTheSessionModel(t *testing.T) {
	data := claudePrompt(claudeTestSession, at(0), false) +
		claudeAssistant(claudeTestSession, at(time.Second), "5e5e0000-0000-4000-8000-000000000001", claudeSyntheticModel, "stop_sequence", claudeUsageJSON{}, "text") +
		claudePrompt(claudeTestSession, at(5*time.Second), false) +
		claudeAssistant(claudeTestSession, at(9*time.Second), "msg_A", "claude-sonnet-5", "end_turn", claudeUsageJSON{3, 9, 100, 0}, "text")
	cands := Parse([]byte(data), defaultRefConfig()).Candidates
	starts := sessionStarts(cands)
	if len(starts) != 1 || starts[0].SessionLifecycle.Model != "claude-sonnet-5" {
		t.Fatalf("starts = %+v, want one carrying claude-sonnet-5", starts)
	}
	assertClaudeUsages(t, "synthetic", cands, []claudeUsageWant{{"msg_A", 3, 9, 100, 0}})
}

// TestClaudeUsageCountsEachMessageOnceFromItsLastRecord is the fix for Claude's doubled usage: one
// USAGE atom per message.id, carrying the usage of the message's LAST record. Taking the first
// would keep a partial streaming count, and taking each field's maximum would double count a
// proxied model whose last record moves input into cache reads.
func TestClaudeUsageCountsEachMessageOnceFromItsLastRecord(t *testing.T) {
	cases := map[string]struct {
		data string
		want []claudeUsageWant
	}{
		"partial streaming counts": {
			data: claudeStreamedSession(),
			want: claudeStreamedWant,
		},
		"final usage repeated on every record": {
			data: claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 674, 11279, 45172}, "thinking") +
				claudeAssistant(claudeTestSession, at(time.Millisecond), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 674, 11279, 45172}, "text") +
				claudeAssistant(claudeTestSession, at(time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 674, 11279, 45172}, "tool_use:toolu_1") +
				claudeToolResult(claudeTestSession, at(2*time.Second), "toolu_1") +
				claudeAssistant(claudeTestSession, at(3*time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 674, 11279, 45172}, "tool_use:toolu_2"),
			want: []claudeUsageWant{{"msg_A", 2, 674, 11279, 45172}},
		},
		"last record moves input into cache reads": {
			data: claudeAssistant(claudeTestSession, at(0), "msg_P", "proxied-model", "", claudeUsageJSON{73960, 0, 0, 0}, "thinking") +
				claudeAssistant(claudeTestSession, at(3*time.Second), "msg_P", "proxied-model", "end_turn", claudeUsageJSON{560, 470, 0, 74240}, "text"),
			want: []claudeUsageWant{{"msg_P", 560, 470, 0, 74240}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertClaudeUsages(t, name, Parse([]byte(tc.data), defaultRefConfig()).Candidates, tc.want)
			for _, restart := range []bool{false, true} {
				for _, polls := range everySplit(tc.data) {
					label := fmt.Sprintf("%s split at %d (restart=%v)", name, len(polls[0]), restart)
					assertClaudeUsages(t, label, ingestPolls(t, polls, restart), tc.want)
				}
			}
		})
	}
}

// TestClaudeMessageWithoutStopReasonClosesWhenTheNextRequestStarts covers a response whose last
// record Claude Code writes without a stop_reason (its tool_use block, written before the response
// finished): it is complete once the next request of its branch begins — a new response following
// from its tool result — and it is counted then with the usage it has.
func TestClaudeMessageWithoutStopReasonClosesWhenTheNextRequestStarts(t *testing.T) {
	branch := chained("r", "",
		claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 3, 1607, 343925}, "thinking"),
		claudeAssistant(claudeTestSession, at(time.Second), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 3, 1607, 343925}, "tool_use:toolu_A"),
		claudeToolResult(claudeTestSession, at(2*time.Second), "toolu_A"),
		claudeAux(claudeTestSession, "attachment", at(2*time.Second)),
		claudeAssistant(claudeTestSession, at(4*time.Second), "msg_B", "claude-opus-5-5", "", claudeUsageJSON{2, 7, 900, 345532}, "thinking"))
	cut := strings.Index(branch, `"uuid":"r5"`) - 1
	data, next := branch[:cut], branch[cut:]
	if got := usageCands(ingestPolls(t, []string{data}, true)); len(got) != 0 {
		t.Fatalf("msg_A counted before anything proved it complete: %s", describeUsages(got))
	}
	for _, restart := range []bool{false, true} {
		cands := ingestPolls(t, []string{data, next}, restart)
		assertClaudeUsages(t, fmt.Sprintf("restart=%v", restart), cands, []claudeUsageWant{{"msg_A", 2, 3, 1607, 343925}})
		if u := usageCands(cands)[0]; u.LineNumber != 1 {
			t.Fatalf("msg_A delivered on line %d of the second poll, want 1 (the record that closed it)", u.LineNumber)
		}
	}
}

// TestClaudeConcurrentResponsesKeepWaitingForTheirOwnFinalRecord covers the interleavings Claude
// Code writes when several API requests stream into one transcript at once, each on its own branch
// of the record tree: a response is counted from its own final record — not closed early with its
// partial usage because another branch's response began, finished, or even followed a tool result
// of its own branch's earlier block.
func TestClaudeConcurrentResponsesKeepWaitingForTheirOwnFinalRecord(t *testing.T) {
	cases := map[string]struct {
		data string
		want []claudeUsageWant
	}{
		// msg_A's first block, then msg_B and msg_C begin and finish on another branch.
		"other branches finish first": {
			data: linked(claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 7, 3624, 99524}, "thinking"), "a1", "x0") +
				chained("b", "y0",
					claudeAssistant(claudeTestSession, at(8*time.Second), "msg_B", "claude-opus-5-5", "", claudeUsageJSON{2, 4, 6354, 101037}, "thinking"),
					claudeAssistant(claudeTestSession, at(9*time.Second), "msg_B", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 2396, 6354, 101037}, "tool_use:toolu_B"),
					claudeToolResult(claudeTestSession, at(9*time.Second+200*time.Millisecond), "toolu_B"),
					claudeAssistant(claudeTestSession, at(11*time.Second), "msg_C", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 158, 3024, 107391}, "tool_use:toolu_C"),
					claudeToolResult(claudeTestSession, at(11*time.Second+200*time.Millisecond), "toolu_C")) +
				linked(claudeAssistant(claudeTestSession, at(19*time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 3423, 3624, 99524}, "tool_use:toolu_A"), "a2", "a1"),
			want: []claudeUsageWant{
				{"msg_B", 2, 2396, 6354, 101037},
				{"msg_C", 2, 158, 3024, 107391},
				{"msg_A", 2, 3423, 3624, 99524},
			},
		},
		// msg_A's first tool runs while msg_A still streams (its result is written before msg_A's
		// next block), and msg_D begins on another branch in between.
		"tool result before the response's final block": {
			data: chained("a", "x0",
				claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 7, 1482, 340239}, "thinking"),
				claudeAssistant(claudeTestSession, at(time.Second), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 7, 1482, 340239}, "tool_use:toolu_A1"),
				claudeToolResult(claudeTestSession, at(time.Second+10*time.Millisecond), "toolu_A1")) +
				linked(claudeAssistant(claudeTestSession, at(time.Second+400*time.Millisecond), "msg_D", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 2045, 702, 393263}, "tool_use:toolu_D"), "d1", "y0") +
				linked(claudeAssistant(claudeTestSession, at(3*time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 1805, 1482, 340239}, "tool_use:toolu_A2"), "a4", "a3"),
			want: []claudeUsageWant{
				{"msg_D", 2, 2045, 702, 393263},
				{"msg_A", 2, 1805, 1482, 340239},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertClaudeUsages(t, "whole", Parse([]byte(tc.data), defaultRefConfig()).Candidates, tc.want)
			for _, restart := range []bool{false, true} {
				for _, polls := range everySplit(tc.data) {
					assertClaudeUsages(t, fmt.Sprintf("split at %d (restart=%v)", len(polls[0]), restart), ingestPolls(t, polls, restart), tc.want)
				}
			}
		})
	}
}

// TestClaudeUserTurnClosesOpenMessagesButInjectedRecordsDoNot pins which user records end the
// response they follow: a turn the user takes (or an interruption) does. A record Claude Code
// injects while a response is still streaming (isMeta: a skill body, an image note, a hook
// message) does not, and neither does a turn that follows no open response — the first record of a
// history a resumed agent copies back into its transcript, written in the middle of a live stream,
// or a turn on another branch.
func TestClaudeUserTurnClosesOpenMessagesButInjectedRecordsDoNot(t *testing.T) {
	data := chained("r", "",
		claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 8, 28482, 0}, "thinking"),
		claudePrompt(claudeTestSession, at(time.Second), true)) +
		linked(claudePrompt(claudeTestSession, at(-time.Hour), false), "copy1", "") +
		linked(claudePrompt(claudeTestSession, at(time.Second), false), "other2", "other1") +
		linked(claudeAssistant(claudeTestSession, at(2*time.Second), "msg_A", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 270, 28482, 0}, "text"), "r3", "r2") +
		chained("s", "r3",
			claudeAssistant(claudeTestSession, at(10*time.Second), "msg_B", "claude-opus-5-5", "", claudeUsageJSON{2, 5, 100, 28482}, "text"),
			claudePrompt(claudeTestSession, at(11*time.Second), false))
	assertClaudeUsages(t, "turns", ingestPolls(t, []string{data}, false), []claudeUsageWant{
		{"msg_A", 2, 270, 28482, 0},
		{"msg_B", 2, 5, 100, 28482},
	})
}

// TestClaudeReplayedHistoryIsNotCountedAgain covers a resumed agent that rewrites its whole history
// into the same transcript: every message id it repeats was already counted, however far back.
func TestClaudeReplayedHistoryIsNotCountedAgain(t *testing.T) {
	var history strings.Builder
	var want []claudeUsageWant
	for i := range 60 {
		id := fmt.Sprintf("msg_H%03d", i)
		tool := fmt.Sprintf("toolu_H%03d", i)
		history.WriteString(claudeAssistant(claudeTestSession, at(time.Duration(i)*time.Second), id, "claude-opus-5-5", "tool_use", claudeUsageJSON{2, int64(10 + i), 100, 1000}, "tool_use:"+tool))
		history.WriteString(claudeToolResult(claudeTestSession, at(time.Duration(i)*time.Second+time.Millisecond), tool))
		want = append(want, claudeUsageWant{id, 2, int64(10 + i), 100, 1000})
	}
	fresh := claudeAssistant(claudeTestSession, at(time.Hour), "msg_NEW", "claude-opus-5-5", "end_turn", claudeUsageJSON{4, 33, 10, 2000}, "text")
	want = append(want, claudeUsageWant{"msg_NEW", 4, 33, 10, 2000})
	for _, restart := range []bool{false, true} {
		cands := ingestPolls(t, []string{history.String(), claudePrompt(claudeTestSession, at(time.Hour), false) + history.String(), fresh}, restart)
		assertClaudeUsages(t, fmt.Sprintf("restart=%v", restart), cands, want)
		if n := len(sessionStarts(cands)); n != 1 {
			t.Fatalf("restart=%v: %d starts, want 1", restart, n)
		}
	}
}

// TestClaudeUsageCarriesItsSessionAcrossARestart pins the attribution that a daemon restart used to
// lose: every candidate parsed after the start carries the transcript's session, from the cursor's
// persisted state, so a sink whose in-memory threading was reset still stamps it.
func TestClaudeUsageCarriesItsSessionAcrossARestart(t *testing.T) {
	data := claudeStreamedSession()
	for _, polls := range everySplit(data) {
		for _, c := range ingestPolls(t, polls, true) {
			if c.Kind == KindSessionLifecycle {
				continue
			}
			if c.Session == nil || c.Session.NativeID != claudeTestSession || c.Session.Provider != claudeProvider {
				t.Fatalf("split at %d: %s candidate carries session %+v, want %s/claude", len(polls[0]), c.Kind, c.Session, claudeTestSession)
			}
		}
	}
}

// TestClaudeSessionSwitchStartsTheNewSession covers a transcript that continues under a different
// session id (a conversation resumed into the same file): the old session's open responses are
// counted under the old session, and the new one gets its own start, with its own model.
func TestClaudeSessionSwitchStartsTheNewSession(t *testing.T) {
	const other = "5e551011-0000-4000-8000-0000000000bb"
	data := claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 9, 50, 0}, "text") +
		claudeAux(other, "queue-operation", at(time.Minute)) +
		claudePrompt(other, at(time.Minute+time.Second), false) +
		claudeAssistant(other, at(time.Minute+5*time.Second), "msg_B", "claude-haiku-5", "end_turn", claudeUsageJSON{1, 4, 0, 50}, "text")
	cands := ingestPolls(t, []string{data}, false)
	starts := sessionStarts(cands)
	if len(starts) != 2 || starts[0].SessionLifecycle.NativeSessionID != claudeTestSession || starts[1].SessionLifecycle.NativeSessionID != other {
		t.Fatalf("starts = %+v, want one per session", starts)
	}
	if starts[1].SessionLifecycle.Model != "claude-haiku-5" || !starts[1].OccurredAt.Equal(claudeT0.Add(time.Minute)) {
		t.Fatalf("second start = %+v at %v", starts[1].SessionLifecycle, starts[1].OccurredAt)
	}
	usages := usageCands(cands)
	if len(usages) != 2 || usages[0].Session.NativeID != claudeTestSession || usages[1].Session.NativeID != other {
		t.Fatalf("usages = %s, want msg_A on the first session and msg_B on the second", describeUsages(usages))
	}
}

// TestCursorFlushesOpenClaudeUsage covers the cursor half of the settle: a message still waiting
// for its final record when the transcript goes quiet is emitted as it stands, exactly once — a
// partial delivery commits only what was delivered, and a later record of a flushed message is not
// counted again.
func TestCursorFlushesOpenClaudeUsage(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 12, 12, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	data := claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 4, 675, 128077}, "thinking") +
		claudeAssistant(claudeTestSession, at(time.Second), "msg_B", "claude-opus-5-5", "", claudeUsageJSON{2, 6, 70, 128077}, "thinking")
	cands, commit := c.Ingest([]byte(data), cfg)
	commit()
	if len(usageCands(cands)) != 0 || !c.HasOpenUsage() {
		t.Fatalf("open messages emitted early (%s) or not tracked", describeUsages(usageCands(cands)))
	}

	flushed, commitFlush := c.FlushOpenUsage()
	assertClaudeUsages(t, "flush", flushed, []claudeUsageWant{{"msg_A", 2, 4, 675, 128077}, {"msg_B", 2, 6, 70, 128077}})
	commitFlush(1) // only msg_A was delivered
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if c, err = LoadCursor(dir, 12, 12, testBigSize, testBigMtime, 0); err != nil {
		t.Fatalf("reload: %v", err)
	}
	again, commitAgain := c.FlushOpenUsage()
	assertClaudeUsages(t, "re-flush", again, []claudeUsageWant{{"msg_B", 2, 6, 70, 128077}})
	commitAgain(len(again))
	if c.HasOpenUsage() {
		t.Fatal("open usage remains after a full flush")
	}

	late := claudeAssistant(claudeTestSession, at(2*time.Second), "msg_A", "claude-opus-5-5", "tool_use", claudeUsageJSON{2, 900, 675, 128077}, "tool_use:toolu_A")
	cands, commit = c.Ingest([]byte(late), cfg)
	commit()
	if got := usageCands(cands); len(got) != 0 {
		t.Fatalf("a flushed message was counted again: %s", describeUsages(got))
	}
}

// TestClaudeUsageWithoutAnIDStandsAlone keeps the id-less fallback: a record with usage but no
// message.id cannot be collapsed with any other, so its usage is emitted as it comes, without a
// message_id.
func TestClaudeUsageWithoutAnIDStandsAlone(t *testing.T) {
	line := `{"type":"assistant","sessionId":"s-1","timestamp":"2026-07-17T10:00:00Z","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":5}}}` + "\n"
	cands := ingestPolls(t, []string{line, line}, false)
	if got := usageCands(cands); len(got) != 2 || got[0].Usage.MessageID != "" {
		t.Fatalf("id-less usage = %s, want two atoms without message_id", describeUsages(got))
	}
}

// TestClaudeOpenResponsesAreBounded pins the bound on persisted per-transcript state: responses that
// never finish and never call tools cannot accumulate past maxOpenClaudeMessages — the oldest is
// counted, with the usage it has, when one more begins.
func TestClaudeOpenResponsesAreBounded(t *testing.T) {
	var b strings.Builder
	for i := range maxOpenClaudeMessages + 1 {
		b.WriteString(claudeAssistant(claudeTestSession, at(time.Duration(i)*time.Second), fmt.Sprintf("msg_%02d", i), "claude-opus-5-5", "", claudeUsageJSON{1, 2, 0, 0}, "text"))
	}
	res := parseWithCarry([]byte(b.String()), defaultRefConfig(), transcriptCarry{})
	assertClaudeUsages(t, "bounded", res.Candidates, []claudeUsageWant{{"msg_00", 1, 2, 0, 0}})
	if n := len(res.carry.claude.Open); n != maxOpenClaudeMessages {
		t.Fatalf("%d responses open, want the bound %d", n, maxOpenClaudeMessages)
	}
}

// TestClaudeOverlongMessageIDStillCollapses pins that collapsing does not depend on the id being a
// usable join key: a message.id too long (or malformed) to carry as message_id still names one
// response, counted once, just without a message_id.
func TestClaudeOverlongMessageIDStillCollapses(t *testing.T) {
	id := "msg_" + strings.Repeat("x", maxJoinKeyID)
	data := claudeAssistant(claudeTestSession, at(0), id, "claude-opus-5-5", "", claudeUsageJSON{2, 8, 300, 0}, "thinking") +
		claudeAssistant(claudeTestSession, at(time.Second), id, "claude-opus-5-5", "", claudeUsageJSON{2, 8, 300, 0}, "text") +
		claudeAssistant(claudeTestSession, at(2*time.Second), id, "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 120, 300, 0}, "text")
	assertClaudeUsages(t, "over-long id", ingestPolls(t, []string{data}, false), []claudeUsageWant{{"", 2, 120, 300, 0}})
}

// TestClaudeCompactionBoundaryContinuesTheBranch covers Claude Code's compaction boundary, which
// starts a new record chain (parentUuid null) and names the record it continues as
// logicalParentUuid: a response left open before it is complete once the conversation continues
// after it.
func TestClaudeCompactionBoundaryContinuesTheBranch(t *testing.T) {
	data := chained("r", "",
		claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "", claudeUsageJSON{2, 4, 500, 9000}, "tool_use:toolu_A"),
		claudeToolResult(claudeTestSession, at(time.Second), "toolu_A")) +
		fmt.Sprintf(`{"type":"system","subtype":"compact_boundary","uuid":"c1","parentUuid":null,"logicalParentUuid":"r2","sessionId":%q,"timestamp":%q}`+"\n", claudeTestSession, at(time.Minute)) +
		linked(claudeAssistant(claudeTestSession, at(time.Minute+time.Second), "msg_B", "claude-opus-5-5", "", claudeUsageJSON{2, 3, 4000, 0}, "thinking"), "r3", "c1")
	assertClaudeUsages(t, "compaction", ingestPolls(t, []string{data}, false), []claudeUsageWant{{"msg_A", 2, 4, 500, 9000}})
}

// TestClaudeReturningToASessionDoesNotStartItAgain covers a transcript that moves to another session
// and back (A, then B, then A): A was already started in this transcript, so the return emits no
// second start for it — across poll splits and daemon restarts, when the sink no longer remembers
// having appended it — while its usage stays attributed to A.
func TestClaudeReturningToASessionDoesNotStartItAgain(t *testing.T) {
	const other = "5e551011-0000-4000-8000-0000000000bb"
	data := claudeAssistant(claudeTestSession, at(0), "msg_A1", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 9, 50, 0}, "text") +
		claudeAssistant(other, at(time.Minute), "msg_B1", "claude-haiku-5", "end_turn", claudeUsageJSON{1, 4, 0, 50}, "text") +
		claudeAssistant(claudeTestSession, at(2*time.Minute), "msg_A2", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 7, 0, 60}, "text")
	for _, restart := range []bool{false, true} {
		for _, polls := range everySplit(data) {
			label := fmt.Sprintf("split at %d (restart=%v)", len(polls[0]), restart)
			cands := ingestPolls(t, polls, restart)
			starts := sessionStarts(cands)
			if len(starts) != 2 || starts[0].SessionLifecycle.NativeSessionID != claudeTestSession || starts[1].SessionLifecycle.NativeSessionID != other {
				t.Fatalf("%s: %d starts, want one for each session", label, len(starts))
			}
			usages := usageCands(cands)
			if len(usages) != 3 || usages[2].Usage.MessageID != "msg_A2" || usages[2].Session == nil || usages[2].Session.NativeID != claudeTestSession {
				t.Fatalf("%s: usages = %s, want msg_A2 attributed to the session it returned to", label, describeUsages(usages))
			}
		}
	}
}
