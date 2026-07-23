package codex

import (
	"encoding/json"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Native capture of a real Claude Code transcript
// (~/.claude/projects/<encoded-cwd>/<sessionId>.jsonl).
//
// Claude writes one JSON envelope per line; the ones that carry cost are the "assistant" records,
// each with a message.model and a message.usage block (input_tokens, output_tokens,
// cache_creation_input_tokens, cache_read_input_tokens). The session id rides every envelope as the
// camelCase "sessionId". Unlike Codex there is no dedicated session record, so the parser
// synthesizes the transcript's single SESSION_LIFECYCLE from the first envelope that carries a
// sessionId, stamping the model peeked from the first assistant record. Per-message usage becomes a
// USAGE observation; the sink threads the session id onto each so the tokens sum into one run.

// claudeProvider stamps SESSION_LIFECYCLE.provider (and provenance.provider, via the sink) for a
// record parsed out of a Claude transcript, so the platform derives a distinct per-session run from
// a co-resident Codex session.
const claudeProvider = "claude"

// peekClaudeModel scans the WHOLE buffer for the first assistant record's message.model — not just
// the first line — so the synthesized SESSION_LIFECYCLE (emitted at the first sessionId-bearing
// envelope, which may be a non-assistant record like a user turn) carries the model without a second
// parser pass over the data.
//
// KNOWN tail-only artifact (model=None mid-session): when capture resumes tail-only-new part-way
// through a session, the first ingested buffer runs from the seed offset to EOF. If that buffer holds
// no assistant record at all (every remaining line is a user/tool turn), the model is absent on the
// synthesized session — the optional model field already tolerates this. It is NOT fixable cheaply:
// the SESSION_LIFECYCLE is emitted and shipped the instant the session is first seen, so backfilling
// a model from a LATER buffer would mean deferring that emission or mutating an already-durable
// observation. The whole-buffer look-ahead here is the cheap win (it catches every model-bearing line
// already in the resume buffer); the residual is inherent to tail-only-new resumption. The
// newline-boundary seed reduces it further by not dropping the in-flight (often model-bearing)
// assistant line at the resume point.
func peekClaudeModel(data []byte) string {
	for _, line := range splitJSONLines(data) {
		var probe formatProbe
		if json.Unmarshal(line, &probe) != nil {
			continue
		}
		if probe.Type != "assistant" || len(probe.Message) == 0 {
			continue
		}
		var m struct {
			Model string `json:"model"`
		}
		if json.Unmarshal(probe.Message, &m) == nil && m.Model != "" {
			return m.Model
		}
	}
	return ""
}

// parseClaudeLine projects one Claude transcript envelope. The first sessionId-bearing envelope in
// the buffer yields the transcript's SESSION_LIFECYCLE (the sink de-dups the recurrence across
// polls); an assistant envelope's message.usage yields a USAGE. The session candidate is ordered
// before the usage so a single assistant record that triggers both still threads correctly.
func (st *parseState) parseClaudeLine(probe formatProbe, lineNo int) []*Candidate {
	ts := probe.probeTime()
	var out []*Candidate
	if probe.SessionIDCamel != "" && !st.claudeSessionEmitted {
		st.claudeSessionEmitted = true
		out = append(out, sessionLifecycleCandidate(probe.SessionIDCamel, claudeProvider, st.claudeModel, ts, lineNo))
	}
	if len(probe.Message) > 0 {
		var m struct {
			ID    string       `json:"id"`
			Usage *claudeUsage `json:"usage"`
		}
		if json.Unmarshal(probe.Message, &m) == nil && m.Usage != nil && m.Usage.hasTokens() {
			out = append(out, m.Usage.candidate(ts, lineNo, m.ID))
		}
	}
	return out
}

// claudeUsage is a Claude message.usage block. Claude splits input into fresh input plus two cache
// counters; the mapping to the USAGE observation is direct field-for-field.
type claudeUsage struct {
	InputTokens              *int64 `json:"input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
}

// hasTokens reports whether the block carries any real token count, so a metadata-only usage stub
// (all fields absent) does not become an empty USAGE observation.
func (u *claudeUsage) hasTokens() bool {
	return nonZero(u.InputTokens) || nonZero(u.OutputTokens) ||
		nonZero(u.CacheCreationInputTokens) || nonZero(u.CacheReadInputTokens)
}

// candidate projects the block to a PROVIDER_REPORTED USAGE candidate. messageID is the assistant
// record's provider message.id (msg_…), carried through as the exact-lane spend-join key; it is
// empty when the record omitted an id (a tail-only or non-standard record), and an empty id stays
// absent on the observation rather than being fabricated.
func (u *claudeUsage) candidate(ts time.Time, lineNo int, messageID string) *Candidate {
	return &Candidate{
		Kind:       KindUsage,
		OccurredAt: ts,
		LineNumber: lineNo,
		Usage: &evidence.UsageCandidate{
			Quality:             wire.UsagePayloadQualityPROVIDERREPORTED,
			InputTokens:         u.InputTokens,
			OutputTokens:        u.OutputTokens,
			CacheCreationTokens: u.CacheCreationInputTokens,
			CacheReadTokens:     u.CacheReadInputTokens,
			ProviderSource:      claudeProvider,
			MessageID:           messageID,
		},
	}
}

// nonZero reports whether an optional count is present and positive.
func nonZero(v *int64) bool { return v != nil && *v > 0 }
