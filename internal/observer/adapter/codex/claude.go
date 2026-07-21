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

// peekClaudeModel scans the buffer for the first assistant record's message.model, so the
// synthesized SESSION_LIFECYCLE (emitted at the first sessionId-bearing envelope, which may be a
// non-assistant record like a user turn) carries the model without a second parser pass over the
// data. Absent when the buffer holds no assistant record yet — the model then fills in on no
// session record, matching the optional model field.
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
			Usage *claudeUsage `json:"usage"`
		}
		if json.Unmarshal(probe.Message, &m) == nil && m.Usage != nil && m.Usage.hasTokens() {
			out = append(out, m.Usage.candidate(ts, lineNo))
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

// candidate projects the block to a PROVIDER_REPORTED USAGE candidate.
func (u *claudeUsage) candidate(ts time.Time, lineNo int) *Candidate {
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
		},
	}
}

// nonZero reports whether an optional count is present and positive.
func nonZero(v *int64) bool { return v != nil && *v > 0 }
