package codex

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Native capture of the REAL provider transcript formats.
//
// Codex warns that its transcript format is not a stable hook interface, and in practice a live
// `codex exec` never writes the normalized codex-transcript-v1 schema — it writes a raw
// rollout-*.jsonl whose records are {"type":"session_meta",...}, {"type":"turn_context",...},
// {"type":"event_msg","payload":{"type":"token_count",...}}, {"type":"response_item",...}. The
// parser projects the two evidence-bearing shapes natively:
//
//   - session_meta.payload.id           -> SESSION_LIFECYCLE.native_session_id
//   - turn_context.payload.model        -> SESSION_LIFECYCLE.model (threaded onto the session)
//   - event_msg token_count.last_token_usage -> a per-turn USAGE (deltas, so the run's sum equals
//     the provider's real total)
//
// This removes the throwaway rollout->normalized translate step: the daemon reads the file the
// agent actually wrote.

// rolloutProvider stamps SESSION_LIFECYCLE.provider (and, via the sink, provenance.provider) for a
// record parsed out of a Codex rollout, so the platform derives its per-session synthetic run.
const rolloutProvider = "codex"

// The recognized rollout record types. Only session_meta and token_count carry evidence this
// adapter projects; every other rollout record (turn_context, response_item, task_* events) is a
// recognized-but-uninteresting line that is skipped silently rather than emitting a diagnostic —
// a rollout is dense with such records and a per-line diagnostic would drown the real signal.
const (
	rolloutSessionMeta  = "session_meta"
	rolloutTurnContext  = "turn_context"
	rolloutEventMsg     = "event_msg"
	rolloutResponseItem = "response_item"
)

// parseState carries the cross-line context a single Parse call needs to project a rollout or
// Claude transcript: the model (which lives on a different record than the session id) discovered
// by a one-pass peek over the buffer, and a per-buffer latch so exactly one SESSION_LIFECYCLE is
// emitted per buffer. Cross-BUFFER de-duplication (a Claude session id recurs on every record, so
// every poll would otherwise re-emit its STARTED) is the sink's job, keyed by transcript identity.
type parseState struct {
	rolloutModel          string
	rolloutSessionEmitted bool
	// rolloutTurnMessageID holds the provider response id (resp_…) of the most recent assistant
	// response_item, threaded onto the token_count USAGE that reports that turn's tokens as the
	// exact-lane spend-join key. It is consumed (cleared) when attached so one response id is never
	// fanned across multiple usage atoms. Empty for the common rollout versions that record no id —
	// those atoms stay exact-lane-ineligible and fall back to the heuristic lane, unchanged.
	rolloutTurnMessageID string

	claudeModel          string
	claudeSessionEmitted bool
}

// newParseState builds the per-buffer parse context, peeking the buffer once for the session model
// each dialect stashes on a record separate from the session id. The peeks are gated on a cheap
// substring probe so a normalized-only buffer pays nothing.
func newParseState(data []byte) *parseState {
	st := &parseState{}
	if bytes.Contains(data, []byte(`"session_meta"`)) || bytes.Contains(data, []byte(`"turn_context"`)) {
		st.rolloutModel = peekRolloutModel(data)
	}
	if bytes.Contains(data, []byte(`"assistant"`)) {
		st.claudeModel = peekClaudeModel(data)
	}
	return st
}

// peekRolloutModel scans the buffer for the first turn_context.payload.model. The model rides its
// own rollout record (turn_context), separate from session_meta which carries the id, so a
// single-pass line parser cannot both emit the session at session_meta AND stamp the model without
// this look-ahead. When session_meta and turn_context split across polls (the file was discovered
// between the two writes) the model is simply absent on that session — an accepted degradation the
// SESSION_LIFECYCLE's optional model field already allows.
func peekRolloutModel(data []byte) string {
	for _, line := range splitJSONLines(data) {
		var probe formatProbe
		if json.Unmarshal(line, &probe) != nil {
			continue
		}
		if probe.Type == rolloutTurnContext && len(probe.Payload) > 0 {
			var tc struct {
				Model string `json:"model"`
			}
			if json.Unmarshal(probe.Payload, &tc) == nil && tc.Model != "" {
				return tc.Model
			}
		}
	}
	return ""
}

// parseRolloutLine projects one raw Codex rollout record. session_meta becomes the transcript's
// single SESSION_LIFECYCLE (with the peeked model); a token_count event becomes a per-turn USAGE;
// every other rollout record is skipped without a diagnostic.
func (st *parseState) parseRolloutLine(probe formatProbe, lineNo int) []*Candidate {
	ts := probe.probeTime()
	switch probe.Type {
	case rolloutSessionMeta:
		var meta struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(probe.Payload, &meta) != nil || meta.ID == "" {
			return nil
		}
		if st.rolloutSessionEmitted {
			return nil
		}
		st.rolloutSessionEmitted = true
		return []*Candidate{sessionLifecycleCandidate(meta.ID, rolloutProvider, st.rolloutModel, ts, lineNo)}
	case rolloutResponseItem:
		// Latch the assistant turn's provider response id (resp_…) when the rollout records one, so the
		// following token_count USAGE can carry it as the exact-lane spend-join key. Most rollout
		// versions leave the id null (user/developer items never carry one), so this is usually a no-op.
		var pl struct {
			Role string `json:"role"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(probe.Payload, &pl) == nil && pl.Role == "assistant" && pl.ID != "" {
			st.rolloutTurnMessageID = pl.ID
		}
		return nil
	case rolloutEventMsg:
		var pl struct {
			Type string `json:"type"`
			Info struct {
				Last *rolloutTokenUsage `json:"last_token_usage"`
			} `json:"info"`
		}
		if json.Unmarshal(probe.Payload, &pl) != nil {
			return nil
		}
		if pl.Type != "token_count" || pl.Info.Last == nil {
			return nil
		}
		messageID := st.rolloutTurnMessageID
		st.rolloutTurnMessageID = ""
		return pl.Info.Last.candidates(ts, lineNo, messageID)
	default:
		return nil
	}
}

// rolloutTokenUsage is one token_count event's per-turn usage delta. Codex reports input_tokens as
// the full input (cached included) and a cached_input_tokens breakdown, mirroring the USAGE
// observation's input_tokens + cache_read_tokens; total_tokens gates whether the turn did any work.
type rolloutTokenUsage struct {
	InputTokens       *int64 `json:"input_tokens"`
	CachedInputTokens *int64 `json:"cached_input_tokens"`
	OutputTokens      *int64 `json:"output_tokens"`
	TotalTokens       *int64 `json:"total_tokens"`
}

// candidates projects a per-turn usage delta to a USAGE candidate, dropping a zero-work turn (a
// token_count whose delta is empty) so a run's usage_totals is not padded with empties. messageID is
// the latched assistant response id (resp_…) when the rollout recorded one, empty otherwise.
func (u *rolloutTokenUsage) candidates(ts time.Time, lineNo int, messageID string) []*Candidate {
	if u.total() == 0 {
		return nil
	}
	return []*Candidate{{
		Kind:       KindUsage,
		OccurredAt: ts,
		LineNumber: lineNo,
		Usage: &evidence.UsageCandidate{
			Quality:         wire.UsagePayloadQualityPROVIDERREPORTED,
			InputTokens:     u.InputTokens,
			OutputTokens:    u.OutputTokens,
			CacheReadTokens: u.CachedInputTokens,
			ProviderSource:  rolloutProvider,
			MessageID:       messageID,
		},
	}}
}

func (u *rolloutTokenUsage) total() int64 {
	if u.TotalTokens != nil {
		return *u.TotalTokens
	}
	var t int64
	if u.InputTokens != nil {
		t += *u.InputTokens
	}
	if u.OutputTokens != nil {
		t += *u.OutputTokens
	}
	return t
}

// sessionLifecycleCandidate builds the STARTED SESSION_LIFECYCLE candidate every native dialect
// emits once per transcript. The native session id is the load-bearing field: the sink threads it
// onto the transcript's later session-free USAGE records so the platform sums their tokens into one
// synthetic run. Model is optional (absent when a split buffer hid it from the peek).
func sessionLifecycleCandidate(nativeID, provider, model string, ts time.Time, lineNo int) *Candidate {
	return &Candidate{
		Kind:       KindSessionLifecycle,
		OccurredAt: ts,
		LineNumber: lineNo,
		SessionLifecycle: &evidence.SessionLifecycleCandidate{
			NativeSessionID: nativeID,
			Provider:        provider,
			StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
			Transition:      wire.SessionLifecyclePayloadTransitionSTARTED,
			Model:           model,
		},
	}
}

// splitJSONLines returns the complete newline-terminated lines of data (blank lines dropped), for
// the model look-ahead peeks. It never allocates the line contents — the returned slices alias data.
func splitJSONLines(data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			break
		}
		line := bytes.TrimSpace(data[:nl])
		if len(line) > 0 {
			out = append(out, line)
		}
		data = data[nl+1:]
	}
	return out
}
