package codex

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
	"time"
	"unicode"

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

	// toolSurfaceByID maps a tool-invocation id (Claude tool_use.id, Codex function_call.call_id)
	// to the effective CLI tool of the command it ran, so the matching later result record
	// (Claude tool_result.tool_use_id, Codex function_call_output.call_id) can be classified for
	// TOOL_RESULT extraction — the result surface gate needs an exact bd/git/gh tool name and the
	// real dialects never carry one on the result record. Populated lazily; a miss (result whose
	// call landed in an earlier buffer) leaves the result unclassified, an accepted degradation.
	toolSurfaceByID map[string]string
}

// recordToolSurface stashes the effective CLI tool of a tool invocation under its call id, keyed
// so the later result record extracts against the same bd/git/gh surface. The first argv token of
// the command is the real CLI (git, gh, bd); the provider tool name (Bash, shell) is only the
// fallback when the command is empty.
func (st *parseState) recordToolSurface(id, name, command string) {
	if id == "" {
		return
	}
	tool := firstToken(command)
	if tool == "" {
		tool = name
	}
	if st.toolSurfaceByID == nil {
		st.toolSurfaceByID = make(map[string]string)
	}
	st.toolSurfaceByID[id] = tool
}

// toolSurfaceFor returns the CLI tool recorded for a result record's call id, empty when the call
// was never seen in this buffer.
func (st *parseState) toolSurfaceFor(id string) string {
	return st.toolSurfaceByID[id]
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
func (st *parseState) parseRolloutLine(probe formatProbe, lineNo int, cfg ReferenceConfig) []*Candidate {
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
		return st.parseRolloutResponseItem(probe.Payload, cfg, ts, lineNo)
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

// The response_item payload shapes this adapter projects. A rollout records the agent's shell
// activity as response_item function/tool calls; their command argv is the TOOL_CALL surface the
// reference extractors read, and the paired *_output records are the TOOL_RESULT surface.
const (
	rolloutItemMessage        = "message"
	rolloutItemFunctionCall   = "function_call"
	rolloutItemLocalShellCall = "local_shell_call"
	rolloutItemFunctionOutput = "function_call_output"
	rolloutItemShellOutput    = "local_shell_call_output"
)

// parseRolloutResponseItem projects one response_item. An assistant message latches the turn's
// response id for the exact-lane usage join (unchanged); a function/shell call becomes a TOOL_CALL
// surface run through the reference extractors; a call output becomes a TOOL_RESULT surface,
// classified against the CLI tool recorded for its call id. Every other item is skipped silently.
func (st *parseState) parseRolloutResponseItem(payload json.RawMessage, cfg ReferenceConfig, ts time.Time, lineNo int) []*Candidate {
	var head struct {
		Type   string `json:"type"`
		Role   string `json:"role"`
		ID     string `json:"id"`
		CallID string `json:"call_id"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return nil
	}
	switch head.Type {
	case rolloutItemMessage:
		// Latch the assistant turn's provider response id (resp_…) when the rollout records one, so
		// the following token_count USAGE can carry it as the exact-lane spend-join key. Most rollout
		// versions leave the id null (user/developer items never carry one), so this is usually a no-op.
		if head.Role == "assistant" && head.ID != "" {
			st.rolloutTurnMessageID = head.ID
		}
		return nil
	case rolloutItemFunctionCall, rolloutItemLocalShellCall:
		name, command := rolloutCallCommand(head.Type, payload)
		if command == "" {
			return nil
		}
		st.recordToolSurface(head.CallID, name, command)
		return extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLCALL, SurfaceText{Tool: name, Text: command}, cfg, ts, lineNo)
	case rolloutItemFunctionOutput, rolloutItemShellOutput:
		tool := st.toolSurfaceFor(head.CallID)
		if tool == "" {
			return nil
		}
		var out struct {
			Output json.RawMessage `json:"output"`
		}
		if json.Unmarshal(payload, &out) != nil {
			return nil
		}
		text := rolloutOutputText(out.Output)
		if text == "" {
			return nil
		}
		return extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLRESULT, SurfaceText{Tool: tool, Text: text}, cfg, ts, lineNo)
	default:
		return nil
	}
}

// rolloutCallCommand recovers the provider tool name and the shell command text from a rollout
// function/shell call. Codex has emitted several call schemas across versions — a function_call
// whose JSON-string arguments carry command (string or ["bash","-lc",script] argv) or cmd, and a
// local_shell_call whose action.command is a raw argv — so the recovery tolerates all of them and
// returns an empty command for a call it cannot read (e.g. apply_patch), which the caller skips.
func rolloutCallCommand(itemType string, payload json.RawMessage) (name, command string) {
	switch itemType {
	case rolloutItemLocalShellCall:
		var pl struct {
			Action struct {
				Command []string `json:"command"`
			} `json:"action"`
		}
		if json.Unmarshal(payload, &pl) != nil {
			return "", ""
		}
		return "shell", commandFromArgv(pl.Action.Command)
	default: // function_call
		var pl struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}
		if json.Unmarshal(payload, &pl) != nil {
			return "", ""
		}
		return pl.Name, shellArgsCommand(pl.Arguments)
	}
}

// shellArgsCommand reads the command out of a function_call's arguments (itself a JSON-encoded
// string). command is honored as either a plain string or a ["bash","-lc",script] argv; cmd is the
// exec_command spelling. An unreadable or command-less arguments blob yields "".
func shellArgsCommand(arguments string) string {
	if arguments == "" {
		return ""
	}
	var a struct {
		Command json.RawMessage `json:"command"`
		Cmd     string          `json:"cmd"`
	}
	if json.Unmarshal([]byte(arguments), &a) != nil {
		return ""
	}
	if len(a.Command) > 0 {
		var s string
		if json.Unmarshal(a.Command, &s) == nil {
			return s
		}
		var argv []string
		if json.Unmarshal(a.Command, &argv) == nil {
			return commandFromArgv(argv)
		}
	}
	return a.Cmd
}

// rolloutOutputText reads a function_call_output's output, which providers encode as either a plain
// string or a structured {"output":"..."} / [{"type":"output_text","text":"..."}] block.
func rolloutOutputText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Output string `json:"output"`
		Text   string `json:"text"`
	}
	if json.Unmarshal(raw, &obj) == nil && (obj.Output != "" || obj.Text != "") {
		if obj.Output != "" {
			return obj.Output
		}
		return obj.Text
	}
	return concatTextBlocks(raw)
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

// commandFromArgv renders a shell-call argv to the command text the reference extractors read. A
// `["bash","-lc",script]` wrapper (the common exec form) unwraps to just the script so the surface
// gate sees the real bd/git/gh invocation at token 0; any other argv (e.g. a direct
// `["git","log"]` exec) is space-joined, which likewise puts the CLI tool first.
func commandFromArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	if len(argv) >= 3 && isShellName(argv[0]) && isDashCFlag(argv[1]) {
		return argv[2]
	}
	return strings.Join(argv, " ")
}

// isShellName reports whether an argv[0] is a POSIX shell, tolerating an absolute path
// (/bin/bash), so a `["/bin/bash","-lc",script]` wrapper is unwrapped like a bare `bash`.
func isShellName(s string) bool {
	switch path.Base(s) {
	case "sh", "bash", "zsh", "dash", "ash":
		return true
	default:
		return false
	}
}

// isDashCFlag reports whether an argv token is a shell command flag (-c and its login/interactive
// combinations), i.e. the next token is the command script.
func isDashCFlag(s string) bool {
	switch s {
	case "-c", "-lc", "-ic", "-lic", "-il", "-cl":
		return true
	default:
		return false
	}
}

// firstToken returns the leading whitespace-delimited token of a command, the effective CLI tool
// (git, gh, bd) used to classify the paired result surface. Empty for an empty command.
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexFunc(s, unicode.IsSpace); i >= 0 {
		return s[:i]
	}
	return s
}

// concatTextBlocks joins the .text of a content-block array (Anthropic/Codex message content, tool
// result content), newline-separated; "" when raw is not such an array.
func concatTextBlocks(raw json.RawMessage) string {
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(bl.Text)
	}
	return b.String()
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
