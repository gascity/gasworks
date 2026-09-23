package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strconv"
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
//   - token_usage_record.payload.usage   -> one USAGE per completed Responses API response
//     (Codex >= 0.153.0), with payload.response_id as its message_id (the resp_… id Manifold
//     records as spend.message_id; see docs/observer-usage-message-id.md)
//   - event_msg token_count.last_token_usage -> a per-turn USAGE, ONLY for a legacy rollout that
//     carries no token_usage_record (Codex < 0.153.0); a rate-limit-only repeat is dropped
//
// This removes the throwaway rollout->normalized translate step: the daemon reads the file the
// agent actually wrote.

// rolloutProvider stamps SESSION_LIFECYCLE.provider (and, via the sink, provenance.provider) for a
// record parsed out of a Codex rollout, so the platform derives its per-session synthetic run.
const rolloutProvider = "codex"

// The recognized rollout record types. session_meta, token_usage_record and (legacy) token_count
// carry the evidence this adapter projects (response_item contributes its tool surfaces); every
// other rollout record (turn_context, task_* events, ...) is a
// recognized-but-uninteresting line that is skipped silently rather than emitting a diagnostic —
// a rollout is dense with such records and a per-line diagnostic would drown the real signal.
const (
	rolloutSessionMeta  = "session_meta"
	rolloutTurnContext  = "turn_context"
	rolloutEventMsg     = "event_msg"
	rolloutResponseItem = "response_item"
	// rolloutTokenUsageRecord (Codex >= 0.153.0) is written exactly once per completed Responses
	// API response that reported usage (turns and compactions alike), before the token_count event
	// that reports the same response. Its payload.usage is that response's billed usage and its
	// payload.response_id is the resp_… id Manifold stores as spend.message_id.
	rolloutTokenUsageRecord = "token_usage_record"
)

// rolloutRecordMinVersion is the first Codex CLI release that writes token_usage_record. A rollout
// whose own session_meta names this version or later derives its usage from the records alone.
var rolloutRecordMinVersion = [3]int{0, 153, 0}

// rolloutCarry is the cross-buffer Codex rollout usage state. Parse state is otherwise per poll
// buffer, but the usage source must be decided per FILE: once a rollout is known to carry
// token_usage_record, every later token_count in it is a second view of usage already counted from
// a record and must not become an atom, even when its record landed in an earlier poll. The
// durable cursor persists this alongside its offset (see Cursor.carry).
type rolloutCarry struct {
	// RecordMode is set once the stream is known to carry token_usage_record: its session_meta
	// names Codex >= 0.153.0, or a record has been seen. From then on usage comes only from records.
	RecordMode bool
	// LegacyTotal is the cumulative total_token_usage of the last legacy token_count, rendered by
	// rolloutTokenUsage.signature. A legacy token_count whose cumulative total equals it reported
	// no new response (a rate-limit-only refresh, or a context-reset recount) and is dropped.
	LegacyTotal string
	// Pending is set only by the pre-#91 cursor upgrade (foldRolloutCarry): a token_usage_record
	// the old daemon consumed without counting, because it counted usage from the token_count that
	// follows each record and stopped before that token_count. The next parse emits it once, as the
	// record's own usage and response id, ahead of its first line.
	Pending *rolloutPending
}

// rolloutPending is one uncounted response carried across the pre-#91 cursor upgrade. It holds
// counts, the provider response id and the record's time — never transcript content — and is
// persisted with the cursor until the parse that emits it is committed.
type rolloutPending struct {
	ResponseID string            `json:"response_id,omitempty"`
	Usage      rolloutTokenUsage `json:"usage"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// candidates projects the pending response to its USAGE atom, anchored on the line the resumed
// parse emits it with.
func (p *rolloutPending) candidates(lineNo int) []*Candidate {
	return p.Usage.candidates(p.OccurredAt, lineNo, p.ResponseID)
}

// foldRolloutCarry reconstructs, from the already-consumed bytes of one file, the rolloutCarry a
// #91+ daemon would have committed at the end of them. It exists for the upgrade from a cursor
// persisted before #91, which carries only an offset: resuming such a file in the zero (legacy)
// state is inexact — a record-bearing rollout's next rate-limit token_count would re-count the
// response the old daemon already counted, and a legacy rollout's next repeat would pass the
// empty repeat signature. The fold applies exactly the carry transitions of parseRolloutLine:
//
//   - the file's first session_meta switches to record mode by cli_version (>= 0.153.0);
//   - any token_usage_record switches to record mode;
//   - outside record mode, a token_count with last and total usage sets the repeat signature.
//
// It also finds the one response a pre-#91 daemon can leave uncounted: that daemon counted each
// response from its token_count (written right after the record), so a record whose token_count
// lies beyond the consumed offset was never counted, while #91+ record mode will ignore that
// token_count. Such a record becomes carry.Pending and is emitted once on resume. The fold only
// reads type-discriminating fields, never delivers anything, and skips any line longer than
// maxLine, which must be positive (the runtime overflow path never parses those either).
func foldRolloutCarry(r io.Reader, maxLine int) (rolloutCarry, error) {
	var carry rolloutCarry
	metaSeen := false
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	skipping := false
	for {
		chunk, err := br.ReadSlice('\n')
		complete := err == nil
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return rolloutCarry{}, err
		}
		if !skipping {
			if len(line)+len(chunk) > maxLine {
				line, skipping = nil, true
			} else {
				line = append(line, chunk...)
			}
		}
		if complete {
			if !skipping {
				foldRolloutLine(bytes.TrimSpace(line), &carry, &metaSeen)
			}
			line, skipping = line[:0], false
		}
		if errors.Is(err, io.EOF) {
			// A trailing unterminated fragment was never consumed by the cursor; ignore it.
			return carry, nil
		}
	}
}

// foldRolloutLine applies one complete line's carry transition (see foldRolloutCarry).
func foldRolloutLine(line []byte, carry *rolloutCarry, metaSeen *bool) {
	if len(line) == 0 {
		return
	}
	var probe formatProbe
	if json.Unmarshal(line, &probe) != nil {
		return
	}
	switch probe.Type {
	case rolloutSessionMeta:
		var meta struct {
			ID         string `json:"id"`
			CLIVersion string `json:"cli_version"`
		}
		if json.Unmarshal(probe.Payload, &meta) != nil || meta.ID == "" || *metaSeen {
			return
		}
		*metaSeen = true
		if writesUsageRecords(meta.CLIVersion) {
			carry.RecordMode = true
		}
	case rolloutTokenUsageRecord:
		carry.RecordMode = true
		carry.Pending = nil
		var rec struct {
			ResponseID json.RawMessage    `json:"response_id"`
			Usage      *rolloutTokenUsage `json:"usage"`
		}
		if json.Unmarshal(probe.Payload, &rec) != nil || rec.Usage == nil || rec.Usage.work() == 0 {
			return
		}
		var responseID string
		if json.Unmarshal(rec.ResponseID, &responseID) != nil {
			responseID = ""
		}
		carry.Pending = &rolloutPending{
			ResponseID: joinKeyID(responseID),
			Usage:      *rec.Usage,
			OccurredAt: probe.probeTime(),
		}
	case rolloutEventMsg:
		var pl struct {
			Type string `json:"type"`
			Info struct {
				Total *rolloutTokenUsage `json:"total_token_usage"`
				Last  *rolloutTokenUsage `json:"last_token_usage"`
			} `json:"info"`
		}
		if json.Unmarshal(probe.Payload, &pl) != nil || pl.Type != "token_count" || pl.Info.Last == nil {
			return
		}
		// The pre-#91 daemon counted this token_count, i.e. the pending record's response.
		carry.Pending = nil
		if !carry.RecordMode && pl.Info.Total != nil {
			carry.LegacyTotal = pl.Info.Total.signature()
		}
	}
}

// maxJoinKeyID mirrors the wire contract's UsagePayload.message_id maxLength (and
// evidence.maxMessageID). An id outside it would make the whole USAGE observation fail validation,
// so the adapter drops the id (keeping the tokens) rather than lose the usage atom.
const maxJoinKeyID = 128

// joinKeyID returns id when it is a plausible provider message/response id for the spend-join key:
// non-empty, within maxJoinKeyID bytes, and free of whitespace/control characters. Anything else
// yields "" — the atom then carries no message_id and falls back to the heuristic lane.
func joinKeyID(id string) string {
	if id == "" || len(id) > maxJoinKeyID {
		return ""
	}
	for _, r := range id {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return ""
		}
	}
	return id
}

// parseState carries the cross-line context a single Parse call needs to project a rollout or
// Claude transcript: the model (which lives on a different record than the session id) discovered
// by a one-pass peek over the buffer, and a per-buffer latch so exactly one SESSION_LIFECYCLE is
// emitted per buffer. Cross-BUFFER de-duplication (a Claude session id recurs on every record, so
// every poll would otherwise re-emit its STARTED) is the sink's job, keyed by transcript identity.
type parseState struct {
	rolloutModel          string
	rolloutSessionEmitted bool
	// rolloutSessionMetaSeen latches after the first session_meta of the buffer. Only the first one
	// can be the rollout's own (a forked rollout copies its parent's session_meta after its own), so
	// only it may switch the stream to record mode by cli_version.
	rolloutSessionMetaSeen bool
	// rolloutCarry is the usage-source state carried in from the previous buffer of the same file
	// and handed back out in ParseResult for the cursor to commit.
	rolloutCarry rolloutCarry

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
func newParseState(data []byte, carry rolloutCarry) *parseState {
	st := &parseState{rolloutCarry: carry}
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
// single SESSION_LIFECYCLE (with the peeked model); a token_usage_record becomes that response's
// USAGE; a token_count event becomes a per-turn USAGE only in a legacy (record-less) rollout; every
// other rollout record is skipped without a diagnostic.
func (st *parseState) parseRolloutLine(probe formatProbe, lineNo int, cfg ReferenceConfig) []*Candidate {
	ts := probe.probeTime()
	switch probe.Type {
	case rolloutSessionMeta:
		var meta struct {
			ID         string `json:"id"`
			CLIVersion string `json:"cli_version"`
		}
		if json.Unmarshal(probe.Payload, &meta) != nil || meta.ID == "" {
			return nil
		}
		if !st.rolloutSessionMetaSeen {
			st.rolloutSessionMetaSeen = true
			if writesUsageRecords(meta.CLIVersion) {
				st.rolloutCarry.RecordMode = true
			}
		}
		if st.rolloutSessionEmitted {
			return nil
		}
		st.rolloutSessionEmitted = true
		return []*Candidate{sessionLifecycleCandidate(meta.ID, rolloutProvider, st.rolloutModel, ts, lineNo)}
	case rolloutResponseItem:
		return st.parseRolloutResponseItem(probe.Payload, cfg, ts, lineNo)
	case rolloutTokenUsageRecord:
		// A record (even a malformed one) proves this Codex writes records, so the file's
		// token_count events are no longer a usage source from here on.
		st.rolloutCarry.RecordMode = true
		var rec struct {
			ResponseID json.RawMessage    `json:"response_id"`
			Usage      *rolloutTokenUsage `json:"usage"`
		}
		if json.Unmarshal(probe.Payload, &rec) != nil || rec.Usage == nil {
			return nil
		}
		// The id is decoded on its own so a missing, mistyped or implausible id only costs the
		// join key (heuristic lane), never the response's tokens.
		var responseID string
		if json.Unmarshal(rec.ResponseID, &responseID) != nil {
			responseID = ""
		}
		return rec.Usage.candidates(ts, lineNo, joinKeyID(responseID))
	case rolloutEventMsg:
		if st.rolloutCarry.RecordMode {
			// Every billed response in a record-bearing rollout already produced its USAGE from its
			// token_usage_record. Its token_count events only re-report that usage (after the
			// record, again on each rate-limit refresh) or report a zeroed estimate after a context
			// reset, so none of them is a usage source.
			return nil
		}
		var pl struct {
			Type string `json:"type"`
			Info struct {
				Total *rolloutTokenUsage `json:"total_token_usage"`
				Last  *rolloutTokenUsage `json:"last_token_usage"`
			} `json:"info"`
		}
		if json.Unmarshal(probe.Payload, &pl) != nil {
			return nil
		}
		if pl.Type != "token_count" || pl.Info.Last == nil {
			return nil
		}
		// Legacy (< 0.153) rollout: token_count is the only usage source. Codex re-emits the
		// unchanged token info on every rate-limit refresh and after a context reset; only a
		// completed response advances the cumulative total, so an unchanged total is a repeat.
		if pl.Info.Total != nil {
			sig := pl.Info.Total.signature()
			if sig == st.rolloutCarry.LegacyTotal {
				return nil
			}
			st.rolloutCarry.LegacyTotal = sig
		}
		return pl.Info.Last.candidates(ts, lineNo, "")
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

// parseRolloutResponseItem projects one response_item. A message item carries no evidence (its id is
// the output item id, which never equals the metered response id, so it is never a message_id); a function/shell call becomes a TOOL_CALL
// surface run through the reference extractors; a call output becomes a TOOL_RESULT surface,
// classified against the CLI tool recorded for its call id. Every other item is skipped silently.
func (st *parseState) parseRolloutResponseItem(payload json.RawMessage, cfg ReferenceConfig, ts time.Time, lineNo int) []*Candidate {
	var head struct {
		Type   string `json:"type"`
		CallID string `json:"call_id"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return nil
	}
	switch head.Type {
	case rolloutItemMessage:
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

// rolloutTokenUsage is one Codex TokenUsage object: a token_usage_record's per-response usage or a
// token_count's last/total usage. Codex reports input_tokens as the full input (cached included)
// and a cached_input_tokens breakdown, mirroring the USAGE observation's input_tokens +
// cache_read_tokens. output_tokens already includes reasoning_output_tokens, which is therefore
// not mapped separately (it would double count); it only participates in the repeat signature.
type rolloutTokenUsage struct {
	InputTokens           *int64 `json:"input_tokens"`
	CachedInputTokens     *int64 `json:"cached_input_tokens"`
	OutputTokens          *int64 `json:"output_tokens"`
	ReasoningOutputTokens *int64 `json:"reasoning_output_tokens"`
	TotalTokens           *int64 `json:"total_tokens"`
}

// candidates projects one usage to a USAGE candidate, dropping a zero-work usage so a run's
// usage_totals is not padded with empties. messageID is the token_usage_record response id (resp_…)
// when there is one, empty otherwise.
func (u *rolloutTokenUsage) candidates(ts time.Time, lineNo int, messageID string) []*Candidate {
	if u.work() == 0 {
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

// work is the billed input+output of a usage. total_tokens is only the fallback for a usage that
// reports neither: after a context reset Codex writes a token_count whose total_tokens is a local
// context-size ESTIMATE with zero input and output, which is not billed work.
func (u *rolloutTokenUsage) work() int64 {
	if u.InputTokens == nil && u.OutputTokens == nil {
		if u.TotalTokens != nil {
			return *u.TotalTokens
		}
		return 0
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

// signature renders every counter of a usage (absent as "-") so two usages compare equal only when
// all of them match. It is persisted in the cursor, so it carries counts only, never content.
func (u *rolloutTokenUsage) signature() string {
	var b strings.Builder
	for i, v := range []*int64{u.InputTokens, u.CachedInputTokens, u.OutputTokens, u.ReasoningOutputTokens, u.TotalTokens} {
		if i > 0 {
			b.WriteByte('/')
		}
		if v == nil {
			b.WriteByte('-')
			continue
		}
		b.WriteString(strconv.FormatInt(*v, 10))
	}
	return b.String()
}

// writesUsageRecords reports whether a session_meta cli_version (e.g. "0.153.4",
// "0.154.0-alpha.1") is at or after rolloutRecordMinVersion. An absent or unparseable version is
// unknown and reports false: the stream then switches to record mode at its first record instead.
func writesUsageRecords(version string) bool {
	if i := strings.IndexAny(version, "-+"); i >= 0 {
		version = version[:i]
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	var v [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return false
		}
		v[i] = n
	}
	for i := range v {
		if v[i] != rolloutRecordMinVersion[i] {
			return v[i] > rolloutRecordMinVersion[i]
		}
	}
	return true
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
