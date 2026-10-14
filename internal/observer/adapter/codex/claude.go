package codex

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Native capture of a real Claude Code transcript
// (~/.claude/projects/<encoded-cwd>/<sessionId>.jsonl, and its subagents/ transcripts).
//
// Claude writes one JSON envelope per line; the session id rides nearly every envelope as the
// camelCase "sessionId", and the ones that carry cost are the "assistant" records, each with a
// message.id, a message.model and a message.usage block (input_tokens, output_tokens,
// cache_creation_input_tokens, cache_read_input_tokens). There is no dedicated session record, so
// the parser synthesizes the transcript's SESSION_LIFECYCLE start — and it does so only at the
// first assistant record that names the model, because the platform prices a session's usage at
// its start's model: a start written from an earlier record could not know it. The start is
// stamped with the session's earliest record time.
//
// Claude Code writes one record per content block of a response, every block repeating the
// response's message.id and its usage as known when the block was written: a block written while
// the response still streams carries partial counts (output_tokens of a handful), and the block
// written once it finished carries the final usage and a stop_reason. Counting every record would
// count each response once per block, so the parser counts each message.id once, with its LAST
// record's usage, emitted once nothing can change it:
//
//   - at its first record with a stop_reason (no later record of a response differs from it);
//   - when the response's branch continues: each record names the record it follows (uuid,
//     parentUuid), and a new response or a user turn that follows from the response's records —
//     its own blocks, its tool results, their attachments — is written only once the response
//     finished. A response whose last block Claude Code wrote before the response finished never
//     gets a stop_reason, and is counted here;
//   - when the transcript moves to another session;
//   - when the transcript stays quiet for openUsageSettle (Cursor.FlushOpenUsage), for a session
//     that ended mid-response.
//
// Responses can stream concurrently into one transcript, interleaving their records, so neither a
// new message.id nor a user record on another branch closes a response: only its own branch does.
// Every counted id is remembered for the file: a resumed agent writes its whole history back into
// its transcript, and those copies count nothing.

// claudeProvider stamps SESSION_LIFECYCLE.provider (and provenance.provider, via the sink) for a
// record parsed out of a Claude transcript, so the platform derives a distinct per-session run from
// a co-resident Codex session.
const claudeProvider = "claude"

// claudeSyntheticModel is the model Claude Code stamps on a placeholder assistant record it writes
// itself — an API error, an interrupted turn — rather than from a model response. It names no
// model and carries no usage.
const claudeSyntheticModel = "<synthetic>"

// isClaudeModel reports whether an assistant record's model is the model that answered: present,
// and not Claude Code's placeholder.
func isClaudeModel(model string) bool { return model != "" && model != claudeSyntheticModel }

// isClaudeBookkeepingType reports whether a top-level type names a Claude Code record that carries
// neither the session envelope nor a message: the file-history checkpoint records and the
// compaction summary. They are part of the format, hold no evidence this adapter projects, and
// are the only Claude records without a "sessionId" — so without this they would each degrade to
// an UNSUPPORTED_FORMAT diagnostic and mark every Claude session a partial capture.
func isClaudeBookkeepingType(t string) bool {
	switch t {
	case "file-history-snapshot", "file-history-delta", "summary":
		return true
	default:
		return false
	}
}

// claudeRecordMessage is the message block of a Claude record, as far as this adapter reads it.
type claudeRecordMessage struct {
	ID         string          `json:"id"`
	Model      string          `json:"model"`
	StopReason json.RawMessage `json:"stop_reason"`
	Usage      *claudeUsage    `json:"usage"`
	Content    json.RawMessage `json:"content"`
}

// finished reports whether the record was written once its response had finished: it carries a
// stop_reason.
func (m claudeRecordMessage) finished() bool {
	return len(m.StopReason) > 0 && !bytes.Equal(m.StopReason, []byte("null"))
}

// parseClaudeLine projects one Claude transcript envelope: its session id moves the transcript's
// session; an assistant record names the model and advances its response's usage; a user turn
// ends the response it follows; every record extends the branch of the response it follows; tool
// blocks feed the reference extractors.
func (st *parseState) parseClaudeLine(probe formatProbe, lineNo int, cfg ReferenceConfig) []*Candidate {
	ts := probe.probeTime()
	var out []*Candidate
	if probe.SessionIDCamel != "" {
		out = st.enterClaudeSession(probe.SessionIDCamel, ts, lineNo)
	}
	var m claudeRecordMessage
	hasMessage := len(probe.Message) > 0 && json.Unmarshal(probe.Message, &m) == nil
	var blocks []claudeContentBlock
	if hasMessage {
		blocks = claudeBlocks(m.Content)
	}
	// The record this one follows. A compaction boundary starts a new chain (parentUuid null) and
	// names the record it continues as logicalParentUuid instead.
	parent := probe.ParentUUID
	if parent == "" {
		parent = probe.LogicalParentUUID
	}
	switch {
	case hasMessage && probe.Type == "assistant":
		out = append(out, st.claudeAssistant(probe.UUID, parent, m, ts, lineNo)...)
	case hasMessage && probe.Type == "user" && !probe.IsMeta && !hasToolResult(blocks):
		// A turn the user took — or Claude Code took for them, recording an interruption — after a
		// response: that response is complete. A record Claude Code injects (isMeta: a skill body,
		// an image note, a hook message) is not a turn, and tool results continue the tool loop.
		out = append(out, st.closeClaudeBranch(parent, lineNo)...)
	}
	st.extendClaudeLineage(probe.UUID, parent)
	if !hasMessage {
		return out
	}
	return append(out, st.attribute(st.claudeToolCandidates(blocks, cfg, ts, lineNo))...)
}

// enterClaudeSession moves the transcript to the session a record names. Records of a new session
// end every response of the previous one, which are counted under it; the new session then waits
// for its own model to start. Until the start goes out, the session's earliest record time is kept
// as its start time.
func (st *parseState) enterClaudeSession(id string, ts time.Time, lineNo int) []*Candidate {
	s := &st.carry.session
	var out []*Candidate
	if s.NativeID != id {
		if s.NativeID != "" {
			out = st.closeClaudeMessages(lineNo)
		}
		*s = sessionCarry{NativeID: id, Provider: claudeProvider}
	}
	if !s.Started && !ts.IsZero() && (s.StartedAt.IsZero() || ts.Before(s.StartedAt)) {
		s.StartedAt = ts
	}
	return out
}

// claudeAssistant starts the session at the first record that names its model and advances the
// record's response: a new response ends the response whose branch it continues (the record
// follows parent), the record joins its response's branch, its usage replaces the response's, and
// a stop_reason counts it. A record without a message.id cannot be collapsed with any other, so its
// usage is counted as it comes.
func (st *parseState) claudeAssistant(uuid, parent string, m claudeRecordMessage, ts time.Time, lineNo int) []*Candidate {
	var out []*Candidate
	if isClaudeModel(m.Model) {
		out = append(out, st.startSession(m.Model, ts, lineNo)...)
	}
	if m.ID == "" {
		if m.Usage != nil && m.Usage.hasTokens() {
			out = append(out, st.attribute([]*Candidate{m.Usage.candidate(ts, lineNo, "")})...)
		}
		return out
	}
	key := idHash(m.ID)
	if st.carry.claude.Counted.has(key) {
		return out
	}
	i := st.claudeOpenIndex(key)
	if i < 0 {
		// A new response is the next request of the branch it follows, which Claude Code sends only
		// once the branch's previous response finished.
		out = append(out, st.closeClaudeBranch(parent, lineNo)...)
		if len(st.carry.claude.Open) == maxOpenClaudeMessages {
			out = append(out, st.closeClaudeMessage(0, lineNo)...)
		}
		st.carry.claude.Open = append(st.carry.claude.Open, claudeMessage{Key: key, ID: joinKeyID(m.ID)})
		i = len(st.carry.claude.Open) - 1
	}
	msg := &st.carry.claude.Open[i]
	if uuid != "" {
		msg.Lineage.add(uuid)
	}
	if m.Usage != nil {
		msg.Usage = *m.Usage
		if !ts.IsZero() {
			msg.OccurredAt = ts
		}
	}
	if m.finished() {
		out = append(out, st.closeClaudeMessage(i, lineNo)...)
	}
	return out
}

// hasToolResult reports whether a user record carries tool results: the tool loop continuing, not a
// turn.
func hasToolResult(blocks []claudeContentBlock) bool {
	for _, b := range blocks {
		if b.Type == "tool_result" {
			return true
		}
	}
	return false
}

// extendClaudeLineage adds a record to the branch of the open response it follows, so the records
// written after that response (its tool results, their attachments) keep pointing back to it.
func (st *parseState) extendClaudeLineage(uuid, parent string) {
	if uuid == "" || parent == "" {
		return
	}
	for i := range st.carry.claude.Open {
		if msg := &st.carry.claude.Open[i]; msg.Lineage.has(parent) {
			msg.Lineage.add(uuid)
		}
	}
}

// closeClaudeBranch counts the open response whose branch the record following parent continues.
// A record that follows no open response's records (a conversation's first record, or one on a
// concurrent branch) closes nothing.
func (st *parseState) closeClaudeBranch(parent string, lineNo int) []*Candidate {
	if parent == "" {
		return nil
	}
	var out []*Candidate
	for i := 0; i < len(st.carry.claude.Open); {
		if st.carry.claude.Open[i].Lineage.has(parent) {
			out = append(out, st.closeClaudeMessage(i, lineNo)...)
			continue
		}
		i++
	}
	return out
}

// claudeOpenIndex returns the index of the open response whose message id hashes to key, or -1.
func (st *parseState) claudeOpenIndex(key uint64) int {
	for i, msg := range st.carry.claude.Open {
		if msg.Key == key {
			return i
		}
	}
	return -1
}

// closeClaudeMessages counts every open response, oldest first.
func (st *parseState) closeClaudeMessages(lineNo int) []*Candidate {
	var out []*Candidate
	for len(st.carry.claude.Open) > 0 {
		out = append(out, st.closeClaudeMessage(0, lineNo)...)
	}
	return out
}

// closeClaudeMessage counts the open response at index i: its id is remembered as counted, and its
// usage — the last its records reported — becomes one USAGE, at the time of the record that
// reported it, delivered with the record at lineNo that closed it.
func (st *parseState) closeClaudeMessage(i, lineNo int) []*Candidate {
	c := &st.carry.claude
	msg := c.Open[i]
	c.Open = append(c.Open[:i], c.Open[i+1:]...)
	if len(c.Open) == 0 {
		c.Open = nil
	}
	c.Counted.add(msg.Key)
	if !msg.Usage.hasTokens() {
		return nil
	}
	return st.attribute([]*Candidate{msg.Usage.candidate(msg.OccurredAt, lineNo, msg.ID)})
}

// claudeContentBlock is one entry of a Claude message.content array. tool_use carries the tool name
// and its structured input (the shell command lives under input.command); tool_result carries the
// paired tool_use_id and the tool's output (a string or a content-block array). Both project onto
// the reference-extraction surfaces so a bd/git/gh invocation inside a real Claude session links.
type claudeContentBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`          // tool_use
	Name      string          `json:"name"`        // tool_use
	Input     json.RawMessage `json:"input"`       // tool_use
	ToolUseID string          `json:"tool_use_id"` // tool_result
	Content   json.RawMessage `json:"content"`     // tool_result (string | content-block array)
}

// claudeBlocks decodes a message.content. It is a string for a plain turn (no blocks) and an array
// when the turn carries blocks, so a failed array decode is the common plain case and yields none.
func claudeBlocks(content json.RawMessage) []claudeContentBlock {
	if len(content) == 0 {
		return nil
	}
	var blocks []claudeContentBlock
	if json.Unmarshal(content, &blocks) != nil {
		return nil
	}
	return blocks
}

// claudeToolCandidates projects a Claude message's tool_use / tool_result content blocks onto the
// reference-extraction surfaces.
func (st *parseState) claudeToolCandidates(blocks []claudeContentBlock, cfg ReferenceConfig, ts time.Time, lineNo int) []*Candidate {
	var out []*Candidate
	for _, b := range blocks {
		switch b.Type {
		case "tool_use":
			command := claudeToolCommand(b.Input)
			st.recordToolSurface(b.ID, b.Name, command)
			if command == "" {
				continue
			}
			out = append(out, extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLCALL, SurfaceText{Tool: b.Name, Text: command}, cfg, ts, lineNo)...)
		case "tool_result":
			tool := st.toolSurfaceFor(b.ToolUseID)
			if tool == "" {
				continue
			}
			text := claudeResultText(b.Content)
			if text == "" {
				continue
			}
			out = append(out, extractedCandidates(wire.ExtractionProvenanceSurfaceTOOLRESULT, SurfaceText{Tool: tool, Text: text}, cfg, ts, lineNo)...)
		}
	}
	return out
}

// claudeToolCommand reads the shell command out of a tool_use input. Only the shell tools (Bash)
// carry input.command; a structured-input tool (Read, Edit, an MCP tool) has none and yields "",
// so it never reaches the surface gate.
func claudeToolCommand(input json.RawMessage) string {
	if len(input) == 0 {
		return ""
	}
	var in struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(input, &in) == nil {
		return in.Command
	}
	return ""
}

// claudeResultText reads a tool_result's content, which Claude encodes as either a plain string or a
// [{"type":"text","text":"..."}] block array.
func claudeResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return concatTextBlocks(raw)
}

// claudeUsage is a Claude message.usage block. Claude splits input into fresh input plus two cache
// counters; the mapping to the USAGE observation is direct field-for-field. It is persisted with
// the cursor while its response is open (counts only).
type claudeUsage struct {
	InputTokens              *int64 `json:"input_tokens,omitempty"`
	OutputTokens             *int64 `json:"output_tokens,omitempty"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`
}

// hasTokens reports whether the block carries any real token count, so a metadata-only usage stub
// (all fields absent) does not become an empty USAGE observation.
func (u *claudeUsage) hasTokens() bool {
	return nonZero(u.InputTokens) || nonZero(u.OutputTokens) ||
		nonZero(u.CacheCreationInputTokens) || nonZero(u.CacheReadInputTokens)
}

// candidate projects the block to a PROVIDER_REPORTED USAGE candidate. messageID is the assistant
// record's provider message.id (msg_…), carried through as the exact-lane spend-join key; it is
// empty when the record omitted an id, and an empty id stays absent on the observation rather than
// being fabricated.
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
