//go:build unix

package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedSessionlessCursor persists the cursor state the previous release leaves after consuming
// data[:at]: offset, anchor and the rollout usage carry, but no transcript session state.
func seedSessionlessCursor(t *testing.T, stateDir string, dev, ino uint64, data []byte, at int, recordMode bool) {
	t.Helper()
	anchor := data[:at]
	if len(anchor) > anchorLen {
		anchor = anchor[len(anchor)-anchorLen:]
	}
	seed := persistedCursor{
		Version: cursorStateVersion, Device: dev, Inode: ino,
		Consumed: int64(at), Size: int64(at), ModNanos: 1,
		AnchorHash: hashBytes(anchor), AnchorSize: len(anchor),
		RolloutRecordMode: recordMode, RolloutCarry: true,
	}
	b, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if bytes.Contains(b, []byte("session")) {
		t.Fatalf("a previous-release seed carries no session state: %s", b)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cursorStatePath(stateDir, dev, ino), b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// resumeUpgraded loads a previous-release cursor at data[:at], derives what it lacks from the
// consumed bytes, and returns the candidates for data[at:] plus how many consumed bytes the
// derivation read.
func resumeUpgraded(t *testing.T, data []byte, at int, recordMode bool) ([]*Candidate, int) {
	t.Helper()
	dir := t.TempDir()
	seedSessionlessCursor(t, dir, 21, 21, data, at, recordMode)
	c, err := LoadCursor(dir, 21, 21, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	if !c.NeedsCarryDerivation() {
		t.Fatal("a previous-release cursor must derive its session before the next parse")
	}
	cr := &countingReader{r: bytes.NewReader(data[:at])}
	if err := c.DeriveCarry(cr); err != nil {
		t.Fatalf("DeriveCarry: %v", err)
	}
	if c.NeedsCarryDerivation() {
		t.Fatal("derivation must complete in one pass")
	}
	cands, commit := c.Ingest(data[at:], defaultRefConfig())
	commit()
	return cands, cr.n
}

// TestCursorUpgradeDerivesTheSessionFromTheHead covers a transcript tailed across the upgrade: the
// previous release already emitted its start and kept the session only in memory, so the resumed
// daemon re-derives the session from the head of the consumed bytes — reading no further than it
// needs — and neither starts the session again nor leaves the rest of its usage unattributed.
func TestCursorUpgradeDerivesTheSessionFromTheHead(t *testing.T) {
	// A long rollout: the session_meta, then far more consumed bytes than the head scan may read.
	var filler strings.Builder
	for i := range 4000 {
		fmt.Fprintf(&filler, `{"timestamp":"2026-09-23T08:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","n":%d}}`+"\n", i)
	}
	rollout := []byte(synthMeta153 + synthTurnContext("gpt-5.4") + synthRecord("resp_1", 100, 40, 5) + filler.String() + synthRecord("resp_2", 300, 200, 7))
	resumeAt := bytes.LastIndex(rollout, []byte(`{"timestamp":"2026-09-23T08:00:01.000Z","type":"token_usage_record"`))
	cands, read := resumeUpgraded(t, rollout, resumeAt, true)
	if starts := sessionStarts(cands); len(starts) != 0 {
		t.Fatalf("upgrade re-emitted the rollout's start: %+v", starts)
	}
	usages := usageCands(cands)
	if len(usages) != 1 || usages[0].Usage.MessageID != "resp_2" || usages[0].Session == nil || usages[0].Session.NativeID != synthRolloutID {
		t.Fatalf("resumed usage = %s with session %+v, want resp_2 on %s", describeUsages(usages), usages[0].Session, synthRolloutID)
	}
	if read*4 > resumeAt {
		t.Fatalf("session derivation read %d of %d consumed bytes; it must stop at the head", read, resumeAt)
	}

	claude := []byte(claudeStreamedSession() + claudeAssistant(claudeTestSession, at(30*time.Second), "msg_C", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 5, 10, 100}, "text"))
	cut := bytes.Index(claude, []byte(`"msg_C"`))
	cut = bytes.LastIndexByte(claude[:cut], '\n') + 1
	cands, _ = resumeUpgraded(t, claude, cut, false)
	if starts := sessionStarts(cands); len(starts) != 0 {
		t.Fatalf("upgrade re-emitted the Claude start: %+v", starts)
	}
	usages = usageCands(cands)
	if len(usages) != 1 || usages[0].Session == nil || usages[0].Session.NativeID != claudeTestSession {
		t.Fatalf("resumed Claude usage = %s, want msg_C on %s", describeUsages(usages), claudeTestSession)
	}
}

// TestCursorUpgradeKeepsWhatTheEarlierBuildCounted pins the Claude half of the upgrade: the earlier
// build counted every record it consumed, so the upgraded daemon must not count those responses
// again — neither the rest of a response whose records straddle the upgrade, nor a resumed agent's
// later copy of the whole history — while a new response still counts.
func TestCursorUpgradeKeepsWhatTheEarlierBuildCounted(t *testing.T) {
	history := claudeStreamedSession() +
		claudeAssistant(claudeTestSession, at(30*time.Second), "msg_C", "claude-opus-5-5", "", claudeUsageJSON{2, 6, 70, 900}, "thinking")
	rest := claudeAssistant(claudeTestSession, at(31*time.Second), "msg_C", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 640, 70, 900}, "text") +
		history + // a resumed agent writes its history back into the transcript
		claudeAssistant(claudeTestSession, at(time.Hour), "msg_D", "claude-opus-5-5", "end_turn", claudeUsageJSON{3, 11, 0, 1000}, "text")
	data := []byte(history + rest)
	cands, _ := resumeUpgraded(t, data, len(history), false)
	if starts := sessionStarts(cands); len(starts) != 0 {
		t.Fatalf("upgrade re-emitted the start: %+v", starts)
	}
	assertClaudeUsages(t, "after upgrade", cands, []claudeUsageWant{{"msg_D", 3, 11, 0, 1000}})
}

// TestCursorUpgradeMidOverflowStillRecoversTheSession covers a cursor that was skipping an
// over-long line when the earlier build stopped: its consumed offset is mid-line, which only rules
// out folding the rollout usage source; the transcript's session is still recovered.
func TestCursorUpgradeMidOverflowStillRecoversTheSession(t *testing.T) {
	head := claudeAssistant(claudeTestSession, at(0), "msg_A", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 9, 50, 0}, "text")
	long := claudePrompt(claudeTestSession, at(time.Second), false)
	long = long[:len(long)-3] + strings.Repeat("x", 4096) + long[len(long)-3:]
	tail := claudeAssistant(claudeTestSession, at(5*time.Second), "msg_B", "claude-opus-5-5", "end_turn", claudeUsageJSON{2, 7, 0, 50}, "text")
	data := []byte(head + long + tail)
	at := len(head) + 1000 // mid-way through the over-long line
	dir := t.TempDir()
	seedSessionlessCursor(t, dir, 22, 22, data, at, false)
	raw, err := os.ReadFile(cursorStatePath(dir, 22, 22))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if err := os.WriteFile(cursorStatePath(dir, 22, 22), bytes.Replace(raw, []byte(`"skipping_partial":false`), []byte(`"skipping_partial":true`), 1), 0o600); err != nil {
		t.Fatalf("mark mid-overflow: %v", err)
	}
	c, err := LoadCursor(dir, 22, 22, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	if err := c.DeriveCarry(bytes.NewReader(data[:at])); err != nil {
		t.Fatalf("DeriveCarry: %v", err)
	}
	cands, commit := c.Ingest(data[at:], defaultRefConfig())
	commit()
	if starts := sessionStarts(cands); len(starts) != 0 {
		t.Fatalf("mid-overflow upgrade re-emitted the start: %+v", starts)
	}
	usages := usageCands(cands)
	if len(usages) != 1 || usages[0].Session == nil || usages[0].Session.NativeID != claudeTestSession {
		t.Fatalf("usages = %s, want msg_B attributed to %s", describeUsages(usages), claudeTestSession)
	}
}

// TestWatcherPersistsTheUpgradeDerivationOfAQuietTranscript covers the transcripts an upgrade meets
// most: finished ones the earlier build consumed whole and nobody writes again. Their derived
// session state must reach disk on the first start, or every later daemon start re-reads each of
// them to the end. Two starts over the same earlier-build cursor: the first derives and persists,
// and the second finds nothing left to derive.
func TestWatcherPersistsTheUpgradeDerivationOfAQuietTranscript(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	data := claudeStreamedSession()
	writeFileString(t, p, data)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	dev, ino, _ := fileIdentityOf(info)
	seedSessionlessCursor(t, state, dev, ino, []byte(data), len(data), false)
	// The earlier build persisted the live mtime it observed; nothing has written the file since.
	raw, err := os.ReadFile(cursorStatePath(state, dev, ino))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	var seed persistedCursor
	if err := json.Unmarshal(raw, &seed); err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	seed.ModNanos = info.ModTime().UnixNano()
	if raw, err = json.Marshal(seed); err != nil {
		t.Fatalf("encode seed: %v", err)
	}
	if err := os.WriteFile(cursorStatePath(state, dev, ino), raw, 0o600); err != nil {
		t.Fatalf("rewrite seed: %v", err)
	}

	for start := 1; start <= 2; start++ {
		sink := &recordingSink{}
		w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
		if err := w.Poll(context.Background()); err != nil {
			t.Fatalf("start %d: Poll: %v", start, err)
		}
		if n := len(sink.all()); n != 0 {
			t.Fatalf("start %d delivered %d candidates for a transcript the earlier build consumed whole", start, n)
		}
		c, err := LoadCursor(state, dev, ino, info.Size(), info.ModTime().UnixNano(), 0)
		if err != nil {
			t.Fatalf("start %d: LoadCursor: %v", start, err)
		}
		if c.NeedsCarryDerivation() {
			t.Fatalf("after start %d the derived state is not on disk: the next start re-reads all %d consumed bytes", start, len(data))
		}
		if c.carry.session.NativeID != claudeTestSession || !c.carry.session.Started {
			t.Fatalf("after start %d the persisted session is %+v, want %s started", start, c.carry.session, claudeTestSession)
		}
		if !c.carry.claude.Counted.has(idHash("msg_A")) || !c.carry.claude.Counted.has(idHash("msg_B")) {
			t.Fatalf("after start %d the responses the earlier build counted are not persisted as counted", start)
		}
	}
}
