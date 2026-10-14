//go:build unix

package codex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// finishedResponses is a Claude transcript of n responses, each finished on its own record.
func finishedResponses(from, n int) []string {
	lines := make([]string, n)
	for i := range n {
		lines[i] = claudeAssistant(claudeTestSession, at(time.Duration(from+i)*time.Second), fmt.Sprintf("msg_%04d", from+i), "claude-opus-5-5", "end_turn", claudeUsageJSON{2, int64(5 + i), 10, 100}, "text")
	}
	return lines
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// TestCursorPersistsCountedIDsIncrementally pins the cost of remembering every counted Claude
// response: each save appends only the ids counted since the last one (8 bytes each) to the
// cursor's sidecar, and the cursor state itself stays small however long the transcript grows. The
// whole set is still there after a reload: a copy of an early response counts nothing.
func TestCursorPersistsCountedIDsIncrementally(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 31, 31, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	sidecar := countedPath(c.StatePath())
	// One response stays open throughout, so every save writes the Claude state it belongs to.
	_, commit := c.Ingest([]byte(claudeAssistant(claudeTestSession, at(0), "msg_open", "claude-opus-5-5", "", claudeUsageJSON{2, 3, 10, 100}, "thinking")), cfg)
	commit()
	var stateSizes []int64
	const polls, perPoll = 50, 4
	for poll := range polls {
		cands, commit := c.Ingest([]byte(strings.Join(finishedResponses(poll*perPoll, perPoll), "")), cfg)
		commit()
		if got := len(usageCands(cands)); got != perPoll {
			t.Fatalf("poll %d counted %d responses, want %d", poll, got, perPoll)
		}
		if err := c.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if got, want := fileSize(t, sidecar), int64(8*perPoll*(poll+1)); got != want {
			t.Fatalf("after poll %d the sidecar holds %d bytes, want %d (8 per counted response)", poll, got, want)
		}
		stateSizes = append(stateSizes, fileSize(t, c.StatePath()))
	}
	if first, last := stateSizes[0], stateSizes[len(stateSizes)-1]; last > first+16 {
		t.Fatalf("cursor state grew from %d to %d bytes with the counted set; it must stay bounded", first, last)
	}
	var want []byte
	for i := range polls * perPoll {
		want = binary.BigEndian.AppendUint64(want, idHash(fmt.Sprintf("msg_%04d", i)))
	}
	if got, err := os.ReadFile(sidecar); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the sidecar must hold each counted id once, appended in counting order (err %v)", err)
	}
	// A save that counted nothing leaves the sidecar alone.
	before, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	_, commit = c.Ingest([]byte(claudeAux(claudeTestSession, "attachment", at(time.Hour))), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if after, err := os.Stat(sidecar); err != nil || !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatalf("a save that counted nothing rewrote the sidecar")
	}

	c, err = LoadCursor(dir, 31, 31, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	copied := strings.Join(finishedResponses(0, 3), "")
	cands, commit := c.Ingest([]byte(copied), cfg)
	commit()
	if got := usageCands(cands); len(got) != 0 {
		t.Fatalf("a copy of responses counted before the reload was counted again: %s", describeUsages(got))
	}
}

// TestCursorCountedSidecarIgnoresWhatACrashedSaveAppended covers a daemon that stops after a save
// appended newly counted ids to the sidecar but before the cursor state recording them was written.
// The cursor resumes at its last saved offset, so those responses are parsed — and counted — again;
// the ids the crashed save left behind must neither suppress that nor be duplicated by it.
func TestCursorCountedSidecarIgnoresWhatACrashedSaveAppended(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 32, 32, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	saved := strings.Join(finishedResponses(0, 2), "")
	_, commit := c.Ingest([]byte(saved), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// The crashed save got as far as appending the next response's id.
	sidecar := countedPath(c.StatePath())
	f, err := os.OpenFile(sidecar, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open sidecar: %v", err)
	}
	if err := binary.Write(f, binary.BigEndian, idHash("msg_0002")); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = f.Close()

	c, err = LoadCursor(dir, 32, 32, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	cands, commit := c.Ingest([]byte(strings.Join(finishedResponses(2, 1), "")), cfg)
	commit()
	assertClaudeUsages(t, "after the crashed save", cands, []claudeUsageWant{{"msg_0002", 2, 5, 10, 100}})
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if len(raw) != 3*8 || bytes.Count(raw, binary.BigEndian.AppendUint64(nil, idHash("msg_0002"))) != 1 {
		t.Fatalf("sidecar holds %d bytes after the retried save, want 3 ids with msg_0002 once", len(raw))
	}
}

// TestCursorCountedSidecarSurvivesLosingItsTail covers a sidecar that lost ids it held (a damaged or
// truncated file): the cursor keeps the ids that are left, and the next save writes its whole set
// again instead of appending after a gap.
func TestCursorCountedSidecarSurvivesLosingItsTail(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 33, 33, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	_, commit := c.Ingest([]byte(strings.Join(finishedResponses(0, 3), "")), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	sidecar := countedPath(c.StatePath())
	if err := os.Truncate(sidecar, 8); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if c, err = LoadCursor(dir, 33, 33, testBigSize, testBigMtime, 0); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !c.carry.claude.Counted.has(idHash("msg_0000")) || c.carry.claude.Counted.has(idHash("msg_0001")) {
		t.Fatal("reload must keep exactly the ids left in the sidecar")
	}
	if err := os.Truncate(sidecar, 0); err != nil { // lost again, behind the loaded cursor's back
		t.Fatalf("truncate: %v", err)
	}
	_, commit = c.Ingest([]byte(strings.Join(finishedResponses(3, 1), "")), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := fileSize(t, sidecar); got != 2*8 {
		t.Fatalf("sidecar holds %d bytes, want the cursor's whole set of 2 ids rewritten", got)
	}
	if c, err = LoadCursor(dir, 33, 33, testBigSize, testBigMtime, 0); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !c.carry.claude.Counted.has(idHash("msg_0000")) || !c.carry.claude.Counted.has(idHash("msg_0003")) {
		t.Fatal("the rewritten sidecar must hold every id the cursor had")
	}
}

// TestCursorResetForgetsCountedIDs pins that a rewritten transcript, which the cursor re-reads from
// byte zero, starts with nothing counted: the ids of the old content stay in the sidecar file until
// the next append cuts them, but the saved state no longer claims them.
func TestCursorResetForgetsCountedIDs(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadCursor(dir, 34, 34, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	_, commit := c.Ingest([]byte(strings.Join(finishedResponses(0, 2), "")), defaultRefConfig())
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c.Reset()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if c, err = LoadCursor(dir, 34, 34, testBigSize, testBigMtime, 0); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(c.carry.claude.Counted) != 0 {
		t.Fatalf("a reset cursor reloaded %d counted ids", len(c.carry.claude.Counted))
	}
}
