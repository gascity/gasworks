//go:build unix

package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/evidence"
)

// seedPre91Cursor persists the cursor state a pre-#91 daemon would have left after consuming
// data[:at]: identity, offset, anchor and corroborating size/mtime, and no rollout usage carry.
func seedPre91Cursor(t *testing.T, stateDir string, dev, ino uint64, data []byte, at int, size, mod int64) {
	t.Helper()
	anchor := data[:at]
	if len(anchor) > anchorLen {
		anchor = anchor[len(anchor)-anchorLen:]
	}
	seed := persistedCursor{
		Version: cursorStateVersion, Device: dev, Inode: ino,
		Consumed: int64(at), Size: size, ModNanos: mod,
		AnchorHash: hashBytes(anchor), AnchorSize: len(anchor),
	}
	b, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if bytes.Contains(b, []byte("rollout_")) {
		t.Fatalf("pre-#91 seed must carry no rollout usage state: %s", b)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cursorStatePath(stateDir, dev, ino), b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// upgradeResume loads a pre-#91 cursor at data[:at], completes the upgrade from the consumed
// bytes, and returns the USAGE atoms the upgraded daemon delivers for data[at:].
func upgradeResume(t *testing.T, data []byte, at int, derive bool) []*evidence.UsageCandidate {
	t.Helper()
	dir := t.TempDir()
	seedPre91Cursor(t, dir, 9, 9, data, at, int64(at), 1)
	c, err := LoadCursor(dir, 9, 9, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	if c.Consumed() != int64(at) {
		t.Fatalf("resumed at %d, want %d", c.Consumed(), at)
	}
	if got, want := c.NeedsCarryDerivation(), at > 0; got != want {
		t.Fatalf("NeedsCarryDerivation = %v, want %v", got, want)
	}
	if derive {
		if err := c.DeriveCarry(bytes.NewReader(data[:at])); err != nil {
			t.Fatalf("DeriveCarry: %v", err)
		}
	}
	cands, commit := c.Ingest(data[at:], defaultRefConfig())
	commit()
	return rolloutUsages(cands)
}

// pre91Counted reports which responses of a record-bearing rollout a pre-#91 daemon had counted
// after consuming data[:at]. That daemon took each response's usage from the token_count written
// right after its token_usage_record, so a response is counted once that token_count is consumed.
func pre91Counted(t *testing.T, data []byte, at int) []bool {
	t.Helper()
	var counted []bool
	awaiting := false
	off := 0
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		off += len(line)
		switch {
		case bytes.Contains(line, []byte(`"type":"token_usage_record"`)):
			counted = append(counted, false)
			awaiting = true
		case awaiting && bytes.Contains(line, []byte(`"type":"token_count"`)):
			counted[len(counted)-1] = off <= at
			awaiting = false
		}
	}
	return counted
}

// TestCursorPre91UpgradeRecordRolloutExactlyOnce is the upgrade made exact: at every line boundary
// a pre-#91 daemon can have stopped at in a record-bearing rollout, the upgraded daemon delivers
// exactly the responses the old one had not counted — each once, from its record, with its id. The
// two ways a naive resume is wrong are both pinned: resuming in the zero (legacy) carry re-counts
// response 1 from the rate-limit token_count that repeats it, and resuming in record mode alone
// (derived only from session_meta) drops a response whose record the old daemon consumed but whose
// token_count it had not yet reached.
func TestCursorPre91UpgradeRecordRolloutExactlyOnce(t *testing.T) {
	data := readFixture(t, "rollout_usage_record.jsonl")
	boundaries := []int{0}
	for i, b := range data {
		if b == '\n' {
			boundaries = append(boundaries, i+1)
		}
	}
	sawZeroCarryDoubleCount, sawPending := false, false
	for _, at := range boundaries {
		counted := pre91Counted(t, data, at)
		var want []rolloutUsageWant
		for i, w := range fixtureRolloutWant {
			if !counted[i] {
				want = append(want, w)
			}
		}
		got := upgradeResume(t, data, at, true)
		if len(got) != len(want) {
			t.Fatalf("resume at %d: %d atoms, want %d (old daemon counted %v)", at, len(got), len(want), counted)
		}
		assertRolloutUsages(t, got, want)

		// The un-derived (zero-carry) resume the fix replaces.
		naive := upgradeResume(t, data, at, false)
		if len(naive) > len(want) {
			sawZeroCarryDoubleCount = true
		}
		for i := range counted {
			if !counted[i] && at > 0 && recordConsumed(data, at, i) {
				sawPending = true
			}
		}
	}
	if !sawZeroCarryDoubleCount {
		t.Fatal("fixture no longer exercises the zero-carry double count this upgrade fixes")
	}
	if !sawPending {
		t.Fatal("fixture no longer exercises a consumed-but-uncounted record")
	}
}

// recordConsumed reports whether the i-th token_usage_record of data lies within data[:at].
func recordConsumed(data []byte, at, i int) bool {
	n, off := 0, 0
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		off += len(line)
		if bytes.Contains(line, []byte(`"type":"token_usage_record"`)) {
			if n == i {
				return off <= at
			}
			n++
		}
	}
	return false
}

// TestCursorPre91UpgradeLegacyRepeatDropped: a legacy (< 0.153) rollout resumed from a pre-#91
// state derives the repeat signature of the last consumed token_count, so a rate-limit repeat right
// after the upgrade is not a second atom.
func TestCursorPre91UpgradeLegacyRepeatDropped(t *testing.T) {
	first := synthMetaOld + synthTokenCount(100, 10, 100, 10, 110)
	data := []byte(first + synthTokenCount(100, 10, 100, 10, 110) + synthTokenCount(250, 30, 150, 20, 170))
	got := upgradeResume(t, data, len(first), true)
	if len(got) != 1 || *got[0].InputTokens != 150 || *got[0].OutputTokens != 20 {
		t.Fatalf("legacy upgrade: got %d atoms, want only the new response 150/20", len(got))
	}
	if naive := upgradeResume(t, data, len(first), false); len(naive) != 2 {
		t.Fatalf("zero-carry resume produced %d atoms; the fixture must exercise the repeat re-count", len(naive))
	}
}

// TestCursorPre91PendingSurvivesRestart: the derived uncounted response rides the persisted cursor
// until the parse that emits it is committed, so a restart (or a poll holding only a partial line)
// between the upgrade and that parse neither loses nor re-derives it twice.
func TestCursorPre91PendingSurvivesRestart(t *testing.T) {
	head := synthMeta153 + synthRecord("resp_pending", 400, 100, 40)
	tail := synthTokenCount(400, 40, 400, 40, 440) + synthRecord("resp_next", 500, 0, 50) + synthTokenCount(900, 90, 500, 50, 550)
	data := []byte(head + tail)
	dir := t.TempDir()
	seedPre91Cursor(t, dir, 3, 3, data, len(head), int64(len(head)), 1)
	c, err := LoadCursor(dir, 3, 3, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	if err := c.DeriveCarry(bytes.NewReader([]byte(head))); err != nil {
		t.Fatalf("DeriveCarry: %v", err)
	}
	// A poll that holds only a partial line commits nothing parsed; the pending must persist.
	partial := []byte(tail[:10])
	cands, commit := c.Ingest(partial, defaultRefConfig())
	commit()
	if len(rolloutUsages(cands)) != 0 {
		t.Fatalf("a partial line must not emit the pending response yet")
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c, err = LoadCursor(dir, 3, 3, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c.NeedsCarryDerivation() {
		t.Fatal("a saved upgraded cursor must not re-derive")
	}
	cands, commit = c.Ingest([]byte(tail), defaultRefConfig())
	commit()
	assertRolloutUsages(t, rolloutUsages(cands), []rolloutUsageWant{
		{"resp_pending", 400, 100, 40},
		{"resp_next", 500, 0, 50},
	})
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(c.StatePath())
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if bytes.Contains(raw, []byte("rollout_pending")) || !bytes.Contains(raw, []byte(`"rollout_carry":true`)) {
		t.Fatalf("committed state must drop the emitted pending and mark the carry: %s", raw)
	}
}

// TestCursorFreshAndPost91StatesSkipDerivation: only a pre-#91 state re-derives.
func TestCursorFreshAndPost91StatesSkipDerivation(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadCursor(dir, 4, 4, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	if c.NeedsCarryDerivation() {
		t.Fatal("a fresh cursor starts at byte zero and needs no derivation")
	}
	data := []byte(synthMetaOld + synthMetaOld)
	_, commit := c.Ingest(data, defaultRefConfig())
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c, err = LoadCursor(dir, 4, 4, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c.NeedsCarryDerivation() {
		t.Fatal("a state saved with the carry marker must not re-derive, even with a zero carry")
	}
}

// TestWatcherUpgradesPre91CursorExactly drives the upgrade through the watcher's drain: a pre-#91
// cursor stopped between response 2's record and its token_count resumes without re-counting the
// rate-limit repeat and without dropping response 2.
func TestWatcherUpgradesPre91CursorExactly(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "rollout-2026-09-23T08-00-00-upgrade.jsonl")
	data := readFixture(t, "rollout_usage_record.jsonl")
	// Stop right after response 2's token_usage_record (ordinal 15).
	idx := bytes.Index(data, []byte(`"ordinal":15,`))
	if idx < 0 {
		t.Fatal("fixture has no ordinal 15")
	}
	at := idx + bytes.IndexByte(data[idx:], '\n') + 1
	if !strings.Contains(string(data[idx:at]), "token_usage_record") {
		t.Fatal("fixture drift: ordinal 15 must be a token_usage_record")
	}
	writeFileString(t, p, string(data))
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	dev, ino, _ := fileIdentityOf(info)
	seedPre91Cursor(t, state, dev, ino, data, at, int64(at), 1)

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	assertRolloutUsages(t, rolloutUsages(sink.all()), fixtureRolloutWant[1:])
}
