//go:build unix

package codex

import (
	"testing"

	"github.com/gascity/gasworks/internal/observer/evidence"
)

// ingestSplit feeds data to a fresh cursor in two polls split at byte offset at, optionally
// persisting and reloading the cursor between them (a daemon restart), and returns every USAGE
// atom in delivery order.
func ingestSplit(t *testing.T, data []byte, at int, restart bool) []*evidence.UsageCandidate {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 7, 7, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	cands, commit := c.Ingest(data[:at], cfg)
	commit()
	usages := rolloutUsages(cands)
	if restart {
		if err := c.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}
		c, err = LoadCursor(dir, 7, 7, testBigSize, testBigMtime, 0)
		if err != nil {
			t.Fatalf("reload LoadCursor: %v", err)
		}
		// A restart re-reads the unconsumed partial line from the file (the remainder is not persisted).
		at = int(c.ReadOffset())
	}
	cands, commit = c.Ingest(data[at:], cfg)
	commit()
	return append(usages, rolloutUsages(cands)...)
}

// TestCursorRolloutUsageExactlyOnceAcrossPollSplit is the #90 split-poll case made exact: for every
// place a poll can split rollout_usage_record.jsonl (between a token_usage_record
// and its token_count, mid-line, ...), with and without a daemon restart in between, the atoms
// delivered are exactly the whole-file atoms — one per response, each with its response id, no
// token_count double counted — because the record-mode carry is committed with the offset.
func TestCursorRolloutUsageExactlyOnceAcrossPollSplit(t *testing.T) {
	data := readFixture(t, "rollout_usage_record.jsonl")
	// Split on both sides of every line boundary and in the middle of every line.
	splits := []int{0, len(data)}
	start := 0
	for i, b := range data {
		if b == '\n' {
			splits = append(splits, i, i+1, start+(i-start)/2)
			start = i + 1
		}
	}
	for _, restart := range []bool{false, true} {
		for _, at := range splits {
			usages := ingestSplit(t, data, at, restart)
			if len(usages) != len(fixtureRolloutWant) {
				t.Fatalf("split at %d (restart=%v): %d atoms, want %d", at, restart, len(usages), len(fixtureRolloutWant))
			}
			for i, w := range fixtureRolloutWant {
				if usages[i].MessageID != w.messageID || *usages[i].InputTokens != w.input {
					t.Fatalf("split at %d (restart=%v): usage[%d] = %q/%d, want %q/%d",
						at, restart, i, usages[i].MessageID, *usages[i].InputTokens, w.messageID, w.input)
				}
			}
		}
	}
}

// TestCursorLegacyRepeatDedupAcrossPollSplit proves the legacy rate-limit repeat de-dup also holds
// when the repeat lands in a later poll (or after a restart) than the token_count it repeats.
func TestCursorLegacyRepeatDedupAcrossPollSplit(t *testing.T) {
	first := synthMetaOld + synthTokenCount(100, 10, 100, 10, 110)
	data := []byte(first + synthTokenCount(100, 10, 100, 10, 110) + synthTokenCount(250, 30, 150, 20, 170))
	for _, restart := range []bool{false, true} {
		usages := ingestSplit(t, data, len(first), restart)
		if len(usages) != 2 {
			t.Fatalf("restart=%v: %d atoms, want 2 (the repeat must be dropped)", restart, len(usages))
		}
		if in, _, out := usageSum(usages); in != 250 || out != 30 {
			t.Fatalf("restart=%v: totals %d/%d, want 250/30", restart, in, out)
		}
	}
}

// TestCursorResetAndSealClearRolloutCarry pins that a rewrite (Reset) or a forward-only baseline
// (SealAt) forgets the usage source: the bytes it was derived from are no longer the stream.
func TestCursorResetAndSealClearRolloutCarry(t *testing.T) {
	c, err := LoadCursor(t.TempDir(), 8, 8, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	c.carry = rolloutCarry{RecordMode: true, LegacyTotal: "1/2/3/4/5"}
	c.Reset()
	if c.carry != (rolloutCarry{}) {
		t.Fatalf("Reset kept carry %+v", c.carry)
	}
	c.carry = rolloutCarry{RecordMode: true}
	c.SealAt(100)
	if c.carry != (rolloutCarry{}) {
		t.Fatalf("SealAt kept carry %+v", c.carry)
	}
}
