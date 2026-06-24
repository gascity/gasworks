package usageaxis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeLedger writes raw bytes to a temp ledger and returns its path.
func writeLedger(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "usage.jsonl")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func appendLedger(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func factLine(runID, model string) string {
	b, _ := json.Marshal(map[string]any{
		"run_id": runID, "session_id": "s", "kind": "model", "model": model,
		"provider": "anthropic", "input_tokens": 10, "output_tokens": 5,
		"cost_usd_estimate": 0.001, "upstream_req_id": runID + "-r", "at": 1_700_000_000_000,
	})
	return string(b) + "\n"
}

func TestTailBasicAssignsMonotonicSeq(t *testing.T) {
	p := writeLedger(t, factLine("run-1", "m1")+factLine("run-2", "m2"))
	facts, next, rotated, err := Tail(p, Cursor{}, 100)
	if err != nil || rotated {
		t.Fatalf("err=%v rotated=%v", err, rotated)
	}
	if len(facts) != 2 {
		t.Fatalf("want 2 facts, got %d", len(facts))
	}
	if facts[0].Seq != 1 || facts[1].Seq != 2 {
		t.Fatalf("seq must be 1-based monotonic: %d, %d", facts[0].Seq, facts[1].Seq)
	}
	if facts[0].RunID != "run-1" || facts[1].Model != "m2" {
		t.Fatalf("fields wrong: %+v", facts)
	}
	if next.NextSeq != 3 {
		t.Fatalf("next seq = %d, want 3", next.NextSeq)
	}
	fi, _ := os.Stat(p)
	if next.Offset != fi.Size() {
		t.Fatalf("offset = %d, want EOF %d", next.Offset, fi.Size())
	}
}

func TestTailLeavesPartialTrailingLine(t *testing.T) {
	// One complete line + a partial (no trailing newline) line.
	p := writeLedger(t, factLine("run-1", "m1")+`{"run_id":"run-2","kind":"mo`)
	facts, next, _, _ := Tail(p, Cursor{}, 100)
	if len(facts) != 1 || facts[0].RunID != "run-1" {
		t.Fatalf("only the complete line should forward: %+v", facts)
	}
	// Offset is at the end of the complete line, NOT EOF (partial left for next scan).
	if next.Offset != int64(len(factLine("run-1", "m1"))) {
		t.Fatalf("offset must stop before the partial line, got %d", next.Offset)
	}
	// Completing the partial line on the next scan forwards it with the next seq.
	appendLedger(t, p, `del","kind":"model","model":"m2","provider":"x","upstream_req_id":"r2","at":1700000000000,"session_id":"s"}`+"\n")
	facts2, _, _, _ := Tail(p, next, 100)
	if len(facts2) != 1 || facts2[0].Seq != 2 {
		t.Fatalf("completed line should forward as seq 2: %+v", facts2)
	}
}

func TestTailSkipsInvalidAndNonModelButAdvances(t *testing.T) {
	content := factLine("run-1", "m1") +
		"not json at all\n" +
		`{"kind":"compute","wall_seconds":3,"run_id":"r","at":1}` + "\n" +
		"\n" + // blank
		factLine("run-2", "m2")
	facts, next, _, _ := Tail(p_helper(t, content), Cursor{}, 100)
	if len(facts) != 2 {
		t.Fatalf("only the 2 model facts forward, got %d: %+v", len(facts), facts)
	}
	// seq is consumed only by forwarded facts: 1 and 2 (not skipped over).
	if facts[0].Seq != 1 || facts[1].Seq != 2 {
		t.Fatalf("seq must skip non-forwarded lines: %d, %d", facts[0].Seq, facts[1].Seq)
	}
	if next.NextSeq != 3 {
		t.Fatalf("next seq = %d, want 3", next.NextSeq)
	}
}

func TestTailRespectsMax(t *testing.T) {
	p := writeLedger(t, factLine("r1", "m")+factLine("r2", "m")+factLine("r3", "m"))
	facts, next, _, _ := Tail(p, Cursor{}, 2)
	if len(facts) != 2 {
		t.Fatalf("max=2 must cap at 2 facts, got %d", len(facts))
	}
	// Next scan from the advanced cursor gets the 3rd with seq 3.
	facts2, _, _, _ := Tail(p, next, 2)
	if len(facts2) != 1 || facts2[0].Seq != 3 {
		t.Fatalf("continuation must yield the 3rd fact as seq 3: %+v", facts2)
	}
}

func TestTailReplayIsStable(t *testing.T) {
	p := writeLedger(t, factLine("r1", "m")+factLine("r2", "m"))
	// Tail from the same start cursor twice (a crash before committing the cursor) —
	// must produce identical facts + seqs so usage-ingest dedups the replay.
	a, _, _, _ := Tail(p, Cursor{}, 100)
	b, _, _, _ := Tail(p, Cursor{}, 100)
	if len(a) != len(b) {
		t.Fatalf("replay length differs")
	}
	for i := range a {
		if a[i].Seq != b[i].Seq || a[i].RunID != b[i].RunID {
			t.Fatalf("replay not stable at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestTailRotationResetsOffsetKeepsSeq(t *testing.T) {
	p := writeLedger(t, factLine("r1", "m")+factLine("r2", "m"))
	_, next, _, _ := Tail(p, Cursor{}, 100) // NextSeq now 3, offset at EOF
	// Rotate: replace the ledger with a fresh, SHORTER one (size < cursor.Offset).
	if err := os.WriteFile(p, []byte(factLine("r3", "m")), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, after, rotated, _ := Tail(p, next, 100)
	if !rotated {
		t.Fatal("a shorter ledger than the cursor offset must be detected as rotated")
	}
	if len(facts) != 1 || facts[0].RunID != "r3" {
		t.Fatalf("rotated ledger must re-read from the top: %+v", facts)
	}
	// seq continues monotonically (3), never colliding with the old file's 1/2.
	if facts[0].Seq != 3 || after.NextSeq != 4 {
		t.Fatalf("seq must stay monotonic across rotation: fact=%d next=%d", facts[0].Seq, after.NextSeq)
	}
}

// The must-fix: a rename-and-recreate rotation where the NEW ledger is already
// LARGER than the prior offset (so size < offset is FALSE) must still be detected by
// file identity, or the new file's early facts are silently dropped.
func TestTailRotationByIdentityWhenLargerThanOffset(t *testing.T) {
	p := writeLedger(t, factLine("r1", "m")+factLine("r2", "m"))
	_, next, _, _ := Tail(p, Cursor{}, 100) // NextSeq 3, offset at EOF, FileID captured
	if next.FileID == 0 {
		t.Skip("no inode identity on this platform; identity rotation detection unavailable")
	}
	oldOffset := next.Offset
	// Rotate the logrotate way: RENAME the old ledger aside (the old inode stays held
	// by the renamed file) and CREATE a fresh ledger at the path — so the new file is
	// guaranteed a DIFFERENT inode even though it is LARGER than the old offset.
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	bigger := factLine("n1", "m") + factLine("n2", "m") + factLine("n3", "m")
	if err := os.WriteFile(p, []byte(bigger), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Size() < oldOffset {
		t.Fatalf("test setup: replacement (%d) must be >= old offset (%d) to exercise identity detection", fi.Size(), oldOffset)
	}
	facts, after, rotated, _ := Tail(p, next, 100)
	if !rotated {
		t.Fatal("a new-inode ledger larger than the offset must be detected as rotated (size check alone misses it)")
	}
	if len(facts) != 3 || facts[0].RunID != "n1" {
		t.Fatalf("rotated larger ledger must re-read from the top: %+v", facts)
	}
	// seq stays monotonic across the rotation: 3, 4, 5 (never colliding with old 1/2).
	if facts[0].Seq != 3 || facts[2].Seq != 5 || after.NextSeq != 6 {
		t.Fatalf("seq must stay monotonic across identity rotation: %+v next=%d", facts, after.NextSeq)
	}
}

func TestTailMissingLedgerIsIdle(t *testing.T) {
	facts, next, _, err := Tail(filepath.Join(t.TempDir(), "nope.jsonl"), Cursor{Offset: 5, NextSeq: 2}, 100)
	if err != nil {
		t.Fatalf("missing ledger must not error: %v", err)
	}
	if len(facts) != 0 || next.Offset != 5 || next.NextSeq != 2 {
		t.Fatalf("missing ledger must leave the cursor unchanged: %+v", next)
	}
}

func p_helper(t *testing.T, content string) string { return writeLedger(t, content) }
