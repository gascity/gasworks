//go:build unix

package codex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// testBigSize / testBigMtime are live-stat values large enough that LoadCursor's same-file-append
// corroboration always passes, so a pure-cursor unit test (which is not bound to a real file)
// exercises the offset/resume mechanics without tripping the inode-reuse guard. Tests that
// specifically exercise the corroboration pass their own smaller values.
const (
	testBigSize  = int64(1) << 40
	testBigMtime = int64(1) << 40
)

// msgLine builds one valid newline-free MESSAGE transcript record whose body is text, so a test
// can identify which record was delivered by inspecting Candidate.Message.Body.
func msgLine(text string) string {
	return fmt.Sprintf(`{"type":"message","role":"user","text":%q,"ts":"2026-07-17T10:00:00Z"}`, text)
}

func messageBodies(cands []*Candidate) []string {
	var out []string
	for _, c := range cands {
		if c.Kind == KindMessage {
			out = append(out, c.Message.Body)
		}
	}
	return out
}

func diagnostics(cands []*Candidate) []*Candidate {
	var out []*Candidate
	for _, c := range cands {
		if c.Kind == KindDiagnostic {
			out = append(out, c)
		}
	}
	return out
}

func TestCursorResumesAtConsumedOffsetAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 1, 42, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	data := []byte(msgLine("a") + "\n" + msgLine("b") + "\n")
	cands, commit := c.Ingest(data, cfg)
	if got := messageBodies(cands); len(got) != 2 {
		t.Fatalf("first ingest: want 2 messages, got %v", got)
	}
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	wantConsumed := int64(len(data))
	if c.Consumed() != wantConsumed {
		t.Fatalf("consumed after two lines: want %d, got %d", wantConsumed, c.Consumed())
	}

	// Simulated restart: a fresh cursor for the same identity resumes at the durable offset.
	c2, err := LoadCursor(dir, 1, 42, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload LoadCursor: %v", err)
	}
	if c2.Consumed() != wantConsumed {
		t.Fatalf("resumed consumed: want %d, got %d", wantConsumed, c2.Consumed())
	}
	if c2.ReadOffset() != wantConsumed {
		t.Fatalf("resumed read offset: want %d, got %d", wantConsumed, c2.ReadOffset())
	}

	// Feeding only the newly appended third line must parse exactly that record — a/b are not
	// re-parsed (the watcher would read from ReadOffset, not from 0) and nothing is skipped.
	third := []byte(msgLine("c") + "\n")
	cands2, commit2 := c2.Ingest(third, cfg)
	commit2()
	if got := messageBodies(cands2); len(got) != 1 || got[0] != "c" {
		t.Fatalf("resumed ingest: want [c], got %v", got)
	}
}

func TestCursorPartialLineCompletesAcrossIngestsExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 2, 7, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	full := msgLine("hello")
	half := len(full) / 2

	cands, commit := c.Ingest([]byte(full[:half]), cfg) // partial: no newline yet
	commit()
	if len(cands) != 0 {
		t.Fatalf("partial line should yield no candidates, got %d", len(cands))
	}
	if c.Consumed() != 0 {
		t.Fatalf("partial line must not advance the durable offset, got %d", c.Consumed())
	}
	if c.ReadOffset() != int64(half) {
		t.Fatalf("read offset should include the buffered remainder: want %d, got %d", half, c.ReadOffset())
	}

	rest := full[half:] + "\n"
	cands2, commit2 := c.Ingest([]byte(rest), cfg) // completes the line
	commit2()
	if got := messageBodies(cands2); len(got) != 1 || got[0] != "hello" {
		t.Fatalf("completed line: want [hello] exactly once, got %v", got)
	}
	if c.Consumed() != int64(len(full)+1) {
		t.Fatalf("consumed after completion: want %d, got %d", len(full)+1, c.Consumed())
	}
}

func TestCursorReplacementAndStaleStateStartFresh(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()

	c, err := LoadCursor(dir, 5, 100, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	_, commit := c.Ingest([]byte(msgLine("a")+"\n"), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A different inode at (conceptually) the same path is a replacement: a brand-new cursor,
	// starting at 0, with its own state file.
	repl, err := LoadCursor(dir, 5, 200, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor replacement: %v", err)
	}
	if repl.Consumed() != 0 {
		t.Fatalf("replacement cursor must start at 0, got %d", repl.Consumed())
	}

	// A stale state record whose recorded identity disagrees with the requested identity (a reused
	// inode number) must be ignored so a resume never binds to the wrong file.
	stalePath := cursorStatePath(dir, 5, 300)
	stale := persistedCursor{Version: cursorStateVersion, Device: 999, Inode: 999, Consumed: 12345}
	b, _ := json.Marshal(stale)
	if err := os.WriteFile(stalePath, b, 0o600); err != nil {
		t.Fatalf("seed stale state: %v", err)
	}
	fresh, err := LoadCursor(dir, 5, 300, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor stale: %v", err)
	}
	if fresh.Consumed() != 0 {
		t.Fatalf("stale/foreign state must start fresh at 0, got %d", fresh.Consumed())
	}
}

func TestCursorCorroborationRejectsInconsistentLiveStat(t *testing.T) {
	dir := t.TempDir()
	// Persist a cursor at offset 100 for identity (9,9) with observed size 100 / mtime 500.
	seed := persistedCursor{Version: cursorStateVersion, Device: 9, Inode: 9, Consumed: 100, Size: 100, ModNanos: 500}
	b, _ := json.Marshal(seed)
	if err := os.WriteFile(cursorStatePath(dir, 9, 9), b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cases := []struct {
		name              string
		liveSize, liveMod int64
		wantConsumed      int64
	}{
		{"clean append continuation resumes", 200, 600, 100},
		{"shrunk file (rewrite) re-reads from 0", 50, 600, 0},
		{"older mtime (reused inode) re-reads from 0", 200, 400, 0},
		{"offset past live size re-reads from 0", 80, 600, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := LoadCursor(dir, 9, 9, tc.liveSize, tc.liveMod, 0)
			if err != nil {
				t.Fatalf("LoadCursor: %v", err)
			}
			if c.Consumed() != tc.wantConsumed {
				t.Fatalf("consumed: want %d, got %d", tc.wantConsumed, c.Consumed())
			}
		})
	}
}

func TestCursorResetRestartsAtZero(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 1, 1, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	_, commit := c.Ingest([]byte(msgLine("a")+"\n"+msgLine("b")+"\n"), cfg)
	commit()
	if c.Consumed() == 0 {
		t.Fatal("precondition: cursor should have advanced")
	}
	c.Reset()
	if c.Consumed() != 0 || c.ReadOffset() != 0 {
		t.Fatalf("Reset must return to 0/0, got consumed=%d readOffset=%d", c.Consumed(), c.ReadOffset())
	}
}

func TestCursorRemainderCapOverflowEmitsDiagnosticAndBoundsMemory(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	const cap = 16
	c, err := LoadCursor(dir, 1, 1, testBigSize, testBigMtime, cap)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}

	// A single unterminated line far larger than the cap must overflow to a diagnostic, not grow
	// memory: after ingest the buffered remainder is empty and the cursor is in skip mode.
	long := strings.Repeat("x", 100)
	cands, commit := c.Ingest([]byte(long), cfg)
	commit()
	ds := diagnostics(cands)
	if len(ds) != 1 {
		t.Fatalf("overflow: want exactly one diagnostic, got %d", len(ds))
	}
	if ds[0].Diagnostic.Code != wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE {
		t.Fatalf("overflow diagnostic code: want PARTIAL_CAPTURE, got %s", ds[0].Diagnostic.Code)
	}
	if len(c.remainder) != 0 {
		t.Fatalf("overflow must not buffer the over-long partial line, remainder=%d bytes", len(c.remainder))
	}
	if !c.skip {
		t.Fatal("overflow must enter skip mode to resynchronize at the next newline")
	}

	// Continue the poison line to its newline, then a clean record: the cursor resynchronizes and
	// parses the following record exactly once.
	resync := strings.Repeat("y", 50) + "\n" + msgLine("after") + "\n"
	cands2, commit2 := c.Ingest([]byte(resync), cfg)
	commit2()
	if got := messageBodies(cands2); len(got) != 1 || got[0] != "after" {
		t.Fatalf("resync ingest: want [after], got %v", got)
	}
	if c.skip {
		t.Fatal("skip mode should clear once a newline resynchronizes the stream")
	}
	if len(c.remainder) != 0 {
		t.Fatalf("remainder should be empty after a fully-terminated resync, got %d", len(c.remainder))
	}
}

func TestCursorSaveIsAtomicNoTempResidueAndReloadsCleanly(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultRefConfig()
	c, err := LoadCursor(dir, 7, 7, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}
	_, commit := c.Ingest([]byte(msgLine("a")+"\n"), cfg)
	commit()
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	assertNoTempResidue(t, dir)
	assertStateFileMode(t, c.StatePath())

	// A second Save (crash-safe replacement) must fully replace the old state with no temp residue.
	_, commit2 := c.Ingest([]byte(msgLine("b")+"\n"), cfg)
	commit2()
	wantConsumed := c.Consumed()
	if err := c.Save(); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	assertNoTempResidue(t, dir)

	reloaded, err := LoadCursor(dir, 7, 7, testBigSize, testBigMtime, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Consumed() != wantConsumed {
		t.Fatalf("reload after atomic replace: want consumed %d, got %d", wantConsumed, reloaded.Consumed())
	}
}

func TestFileIdentityOfIsInodeStable(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	infoA, _ := os.Stat(a)
	devA, inoA, ok := fileIdentityOf(infoA)
	if !ok || inoA == 0 {
		t.Fatalf("identity of a: ok=%v ino=%d", ok, inoA)
	}

	// A hard link shares device+inode: same identity.
	link := filepath.Join(dir, "a-link")
	if err := os.Link(a, link); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	infoL, _ := os.Stat(link)
	devL, inoL, _ := fileIdentityOf(infoL)
	if devL != devA || inoL != inoA {
		t.Fatalf("hard link should share identity: (%d,%d) vs (%d,%d)", devL, inoL, devA, inoA)
	}

	// A distinct file has a distinct inode.
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(b, []byte("y"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}
	infoB, _ := os.Stat(b)
	_, inoB, _ := fileIdentityOf(infoB)
	if inoB == inoA {
		t.Fatalf("distinct files must not share an inode: %d", inoB)
	}
}

func assertNoTempResidue(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("atomic write left temp residue: %s", e.Name())
		}
	}
}

func assertStateFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cursor state must be owner-only 0600, got %o", info.Mode().Perm())
	}
}
