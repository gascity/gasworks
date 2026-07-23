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
)

// jsonlMatch mirrors the daemon's transcript filename filter (cmd/gasworks-observer:transcriptNameMatch):
// only .jsonl basenames are real session transcripts; every sidecar under the roots is a different
// extension. The watcher passes the basename, so the predicate is name-based.
func jsonlMatch(name string) bool { return strings.HasSuffix(name, ".jsonl") }

// TestWatcherMatchTracksOnlyTranscripts proves the Match filter keeps discovery on real transcripts:
// a non-transcript .txt / .meta.json under a watched root is NOT tracked (so it never produces the
// "malformed transcript line" flood), while a real .jsonl IS tracked and its records flow. This is
// the FIX 1 behavior the daemon relies on.
func TestWatcherMatchTracksOnlyTranscripts(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()

	real := filepath.Join(root, "session.jsonl")
	writeFileString(t, real, msgLine("real")+"\n")
	// Non-transcript sidecars that share the root. If the watcher tracked these, the .txt alone
	// would emit one malformed diagnostic per line — the 87%-junk flood the soak surfaced.
	writeFileString(t, filepath.Join(root, "tool-result.txt"), "this is not json at all\nnor is this line\n")
	writeFileString(t, filepath.Join(root, "message.meta.json"), `{"role":"user"}`+"\n")
	writeFileString(t, filepath.Join(root, "sessions-index.json"), `{"sessions":[]}`+"\n")

	sink := &recordingSink{}
	w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, Match: jsonlMatch})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(w.tracked) != 1 {
		t.Fatalf("watcher tracked %d files, want 1 (the .jsonl transcript only)", len(w.tracked))
	}
	realIno := inodeOf(t, real)
	tracked := false
	for k := range w.tracked {
		if k.ino == realIno {
			tracked = true
		}
	}
	if !tracked {
		t.Fatal("the real .jsonl transcript was not tracked")
	}
	if got := messageBodies(sink.all()); len(got) != 1 || got[0] != "real" {
		t.Fatalf("message bodies = %v, want [real]", got)
	}
	if d := diagnostics(sink.all()); len(d) != 0 {
		t.Fatalf("non-transcript files produced %d diagnostics, want 0", len(d))
	}
}

// lastNewlineTailOffset returns the tail-only-new resume offset for a file whose current bytes are
// data: the offset just past the last '\n' (0 when data has no newline yet). It is the in-repo model
// of the operational seeder's newline-boundary computation (FIX 2) — seeding here, rather than at the
// raw file size, is what stops a resume from landing mid-line and dropping the in-flight record.
func lastNewlineTailOffset(data []byte) int64 {
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return int64(i + 1)
	}
	return 0
}

// seedTailCursor writes a durable cursor state file for path that resumes at consumed, fingerprinting
// the <=anchorLen bytes ending at consumed exactly as the live cursor persists its own position. It
// is the in-repo model of the tail-only-new seeder, used to prove the newline-boundary seed semantics
// against the real Watcher/Cursor.
func seedTailCursor(t *testing.T, stateDir, path string, consumed int64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatalf("no identity for %s", path)
	}
	pc := persistedCursor{
		Version:  cursorStateVersion,
		Device:   dev,
		Inode:    ino,
		Consumed: consumed,
		Size:     info.Size(),
		ModNanos: info.ModTime().UnixNano(),
	}
	if consumed > 0 {
		alen := int64(anchorLen)
		if alen > consumed {
			alen = consumed
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		buf := make([]byte, alen)
		n, _ := f.ReadAt(buf, consumed-alen)
		f.Close()
		if int64(n) < alen {
			t.Fatalf("short anchor read: %d < %d", n, alen)
		}
		pc.AnchorHash = hashBytes(buf)
		pc.AnchorSize = n
	}
	data, err := json.Marshal(pc)
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	if err := atomicWriteCursorFile(cursorStatePath(stateDir, dev, ino), data); err != nil {
		t.Fatalf("write seeded cursor: %v", err)
	}
}

// TestNewlineBoundarySeedCapturesInFlightLine is the FIX 2 proof. A transcript ends with a complete
// line plus an in-flight partial line (no terminating newline). Seeding the tail-only-new cursor at
// the last newline boundary captures that record intact once it completes; seeding at the raw file
// size lands mid-line, so the resume re-reads only the record's tail — invalid JSON — dropping the
// record and emitting the "not valid JSON" diagnostic the soak saw trip has_partial_capture.
func TestNewlineBoundarySeedCapturesInFlightLine(t *testing.T) {
	ctx := context.Background()
	line1 := msgLine("first") + "\n"
	partial := `{"type":"message","role":"user","text":"second` // an in-flight record: no newline yet
	completion := `","ts":"2026-07-17T10:00:00Z"}` + "\n"       // completes line2 to valid JSON

	t.Run("newline-boundary seed keeps the completed record", func(t *testing.T) {
		root, state := t.TempDir(), t.TempDir()
		p := filepath.Join(root, "session.jsonl")
		writeFileString(t, p, line1+partial)

		off := lastNewlineTailOffset([]byte(line1 + partial))
		if off != int64(len(line1)) {
			t.Fatalf("newline-boundary offset = %d, want %d (just past line 1)", off, len(line1))
		}
		seedTailCursor(t, state, p, off)
		appendString(t, p, completion) // the in-flight record finishes

		sink := &recordingSink{}
		w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, Match: jsonlMatch})
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("poll: %v", err)
		}
		if got := messageBodies(sink.all()); len(got) != 1 || got[0] != "second" {
			t.Fatalf("message bodies = %v, want [second] (the completed in-flight record)", got)
		}
		if d := diagnostics(sink.all()); len(d) != 0 {
			t.Fatalf("newline-boundary seed produced %d diagnostics, want 0", len(d))
		}
	})

	t.Run("raw-size seed drops the in-flight record", func(t *testing.T) {
		root, state := t.TempDir(), t.TempDir()
		p := filepath.Join(root, "session.jsonl")
		writeFileString(t, p, line1+partial)

		rawSize := int64(len(line1 + partial)) // the buggy seed: mid-line
		seedTailCursor(t, state, p, rawSize)
		appendString(t, p, completion)

		sink := &recordingSink{}
		w := mustWatcher(t, WatchConfig{ApprovedRoots: []string{root}, StateDir: state, Sink: sink, Match: jsonlMatch})
		if err := w.Poll(ctx); err != nil {
			t.Fatalf("poll: %v", err)
		}
		for _, b := range messageBodies(sink.all()) {
			if b == "second" {
				t.Fatal("raw-size seed unexpectedly captured the in-flight record intact")
			}
		}
		var malformed bool
		for _, d := range diagnostics(sink.all()) {
			if strings.Contains(d.Diagnostic.Context, "not valid JSON") {
				malformed = true
			}
		}
		if !malformed {
			t.Fatal("raw-size (mid-line) seed must trip a 'not valid JSON' diagnostic — the FIX 2 symptom")
		}
	})
}
