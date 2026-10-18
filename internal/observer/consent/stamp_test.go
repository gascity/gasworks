//go:build linux || darwin

package consent

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestInPlaceRewriteKeepingSizeAndMtimeIsDetected: a rewrite in place that preserves the file's
// size and modification time (a copy that kept the timestamp) still moves its change time, so it is
// re-read rather than mistaken for the document already held.
func TestInPlaceRewriteKeepingSizeAndMtimeIsDetected(t *testing.T) {
	root := t.TempDir()
	body := v3(true, record(root, 1, true))
	f := newPolicyFile(t, body)
	src := open(t, Config{Path: f.path})
	info, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte(strings.Repeat("x", len(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f.path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if p := src.Current(); p.Valid() || p.ContentUpload {
		t.Fatalf("an in-place rewrite that kept size and mtime went unnoticed: %+v", p)
	}
}

// TestPolicyReplacedByAFIFOFailsClosedWithoutBlocking: a policy path that is no longer a regular
// file — here a FIFO, which a plain read would block on forever — fails closed at once, and the
// narrowing fallback does not block on it either.
func TestPolicyReplacedByAFIFOFailsClosedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	f := newPolicyFile(t, v3(true, record(root, 1, true)))
	src := open(t, Config{Path: f.path})
	fifo := f.path + ".fifo"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := os.Rename(fifo, f.path); err != nil {
		t.Fatal(err)
	}
	if p := src.Current(); p.Valid() || p.ContentUpload || !p.Allows(root, 1) {
		t.Fatalf("a FIFO policy yielded %+v, want content withdrawn and the last valid roots kept", p)
	}
}
