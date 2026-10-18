//go:build linux || darwin

package consent

import (
	"os"
	"syscall"
	"testing"
)

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
