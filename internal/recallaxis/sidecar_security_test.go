//go:build !windows

package recallaxis

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadGCSessionID_RejectsSymlink is the credential-exfil regression: a
// planted symlinked sidecar pointing at a single-line secret must NOT be read
// (the hardened open uses O_NOFOLLOW). The secret shape passes isSafeHeaderValue,
// so only the refusal-to-follow keeps it off the wire.
func TestReadGCSessionID_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("sk-live-DEADBEEF"), 0o600); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, "t.jsonl")
	if err := os.Symlink(secret, transcript+sidecarSuffix); err != nil {
		t.Fatal(err)
	}
	if got := readGCSessionID(transcript); got != "" {
		t.Fatalf("symlinked sidecar leaked %q, want \"\"", got)
	}
}

// TestReadGCSessionID_RejectsFIFO: a writerless FIFO sidecar must return ""
// immediately (O_NONBLOCK + regular-file check), never blocking the single
// scan goroutine.
func TestReadGCSessionID_RejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "t.jsonl")
	if err := syscall.Mkfifo(transcript+sidecarSuffix, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan string, 1)
	go func() { done <- readGCSessionID(transcript) }()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("FIFO sidecar => %q, want \"\"", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readGCSessionID blocked on a writerless FIFO sidecar")
	}
}

// TestReadGCSessionID_RejectsOversizedRegular: a >cap regular sidecar is dropped
// by the size cap (never fully read into memory).
func TestReadGCSessionID_RejectsOversizedRegular(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "t.jsonl")
	big := make([]byte, maxSidecarBytes+50)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(transcript+sidecarSuffix, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readGCSessionID(transcript); got != "" {
		t.Fatalf("oversized sidecar => %q, want \"\"", got)
	}
}

// TestUploadDoesNotExfilSymlinkedSidecar is the end-to-end exfil regression: a
// symlinked sidecar must not place a secret on the wire.
func TestUploadDoesNotExfilSymlinkedSidecar(t *testing.T) {
	root := setupSingleTranscriptRoot(t)
	transcript := filepath.Join(root, "proj", singleTranscriptName)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("sk-live-DEADBEEF"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, transcript+sidecarSuffix); err != nil {
		t.Fatal(err)
	}

	var got http.Header
	runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(201)
	})
	if _, present := got["X-Cass-Gc-Session-Id"]; present {
		t.Errorf("symlinked sidecar leaked header: %q", got.Get("X-Cass-Gc-Session-Id"))
	}
}
