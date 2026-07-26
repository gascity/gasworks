//go:build darwin

package codex

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinOpenValidatedTranscriptWalksBeneathRoot(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, "nested", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(transcript, []byte("metadata\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(transcript)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatal("file identity unavailable")
	}

	file, size, _, err := openValidatedTranscript(root, filepath.Join("nested", "session.jsonl"), dev, ino)
	if err != nil {
		t.Fatalf("openValidatedTranscript: %v", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "metadata\n" || size != int64(len(data)) {
		t.Fatalf("opened transcript = %q size=%d", data, size)
	}
}

func TestDarwinOpenValidatedTranscriptRefusesParentSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "session.jsonl")
	if err := os.WriteFile(target, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatal("file identity unavailable")
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	file, _, _, err := openValidatedTranscript(root, filepath.Join("redirect", "session.jsonl"), dev, ino)
	if file != nil {
		_ = file.Close()
		t.Fatal("openValidatedTranscript returned escaped file")
	}
	if !errors.Is(err, errRefusedResolve) {
		t.Fatalf("openValidatedTranscript error = %v, want errRefusedResolve", err)
	}
}

func TestDarwinOpenValidatedTranscriptDoesNotBlockOnFIFOReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "session.jsonl")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	dev, ino, ok := fileIdentityOf(info)
	if !ok {
		t.Fatal("file identity unavailable")
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		time.Sleep(250 * time.Millisecond)
		fd, openErr := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if openErr == nil {
			_ = unix.Close(fd)
		}
	}()

	start := time.Now()
	file, _, _, err := openValidatedTranscript(root, "session.jsonl", dev, ino)
	elapsed := time.Since(start)
	if file != nil {
		_ = file.Close()
		t.Fatal("openValidatedTranscript returned FIFO")
	}
	if !errors.Is(err, errNotRegular) {
		t.Fatalf("openValidatedTranscript error = %v, want errNotRegular", err)
	}
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("openValidatedTranscript blocked on FIFO for %v", elapsed)
	}
	<-writerDone
}
