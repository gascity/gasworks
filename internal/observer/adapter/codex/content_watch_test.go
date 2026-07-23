//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// recordingContentObserver records every ContentObservation the watcher fires.
type recordingContentObserver struct {
	mu  sync.Mutex
	obs []ContentObservation
}

func (o *recordingContentObserver) ObserveContent(_ context.Context, obs ContentObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.obs = append(o.obs, obs)
}

func (o *recordingContentObserver) last() (ContentObservation, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.obs) == 0 {
		return ContentObservation{}, false
	}
	return o.obs[len(o.obs)-1], true
}

func TestWatcherFiresContentObserverWithStat(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	sink := &recordingSink{}
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            sink,
		ContentObserver: obs,
	})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	got, ok := obs.last()
	if !ok {
		t.Fatalf("no content observation after poll")
	}
	if got.Path != p {
		t.Fatalf("obs path = %q, want %q", got.Path, p)
	}
	if got.Device == 0 || got.Inode != inodeOf(t, p) {
		t.Fatalf("obs identity = (%d,%d), want inode %d", got.Device, got.Inode, inodeOf(t, p))
	}
	info, _ := os.Stat(p)
	if got.Size != info.Size() {
		t.Fatalf("obs size = %d, want %d", got.Size, info.Size())
	}

	// A poll with no new bytes still fires the observer (steady stability signal), with the same size.
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	got2, _ := obs.last()
	if got2.Size != info.Size() {
		t.Fatalf("second obs size = %d, want %d", got2.Size, info.Size())
	}
}

func TestReadValidatedTranscriptWholeFileAndOversize(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	content := "line1\nline2\nline3\n"
	writeFileString(t, p, content)

	info, _ := os.Stat(p)
	dev, ino, _ := fileIdentityOf(info)

	got, size, _, err := ReadValidatedTranscript(root, "session.jsonl", dev, ino, 0)
	if err != nil {
		t.Fatalf("ReadValidatedTranscript: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", size, len(content))
	}

	// Oversize: the file exceeds the ceiling, so it is refused without reading content.
	_, sz, _, err := ReadValidatedTranscript(root, "session.jsonl", dev, ino, 4)
	if err != ErrTranscriptTooLarge {
		t.Fatalf("oversize err = %v, want ErrTranscriptTooLarge", err)
	}
	if sz != int64(len(content)) {
		t.Fatalf("oversize reported size = %d, want %d", sz, len(content))
	}
}
