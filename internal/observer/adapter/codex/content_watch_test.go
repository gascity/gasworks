//go:build unix

package codex

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// recordingContentObserver records every ContentObservation the watcher fires, and every identity it
// forgets when a transcript is dropped.
type recordingContentObserver struct {
	mu     sync.Mutex
	obs    []ContentObservation
	forgot [][2]uint64
}

func (o *recordingContentObserver) ObserveContent(_ context.Context, obs ContentObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.obs = append(o.obs, obs)
}

func (o *recordingContentObserver) ForgetContent(device, inode uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.forgot = append(o.forgot, [2]uint64{device, inode})
}

func (o *recordingContentObserver) forgotten() [][2]uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][2]uint64(nil), o.forgot...)
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

func TestWatcherContentObservationReadsExactGCSessionIDSidecar(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("a")+"\n")
	// Gas City's transcriptmeta writer stores one opaque id followed by a record newline.
	writeFileString(t, p+".gcmeta", "gc_authoritative_123\n")

	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            &recordingSink{},
		Match:           func(name string) bool { return name == "session.jsonl" },
		ContentObserver: obs,
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll: %v", err)
	}
	got, ok := obs.last()
	if !ok {
		t.Fatal("no content observation")
	}
	if got.GCSessionID != "gc_authoritative_123" {
		t.Fatalf("GC session id = %q, want exact sidecar value", got.GCSessionID)
	}
}

func TestWatcherContentObservationRejectsUnsafeGCSessionIDSidecars(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "leading whitespace", value: " gc_123"},
		{name: "extra trailing whitespace", value: "gc_123 \n"},
		{name: "control", value: "gc_\x00123"},
		{name: "format", value: "gc_\u200b123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root, state := t.TempDir(), t.TempDir()
			p := filepath.Join(root, "session.jsonl")
			writeFileString(t, p, msgLine("a")+"\n")
			writeFileString(t, p+".gcmeta", tc.value)
			obs := &recordingContentObserver{}
			w := mustWatcher(t, WatchConfig{
				ApprovedRoots:   []string{root},
				StateDir:        state,
				Sink:            &recordingSink{},
				Match:           func(name string) bool { return name == "session.jsonl" },
				ContentObserver: obs,
			})
			if err := w.Poll(ctx); err != nil {
				t.Fatalf("poll: %v", err)
			}
			got, ok := obs.last()
			if !ok {
				t.Fatal("no content observation")
			}
			if got.GCSessionID != "" {
				t.Fatalf("GC session id = %q, want rejected sidecar omitted", got.GCSessionID)
			}
		})
	}
}

func TestWatcherGCSessionIDSidecarIsNoSymlinkAndBoundedCadence(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	writeFileString(t, p, msgLine("a")+"\n")
	outside := filepath.Join(t.TempDir(), "binding.gcmeta")
	writeFileString(t, outside, "gc_outside")
	if err := os.Symlink(outside, p+".gcmeta"); err != nil {
		t.Fatalf("symlink sidecar: %v", err)
	}

	now := time.Unix(1_700_000_000, 0)
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            &recordingSink{},
		Match:           func(name string) bool { return name == "session.jsonl" },
		ContentObserver: obs,
		Now:             func() time.Time { return now },
	})
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll symlink: %v", err)
	}
	if got, _ := obs.last(); got.GCSessionID != "" {
		t.Fatalf("symlink sidecar GC session id = %q, want omitted", got.GCSessionID)
	}
	if err := os.Remove(p + ".gcmeta"); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}
	writeFileString(t, p+".gcmeta", "gc_late\n")

	// A sidecar is checked at a bounded cadence rather than every 500ms watcher poll.
	now = now.Add(gcMetaCheckInterval - time.Nanosecond)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll before cadence: %v", err)
	}
	if got, _ := obs.last(); got.GCSessionID != "" {
		t.Fatalf("GC session id before cadence = %q, want cached empty value", got.GCSessionID)
	}
	now = now.Add(time.Nanosecond)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll at cadence: %v", err)
	}
	if got, _ := obs.last(); got.GCSessionID != "gc_late" {
		t.Fatalf("GC session id at cadence = %q, want late sidecar", got.GCSessionID)
	}

	// Once established, the exact binding is immutable for this transcript identity. A later
	// sidecar replacement must not silently re-home already uploaded content.
	writeFileString(t, p+".gcmeta", "gc_replaced\n")
	now = now.Add(gcMetaCheckInterval)
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll after sidecar replacement: %v", err)
	}
	if got, _ := obs.last(); got.GCSessionID != "gc_late" {
		t.Fatalf("GC session id after sidecar replacement = %q, want immutable gc_late", got.GCSessionID)
	}
}

// TestWatcherForgetsContentOnDrop proves the watcher notifies the content observer (once) when a
// tracked transcript is fully removed, at the same reconcile that GCs the cursor state — so the
// content side channel can release its per-identity state and durable marker.
func TestWatcherForgetsContentOnDrop(t *testing.T) {
	ctx := context.Background()
	root, state := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "session.jsonl")
	obs := &recordingContentObserver{}
	w := mustWatcher(t, WatchConfig{
		ApprovedRoots:   []string{root},
		StateDir:        state,
		Sink:            &recordingSink{},
		ContentObserver: obs,
	})

	writeFileString(t, p, msgLine("a")+"\n")
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	pinfo, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	dev, ino, ok := fileIdentityOf(pinfo)
	if !ok {
		t.Fatalf("file identity")
	}
	if len(obs.forgotten()) != 0 {
		t.Fatalf("forgot before drop: %v", obs.forgotten())
	}

	// Remove the transcript; the next poll must GC the identity and forget the content state.
	if err := os.Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := w.Poll(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	got := obs.forgotten()
	if len(got) != 1 || got[0] != [2]uint64{dev, ino} {
		t.Fatalf("forgot = %v, want exactly [(%d,%d)]", got, dev, ino)
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
