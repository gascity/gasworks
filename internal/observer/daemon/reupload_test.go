//go:build linux

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

const (
	reupCodexA = "019a0001-0000-7000-8000-00000000000a"
	reupCodexB = "019a0001-0000-7000-8000-00000000000b"
	reupCodexC = "019a0001-0000-7000-8000-00000000000c"
	reupClaude = "5b0c0f2e-0000-4000-8000-00000000000d"
)

var (
	reupOld = time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC) // the pre-cutover bulk upload
	reupNew = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
)

// reuploadFixture is a producer's transcript root and marker dir.
type reuploadFixture struct {
	t                    *testing.T
	root, state, journal string
	sleeps               []time.Duration
	mu                   sync.Mutex
}

func newReuploadFixture(t *testing.T) *reuploadFixture {
	return &reuploadFixture{t: t, root: t.TempDir(), state: t.TempDir(), journal: filepath.Join(t.TempDir(), "progress.jsonl")}
}

// transcript writes a transcript under the root and a marker for it uploaded at uploadedAt, and
// returns its identity. native "" writes no marker.
func (f *reuploadFixture) transcript(name, body, native, provider string, uploadedAt time.Time) transcriptIdentity {
	f.t.Helper()
	p := filepath.Join(f.root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		f.t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	id := transcriptIdentity{device: uint64(st.Dev), inode: st.Ino}
	if native != "" {
		// The marker recorded the whole file as it is now: the pre-cutover upload of an unchanged
		// transcript.
		f.marker(contentMarker{Version: contentMarkerVersion, Device: id.device, Inode: id.inode, ContentSHA256: hashOf(body), Size: int64(len(body)), ModNanos: 1, NativeSessionID: native, Provider: provider, UploadedAt: uploadedAt.Format(time.RFC3339Nano)})
	}
	return id
}

func (f *reuploadFixture) marker(m contentMarker) {
	f.t.Helper()
	data, _ := json.Marshal(m)
	if err := os.WriteFile(contentMarkerPath(f.state, m.Device, m.Inode), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *reuploadFixture) readMarker(id transcriptIdentity) contentMarker {
	f.t.Helper()
	data, err := os.ReadFile(contentMarkerPath(f.state, id.device, id.inode))
	if err != nil {
		f.t.Fatal(err)
	}
	var m contentMarker
	if err := json.Unmarshal(data, &m); err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *reuploadFixture) config(sender ContentSender) ReuploadConfig {
	return ReuploadConfig{
		Sender:       sender,
		StateDir:     f.state,
		Roots:        []string{f.root},
		Before:       ContentReuploadCutover,
		ProgressFile: f.journal,
		Interval:     time.Second,
		now:          func() time.Time { return time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) },
		sleep: func(_ context.Context, d time.Duration) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sleeps = append(f.sleeps, d)
			return nil
		},
	}
}

func (f *reuploadFixture) journalLines() int {
	data, err := os.ReadFile(f.journal)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// claudeName is where Claude Code writes a session's own transcript: <project>/<uuid>.jsonl.
func claudeName(id string) string { return filepath.Join("-work-p", id+".jsonl") }

func rolloutName(id string) string {
	return filepath.Join("2026", "07", "28", "rollout-2026-07-28T10-00-00-"+id+".jsonl")
}

func TestContentReuploadDryRunCountsOnly(t *testing.T) {
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld) // selected, located
	f.transcript(rolloutName(reupCodexB), "b\n", reupCodexB, "codex", reupNew) // after the cutoff
	f.transcript(claudeName(reupClaude), "c\n", reupClaude, "claude", reupOld) // selected, located
	// A marker whose transcript is gone.
	f.marker(contentMarker{Version: contentMarkerVersion, Device: 1, Inode: 99, ContentSHA256: "h", NativeSessionID: reupCodexC, Provider: "codex", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	before, _ := filepath.Glob(filepath.Join(f.state, "*"))

	sender := &fakeContentSender{}
	cfg := f.config(sender)
	cfg.DryRun = true
	rep, err := RunContentReupload(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if rep.Markers != 4 || rep.Selected != 3 || rep.Located != 2 || rep.Missing != 1 || rep.SelectedByProvider["codex"] != 2 || rep.SelectedByProvider["claude"] != 1 {
		t.Fatalf("dry-run report = %+v", rep)
	}
	if sender.count() != 0 || rep.Sent != 0 || f.journalLines() != 0 {
		t.Fatalf("a dry run sent %d / journaled %d", sender.count(), f.journalLines())
	}
	after, _ := filepath.Glob(filepath.Join(f.state, "*"))
	if len(after) != len(before) {
		t.Fatalf("a dry run changed the state dir: %d → %d files", len(before), len(after))
	}
}

func TestContentReuploadSendsPacedAndAdvancesMarkers(t *testing.T) {
	f := newReuploadFixture(t)
	a := f.transcript(rolloutName(reupCodexA), "rollout a\n", reupCodexA, "codex", reupOld)
	c := f.transcript(claudeName(reupClaude), "claude c\n", reupClaude, "claude", reupOld)
	b := f.transcript(rolloutName(reupCodexB), "rollout b\n", reupCodexB, "codex", reupNew)
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			return &upload.ContentResult{StatusCode: 200, Status: "duplicate"}, nil
		}
		return &upload.ContentResult{StatusCode: 201, Status: "accepted"}, nil
	}}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Sent != 2 || rep.Accepted != 2 || rep.Duplicate != 1 || sender.count() != 2 {
		t.Fatalf("report = %+v, posts = %d", rep, sender.count())
	}
	if len(f.sleeps) != 1 || f.sleeps[0] != time.Second {
		t.Fatalf("pacing sleeps = %v, want one 1s pause between the two uploads", f.sleeps)
	}
	for i := 0; i < sender.count(); i++ {
		req := sender.at(i)
		if (req.NativeSessionID != reupCodexA || req.Provider != "codex") && (req.NativeSessionID != reupClaude || req.Provider != "claude") {
			t.Fatalf("unexpected upload keyed (%q, %q)", req.NativeSessionID, req.Provider)
		}
	}
	for id, body := range map[transcriptIdentity]string{a: "rollout a\n", c: "claude c\n"} {
		m := f.readMarker(id)
		sum := sha256.Sum256([]byte(body))
		if m.ContentSHA256 != hex.EncodeToString(sum[:]) || m.Size != int64(len(body)) || m.UploadedAt != "2026-10-21T00:00:00Z" {
			t.Fatalf("marker not advanced: %+v", m)
		}
	}
	if m := f.readMarker(b); m.UploadedAt != reupNew.Format(time.RFC3339Nano) {
		t.Fatalf("an unselected marker changed: %+v", m)
	}
	if f.journalLines() != 2 {
		t.Fatalf("journal lines = %d, want 2", f.journalLines())
	}

	// Resumable: a rerun selects nothing by the cutoff (the markers moved past it), and an id-list
	// rerun of the same ids skips them as already done.
	sender2 := &fakeContentSender{}
	rep, err = RunContentReupload(context.Background(), f.config(sender2))
	if err != nil || rep.Selected != 0 || sender2.count() != 0 {
		t.Fatalf("cutoff rerun: rep=%+v err=%v posts=%d", rep, err, sender2.count())
	}
	cfg := f.config(sender2)
	cfg.Before = time.Time{}
	cfg.IDs = map[string]bool{reupCodexA: true}
	rep, err = RunContentReupload(context.Background(), cfg)
	if err != nil || rep.Selected != 1 || rep.AlreadyDone != 1 || sender2.count() != 0 {
		t.Fatalf("id rerun: rep=%+v err=%v posts=%d", rep, err, sender2.count())
	}
}

func TestContentReuploadStopsOnFailuresAndResumes(t *testing.T) {
	f := newReuploadFixture(t)
	a := f.transcript(rolloutName(reupCodexA), "rollout a\n", reupCodexA, "codex", reupOld)
	down := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 503}, nil
	}}
	cfg := f.config(down)
	cfg.MaxConsecutiveFailures = 1
	rep, err := RunContentReupload(context.Background(), cfg)
	if !errors.Is(err, ErrReuploadTooManyFailures) || rep.Failed != 1 {
		t.Fatalf("outage: rep=%+v err=%v", rep, err)
	}
	if down.count() != reuploadAttempts {
		t.Fatalf("attempts = %d, want %d", down.count(), reuploadAttempts)
	}
	if f.journalLines() != 0 || f.readMarker(a).UploadedAt != reupOld.Format(time.RFC3339Nano) {
		t.Fatal("a failed upload was settled")
	}

	up := &fakeContentSender{}
	rep, err = RunContentReupload(context.Background(), f.config(up))
	if err != nil || rep.Accepted != 1 || up.count() != 1 {
		t.Fatalf("resume: rep=%+v err=%v", rep, err)
	}
}

func TestContentReuploadStopsOnRefusal(t *testing.T) {
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld)
	f.transcript(rolloutName(reupCodexB), "b\n", reupCodexB, "codex", reupOld)
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 401}, nil
	}}
	_, err := RunContentReupload(context.Background(), f.config(sender))
	if !errors.Is(err, ErrReuploadRefused) || sender.count() != 1 || f.journalLines() != 0 {
		t.Fatalf("refusal: err=%v posts=%d", err, sender.count())
	}
}

func TestContentReuploadDropsARefusedGCBinding(t *testing.T) {
	f := newReuploadFixture(t)
	a := f.transcript(rolloutName(reupCodexA), "a\n", "", "", time.Time{})
	f.marker(contentMarker{Version: contentMarkerVersion, Device: a.device, Inode: a.inode, ContentSHA256: hashOf("a\n"), Size: 2, NativeSessionID: reupCodexA, Provider: "codex", GCSessionID: "gc-1", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	sender := &fakeContentSender{respond: func(_ int, r upload.ContentRequest) (*upload.ContentResult, error) {
		if r.GCSessionID != "" {
			return &upload.ContentResult{StatusCode: 409, Code: wire.ObserverErrorBodyCodeSOURCEBINDINGCONFLICT}, nil
		}
		return &upload.ContentResult{StatusCode: 201}, nil
	}}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil || rep.Accepted != 1 || sender.count() != 2 || sender.at(0).GCSessionID != "gc-1" || sender.at(1).GCSessionID != "" {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if m := f.readMarker(a); !m.GCBindingRefused || m.GCSessionID != "gc-1" {
		t.Fatalf("marker = %+v, want the binding kept and recorded as refused", m)
	}
}

// A marker whose identity now belongs to another transcript (a reused inode) is never sent, and a
// Claude transcript whose marker id is not its file uuid (a resumed or forked session) is counted.
func TestContentReuploadIdentityChecks(t *testing.T) {
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexB, "codex", reupOld) // marker names B, file is A
	f.transcript(claudeName(reupClaude), "c\n", "11111111-2222-4333-8444-555555555555", "claude", reupOld)
	cfg := f.config(&fakeContentSender{})
	cfg.DryRun = true
	rep, err := RunContentReupload(context.Background(), cfg)
	if err != nil || rep.IdentityMismatch != 1 || rep.NativeDiffersName != 1 || rep.Located != 2 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

// The file must still be the transcript the marker recorded: its first marker.Size bytes hash to the
// marker's content_sha256. A reused inode (here a Claude file whose name even matches the marker id,
// and a marker with a legacy non-UUID id) is never sent; a transcript that only grew is.
func TestContentReuploadRequiresTheMarkersContentPrefix(t *testing.T) {
	f := newReuploadFixture(t)
	reusedClaude := f.transcript(claudeName(reupClaude), "a different, longer transcript\n", "", "", time.Time{})
	f.marker(contentMarker{Version: contentMarkerVersion, Device: reusedClaude.device, Inode: reusedClaude.inode, ContentSHA256: hashOf("the recorded transcript\n"), Size: 24, NativeSessionID: reupClaude, Provider: "claude", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	legacy := f.transcript(rolloutName(reupCodexC), "some other bytes\n", "", "", time.Time{})
	f.marker(contentMarker{Version: legacyContentMarkerVersion, Device: legacy.device, Inode: legacy.inode, ContentSHA256: hashOf("old"), Size: 3, NativeSessionID: "legacy-stem-id", Provider: "codex", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	short := f.transcript(rolloutName(reupCodexB), "x\n", "", "", time.Time{})
	f.marker(contentMarker{Version: contentMarkerVersion, Device: short.device, Inode: short.inode, ContentSHA256: hashOf("x\nlonger than the file\n"), Size: 24, NativeSessionID: reupCodexB, Provider: "codex", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	grown := f.transcript(rolloutName(reupCodexA), "line 1\nline 2\n", "", "", time.Time{})
	f.marker(contentMarker{Version: contentMarkerVersion, Device: grown.device, Inode: grown.inode, ContentSHA256: hashOf("line 1\n"), Size: 7, NativeSessionID: reupCodexA, Provider: "codex", UploadedAt: reupOld.Format(time.RFC3339Nano)})

	sender := &fakeContentSender{}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.IdentityMismatch != 3 || rep.Sent != 1 || rep.Accepted != 1 || sender.count() != 1 {
		t.Fatalf("rep=%+v posts=%d, want 3 identity mismatches and only the grown transcript sent", rep, sender.count())
	}
	if req := sender.at(0); req.NativeSessionID != reupCodexA || string(req.Body) != "line 1\nline 2\n" {
		t.Fatalf("sent session %q (%d bytes), want the grown transcript", req.NativeSessionID, len(req.Body))
	}
	for _, id := range []transcriptIdentity{reusedClaude, legacy, short} {
		if m := f.readMarker(id); m.UploadedAt != reupOld.Format(time.RFC3339Nano) {
			t.Fatalf("a mismatched marker changed: %+v", m)
		}
	}
	if f.journalLines() != 1 {
		t.Fatalf("journal lines = %d, want 1 (mismatches are not settled)", f.journalLines())
	}
}

// A 429's Retry-After is honored, and capped at maxContentHold.
func TestContentReuploadHonorsAndCapsRetryAfter(t *testing.T) {
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld)
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		switch n {
		case 0:
			return &upload.ContentResult{StatusCode: 429, RetryAfter: 7 * time.Second}, nil
		case 1:
			return &upload.ContentResult{StatusCode: 429, RetryAfter: 3 * time.Hour}, nil
		}
		return &upload.ContentResult{StatusCode: 201}, nil
	}}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil || rep.Accepted != 1 || rep.Sent != 1 || sender.count() != 3 {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if len(f.sleeps) != 2 || f.sleeps[0] != 7*time.Second || f.sleeps[1] != maxContentHold {
		t.Fatalf("sleeps = %v, want [7s %s]", f.sleeps, maxContentHold)
	}
}

// When the re-send without a refused GC binding is ALSO answered SOURCE_BINDING_CONFLICT, the store
// binds the path or id to another transcript: a conflict, never an acceptance. The marker is left as
// it was and nothing is journaled, so a rerun retries.
func TestContentReuploadDoubleBindingConflictIsAConflict(t *testing.T) {
	f := newReuploadFixture(t)
	a := f.transcript(rolloutName(reupCodexA), "a\n", "", "", time.Time{})
	f.marker(contentMarker{Version: contentMarkerVersion, Device: a.device, Inode: a.inode, ContentSHA256: hashOf("a\n"), Size: 2, NativeSessionID: reupCodexA, Provider: "codex", GCSessionID: "gc-1", UploadedAt: reupOld.Format(time.RFC3339Nano)})
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 409, Code: wire.ObserverErrorBodyCodeSOURCEBINDINGCONFLICT}, nil
	}}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil || rep.Conflict != 1 || rep.Accepted != 0 || sender.count() != 2 || sender.at(1).GCSessionID != "" {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if m := f.readMarker(a); m.UploadedAt != reupOld.Format(time.RFC3339Nano) || m.GCBindingRefused {
		t.Fatalf("marker changed on a conflict: %+v", m)
	}
	if f.journalLines() != 0 {
		t.Fatalf("journal lines = %d, want 0 (a conflict is retried by a rerun)", f.journalLines())
	}
}

// A plain 409 leaves the marker unchanged and is not journaled.
func TestContentReuploadPlainConflictLeavesTheMarker(t *testing.T) {
	f := newReuploadFixture(t)
	a := f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld)
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		return &upload.ContentResult{StatusCode: 409, Message: "content conflicts with a durable snapshot"}, nil
	}}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil || rep.Conflict != 1 || sender.count() != 1 {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if m := f.readMarker(a); m.UploadedAt != reupOld.Format(time.RFC3339Nano) || m.ContentSHA256 != hashOf("a\n") {
		t.Fatalf("marker changed on a conflict: %+v", m)
	}
	if f.journalLines() != 0 {
		t.Fatalf("journal lines = %d, want 0", f.journalLines())
	}
}

// A run of consecutive non-accepted answers (a systematic conflict or rejection) stops the run
// instead of walking the whole selection.
func TestContentReuploadStopsOnSystematicConflicts(t *testing.T) {
	f := newReuploadFixture(t)
	for _, id := range []string{reupCodexA, reupCodexB, reupCodexC} {
		f.transcript(rolloutName(id), id+"\n", id, "codex", reupOld)
	}
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			return &upload.ContentResult{StatusCode: 422}, nil
		}
		return &upload.ContentResult{StatusCode: 409, Code: wire.ObserverErrorBodyCodeSOURCEBINDINGCONFLICT}, nil
	}}
	cfg := f.config(sender)
	cfg.MaxConsecutiveConflicts = 2
	rep, err := RunContentReupload(context.Background(), cfg)
	if !errors.Is(err, ErrReuploadTooManyConflicts) || sender.count() != 2 || rep.Rejected != 1 || rep.Conflict != 1 {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if f.journalLines() != 1 {
		t.Fatalf("journal lines = %d, want 1 (the rejection only)", f.journalLines())
	}
}

// Two runs cannot share one progress journal.
func TestContentReuploadLocksTheJournal(t *testing.T) {
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld)
	held, err := lockReuploadJournal(f.journal)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	sender := &fakeContentSender{}
	if _, err := RunContentReupload(context.Background(), f.config(sender)); !errors.Is(err, ErrReuploadJournalLocked) || sender.count() != 0 {
		t.Fatalf("second run: err=%v posts=%d", err, sender.count())
	}
	_ = held.Close()
	if rep, err := RunContentReupload(context.Background(), f.config(sender)); err != nil || rep.Accepted != 1 {
		t.Fatalf("after release: rep=%+v err=%v", rep, err)
	}
}

// A marker that cannot be written after an accepted upload does not stop the run: the transcript is
// counted, left unjournaled (a rerun re-sends it), and the next one is still sent.
func TestContentReuploadSurvivesAMarkerWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permission this test relies on")
	}
	f := newReuploadFixture(t)
	f.transcript(rolloutName(reupCodexA), "a\n", reupCodexA, "codex", reupOld)
	f.transcript(rolloutName(reupCodexB), "b\n", reupCodexB, "codex", reupOld)
	if err := os.Chmod(f.state, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.state, 0o700) })
	sender := &fakeContentSender{}
	rep, err := RunContentReupload(context.Background(), f.config(sender))
	if err != nil || rep.Accepted != 2 || rep.MarkerWriteErrors != 2 || sender.count() != 2 {
		t.Fatalf("rep=%+v err=%v posts=%d", rep, err, sender.count())
	}
	if f.journalLines() != 0 {
		t.Fatalf("journal lines = %d, want 0", f.journalLines())
	}
}
