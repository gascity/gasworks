//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// pendingRecords lists the pending-content records in a content state dir.
func pendingRecords(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "content-pending-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// restartedUploader is a fresh uploader over the harness's state dir, as a daemon restart builds it:
// its sink threading is empty (a transcript the previous run consumed to EOF is never parsed again),
// and it talks to sender.
func (h *contentHarness) restartedUploader(t *testing.T, sender *fakeContentSender) *contentUploader {
	t.Helper()
	u, err := newContentUploader(contentUploaderConfig{
		sender:   sender,
		sessions: newSessions(),
		stateDir: h.stateDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
		log:      h.appendLog,
	})
	if err != nil {
		t.Fatalf("restart newContentUploader: %v", err)
	}
	return u
}

func observeOn(u *contentUploader, dev, ino uint64, size, mod int64) {
	observeNamed(u, "s.jsonl", dev, ino, size, mod)
}

// observeNamed reports a transcript at locator below the root.
func observeNamed(u *contentUploader, locator string, dev, ino uint64, size, mod int64) {
	u.ObserveContent(context.Background(), codex.ContentObservation{
		Root: "/root", Locator: locator, Path: testCodexPath, Device: dev, Inode: ino, Size: size, ModNanos: mod,
	})
}

// TestContentRefusalQueueSurvivesARestart is the regression for content queued during a refusal
// being lost to a restart: the previous run consumed those transcripts' metadata to EOF, so the
// restarted daemon never parses them again and has no session to key their content by. Everything
// queued — the refused transcript, one first observed during the refusal, and one still settling
// when the daemon stopped — is uploaded after the restart once the collector accepts, under the
// session it was queued with, exactly once, and leaves no pending record behind.
func TestContentRefusalQueueSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	h := newContentHarness(t, contentUploaderConfig{sender: refusingWith(401).sender()})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx) // refused
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(2, 2, "bbbb", 1)
	h.observe(2, 2, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx) // the retry is refused again before the transcript queued behind it is attempted
	h.sessions.set(3, 3, "s3", "codex")
	h.reader.set(3, 3, "ccccc", 1)
	h.observe(3, 3, testCodexPath, 5, 1)
	h.u.tick(ctx) // still settling, and the refusal holds
	if got := h.sender.count(); got != 2 {
		t.Fatalf("attempts before the restart = %d, want the 2 refused attempts", got)
	}

	accepting := &fakeContentSender{}
	u := h.restartedUploader(t, accepting)
	for ino, size := range map[uint64]int64{1: 3, 2: 4, 3: 5} {
		observeOn(u, ino, ino, size, 1)
	}
	h.clock.advance(31 * time.Second)
	u.tick(ctx)
	if accepting.count() != 3 {
		t.Fatalf("uploads after the restart = %d, want all 3 queued transcripts", accepting.count())
	}
	sessionOf := map[string]string{}
	for i := range accepting.count() {
		r := accepting.at(i)
		sessionOf[string(r.Body)] = r.NativeSessionID
	}
	for body, want := range map[string]string{"aaa": "s1", "bbbb": "s2", "ccccc": "s3"} {
		if sessionOf[body] != want {
			t.Fatalf("transcript %q uploaded under session %q, want %q (the session it was queued with)", body, sessionOf[body], want)
		}
	}
	h.clock.advance(31 * time.Second)
	u.tick(ctx)
	if accepting.count() != 3 {
		t.Fatalf("uploads after a further tick = %d, want each transcript exactly once", accepting.count())
	}
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("pending records left after every queued transcript was accepted: %v", left)
	}

	// A second restart finds every transcript already uploaded.
	again := &fakeContentSender{}
	u = h.restartedUploader(t, again)
	for ino, size := range map[uint64]int64{1: 3, 2: 4, 3: 5} {
		observeOn(u, ino, ino, size, 1)
	}
	h.clock.advance(31 * time.Second)
	u.tick(ctx)
	if again.count() != 0 {
		t.Fatalf("a second restart re-uploaded %d transcripts", again.count())
	}
}

// TestContentPendingIsNotWrittenForAnUploadedTranscript: a transcript whose upload was accepted is
// keyed after a restart by its marker, so neither its acceptance nor its growth leaves a pending
// record — the pending set costs disk writes only for content not yet accepted once.
func TestContentPendingIsNotWrittenForAnUploadedTranscript(t *testing.T) {
	ctx := context.Background()
	h := newContentHarness(t, contentUploaderConfig{})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx)
	if h.sender.count() != 1 {
		t.Fatalf("uploads = %d, want 1", h.sender.count())
	}
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("an accepted upload left a pending record: %v", left)
	}
	h.reader.set(1, 1, "aaabbb", 2)
	h.observe(1, 1, testCodexPath, 6, 2)
	h.u.tick(ctx) // owed again, still settling
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("a transcript its marker already keys wrote a pending record: %v", left)
	}
}

// TestContentPendingDoesNotKeyAReusedInode: a pending record names the transcript it was queued for
// by identity, name, and the size it had then. A new transcript that reused the inode after the old
// one was deleted while the daemon was stopped — larger than the record by then, under its own name —
// is not keyed by the old transcript's session; it uploads once its own session is known.
func TestContentPendingDoesNotKeyAReusedInode(t *testing.T) {
	ctx := context.Background()
	h := newContentHarness(t, contentUploaderConfig{sender: refusingWith(401).sender()})
	h.sessions.set(9, 9, "old-session", "codex")
	h.reader.set(9, 9, "old head", 1)
	observeNamed(h.u, "rollout-old.jsonl", 9, 9, 8, 1)
	h.u.tick(ctx) // owed while still settling: recorded at its head
	if len(pendingRecords(t, h.stateDir)) != 1 {
		t.Fatal("no pending record for the owed transcript")
	}

	accepting := &fakeContentSender{}
	sessions := newSessions()
	u, err := newContentUploader(contentUploaderConfig{
		sender: accepting, sessions: sessions, stateDir: h.stateDir, read: h.reader.read,
		now: h.clock.now, debounce: 30 * time.Second, log: h.appendLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.reader.set(9, 9, "an unrelated transcript, longer than the old one's head", 2)
	observeNamed(u, "rollout-new.jsonl", 9, 9, 55, 2)
	h.clock.advance(31 * time.Second)
	u.tick(ctx)
	if accepting.count() != 0 {
		t.Fatalf("a reused inode was uploaded under the previous transcript's session %q", accepting.at(0).NativeSessionID)
	}
	sessions.set(9, 9, "new-session", "codex")
	u.tick(ctx)
	if accepting.count() != 1 || accepting.at(0).NativeSessionID != "new-session" {
		t.Fatalf("the new transcript was not uploaded under its own session once known: %d uploads", accepting.count())
	}
}

// TestContentOwedDuringAnUploadIsRecordedWhenItEnds: an upload can take minutes. Content first owed
// while one is in flight is recorded as soon as it ends — not at the next tick — so a daemon stopped
// in the middle of a long upload burst still resumes it after the restart.
func TestContentOwedDuringAnUploadIsRecordedWhenItEnds(t *testing.T) {
	inFlight, release := make(chan struct{}), make(chan struct{})
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			close(inFlight)
			<-release
		}
		return &upload.ContentResult{StatusCode: 201}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	done := make(chan struct{})
	go func() {
		h.u.tick(context.Background())
		close(done)
	}()
	<-inFlight
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(2, 2, "bbbb", 1)
	h.observe(2, 2, testCodexPath, 4, 1)
	h.clock.advance(time.Minute) // a long upload
	close(release)
	<-done
	if _, ok := readContentPending(filepath.Join(h.stateDir, contentPendingName(2, 2))); !ok {
		t.Fatal("content first owed during an upload was not recorded when the upload ended")
	}
}

// TestServiceShutdownRecordsOwedContent: content first owed after the content loop last planned —
// here, before it ever ran — is recorded as the daemon stops, so the restarted daemon, which never
// parses the transcript again, uploads it once, under its session.
func TestServiceShutdownRecordsOwedContent(t *testing.T) {
	root, cursorDir, stateDir := t.TempDir(), t.TempDir(), t.TempDir()
	clock := newClock()
	sender := &fakeContentSender{}
	start := func() *Service {
		t.Helper()
		svc, err := NewService(ServiceConfig{
			Dir: stateDir, SourceID: testSourceID, Capacity: permissiveCapacity(), PeerUID: euidPeer, Now: clock.now,
			Watch:         &WatchLoopConfig{ApprovedRoots: []string{root}, StateDir: cursorDir, Policy: serviceWatchPolicy(), Interval: time.Hour},
			ContentUpload: &ContentUploadLoopConfig{Sender: sender, Interval: time.Hour, Debounce: 30 * time.Second},
		})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		if err := svc.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return svc
	}
	stop := func(svc *Service) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := svc.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	}
	const session = "01a0f1f1-0000-7000-8000-0000000000d1"
	appendTranscript(t, filepath.Join(root, "rollout-owed.jsonl"), rolloutLines(session, 2))

	svc := start()
	if err := svc.PollTranscripts(context.Background()); err != nil {
		t.Fatalf("PollTranscripts: %v", err)
	}
	stop(svc) // the content loop never ran
	svc = start()
	defer stop(svc)
	if err := svc.PollTranscripts(context.Background()); err != nil { // consumed to its end: nothing parsed
		t.Fatalf("PollTranscripts: %v", err)
	}
	clock.advance(31 * time.Second)
	svc.TickContentUploads(context.Background())
	if sender.count() != 1 || sender.at(0).NativeSessionID != session {
		t.Fatalf("content owed when the daemon stopped: %d uploads after the restart, want 1 under %s", sender.count(), session)
	}
}

// TestDiscardQueuedContentKeepsUploadMarkers: discarding the queue deletes the pending records and
// nothing else — the markers of transcripts already uploaded stay.
func TestDiscardQueuedContentKeepsUploadMarkers(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "uploaded", 1)
	h.observe(1, 1, testCodexPath, 8, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background()) // uploaded: its marker stays
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(2, 2, "queued", 1)
	h.observe(2, 2, testCodexPath, 6, 1)
	h.u.tick(context.Background()) // queued, settling
	if len(pendingRecords(t, h.stateDir)) != 1 {
		t.Fatal("no pending record for the queued transcript")
	}

	n, err := DiscardQueuedContent(h.stateDir)
	if err != nil || n != 1 {
		t.Fatalf("DiscardQueuedContent = %d, %v; want 1 discarded", n, err)
	}
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("pending records left: %v", left)
	}
	if _, ok := h.u.loadMarker(transcriptIdentity{device: 1, inode: 1}); !ok {
		t.Fatal("discarding the queue removed an upload marker")
	}
}

// TestContentPendingIsForgottenWithItsTranscript: when the watcher drops a transcript identity, its
// pending record goes with its marker and its in-memory state.
func TestContentPendingIsForgottenWithItsTranscript(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{sender: refusingWith(401).sender()})
	h.sessions.set(5, 5, "s", "codex")
	h.reader.set(5, 5, "body", 1)
	h.observe(5, 5, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	if len(pendingRecords(t, h.stateDir)) != 1 {
		t.Fatal("no pending record for the refused transcript")
	}
	h.u.ForgetContent(5, 5)
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("pending record kept after the transcript was forgotten: %v", left)
	}
}

// TestContentPendingWriteFailureIsLoggedOnce: a pending record that cannot be written is retried on
// every tick but reported once per failure streak — not once per tick, and not again because other
// transcripts' records and uploads succeed meanwhile — and the record lands as soon as the write
// succeeds. A directory in the record's place makes the write fail whatever the privileges.
func TestContentPendingWriteFailureIsLoggedOnce(t *testing.T) {
	h := newContentHarness(t, contentUploaderConfig{})
	squatter := filepath.Join(h.stateDir, "content-pending-5-5.json")
	if err := os.MkdirAll(filepath.Join(squatter, "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.sessions.set(5, 5, "s", "codex")
	h.reader.set(5, 5, "body", 1)
	h.observe(5, 5, testCodexPath, 4, 1)
	for i := range uint64(3) {
		// Another transcript is accepted on each tick, while this one still settles.
		h.sessions.set(10+i, 10+i, "other", "codex")
		h.reader.set(10+i, 10+i, "other", 1)
		h.observe(10+i, 10+i, testCodexPath, 5, 1)
		h.clock.advance(31 * time.Second)
		h.observe(5, 5, testCodexPath, 4, int64(i+2)) // still growing
		h.u.tick(context.Background())
	}
	if h.sender.count() != 3 {
		t.Fatalf("uploads of the other transcripts = %d, want 3", h.sender.count())
	}
	if n := len(h.logsContaining("record the queued content")); n != 1 {
		t.Fatalf("a failing pending-record write was logged %d times over 3 ticks, want once", n)
	}
	if err := os.RemoveAll(squatter); err != nil {
		t.Fatal(err)
	}
	h.u.tick(context.Background())
	if _, ok := readContentPending(squatter); !ok {
		t.Fatal("the pending record was not written once the write could succeed")
	}
}

// newConsentUploader builds an uploader under the live policy at policyPath over stateDir, as a
// daemon start does, subscribed to the policy's changes.
func newConsentUploader(t *testing.T, policyPath, stateDir string, sender *fakeContentSender, sessions *fakeSessions, reader *fakeReader, clock *fakeClock) *contentUploader {
	t.Helper()
	src, err := consent.Open(consent.Config{Path: policyPath})
	if err != nil {
		t.Fatalf("consent.Open: %v", err)
	}
	u, err := newContentUploader(contentUploaderConfig{
		sender: sender, sessions: sessions, stateDir: stateDir, read: reader.read,
		now: clock.now, debounce: 30 * time.Second, consent: src,
	})
	if err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	src.Subscribe(u.onConsentChange)
	return u
}

// TestContentConsentWithdrawnDuringARefusalDropsTheQueue: consent wins over the retry. Content
// consent withdrawn while the collector refuses content upload drops the queue for good: nothing
// queued before the withdrawal is sent once the collector accepts again, its pending record is
// deleted at once, and a later restart under a policy that grants content again does not resurrect
// it.
func TestContentConsentWithdrawnDuringARefusalDropsTheQueue(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	coll := refusingWith(401)
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), coll.sender())
	h.transcript(1, 1, "first\n")
	h.observe(gens, root, 1, 1, 6)
	h.settleAndTick() // refused
	if h.sender.count() != 1 || len(pendingRecords(t, h.markerDir)) != 1 {
		t.Fatalf("want 1 refused attempt and its pending record; got %d attempts, records %v", h.sender.count(), pendingRecords(t, h.markerDir))
	}

	writePolicyAtomic(t, h.policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	h.src.Current()
	if left := pendingRecords(t, h.markerDir); len(left) != 0 {
		t.Fatalf("content consent was withdrawn but the queued content's pending record is kept: %v", left)
	}
	coll.accept()
	h.clock.advance(10 * time.Minute)
	h.u.tick(context.Background())
	if h.sender.count() != 1 {
		t.Fatalf("content queued before the withdrawal was sent once the collector accepted (%d attempts)", h.sender.count())
	}

	// A restart under a policy granting content again does not send the dropped queue.
	writePolicyAtomic(t, h.policyPath, consentPolicyBody(true, consentRoot{root, 1, true}))
	accepting := &fakeContentSender{}
	u := newConsentUploader(t, h.policyPath, h.markerDir, accepting, newSessions(), h.reader, h.clock)
	consentContentObserver{u: u, generations: gens}.ObserveContent(context.Background(), codex.ContentObservation{
		Root: root, ConsentRoot: root, Locator: "rollout-x.jsonl", Path: filepath.Join(root, "rollout-x.jsonl"),
		Device: 1, Inode: 1, Size: 6, ModNanos: 1,
	})
	h.clock.advance(31 * time.Second)
	u.tick(context.Background())
	if accepting.count() != 0 {
		t.Fatalf("a restart resurrected content queued before consent was withdrawn (%d uploads)", accepting.count())
	}
}

// TestContentQueuedUnderAnEarlierGenerationIsNotResumed: content queued under one consent generation
// is never uploaded under another. A root re-registered while the daemon was stopped leaves the
// content the previous run queued under the earlier generation unsent after the restart, and its
// pending record is deleted at start.
func TestContentQueuedUnderAnEarlierGenerationIsNotResumed(t *testing.T) {
	root := t.TempDir()
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), refusingWith(401).sender())
	h.transcript(1, 1, "first\n")
	h.observe(map[string]uint64{root: 1}, root, 1, 1, 6)
	h.settleAndTick() // refused, queued under generation 1
	if len(pendingRecords(t, h.markerDir)) != 1 {
		t.Fatal("no pending record for the refused transcript")
	}

	writePolicyAtomic(t, h.policyPath, consentPolicyBody(true, consentRoot{root, 2, true}))
	accepting := &fakeContentSender{}
	u := newConsentUploader(t, h.policyPath, h.markerDir, accepting, newSessions(), h.reader, h.clock)
	if left := pendingRecords(t, h.markerDir); len(left) != 0 {
		t.Fatalf("a pending record of a superseded generation survived the start: %v", left)
	}
	consentContentObserver{u: u, generations: map[string]uint64{root: 2}}.ObserveContent(context.Background(), codex.ContentObservation{
		Root: root, ConsentRoot: root, Locator: "rollout-x.jsonl", Path: filepath.Join(root, "rollout-x.jsonl"),
		Device: 1, Inode: 1, Size: 6, ModNanos: 1,
	})
	h.clock.advance(31 * time.Second)
	u.tick(context.Background())
	if accepting.count() != 0 {
		t.Fatalf("content queued under generation 1 was uploaded under generation 2 (%d uploads)", accepting.count())
	}
}

// TestServiceWithoutAContentChannelFollowsConsentForQueuedContent: a run under the live policy that
// has no content channel (no collector) uploads no content, but the content an earlier run queued
// still follows the policy: kept while it consents, discarded as soon as it withdraws content consent,
// so a later run with a collector cannot send it.
func TestServiceWithoutAContentChannelFollowsConsentForQueuedContent(t *testing.T) {
	root := t.TempDir()
	d := &consentDaemon{
		t:          t,
		stateDir:   t.TempDir(),
		cursorDir:  t.TempDir(),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		coll:       newLaneCollector(),
		logs:       &logLines{},
		noUploader: true,
	}
	writePolicyAtomic(t, d.policyPath, consentPolicyBody(true, consentRoot{root, 1, true}))
	rec := contentPending{
		Version: contentPendingVersion, Device: 1, Inode: 1, NativeSessionID: "s1", Provider: "codex",
		ConsentRoot: root, ConsentGeneration: 1, Locator: "rollout-queued.jsonl", Size: 6, ModNanos: 1,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStateFile(d.cursorDir, contentPendingName(1, 1), contentPendingTempPrefix, data); err != nil {
		t.Fatal(err)
	}
	d.start()
	if len(pendingRecords(t, d.cursorDir)) != 1 {
		t.Fatal("content queued under consent the policy still grants was discarded at start")
	}
	d.setPolicy(consentPolicyBody(false, consentRoot{root, 1, true}))
	d.poll()
	if left := pendingRecords(t, d.cursorDir); len(left) != 0 {
		t.Fatalf("content consent was withdrawn but the queued content is kept: %v", left)
	}
}

// TestSweepContentPendingContinuesPastAFailedDelete: a pending record the sweep cannot delete does not
// stop it. Every other record it should delete goes, the one it keeps stays, and the failure is
// reported. A non-empty directory under a record's name cannot be deleted whatever the privileges.
func TestSweepContentPendingContinuesPastAFailedDelete(t *testing.T) {
	dir := t.TempDir()
	stuck := filepath.Join(dir, contentPendingName(1, 1))
	if err := os.MkdirAll(filepath.Join(stuck, "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	record := func(dev, ino uint64, root string) string {
		t.Helper()
		data, err := json.Marshal(contentPending{
			Version: contentPendingVersion, Device: dev, Inode: ino, NativeSessionID: "s", Provider: "codex",
			ConsentRoot: root, ConsentGeneration: 1, Locator: "rollout-x.jsonl",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeStateFile(dir, contentPendingName(dev, ino), contentPendingTempPrefix, data); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir, contentPendingName(dev, ino))
	}
	withdrawn := record(2, 2, "/withdrawn")
	kept := record(3, 3, "/kept")

	n, err := sweepContentPending(dir, func(o consentOrigin) bool { return o.root == "/kept" })
	if n != 1 {
		t.Fatalf("deleted %d records, want the 1 withdrawn one", n)
	}
	if err == nil || !strings.Contains(err.Error(), contentPendingName(1, 1)) {
		t.Fatalf("sweep error = %v, want it to report the record it could not delete", err)
	}
	if _, err := os.Stat(withdrawn); !os.IsNotExist(err) {
		t.Fatalf("a failed delete stopped the sweep before the withdrawn record: %v", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the sweep deleted a record it should keep: %v", err)
	}
}

// TestContentOwedBetweenUploadsIsRecordedOncePerInterval: between the uploads of one tick, owed
// content is recorded at most once per content interval — the content loop's configured cadence, not
// a fixed one — so a long burst neither replans after every upload nor records later than one
// interval.
func TestContentOwedBetweenUploadsIsRecordedOncePerInterval(t *testing.T) {
	var h *contentHarness
	var recordedAtStart []bool
	sender := &fakeContentSender{respond: func(n int, _ upload.ContentRequest) (*upload.ContentResult, error) {
		if n == 0 {
			// A transcript is first owed while the first upload is in flight.
			h.sessions.set(9, 9, "s9", "codex")
			h.reader.set(9, 9, "late", 1)
			h.observe(9, 9, testCodexPath, 4, 1)
		}
		_, err := os.Stat(filepath.Join(h.stateDir, contentPendingName(9, 9)))
		recordedAtStart = append(recordedAtStart, err == nil)
		h.clock.advance(time.Minute) // each upload takes a minute
		return &upload.ContentResult{StatusCode: 201}, nil
	}}
	h = newContentHarness(t, contentUploaderConfig{sender: sender, interval: 2 * time.Minute})
	for i := uint64(1); i <= 3; i++ {
		body := strings.Repeat("x", int(i))
		h.sessions.set(i, i, fmt.Sprintf("s%d", i), "codex")
		h.reader.set(i, i, body, 1)
		h.observe(i, i, testCodexPath, int64(len(body)), 1)
	}
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
	// The plan ran at the start; one minute later the interval has not passed, two minutes later it has.
	if want := []bool{false, false, true}; !slices.Equal(recordedAtStart, want) {
		t.Fatalf("pending record present at the start of each upload = %v, want %v", recordedAtStart, want)
	}
}

// TestServiceGivesTheContentChannelItsConfiguredInterval: what paces recording owed content between
// uploads is the content loop's configured cadence, handed to the content channel by the service.
func TestServiceGivesTheContentChannelItsConfiguredInterval(t *testing.T) {
	svc, err := NewService(ServiceConfig{
		Dir: t.TempDir(), SourceID: testSourceID, Capacity: permissiveCapacity(), PeerUID: euidPeer,
		Watch:         &WatchLoopConfig{ApprovedRoots: []string{t.TempDir()}, StateDir: t.TempDir(), Policy: serviceWatchPolicy(), Interval: time.Hour},
		ContentUpload: &ContentUploadLoopConfig{Sender: &fakeContentSender{}, Interval: 2 * time.Minute},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	if got := svc.content.interval; got != 2*time.Minute {
		t.Fatalf("content channel paced by %s, want the configured 2m0s", got)
	}
}
