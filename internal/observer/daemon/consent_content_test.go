//go:build linux

package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// consentContent is a content uploader under a live consent policy, with in-memory transcripts.
type consentContent struct {
	t          *testing.T
	policyPath string
	src        *consent.Source
	u          *contentUploader
	sender     *fakeContentSender
	sessions   *fakeSessions
	reader     *fakeReader
	clock      *fakeClock
	logs       *logLines
	markerDir  string
}

func newConsentContent(t *testing.T, policyBody string, sender *fakeContentSender) *consentContent {
	t.Helper()
	h := &consentContent{
		t:          t,
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		sender:     sender,
		sessions:   newSessions(),
		reader:     newReader(),
		clock:      newClock(),
		logs:       &logLines{},
		markerDir:  t.TempDir(),
	}
	writePolicyAtomic(t, h.policyPath, policyBody)
	src, err := consent.Open(consent.Config{Path: h.policyPath, Log: h.logs.log})
	if err != nil {
		t.Fatalf("consent.Open: %v", err)
	}
	h.src = src
	u, err := newContentUploader(contentUploaderConfig{
		sender:   sender,
		sessions: h.sessions,
		stateDir: h.markerDir,
		read:     h.reader.read,
		now:      h.clock.now,
		debounce: 30 * time.Second,
		log:      h.logs.log,
		consent:  src,
	})
	if err != nil {
		t.Fatalf("newContentUploader: %v", err)
	}
	src.Subscribe(u.onConsentChange)
	h.u = u
	return h
}

// transcript makes one in-memory transcript under root, with a threaded session.
func (h *consentContent) transcript(dev, ino uint64, body string) {
	h.reader.set(dev, ino, body, 1)
	h.sessions.set(dev, ino, "sess-"+string(rune('a'+ino)), "codex")
}

// observe reports the transcript to the uploader the way a watcher built for gens does.
func (h *consentContent) observe(gens map[string]uint64, root string, dev, ino uint64, size int64) {
	consentContentObserver{u: h.u, generations: gens}.ObserveContent(context.Background(), codex.ContentObservation{
		Root: root, ConsentRoot: root, Locator: "rollout-x.jsonl", Path: filepath.Join(root, "rollout-x.jsonl"),
		Device: dev, Inode: ino, Size: size, ModNanos: 1,
	})
}

func (h *consentContent) settleAndTick() {
	h.clock.advance(31 * time.Second)
	h.u.tick(context.Background())
}

func (h *consentContent) queued() int {
	h.u.mu.Lock()
	defer h.u.mu.Unlock()
	return len(h.u.files)
}

// TestContentConsentWithdrawalStopsUploadsAndDropsTheQueue: turning content upload off mid-session
// stops every further upload at the next check and drops the transcripts queued for upload, while a
// tick that finds content withdrawn never reads a transcript.
func TestContentConsentWithdrawalStopsUploadsAndDropsTheQueue(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), &fakeContentSender{})
	h.transcript(1, 1, "first\n")
	h.observe(gens, root, 1, 1, 6)
	h.settleAndTick()
	if h.sender.count() != 1 {
		t.Fatalf("uploads before the withdrawal = %d, want 1", h.sender.count())
	}

	// The transcript grows and is queued again, then content consent is withdrawn.
	h.transcript(1, 1, "first\nsecond\n")
	h.observe(gens, root, 1, 1, 13)
	writePolicyAtomic(t, h.policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	reads := h.reader.readCount()
	h.settleAndTick()
	if h.sender.count() != 1 {
		t.Fatalf("an upload was sent after content consent was withdrawn (%d uploads)", h.sender.count())
	}
	if h.queued() != 0 {
		t.Fatalf("%d transcripts still queued after the withdrawal", h.queued())
	}
	if h.reader.readCount() != reads {
		t.Fatal("a transcript was read after content consent was withdrawn")
	}
	if len(h.logs.containing("dropped 1 queued transcripts without sending them")) != 1 {
		t.Fatalf("the dropped queue was not logged: %q", h.logs.containing("content upload"))
	}

	// Observations while withdrawn are not queued at all.
	h.observe(gens, root, 1, 1, 13)
	if h.queued() != 0 {
		t.Fatal("an observation was queued while content consent is withdrawn")
	}
}

// TestContentConsentRootWithdrawalKeepsTheOtherRoots: withdrawing one root drops and never uploads
// its queued transcript, while a still-consented root's transcript uploads.
func TestContentConsentRootWithdrawalKeepsTheOtherRoots(t *testing.T) {
	rootA, rootB := t.TempDir(), t.TempDir()
	gens := map[string]uint64{rootA: 1, rootB: 1}
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{rootA, 1, true}, consentRoot{rootB, 1, true}), &fakeContentSender{})
	h.transcript(1, 1, "a\n")
	h.transcript(1, 2, "b\n")
	h.observe(gens, rootA, 1, 1, 2)
	h.observe(gens, rootB, 1, 2, 2)

	writePolicyAtomic(t, h.policyPath, consentPolicyBody(true, consentRoot{rootA, 2, false}, consentRoot{rootB, 1, true}))
	h.settleAndTick()
	if h.sender.count() != 1 || h.sender.at(0).SourcePath != filepath.Join(rootB, "rollout-x.jsonl") {
		t.Fatalf("uploads = %d, want exactly the consented root's transcript", h.sender.count())
	}
}

// TestContentConsentCancelsTheUploadInFlight: a withdrawal observed by any daemon loop while an
// upload is being sent cancels that request. It is not treated as a collector failure — no hold is
// armed, nothing is retried — and the transcript is not queued again.
func TestContentConsentCancelsTheUploadInFlight(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	started := make(chan struct{})
	cancelled := make(chan error, 1)
	sender := &blockingContentSender{started: started, cancelled: cancelled}
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), &fakeContentSender{})
	h.u.sender = sender
	h.transcript(1, 1, "body\n")
	h.observe(gens, root, 1, 1, 5)
	h.clock.advance(31 * time.Second)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.u.tick(context.Background())
	}()
	<-started
	writePolicyAtomic(t, h.policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
	h.src.Current() // another daemon loop's check observes the withdrawal
	if err := <-cancelled; err == nil {
		t.Fatal("the in-flight upload's request was not cancelled")
	}
	<-done

	h.u.mu.Lock()
	hold := h.u.holdUntil
	h.u.mu.Unlock()
	if !hold.IsZero() {
		t.Fatalf("a consent cancellation armed the transient hold until %v", hold)
	}
	if h.queued() != 0 {
		t.Fatal("the withdrawn transcript is still queued")
	}
	if len(h.logs.containing("withdrew the in-flight upload")) != 1 {
		t.Fatalf("the cancellation was not logged: %q", h.logs.containing("content upload"))
	}
}

// blockingContentSender holds every request until its context is cancelled, reporting both.
type blockingContentSender struct {
	started   chan struct{}
	cancelled chan error
}

func (b *blockingContentSender) PostContent(ctx context.Context, _ upload.ContentRequest) (*upload.ContentResult, error) {
	close(b.started)
	select {
	case <-ctx.Done():
		b.cancelled <- ctx.Err()
		return nil, ctx.Err()
	case <-time.After(10 * time.Second): // a safety deadline: a request never cancelled fails the test
		b.cancelled <- nil
		return nil, errors.New("the in-flight request was never cancelled")
	}
}

// TestContentConsentNarrowedDuringTheReadIsNeverSent: a narrowing observed after an upload job was
// picked but before its request was sent — here, while its transcript is being read — means the
// request is never sent at all.
func TestContentConsentNarrowedDuringTheReadIsNeverSent(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), &fakeContentSender{})
	h.transcript(1, 1, "body\n")
	h.observe(gens, root, 1, 1, 5)
	read := h.u.read
	h.u.read = func(root, locator string, dev, ino uint64, maxBytes int64) ([]byte, int64, int64, error) {
		writePolicyAtomic(t, h.policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
		h.src.Current() // another daemon loop observes the withdrawal mid-read
		return read(root, locator, dev, ino, maxBytes)
	}
	h.settleAndTick()
	if h.sender.count() != 0 {
		t.Fatalf("an upload whose consent was withdrawn during its read was sent (%d uploads)", h.sender.count())
	}
}

// TestContentConsentFailsClosedOnAnUnusablePolicy: a malformed policy file stops content upload at
// once; once a valid policy is written again, uploads resume.
func TestContentConsentFailsClosedOnAnUnusablePolicy(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	valid := consentPolicyBody(true, consentRoot{root, 1, true})
	h := newConsentContent(t, valid, &fakeContentSender{})
	h.transcript(1, 1, "body\n")
	h.observe(gens, root, 1, 1, 5)

	writePolicyAtomic(t, h.policyPath, `{"schema_version":"gasworks.companion.root-policy/v3","content_upload":true,"roots":[`)
	h.settleAndTick()
	if h.sender.count() != 0 {
		t.Fatal("content was uploaded under an unreadable policy")
	}
	if len(h.logs.containing("content upload is withdrawn (fail closed)")) != 1 {
		t.Fatalf("the fail-closed transition was not logged loudly: %q", h.logs.containing("consent policy"))
	}

	writePolicyAtomic(t, h.policyPath, valid)
	h.src.Current()
	h.observe(gens, root, 1, 1, 5)
	h.settleAndTick()
	if h.sender.count() != 1 {
		t.Fatalf("uploads after the policy was repaired = %d, want 1", h.sender.count())
	}
}

// TestContentConsentWideningAppliesToTheNextObservation: content consent granted while the daemon
// runs applies from the next observation on.
func TestContentConsentWideningAppliesToTheNextObservation(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	h := newConsentContent(t, consentPolicyBody(false, consentRoot{root, 1, true}), &fakeContentSender{})
	h.transcript(1, 1, "body\n")
	h.observe(gens, root, 1, 1, 5)
	h.settleAndTick()
	if h.sender.count() != 0 || h.queued() != 0 {
		t.Fatalf("content queued or sent without consent: %d sent, %d queued", h.sender.count(), h.queued())
	}

	writePolicyAtomic(t, h.policyPath, consentPolicyBody(true, consentRoot{root, 1, true}))
	h.src.Current()
	h.observe(gens, root, 1, 1, 5)
	h.settleAndTick()
	if h.sender.count() != 1 {
		t.Fatalf("uploads after content consent was granted = %d, want 1", h.sender.count())
	}
}

// TestContentConsentIsCheckedRightBeforeEveryPOST: a narrowing written while a transcript is being
// read — and observed by nothing else — is caught by the check right before the request: the upload
// is never sent.
func TestContentConsentIsCheckedRightBeforeEveryPOST(t *testing.T) {
	root := t.TempDir()
	gens := map[string]uint64{root: 1}
	h := newConsentContent(t, consentPolicyBody(true, consentRoot{root, 1, true}), &fakeContentSender{})
	h.transcript(1, 1, "body\n")
	h.observe(gens, root, 1, 1, 5)
	read := h.u.read
	h.u.read = func(root, locator string, dev, ino uint64, maxBytes int64) ([]byte, int64, int64, error) {
		// Only the file changes: no daemon loop checks it before the request would go out.
		writePolicyAtomic(t, h.policyPath, consentPolicyBody(false, consentRoot{root, 1, true}))
		return read(root, locator, dev, ino, maxBytes)
	}
	h.settleAndTick()
	if h.sender.count() != 0 {
		t.Fatalf("an upload was sent although content consent was withdrawn before its request (%d uploads)", h.sender.count())
	}
}
