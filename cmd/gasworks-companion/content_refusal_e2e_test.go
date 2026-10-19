//go:build linux

package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/daemon"
	"github.com/gascity/gasworks/internal/observer/upload"
)

// These are the end-to-end proofs that a collector refusing the companion's credential no longer
// switches content upload off for the rest of the run, and that the content queued during the
// refusal reaches the collector once it accepts the credential again. A REAL assembled daemon, wired
// by the helpers runDaemon uses (buildCollectorClient over a real -token-file,
// newContentUploadLoopConfig, openConsentPolicy, newConsentWatchLoopConfig), tails a real transcript
// root and uploads through the real HTTPS client to a stub collector that refuses every bearer token
// but the one it accepts, on the batch and the content routes alike. The token file is renewed the
// way an operator or a credential helper renews it (temp file + rename), and the collector's view is
// asserted after each step. Every loop is idle; the test drives each pass, on the daemon's own clock.

// The credentials of these tests: the one the companion starts with, which the collector refuses, and
// the renewed one it accepts.
const (
	expiredToken = "expired-token"
	renewedToken = "renewed-token"
)

// refusingCollector is the consent stub behind a bearer check: a request carrying any token but the
// accepted one is refused with 401, as a collector refuses an expired or revoked credential.
type refusingCollector struct {
	*consentStub
	accepted string

	mu             sync.Mutex
	refusedContent int
}

func newRefusingCollector(t *testing.T, accepted string) *refusingCollector {
	t.Helper()
	c := &refusingCollector{
		consentStub: &consentStub{strictCollector: &strictCollector{t: t, kindCount: map[string]int{}}, arrived: make(chan struct{}, 1)},
		accepted:    accepted,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)
	c.url, c.cert = srv.URL, srv.Certificate()
	return c
}

func (c *refusingCollector) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "Bearer "+c.accepted {
		c.consentStub.serve(w, r)
		return
	}
	if r.URL.Path == "/v1/artifacts/content" {
		c.mu.Lock()
		c.refusedContent++
		c.mu.Unlock()
	}
	writeObserverError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "credential not accepted")
	c.signal()
}

// refused counts the content uploads the collector refused.
func (c *refusingCollector) refused() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refusedContent
}

// refusalE2E is the assembled daemon of these tests and everything it is wired to.
type refusalE2E struct {
	t          *testing.T
	collector  *refusingCollector
	root       string
	caFile     string
	tokenFile  string
	policyPath string
	stateDir   string
	cursorDir  string
	clock      *e2eClock
	logs       *lineLog
	svc        *daemon.Service
	// static runs the static configuration (-approved-root -content-upload) instead of the live
	// policy (-root-policy-file).
	static bool
}

// newRefusalE2E prepares a daemon holding the expired credential, under a policy consenting to one
// transcript root and to content upload; start runs it.
func newRefusalE2E(t *testing.T) *refusalE2E {
	t.Helper()
	e := &refusalE2E{
		t:          t,
		collector:  newRefusingCollector(t, renewedToken),
		root:       t.TempDir(),
		caFile:     filepath.Join(t.TempDir(), "collector-ca.pem"),
		tokenFile:  filepath.Join(t.TempDir(), "token"),
		policyPath: filepath.Join(t.TempDir(), "root-policy.json"),
		stateDir:   t.TempDir(),
		cursorDir:  t.TempDir(),
		clock:      &e2eClock{t: time.Unix(1_800_000_000, 0)},
		logs:       newLineLog(),
	}
	writeFile(t, e.caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.collector.cert.Raw})))
	e.renewToken(expiredToken)
	writePolicy(t, e.policyPath, e2ePolicy(true, e2eRoot{e.root, 1, true}))
	t.Cleanup(e.stop)
	return e
}

// start runs the daemon the way runDaemon wires -collector -token-file with -root-policy-file, or
// with -approved-root -content-upload when the harness is static.
func (e *refusalE2E) start() {
	e.t.Helper()
	client, err := buildCollectorClient(e.collector.url, e2eSourceID, e.tokenFile, false, []string{e.caFile})
	if err != nil {
		e.t.Fatalf("buildCollectorClient: %v", err)
	}
	content := newContentUploadLoopConfig(client, e.tokenFile)
	content.Interval, content.Debounce = time.Hour, 30*time.Second
	cfg := daemon.ServiceConfig{
		Dir:               e.stateDir,
		SourceID:          e2eSourceID,
		Capacity:          permissiveCap(),
		RegistrySource:    e2eSourceID,
		RegistryWorkspace: "ws-e2e",
		Upload:            &daemon.UploadLoopConfig{Sender: client, Interval: time.Hour, Retry: upload.RetryPolicy{MaxAttempts: 1}},
		ContentUpload:     content,
		ConsentInterval:   time.Hour,
		PeerUID:           euidPeerE2E,
		Now:               e.clock.now,
		Log:               e.logs.add,
	}
	if e.static {
		cfg.Watch = newWatchLoopConfig([]string{e.root}, e.cursorDir, time.Hour, newReferenceConfig(nil, ""))
	} else {
		src, err := openConsentPolicy(e.policyPath, false, e.logs.add)
		if err != nil {
			e.t.Fatalf("openConsentPolicy: %v", err)
		}
		cfg.Consent = src
		cfg.Watch = newConsentWatchLoopConfig(e.cursorDir, time.Hour, newReferenceConfig(nil, ""))
	}
	svc, err := daemon.NewService(cfg)
	if err != nil {
		e.t.Fatalf("NewService: %v", err)
	}
	if err := svc.Start(); err != nil {
		e.t.Fatalf("Start: %v", err)
	}
	e.svc = svc
}

// stop shuts the daemon down gracefully, as SIGTERM does.
func (e *refusalE2E) stop() {
	if e.svc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.svc.Shutdown(ctx); err != nil {
		e.t.Errorf("Shutdown: %v", err)
	}
	e.svc = nil
}

// renewToken replaces the token file atomically, as an operator or a credential helper does.
func (e *refusalE2E) renewToken(token string) {
	e.t.Helper()
	tmp := e.tokenFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Rename(tmp, e.tokenFile); err != nil {
		e.t.Fatal(err)
	}
}

// poll runs one watcher pass: it captures new transcript bytes and queues their content.
func (e *refusalE2E) poll() {
	e.t.Helper()
	if err := e.svc.PollTranscripts(context.Background()); err != nil {
		e.t.Fatalf("PollTranscripts: %v", err)
	}
}

// settle advances the daemon's clock past the content debounce (and past the first refusal
// back-off).
func (e *refusalE2E) settle() { e.clock.advance(31 * time.Second) }

// tick runs one content pass at the daemon's current time.
func (e *refusalE2E) tick() { e.svc.TickContentUploads(context.Background()) }

// transcript writes a Codex rollout of n responses into the consented root.
func (e *refusalE2E) transcript(name, session string, n int) string {
	e.t.Helper()
	path := filepath.Join(e.root, name)
	writeFile(e.t, path, rollout(session, n))
	return path
}

// wantContentOnce fails unless the collector accepted exactly one content upload of each transcript,
// under the session it names.
func (e *refusalE2E) wantContentOnce(sessions map[string]string) {
	e.t.Helper()
	for path, session := range sessions {
		posts := e.collector.contentFor(path)
		if len(posts) != 1 {
			e.t.Fatalf("%s: %d content uploads accepted, want exactly 1; log:\n%s", filepath.Base(path), len(posts), e.logs.dump())
		}
		if posts[0].session != session {
			e.t.Fatalf("%s: uploaded under session %q, want %q", filepath.Base(path), posts[0].session, session)
		}
	}
}

// countLines counts the logged lines containing sub.
func (e *refusalE2E) countLines(sub string) int {
	n := 0
	for _, l := range strings.Split(e.logs.dump(), "\n") {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// TestCompanionResumesRefusedContentWhenTheTokenIsRenewed: the collector refuses the companion's
// credential, sessions keep running, and the operator renews the token file. Without a restart, and
// without waiting out the back-off, the next content pass uploads the refused transcript and every
// transcript first seen during the refusal, each exactly once; the metadata lane catches up too.
func TestCompanionResumesRefusedContentWhenTheTokenIsRenewed(t *testing.T) {
	e := newRefusalE2E(t)
	e.start()
	sessions := map[string]string{}
	first := e.transcript("rollout-first.jsonl", "01a0f1f1-0000-7000-8000-00000000c0a1", 2)
	sessions[first] = "01a0f1f1-0000-7000-8000-00000000c0a1"
	e.poll()
	e.settle()
	e.tick()
	if got := e.collector.refused(); got != 1 {
		t.Fatalf("refused content uploads = %d, want the 1 sent with the expired credential", got)
	}
	if err := e.svc.DrainUploads(context.Background()); err == nil {
		t.Fatal("the collector accepted metadata under the expired credential")
	}

	// Sessions keep running while the collector refuses the credential.
	for _, s := range []struct {
		name, session string
		responses     int
	}{
		{"rollout-gap-1.jsonl", "01a0f1f1-0000-7000-8000-00000000c0b1", 1},
		{"rollout-gap-2.jsonl", "01a0f1f1-0000-7000-8000-00000000c0b2", 3},
	} {
		sessions[e.transcript(s.name, s.session, s.responses)] = s.session
	}
	e.poll()
	e.settle()
	e.tick() // the back-off has passed: one retry, refused again
	if got := e.collector.refused(); got != 2 {
		t.Fatalf("refused content uploads = %d, want 2 (one retry per back-off, never one per transcript)", got)
	}
	for path := range sessions {
		if n := len(e.collector.contentFor(path)); n != 0 {
			t.Fatalf("%s: content accepted under the expired credential", filepath.Base(path))
		}
	}

	// The operator renews the credential. The very next content pass uploads everything queued.
	e.renewToken(renewedToken)
	e.tick()
	e.wantContentOnce(sessions)
	e.poll()
	e.settle()
	e.tick()
	e.wantContentOnce(sessions)
	if got := e.collector.refused(); got != 2 {
		t.Fatalf("refused content uploads = %d after the renewal, want still 2", got)
	}
	if n := e.countLines("the collector refused content upload"); n != 1 {
		t.Fatalf("the refusal was logged %d times, want once; log:\n%s", n, e.logs.dump())
	}
	if n := e.countLines("the collector accepted content upload again"); n != 1 {
		t.Fatalf("the resumption was logged %d times, want once; log:\n%s", n, e.logs.dump())
	}

	if err := e.svc.DrainUploads(context.Background()); err != nil {
		t.Fatalf("metadata upload under the renewed credential: %v", err)
	}
	for path := range sessions {
		if e.collector.countLocator(t, filepath.Base(path)) == 0 {
			t.Fatalf("%s: no metadata reached the collector after the renewal", filepath.Base(path))
		}
	}
}

// TestCompanionUploadsRefusedContentAfterARestart: the companion restarts while the collector still
// refuses its credential. Both transcripts queued before the restart — the refused one, and one still
// settling when the daemon stopped — were consumed to their end, so the restarted daemon never parses
// them again; their queued content survives the restart all the same, and once the operator renews
// the credential each is uploaded exactly once, under its own session, and never again after a further
// restart.
func TestCompanionUploadsRefusedContentAfterARestart(t *testing.T) {
	e := newRefusalE2E(t)
	e.start()
	refusedPath := e.transcript("rollout-refused.jsonl", "01a0f1f1-0000-7000-8000-00000000c0d1", 2)
	e.poll()
	e.settle()
	e.tick() // refused
	settlingPath := e.transcript("rollout-settling.jsonl", "01a0f1f1-0000-7000-8000-00000000c0d2", 1)
	e.poll()
	e.tick() // queued behind the refusal, still settling
	sessions := map[string]string{
		refusedPath:  "01a0f1f1-0000-7000-8000-00000000c0d1",
		settlingPath: "01a0f1f1-0000-7000-8000-00000000c0d2",
	}

	e.stop()
	e.start()
	e.poll() // both transcripts were consumed to their end before the restart: nothing is parsed
	e.settle()
	e.tick() // still the expired credential: refused, the queue kept
	if got := e.collector.refused(); got != 2 {
		t.Fatalf("refused content uploads = %d, want 2 (one before the restart, one after)", got)
	}

	e.renewToken(renewedToken)
	e.tick()
	e.wantContentOnce(sessions)

	e.stop()
	e.start()
	e.poll()
	e.settle()
	e.tick()
	e.wantContentOnce(sessions)
}

// TestCompanionDropsRefusedContentWhenConsentIsWithdrawn: consent wins over the retry. The owner
// withdraws content consent while the collector refuses the credential; once the credential is
// renewed, nothing queued before the withdrawal is uploaded, while the still-consented metadata flows.
func TestCompanionDropsRefusedContentWhenConsentIsWithdrawn(t *testing.T) {
	e := newRefusalE2E(t)
	e.start()
	path := e.transcript("rollout-withdrawn.jsonl", "01a0f1f1-0000-7000-8000-00000000c0e1", 2)
	e.poll()
	e.settle()
	e.tick() // refused

	writePolicy(t, e.policyPath, e2ePolicy(false, e2eRoot{e.root, 1, true}))
	e.renewToken(renewedToken)
	e.tick()
	e.poll()
	e.settle()
	e.tick()
	if n := len(e.collector.contentFor(path)); n != 0 {
		t.Fatalf("content queued before consent was withdrawn was uploaded once the credential was renewed (%d uploads)", n)
	}
	if got := e.collector.refused(); got != 1 {
		t.Fatalf("content upload was attempted after consent was withdrawn: %d refused attempts, want the 1 before", got)
	}
	if err := e.svc.DrainUploads(context.Background()); err != nil {
		t.Fatalf("metadata upload under the renewed credential: %v", err)
	}
	if e.collector.countLocator(t, filepath.Base(path)) == 0 {
		t.Fatal("the still-consented metadata did not reach the collector after the renewal")
	}
}

// TestCompanionDiscardsQueuedContentWhenContentUploadIsSwitchedOff: in the static configuration
// (-approved-root) the -content-upload flag is the content consent. A start with the flag off is a
// withdrawal: it discards the content an earlier run queued while the collector refused it, so a
// later run with the flag on again — and a renewed credential — does not send it.
func TestCompanionDiscardsQueuedContentWhenContentUploadIsSwitchedOff(t *testing.T) {
	e := newRefusalE2E(t)
	e.static = true
	e.start()
	path := e.transcript("rollout-static.jsonl", "01a0f1f1-0000-7000-8000-00000000c0f1", 2)
	e.poll()
	e.settle()
	e.tick() // refused: queued
	e.stop()

	// The next start has -content-upload off, as runDaemon applies it.
	discardWithdrawnContent(false, newWatchLoopConfig([]string{e.root}, e.cursorDir, time.Hour, newReferenceConfig(nil, "")), e.logs.add)
	if n := e.countLines("content upload is off: discarded the queued content of 1 transcripts"); n != 1 {
		t.Fatalf("the withdrawal did not discard the queued content; log:\n%s", e.logs.dump())
	}

	e.renewToken(renewedToken)
	e.start()
	e.poll()
	e.settle()
	e.tick()
	if n := len(e.collector.contentFor(path)); n != 0 {
		t.Fatalf("content queued before -content-upload was switched off was uploaded once it was on again (%d uploads)", n)
	}
}
