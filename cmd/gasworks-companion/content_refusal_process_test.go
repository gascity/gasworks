//go:build linux

package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These drive the real `gasworks-companion daemon` command line (this test binary re-run as the
// command, see TestMain) in the static configuration (-approved-root), where the -content-upload flag
// is the content consent, to prove runDaemon's own wiring of the credential-refusal handling: what it
// does with the content an earlier run queued, and that the collector client's -token-file reaches
// the content channel. Both are settled before the daemon serves, so each test asserts once the
// "serving at" line is out.

// Records an earlier run left in the cursor directory, in the content channel's on-disk formats: the
// pending record of content queued but never accepted, and the marker of an accepted upload.
const (
	queuedContentRecord = `{"version":1,"device":1,"inode":2,"native_session_id":"01a0f1f1-0000-7000-8000-0000000000f1","provider":"codex","locator":"rollout-queued.jsonl","observed_size":10,"observed_mtime_nanos":1}`
	uploadMarkerRecord  = `{"version":2,"device":3,"inode":4,"content_sha256":"0f343b0931126a20f133d67c2b018a3b5e4d4b5c4f1f1e1e1e1e1e1e1e1e1e1e","size":10,"observed_mtime_nanos":1,"native_session_id":"01a0f1f1-0000-7000-8000-0000000000f2","provider":"codex","uploaded_at":"2026-09-01T10:00:00Z"}`
)

// staticCompanion is a daemon command line in the static configuration, uploading to a stub
// collector, over a cursor directory seeded with an earlier run's queued content and upload marker.
type staticCompanion struct {
	args      []string
	tokenFile string
	queued    string // the pending record's path
	marker    string // the upload marker's path
}

func newStaticCompanion(t *testing.T) *staticCompanion {
	t.Helper()
	stub, _ := newConsentStub(t)
	caFile := filepath.Join(t.TempDir(), "collector-ca.pem")
	writeFile(t, caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stub.cert.Raw})))
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "e2e-token\n")
	cursorDir := t.TempDir()
	c := &staticCompanion{
		tokenFile: tokenFile,
		queued:    filepath.Join(cursorDir, "content-pending-1-2.json"),
		marker:    filepath.Join(cursorDir, "content-marker-3-4.json"),
		args: []string{
			"-dir", t.TempDir(), "-source-id", e2eSourceID,
			"-collector", stub.url, "-token-file", tokenFile, "-ca-file", caFile,
			"-approved-root", t.TempDir(), "-cursor-dir", cursorDir, "-poll-interval", "20ms",
		},
	}
	writeFile(t, c.queued, queuedContentRecord)
	writeFile(t, c.marker, uploadMarkerRecord)
	return c
}

// TestCompanionDaemonCommandDiscardsQueuedContentWhenContentUploadIsOff: a start with -content-upload
// off withdraws content consent, so before it serves the daemon discards the content an earlier run
// queued — even with a collector configured — and keeps the marker of what was already uploaded.
func TestCompanionDaemonCommandDiscardsQueuedContentWhenContentUploadIsOff(t *testing.T) {
	c := newStaticCompanion(t)
	p := startCompanionProcess(t, []string{"OBSERVER_CONTENT_UPLOAD="}, c.args...)
	deadline := time.After(20 * time.Second)
	p.waitFor(t, "serving at", deadline)
	if !p.logs.has("content upload is off: discarded the queued content of 1 transcripts") {
		t.Fatalf("a start with -content-upload off did not discard the queued content; log:\n%s", p.logs.dump())
	}
	if _, err := os.Stat(c.queued); !os.IsNotExist(err) {
		t.Fatalf("the queued content's pending record survived a start with -content-upload off: %v", err)
	}
	if _, err := os.Stat(c.marker); err != nil {
		t.Fatalf("discarding the queue removed an upload marker: %v", err)
	}
	if err := p.stop(t, deadline); err != nil {
		t.Fatalf("daemon exit after SIGTERM: %v", err)
	}
}

// TestCompanionDaemonCommandWiresTheTokenFileIntoContentUpload: a start with -content-upload on keeps
// the content an earlier run queued, and hands the content channel the collector client's
// -token-file, so a refused credential is retried as soon as that file is renewed.
func TestCompanionDaemonCommandWiresTheTokenFileIntoContentUpload(t *testing.T) {
	c := newStaticCompanion(t)
	p := startCompanionProcess(t, []string{"OBSERVER_CONTENT_UPLOAD="}, append(c.args, "-content-upload")...)
	deadline := time.After(20 * time.Second)
	p.waitFor(t, "serving at", deadline)
	if !p.logs.has("a refused credential is retried as soon as the token file " + c.tokenFile + " is renewed") {
		t.Fatalf("the content channel does not follow -token-file %s; log:\n%s", c.tokenFile, p.logs.dump())
	}
	if _, err := os.Stat(c.queued); err != nil {
		t.Fatalf("a start with content consent discarded the queued content: %v", err)
	}
	if err := p.stop(t, deadline); err != nil {
		t.Fatalf("daemon exit after SIGTERM: %v", err)
	}
}
