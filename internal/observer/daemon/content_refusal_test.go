//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/upload"
)

// switchableCollector answers every content upload with the status the test has switched it to: a
// refusal while that status is non-zero, an acceptance (201) once it is zero.
type switchableCollector struct{ status atomic.Int32 }

func refusingWith(status int) *switchableCollector {
	c := &switchableCollector{}
	c.status.Store(int32(status))
	return c
}

func (c *switchableCollector) accept() { c.status.Store(0) }

func (c *switchableCollector) sender() *fakeContentSender {
	return &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		if s := int(c.status.Load()); s != 0 {
			return &upload.ContentResult{StatusCode: s, Message: "credential not accepted"}, nil
		}
		return &upload.ContentResult{StatusCode: 201, ReceiptID: "r", Status: "DURABLY_RECORDED"}, nil
	}}
}

// logsContaining returns the harness log lines that contain sub.
func (h *contentHarness) logsContaining(sub string) []string {
	var out []string
	for _, l := range h.logLines() {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// Log fragments of the refusal transitions.
const (
	refusedLog = "the collector refused content upload"
	resumedLog = "the collector accepted content upload again"
)

// TestContentRefusalBacksOffAndResumes is the regression for a collector refusal latching content
// upload off for the rest of the process lifetime. For each refusing status — 401/403 (the
// credential) and 404/501 (content upload not provisioned or disabled for this source) — content
// upload backs off for 15s, doubling up to 5 minutes, and never gives up on the refused snapshot
// however often it is refused; a transcript first observed during the refusal is queued, not
// attempted; and the first retry the collector accepts uploads every queued transcript exactly once.
func TestContentRefusalBacksOffAndResumes(t *testing.T) {
	for _, status := range []int{401, 403, 404, 501} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ctx := context.Background()
			coll := refusingWith(status)
			h := newContentHarness(t, contentUploaderConfig{sender: coll.sender()})
			h.sessions.set(1, 1, "s1", "codex")
			h.reader.set(1, 1, "aaa", 1)
			h.observe(1, 1, testCodexPath, 3, 1)
			h.clock.advance(31 * time.Second)
			h.u.tick(ctx)
			if h.sender.count() != 1 {
				t.Fatalf("uploads attempted = %d, want the 1 refused attempt", h.sender.count())
			}

			// A transcript first observed during the refusal is queued behind it.
			h.sessions.set(2, 2, "s2", "codex")
			h.reader.set(2, 2, "bbbb", 1)
			h.observe(2, 2, testCodexPath, 4, 1)

			for i, backoff := range []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
				attempts := h.sender.count()
				h.clock.advance(backoff - time.Second)
				h.u.tick(ctx)
				if h.sender.count() != attempts {
					t.Fatalf("refusal %d: retried %s into a %s back-off", i+1, backoff-time.Second, backoff)
				}
				h.clock.advance(time.Second)
				h.u.tick(ctx)
				if got := h.sender.count() - attempts; got != 1 {
					t.Fatalf("refusal %d: %d attempts once the %s back-off passed, want exactly 1 (the retry, stopped by its refusal)", i+1, got, backoff)
				}
			}

			coll.accept()
			attempts := h.sender.count()
			h.clock.advance(5 * time.Minute)
			h.u.tick(ctx)
			if got := h.sender.count() - attempts; got != 2 {
				t.Fatalf("uploads once the collector accepted = %d, want both queued transcripts", got)
			}
			if a, b := string(h.sender.at(attempts).Body), string(h.sender.at(attempts+1).Body); a != "aaa" || b != "bbbb" {
				t.Fatalf("uploaded %q and %q, want the refused transcript and the one queued behind it", a, b)
			}
			for range 3 {
				h.clock.advance(5 * time.Minute)
				h.u.tick(ctx)
			}
			if got := h.sender.count() - attempts; got != 2 {
				t.Fatalf("uploads after the resumption = %d, want each queued transcript exactly once", got)
			}
			if n := len(h.logsContaining(refusedLog)); n != 1 {
				t.Fatalf("the refusal was logged %d times, want once however often it repeated", n)
			}
			if n := len(h.logsContaining(resumedLog)); n != 1 {
				t.Fatalf("the resumption was logged %d times, want once", n)
			}
			if line := h.logsContaining(refusedLog)[0]; !strings.Contains(line, fmt.Sprintf("status %d", status)) || !strings.Contains(line, "credential not accepted") {
				t.Fatalf("refusal log line %q lacks the status or the collector's message", line)
			}
		})
	}
}

// TestContentRefusalFollowsTheTokenFile walks a refusal through every transition the token file
// drives. The collector client reads the token file on every attempt, so a renewed credential is
// what ends a credential refusal: while the file is unchanged content upload waits out its back-off,
// while a file rewritten in place or atomically replaced is retried on the very next tick. Each
// transition — the first refusal, a different refusing status, a renewed credential refused too,
// the resumption — is logged exactly once.
func TestContentRefusalFollowsTheTokenFile(t *testing.T) {
	ctx := context.Background()
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeTokenInPlace(t, tokenFile, "expired-token")
	var status atomic.Int32
	status.Store(401)
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		tok, err := upload.TokenFileSource{Path: tokenFile}.Token(ctx)
		if err != nil {
			return nil, err
		}
		if tok == "renewed-token" {
			return &upload.ContentResult{StatusCode: 201, ReceiptID: "r", Status: "DURABLY_RECORDED"}, nil
		}
		return &upload.ContentResult{StatusCode: int(status.Load())}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender, tokenFile: tokenFile})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)

	step := func(name string, advance time.Duration, wantAttempts, wantRefusedLogs, wantResumedLogs int) {
		t.Helper()
		h.clock.advance(advance)
		h.u.tick(ctx)
		if got := h.sender.count(); got != wantAttempts {
			t.Fatalf("%s: %d upload attempts, want %d", name, got, wantAttempts)
		}
		if got := len(h.logsContaining(refusedLog)); got != wantRefusedLogs {
			t.Fatalf("%s: %d refusal log lines, want %d; log:\n%s", name, got, wantRefusedLogs, strings.Join(h.logLines(), "\n"))
		}
		if got := len(h.logsContaining(resumedLog)); got != wantResumedLogs {
			t.Fatalf("%s: %d resumption log lines, want %d", name, got, wantResumedLogs)
		}
	}
	step("first attempt", 0, 1, 1, 0)
	step("token unchanged", 0, 1, 1, 0)
	step("back-off passed, same refusal", 15*time.Second, 2, 1, 0)
	status.Store(501)
	step("back-off passed, a different refusing status", 30*time.Second, 3, 2, 0)
	writeTokenInPlace(t, tokenFile, "another-expired-token")
	step("token rewritten in place, still refused", 0, 4, 3, 0)
	step("token unchanged again", 0, 4, 3, 0)
	writeTokenAtomically(t, tokenFile, "renewed-token")
	step("token replaced with a renewed credential", 0, 5, 3, 1)
	if got := string(h.sender.at(4).Body); got != "aaa" {
		t.Fatalf("uploaded %q after the renewal, want the refused transcript", got)
	}
	step("nothing left to send", 5*time.Minute, 5, 3, 1)
}

// TestContentRefusalEndsWhenTheCollectorJudgesTheBytes: a retry the collector answers with a
// permanent rejection of the bytes (400/413/422) shows it accepted the credential, so the refusal
// ends there: the resumption is logged, the rejected content is no longer recorded as owed, and a
// later refusal is a new one — logged again, its back-off back at the start.
func TestContentRefusalEndsWhenTheCollectorJudgesTheBytes(t *testing.T) {
	ctx := context.Background()
	coll := refusingWith(401)
	h := newContentHarness(t, contentUploaderConfig{sender: coll.sender()})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "aaa", 1)
	h.observe(1, 1, testCodexPath, 3, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx) // refused
	coll.status.Store(422)
	h.clock.advance(15 * time.Second)
	h.u.tick(ctx) // the retry is judged on its bytes
	if n := len(h.logsContaining(resumedLog)); n != 1 {
		t.Fatalf("a retry the collector judged on its bytes logged %d resumptions, want 1", n)
	}
	if left := pendingRecords(t, h.stateDir); len(left) != 0 {
		t.Fatalf("content the collector rejected for good is still recorded as owed: %v", left)
	}

	coll.status.Store(401)
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(2, 2, "bbbb", 1)
	h.observe(2, 2, testCodexPath, 4, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx) // refused anew
	refusals := h.logsContaining(refusedLog)
	if len(refusals) != 2 || !strings.Contains(refusals[1], "retrying in 15s") {
		t.Fatalf("a refusal after the collector accepted the credential is not a new one: %q", refusals)
	}
}

// TestContentOutageSpreadsFailuresOverTheQueue: during a collector outage of a few minutes each
// transient hold lets one upload fail. A snapshot that just failed goes behind those that have not, so
// the failures spread over the queue instead of exhausting one transcript's attempts after another,
// and every queued transcript is uploaded once the collector recovers.
func TestContentOutageSpreadsFailuresOverTheQueue(t *testing.T) {
	ctx := context.Background()
	var down atomic.Bool
	down.Store(true)
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		if down.Load() {
			return &upload.ContentResult{StatusCode: 503}, nil
		}
		return &upload.ContentResult{StatusCode: 201}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	const queued = 8
	for i := uint64(1); i <= queued; i++ {
		body := strings.Repeat("x", int(i))
		h.sessions.set(i, i, fmt.Sprintf("s%d", i), "codex")
		h.reader.set(i, i, body, 1)
		h.observe(i, i, testCodexPath, int64(len(body)), 1)
	}
	h.clock.advance(31 * time.Second)
	for range 2 * queued { // an outage of 4 minutes: one failure per transient hold
		h.u.tick(ctx)
		h.clock.advance(contentTransientHold)
	}
	if n := len(h.logsContaining("giving up on")); n != 0 {
		t.Fatalf("an outage of a few minutes made the uploader give up on %d queued transcripts", n)
	}
	down.Store(false)
	h.u.tick(ctx)
	uploaded := map[string]int{}
	for i := range h.sender.count() {
		if r := h.sender.at(i); i >= 2*queued {
			uploaded[string(r.Body)]++
		}
	}
	for i := 1; i <= queued; i++ {
		if got := uploaded[strings.Repeat("x", i)]; got != 1 {
			t.Fatalf("transcript %d uploaded %d times after the outage, want once", i, got)
		}
	}
}

// TestContentRefusalProbesWithTheSmallestTranscript: while a refusal holds, each retry only probes the
// collector, so it is made with the cheapest queued transcript — even after a network blip charged
// that transcript with a failure, which outside a refusal would send it to the back of the queue.
func TestContentRefusalProbesWithTheSmallestTranscript(t *testing.T) {
	ctx := context.Background()
	var blip atomic.Bool
	sender := &fakeContentSender{respond: func(int, upload.ContentRequest) (*upload.ContentResult, error) {
		if blip.Swap(false) {
			return nil, errors.New("connection reset")
		}
		return &upload.ContentResult{StatusCode: 401}, nil
	}}
	h := newContentHarness(t, contentUploaderConfig{sender: sender})
	h.sessions.set(1, 1, "s1", "codex")
	h.reader.set(1, 1, "small", 1)
	h.observe(1, 1, testCodexPath, 5, 1)
	h.sessions.set(2, 2, "s2", "codex")
	h.reader.set(2, 2, strings.Repeat("large", 1000), 1)
	h.observe(2, 2, testCodexPath, 5000, 1)
	h.clock.advance(31 * time.Second)
	h.u.tick(ctx) // refused
	blip.Store(true)
	h.clock.advance(15 * time.Second)
	h.u.tick(ctx) // the retry hits a network blip
	h.clock.advance(time.Minute)
	h.u.tick(ctx) // the next retry
	if h.sender.count() != 3 {
		t.Fatalf("attempts = %d, want 3 (one per retry)", h.sender.count())
	}
	for i := range 3 {
		if got := string(h.sender.at(i).Body); got != "small" {
			t.Fatalf("attempt %d probed a refusal with a %d-byte transcript, want the smallest", i+1, len(got))
		}
	}
}

// writeTokenInPlace rewrites the token file in place, keeping its inode.
func writeTokenInPlace(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTokenAtomically replaces the token file the way a credential helper does: a temporary file
// renamed over it.
func writeTokenAtomically(t *testing.T, path, token string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}
