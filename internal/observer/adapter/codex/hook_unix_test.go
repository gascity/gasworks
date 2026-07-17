//go:build unix

package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func hookJSON(t *testing.T, sessionID string, transcriptPath *string, cwd, source string) []byte {
	t.Helper()
	m := map[string]any{
		"session_id":      sessionID,
		"cwd":             cwd,
		"source":          source,
		"hook_event_name": "SessionStart", // additive documented field: proves decode tolerance
		"permission_mode": "default",
	}
	if transcriptPath != nil {
		m["transcript_path"] = *transcriptPath
	} else {
		m["transcript_path"] = nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal hook json: %v", err)
	}
	return b
}

func runHook(t *testing.T, seam DaemonSeam, cfg HookConfig, input []byte) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := Run(context.Background(), seam, cfg, bytes.NewReader(input), &out)
	return out.Bytes(), err
}

func lastSessionLifecycle(t *testing.T, seam *fakeSeam) wire.SessionLifecycleObservation {
	t.Helper()
	c := seam.lastAppend(t)
	sl, err := c.sealed.AsSessionLifecycleObservation()
	if err != nil {
		t.Fatalf("AsSessionLifecycleObservation: %v", err)
	}
	return sl
}

func parseHookResponse(t *testing.T, b []byte) hookResponse {
	t.Helper()
	var r hookResponse
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal hook response %q: %v", b, err)
	}
	return r
}

// TestHookSupportedFixturesAttachCorrectly drives the hook over every supported SessionStart
// source with no wrapper context: startup/resume become passive INFERRED intervals (no run
// context, correct transition) and clear/compact are within-session lifecycle only.
func TestHookSupportedFixturesAttachCorrectly(t *testing.T) {
	for _, tc := range []struct {
		source     string
		transition wire.SessionLifecyclePayloadTransition
	}{
		{"startup", wire.SessionLifecyclePayloadTransitionSTARTED},
		{"resume", wire.SessionLifecyclePayloadTransitionRESUMED},
		{"clear", wire.SessionLifecyclePayloadTransitionCLEARED},
		{"compact", wire.SessionLifecyclePayloadTransitionCOMPACTED},
	} {
		t.Run(tc.source, func(t *testing.T) {
			seam := newFakeSeam()
			cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid()}
			out, err := runHook(t, seam, cfg, hookJSON(t, "sess-"+tc.source, nil, "/work/dir", tc.source))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(out) != 0 {
				t.Fatalf("success must write no output, got %q", out)
			}
			if seam.appendCount() != 1 {
				t.Fatalf("append count = %d, want 1", seam.appendCount())
			}
			sl := lastSessionLifecycle(t, seam)
			if sl.SessionLifecycle.Transition != tc.transition {
				t.Fatalf("transition = %q, want %q", sl.SessionLifecycle.Transition, tc.transition)
			}
			if sl.RunContext != nil {
				t.Fatalf("passive/within-session observation must carry no run context, got %+v", sl.RunContext)
			}
		})
	}
}

// TestHookWrappedSessionAttachesHigh proves a session whose inherited GASWORKS_RUN_ID resolves
// to an OPEN same-source boundary attaches HIGH and stamps the INHERITED_RUN_ID run context.
func TestHookWrappedSessionAttachesHigh(t *testing.T) {
	seam := newFakeSeam()
	seam.resolve("gwr_wrapped", InheritedOpenSameScope)
	cfg := HookConfig{SourceID: "src_1", InheritedRunID: "gwr_wrapped", HookPID: os.Getpid()}
	out, err := runHook(t, seam, cfg, hookJSON(t, "sess-1", nil, "/work/dir", "startup"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("success must write no output, got %q", out)
	}
	sl := lastSessionLifecycle(t, seam)
	if sl.RunContext == nil {
		t.Fatal("wrapped session must stamp a run context")
	}
	if sl.RunContext.RunId != "gwr_wrapped" {
		t.Fatalf("run id = %q, want gwr_wrapped", sl.RunContext.RunId)
	}
	if sl.RunContext.MembershipEvidence != wire.RunContextMembershipEvidenceINHERITEDRUNID {
		t.Fatalf("membership = %q, want INHERITED_RUN_ID", sl.RunContext.MembershipEvidence)
	}
}

// TestHookQuarantinedInheritedIDStampsNoRunContext proves an unknown inherited id is quarantined:
// the session is still captured, but with no trusted run context.
func TestHookQuarantinedInheritedIDStampsNoRunContext(t *testing.T) {
	seam := newFakeSeam() // "gwr_ghost" resolves to InheritedUnknown by default
	cfg := HookConfig{SourceID: "src_1", InheritedRunID: "gwr_ghost", HookPID: os.Getpid()}
	if _, err := runHook(t, seam, cfg, hookJSON(t, "sess-1", nil, "/work/dir", "startup")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	sl := lastSessionLifecycle(t, seam)
	if sl.RunContext != nil {
		t.Fatalf("quarantined inherited id must not stamp a run context, got %+v", sl.RunContext)
	}
}

// TestHookDefaultTimeoutIsTwoSeconds pins the hook's self-imposed deadline well below Codex's
// documented 600s default.
func TestHookDefaultTimeoutIsTwoSeconds(t *testing.T) {
	if DefaultHookTimeout != 2*time.Second {
		t.Fatalf("DefaultHookTimeout = %v, want 2s", DefaultHookTimeout)
	}
}

// TestHookTimeoutReturnsContentFreeSystemMessage proves a stalled daemon cannot stall startup:
// the hook's own timeout fires, it returns a bounded content-free systemMessage (continue=true),
// captures nothing, and leaks no session id or path.
func TestHookTimeoutReturnsContentFreeSystemMessage(t *testing.T) {
	seam := newFakeSeam()
	seam.blockAppend = true
	const sessionID = "sess-secret-abc"
	const cwd = "/home/secret/project"
	cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid(), Timeout: 150 * time.Millisecond}

	start := time.Now()
	out, err := runHook(t, seam, cfg, hookJSON(t, sessionID, nil, cwd, "startup"))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hook did not self-limit: elapsed %v", elapsed)
	}
	if seam.appendCount() != 0 {
		t.Fatalf("a stalled append must not record a durable capture, got %d", seam.appendCount())
	}
	resp := parseHookResponse(t, out)
	if !resp.Continue {
		t.Fatal("continue must be true so startup is never blocked")
	}
	if resp.SystemMessage != captureFailureMessage {
		t.Fatalf("systemMessage = %q, want the fixed capture-failure message", resp.SystemMessage)
	}
	if strings.Contains(string(out), sessionID) || strings.Contains(string(out), cwd) {
		t.Fatalf("capture-failure response leaked content: %q", out)
	}
}

// TestHookAppendFailureReturnsSystemMessage proves a durable-append error (not a timeout) also
// yields the content-free capture-failure response.
func TestHookAppendFailureReturnsSystemMessage(t *testing.T) {
	seam := newFakeSeam()
	seam.appendErr = context.DeadlineExceeded
	cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid()}
	out, err := runHook(t, seam, cfg, hookJSON(t, "sess-1", nil, "/work/dir", "startup"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	resp := parseHookResponse(t, out)
	if resp.SystemMessage != captureFailureMessage {
		t.Fatalf("systemMessage = %q, want capture-failure message", resp.SystemMessage)
	}
}

// TestHookDecodeAndSourceFailures proves malformed input, missing required fields, and an
// unsupported source never stall: each returns a bounded content-free response and captures
// nothing.
func TestHookDecodeAndSourceFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte(""), captureFailureMessage},
		{"malformed json", []byte("{not json"), captureFailureMessage},
		{"missing session_id", hookJSON(t, "", nil, "/work/dir", "startup"), captureFailureMessage},
		{"missing cwd", hookJSON(t, "sess-1", nil, "", "startup"), captureFailureMessage},
		{"unsupported source", hookJSON(t, "sess-1", nil, "/work/dir", "reboot"), unsupportedSourceMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seam := newFakeSeam()
			cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid()}
			out, err := runHook(t, seam, cfg, tc.input)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if seam.appendCount() != 0 {
				t.Fatalf("no capture expected, got %d", seam.appendCount())
			}
			resp := parseHookResponse(t, out)
			if !resp.Continue {
				t.Fatal("continue must be true")
			}
			if resp.SystemMessage != tc.want {
				t.Fatalf("systemMessage = %q, want %q", resp.SystemMessage, tc.want)
			}
		})
	}
}

// TestCanonicalizeTranscriptRefusals proves symlink, non-regular, root-escape, and non-absolute
// transcript paths are refused and never yield a locator.
func TestCanonicalizeTranscriptRefusals(t *testing.T) {
	root := filepath.Join(t.TempDir(), "approved")
	mustMkdir(t, root)
	realFile := filepath.Join(root, "transcript.jsonl")
	mustWrite(t, realFile, "{}")

	// symlink to a real regular file inside the root
	link := filepath.Join(root, "link.jsonl")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// a directory (non-regular)
	dir := filepath.Join(root, "adir")
	mustMkdir(t, dir)
	// a file outside every approved root
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	mustWrite(t, outside, "{}")

	for _, tc := range []struct {
		name   string
		path   string
		reason transcriptRefusal
	}{
		{"symlink", link, refusalSymlink},
		{"non-regular", dir, refusalNonRegular},
		{"root-escape", outside, refusalRootEscape},
		{"not-absolute", "relative/transcript.jsonl", refusalNotAbsolute},
		{"missing", filepath.Join(root, "nope.jsonl"), refusalUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc, ok, reason := canonicalizeTranscript(tc.path, []string{root})
			if ok {
				t.Fatalf("expected refusal, got locator %q", loc)
			}
			if reason != tc.reason {
				t.Fatalf("reason = %v, want %v", reason, tc.reason)
			}
		})
	}
}

// TestHookRefusedTranscriptStillCaptures proves a refused transcript path is non-fatal: the
// session is still captured, just with no source locator.
func TestHookRefusedTranscriptStillCaptures(t *testing.T) {
	root := filepath.Join(t.TempDir(), "approved")
	mustMkdir(t, root)
	realFile := filepath.Join(root, "real.jsonl")
	mustWrite(t, realFile, "{}")
	link := filepath.Join(root, "link.jsonl")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	tp := link
	seam := newFakeSeam()
	cfg := HookConfig{SourceID: "src_1", ApprovedRoots: []string{root}, HookPID: os.Getpid()}
	if _, err := runHook(t, seam, cfg, hookJSON(t, "sess-1", &tp, root, "startup")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	sl := lastSessionLifecycle(t, seam)
	if sl.Provenance.SourceLocator != nil {
		t.Fatalf("refused transcript must emit no locator, got %q", *sl.Provenance.SourceLocator)
	}
}

// TestHookNeverEmitsAbsoluteTranscriptPath is the sentinel scan: it captures a real transcript
// under an approved root whose absolute path contains a unique sentinel, and proves the emitted
// observation carries only the provider-relative locator — the absolute path never appears in
// the canonical bytes.
func TestHookNeverEmitsAbsoluteTranscriptPath(t *testing.T) {
	const sentinel = "SENTINELROOT9z"
	root := filepath.Join(t.TempDir(), "approved_"+sentinel)
	sub := filepath.Join(root, "sess")
	mustMkdir(t, sub)
	transcript := filepath.Join(sub, "transcript.jsonl")
	mustWrite(t, transcript, `{"line":1}`)

	seam := newFakeSeam()
	cfg := HookConfig{SourceID: "src_1", ApprovedRoots: []string{root}, HookPID: os.Getpid()}
	tp := transcript
	if _, err := runHook(t, seam, cfg, hookJSON(t, "sess-1", &tp, root, "startup")); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sl := lastSessionLifecycle(t, seam)
	if sl.Provenance.SourceLocator == nil {
		t.Fatal("expected a provider-relative locator")
	}
	if got := *sl.Provenance.SourceLocator; got != "sess/transcript.jsonl" {
		t.Fatalf("locator = %q, want sess/transcript.jsonl", got)
	}

	canon := string(seam.lastAppend(t).canon)
	if strings.Contains(canon, sentinel) {
		t.Fatalf("absolute-root sentinel leaked into canonical bytes:\n%s", canon)
	}
	if strings.Contains(canon, root) || strings.Contains(canon, transcript) {
		t.Fatalf("absolute path leaked into canonical bytes:\n%s", canon)
	}
	if !strings.Contains(canon, "sess/transcript.jsonl") {
		t.Fatalf("relative locator missing from canonical bytes:\n%s", canon)
	}
}

// blockingReader blocks every Read until release is closed, simulating a stdin pipe held open
// with a slow drip that never delivers EOF or fills the size cap.
type blockingReader struct{ release chan struct{} }

func (r *blockingReader) Read(p []byte) (int, error) {
	<-r.release
	return 0, io.EOF
}

// TestHookSlowDripStdinRespectsTimeout proves red-team finding 1 is fixed: a stdin pipe held open
// without EOF can no longer defeat the hook's hard deadline. The context-bounded read abandons the
// stalled stdin, Run returns within the timeout budget, captures nothing, and emits the same
// content-free capture-failure systemMessage — no session id/cwd/path leak.
func TestHookSlowDripStdinRespectsTimeout(t *testing.T) {
	r := &blockingReader{release: make(chan struct{})}
	t.Cleanup(func() { close(r.release) }) // unblock the read goroutine once the test is done

	seam := newFakeSeam()
	cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid(), Timeout: 150 * time.Millisecond}
	var out bytes.Buffer
	start := time.Now()
	err := Run(context.Background(), seam, cfg, r, &out)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("slow-drip stdin defeated the hook timeout: elapsed %v", elapsed)
	}
	if seam.appendCount() != 0 {
		t.Fatalf("a stalled read must not record a capture, got %d", seam.appendCount())
	}
	resp := parseHookResponse(t, out.Bytes())
	if !resp.Continue {
		t.Fatal("continue must be true so startup is never blocked")
	}
	if resp.SystemMessage != captureFailureMessage {
		t.Fatalf("systemMessage = %q, want the fixed capture-failure message", resp.SystemMessage)
	}
}

// TestHookOversizedInputFailsClosed proves the fast oversized path still fails closed after the
// read was made context-aware: an input above the byte ceiling is refused and captures nothing.
func TestHookOversizedInputFailsClosed(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxHookInputBytes+16)
	seam := newFakeSeam()
	cfg := HookConfig{SourceID: "src_1", HookPID: os.Getpid()}
	out, err := runHook(t, seam, cfg, big)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seam.appendCount() != 0 {
		t.Fatalf("oversized input must not capture, got %d", seam.appendCount())
	}
	resp := parseHookResponse(t, out)
	if resp.SystemMessage != captureFailureMessage {
		t.Fatalf("systemMessage = %q, want capture-failure message", resp.SystemMessage)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
