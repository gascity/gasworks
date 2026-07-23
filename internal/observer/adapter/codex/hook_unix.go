//go:build unix

package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// PendingObservation is the pre-sequence, policy-clean observation the daemon seals and
// appends. It aliases the evidence constructor's type so the seam surface reads cleanly.
type PendingObservation = evidence.PendingObservation

// Provider is the native provider name stamped on every Codex observation and hashed into the
// deterministic synthetic run id.
const Provider = "codex"

// AdapterName and AdapterVersion identify the capturing adapter in provenance. The version is a
// qualification-manifest concern (the spec pins the exact Codex release and its hook/transcript
// fixture digest); this is the adapter's own contract version, bumped when its output changes.
const (
	AdapterName    = "codex-hook"
	AdapterVersion = "0.1.0"
)

// DefaultHookTimeout is the hook's own hard deadline on durable capture. It sits well below
// Codex's documented 600-second default (https://learn.chatgpt.com/docs/hooks) so a stalled or
// unreachable daemon can never stall Codex session startup: the hook self-limits, emits its
// bounded capture-failure systemMessage, and exits.
const DefaultHookTimeout = 2 * time.Second

// maxHookInputBytes bounds the stdin read so a hostile or pathological hook payload cannot
// exhaust memory. A Codex SessionStart event is a small JSON object; 1 MiB is generous.
const maxHookInputBytes = 1 << 20

// captureFailureMessage is the fixed, content-free warning the hook returns when it cannot
// durably capture. It names no session, path, run, or transcript content — only the operational
// fact that this interval's evidence may be incomplete.
const captureFailureMessage = "Gasworks Observer could not durably capture this Codex session start; evidence for this interval may be incomplete."

// unsupportedSourceMessage is the fixed, content-free warning for a SessionStart whose source
// is not one this adapter version supports. Identity capture degrades rather than stalling.
const unsupportedSourceMessage = "Gasworks Observer does not support this Codex session-start source; this session was not attributed to a run."

// hookInput is the strict-typed decode of the Codex SessionStart hook JSON read from stdin. It
// models only the documented load-bearing fields (session_id, transcript_path, cwd, source);
// other documented Codex fields (hook_event_name, model, permission_mode) are tolerated and
// ignored here — identity attachment is hook-based, while content/model capture is the
// versioned transcript parser's job (E1.8). Decoding is NOT DisallowUnknownFields: Codex may add
// fields across releases, and rejecting an additive field would break a qualified release.
type hookInput struct {
	SessionID      string  `json:"session_id"`
	TranscriptPath *string `json:"transcript_path"`
	CWD            string  `json:"cwd"`
	Source         string  `json:"source"`
}

// HookConfig is the endpoint-owned configuration the hook runs under. Everything the hook needs
// from its environment is injected, so Run is a pure function of its inputs and fully testable:
// the production entry point (E1.10) supplies SourceID, ApprovedRoots, the resolved
// GASWORKS_RUN_ID, and the workspace resolver.
type HookConfig struct {
	// SourceID is this installation's Observer source id; it participates in the synthetic run id
	// and in the same-source scoping of an inherited run id.
	SourceID string
	// ApprovedRoots are the absolute directory roots beneath which a transcript path is allowed.
	ApprovedRoots []string
	// InheritedRunID is the resolved GASWORKS_RUN_ID (E1.10 passes os.Getenv); "" means none.
	InheritedRunID string
	// HookPID is the process whose ancestry proves lineage; 0 defaults to os.Getpid().
	HookPID int
	// Workspace maps the hook cwd to a workspace token used only for the same-workspace
	// comparison of an inherited run id; the token is never emitted on the wire. nil defaults to
	// the identity mapping.
	Workspace func(cwd string) string
	// Timeout overrides DefaultHookTimeout; 0 uses the default.
	Timeout time.Duration
	// Now overrides the clock; nil uses time.Now.
	Now func() time.Time
}

func (c HookConfig) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultHookTimeout
}

func (c HookConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c HookConfig) workspace(cwd string) string {
	if c.Workspace != nil {
		return c.Workspace(cwd)
	}
	return cwd
}

func (c HookConfig) hookPID() int {
	if c.HookPID > 0 {
		return c.HookPID
	}
	return os.Getpid()
}

// Run decodes one Codex SessionStart hook event from stdin, decides the session's run
// attachment, durably captures a SESSION_LIFECYCLE observation through the seam, and — on any
// durable-capture failure — writes a bounded, content-free SessionStart response to stdout so
// startup is never stalled.
//
// It writes NO captured content to stdout/stderr: a successful capture produces empty stdout
// (Codex treats exit 0 with no output as success); a failed capture produces only the fixed
// systemMessage. The returned error is reserved for a stdout write failure; every capture or
// decode problem is handled by emitting the content-free response and returning nil.
func Run(ctx context.Context, seam DaemonSeam, cfg HookConfig, stdin io.Reader, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()

	in, err := decodeHookInput(ctx, stdin)
	if err != nil {
		return writeCaptureFailure(stdout, captureFailureMessage)
	}

	source, okSource := parseSource(in.Source)
	if !okSource {
		return writeCaptureFailure(stdout, unsupportedSourceMessage)
	}

	// The transcript path is optional and its refusal is non-fatal: identity attachment does not
	// depend on the transcript. A refused path simply yields no locator; the absolute path is
	// never emitted regardless.
	var locator string
	if in.TranscriptPath != nil && *in.TranscriptPath != "" {
		if loc, ok, _ := canonicalizeTranscript(*in.TranscriptPath, cfg.ApprovedRoots); ok {
			locator = loc
		}
	}

	decision := Decide(ctx, seam, AttachInput{
		SourceID:        cfg.SourceID,
		Provider:        Provider,
		NativeSessionID: in.SessionID,
		Workspace:       cfg.workspace(in.CWD),
		StartSource:     source,
		InheritedRunID:  cfg.InheritedRunID,
		HookPID:         cfg.hookPID(),
	})

	obs, ok := buildObservation(cfg, in, source, locator, decision)
	if !ok {
		return writeCaptureFailure(stdout, captureFailureMessage)
	}

	if _, err := seam.CaptureSessionLifecycle(ctx, obs); err != nil {
		return writeCaptureFailure(stdout, captureFailureMessage)
	}
	// Success: exit 0 with no output. Nothing captured reaches stdout/stderr.
	return nil
}

// decodeHookInput reads the bounded hook JSON UNDER the hook context and validates the
// load-bearing fields. The read runs on a goroutine so a slow-drip stdin pipe held open below the
// size cap — which io.ReadAll alone would block on forever — cannot outlast the hook's hard
// deadline: on ctx.Done the read is abandoned and a context error is returned, driving the same
// content-free capture-failure response every other failure branch uses. It rejects an oversized
// payload, a missing/empty session id, and a missing cwd, and never echoes the input.
func decodeHookInput(ctx context.Context, r io.Reader) (hookInput, error) {
	type readResult struct {
		data []byte
		err  error
	}
	// Buffered so the reader goroutine never blocks on send after a ctx.Done abandonment; the
	// goroutine ends when the reader unblocks (or at process exit for a never-closing pipe).
	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(r, maxHookInputBytes+1))
		ch <- readResult{data: data, err: err}
	}()

	var res readResult
	select {
	case <-ctx.Done():
		return hookInput{}, fmt.Errorf("codex hook: read stdin: %w", ctx.Err())
	case res = <-ch:
	}
	if res.err != nil {
		return hookInput{}, fmt.Errorf("codex hook: read stdin: %w", res.err)
	}
	data := res.data
	if len(data) > maxHookInputBytes {
		return hookInput{}, errors.New("codex hook: input exceeds maximum size")
	}
	var in hookInput
	if err := json.Unmarshal(data, &in); err != nil {
		return hookInput{}, fmt.Errorf("codex hook: decode input: %w", err)
	}
	if in.SessionID == "" {
		return hookInput{}, errors.New("codex hook: missing session_id")
	}
	if in.CWD == "" {
		return hookInput{}, errors.New("codex hook: missing cwd")
	}
	return in, nil
}

// parseSource maps the Codex source string to its wire start-source enum. An unrecognized value
// is refused (ok=false) so a future/unsupported source degrades visibly rather than being cast
// blindly.
func parseSource(s string) (wire.SessionLifecyclePayloadStartSource, bool) {
	switch s {
	case "startup":
		return wire.SessionLifecyclePayloadStartSourceSTARTUP, true
	case "resume":
		return wire.SessionLifecyclePayloadStartSourceRESUME, true
	case "clear":
		return wire.SessionLifecyclePayloadStartSourceCLEAR, true
	case "compact":
		return wire.SessionLifecyclePayloadStartSourceCOMPACT, true
	default:
		return "", false
	}
}

// buildObservation projects the decision and decoded event onto a policy-clean
// SESSION_LIFECYCLE PendingObservation. A run context is stamped ONLY for a HIGH attachment;
// inferred, quarantined, and within-session events carry no run context (the passive/quarantine
// discipline). ok=false means the policy transform could not even build its fail-closed
// diagnostic — a daemon misconfiguration — which the caller surfaces as a capture failure.
func buildObservation(cfg HookConfig, in hookInput, source wire.SessionLifecyclePayloadStartSource, locator string, decision Decision) (PendingObservation, bool) {
	policy := evidence.Policy{
		Adapter:        AdapterName,
		AdapterVersion: AdapterVersion,
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
	var rc *wire.RunContext
	if decision.Disposition == DispositionAttachHigh {
		rc = &wire.RunContext{RunId: decision.RunID, MembershipEvidence: decision.Membership}
	}
	now := cfg.now()
	env := evidence.PolicyEnvelope{
		OccurredAt: now,
		CapturedAt: now,
		Provenance: evidence.RawProvenance{
			Provider:            Provider,
			NativeSessionID:     in.SessionID,
			RootRelativeLocator: locator,
		},
		RunContext: rc,
	}
	tr := policy.TransformSessionLifecycle(env, evidence.SessionLifecycleCandidate{
		NativeSessionID: in.SessionID,
		Provider:        Provider,
		StartSource:     source,
		Transition:      decision.Transition,
	})
	if !tr.HasObservation() {
		return PendingObservation{}, false
	}
	return tr.Observation, true
}

// ---- transcript path canonicalization ----

// transcriptRefusal classifies why a transcript path was refused. It is diagnostic only; the
// absolute path is never emitted for any reason.
type transcriptRefusal int

const (
	refusalNone transcriptRefusal = iota
	refusalNotAbsolute
	refusalUnreadable
	refusalSymlink
	refusalNonRegular
	refusalRootEscape
)

// canonicalizeTranscript validates a Codex-supplied transcript path beneath the approved roots
// and returns a provider-relative locator. It refuses a non-absolute path, a symlink (final
// component), a non-regular file, and any path that — after resolving parent symlinks — escapes
// every approved root. It NEVER returns the absolute path: the locator is the path relative to
// the matched approved root. ok=false means no locator should be emitted.
func canonicalizeTranscript(path string, approvedRoots []string) (string, bool, transcriptRefusal) {
	if !filepath.IsAbs(path) {
		return "", false, refusalNotAbsolute
	}
	clean := filepath.Clean(path)

	// The final component must be a real regular file, not a symlink: a symlink could point
	// outside an approved root even when the link path itself looks contained.
	info, err := os.Lstat(clean)
	if err != nil {
		return "", false, refusalUnreadable
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", false, refusalSymlink
	}
	if !info.Mode().IsRegular() {
		return "", false, refusalNonRegular
	}

	// Resolve parent symlinks so a symlinked directory cannot smuggle the file outside a root,
	// then rejoin the (already proven non-symlink) base name.
	realParent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", false, refusalUnreadable
	}
	realPath := filepath.Join(realParent, filepath.Base(clean))

	for _, root := range approvedRoots {
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(realRoot, realPath)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			continue // escapes this root
		}
		return rel, true, refusalNone
	}
	return "", false, refusalRootEscape
}

// ---- content-free hook response ----

// hookResponse is the bounded Codex SessionStart response. continue is always true so a capture
// failure never marks the session stopped; systemMessage carries only the fixed content-free
// warning.
type hookResponse struct {
	Continue      bool   `json:"continue"`
	SystemMessage string `json:"systemMessage"`
}

// writeCaptureFailure emits the content-free SessionStart response to stdout. The message is a
// fixed constant; no session id, path, run id, or transcript byte is ever written.
func writeCaptureFailure(w io.Writer, message string) error {
	payload, err := json.Marshal(hookResponse{Continue: true, SystemMessage: message})
	if err != nil {
		return fmt.Errorf("codex hook: marshal response: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("codex hook: write response: %w", err)
	}
	return nil
}
