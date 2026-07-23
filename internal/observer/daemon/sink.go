//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// CandidateSinkAdapter adapts a local.Client to the codex.CandidateSink the committed transcript
// watcher (E1.8) delivers parsed candidates to. For each candidate it runs the committed evidence
// Policy transform — the single content-stripping choke point — and durably appends the resulting
// observation through the daemon. Delivery is at-least-once and ordered: it appends candidates in
// transcript order and STOPS on the first failure, so no candidate past a failure ever reaches the
// WAL, and it returns a non-nil error so the watcher does NOT advance its cursor past the batch and
// re-reads it on the next poll.
//
// AT-LEAST-ONCE DUPLICATE HANDLING (deliberately deferred to E1.10b): a retry re-delivers the WHOLE
// batch, and the single-writer daemon assigns a FRESH sequence and observation id to every append,
// so the already-durable prefix of a partially-delivered batch is re-appended as distinct frames.
// The platform's logical dedup key is (source_id, sequence, observation_id) — none stable across a
// sink re-append — so that duplicate is NOT collapsed by logical dedup (which only cancels an
// identical same-sequence physical replay, e.g. the E1.9 uploader). Collapsing a partial-batch
// retry belongs to the watcher-cursor partial-commit / daemon idempotency-token wiring assembled in
// E1.10b, not to this adapter; this adapter guarantees only ordered, stop-on-first-failure,
// at-least-once delivery. Duplicates are content-free (the METADATA_ONLY transform still strips
// content) and never affect an attach decision, which rides the separate registry/seam path.
type CandidateSinkAdapter struct {
	client           *local.Client
	policy           evidence.Policy
	provider         string
	parserVersion    string
	transformVersion string
	now              func() time.Time
	// runResolver maps a native session id to the explicit run a wrapper bound it to, so the sink
	// can stamp run_context onto that session's observations. nil disables run binding (passive
	// capture only); the daemon injects its Registry, so the lookup is an in-process map read.
	runResolver sessionRunResolver

	// sessionMu guards sessions. The watcher drives delivery from a single goroutine, but the guard
	// keeps the session-threading state race-free even if a caller ever fans delivery out.
	sessionMu sync.Mutex
	// sessions remembers, per transcript filesystem identity, the native session id and provider last
	// seen on that transcript's SESSION_LIFECYCLE record (and whether one has already been appended).
	// A transcript is one native session, so once its session record is observed the id and provider
	// are stamped onto every later record whose own kind carries neither — the transcript's USAGE
	// record has no session field of its own, so without this the endpoint would emit a USAGE
	// observation with an empty provenance.native_session_id and the platform's run-builder could not
	// derive its SyntheticRunID(source, provider, native) to sum it into a run's usage_totals. The
	// provider is threaded the same way so one watcher can tail Codex and Claude roots together and
	// each session still gets its true provider on provenance.
	sessions map[transcriptIdentity]*transcriptSession
}

// sessionRunResolver looks up the explicit run a native session was bound to (satisfied by the
// daemon Registry). It is the read seam the sink uses to stamp run_context; keeping it an interface
// lets the sink stay testable without a full daemon and avoids a hard dependency cycle.
type sessionRunResolver interface {
	LookupSessionRun(nativeSessionID string) (runID string, found bool)
}

// transcriptSession is the per-transcript session-threading state.
type transcriptSession struct {
	nativeID string
	provider string
	// emitted is true once a SESSION_LIFECYCLE for nativeID has been appended, so a later duplicate
	// STARTED for the same session — Claude re-synthesizes the session record on every poll because
	// its native session id recurs on every envelope — is threaded but not re-appended.
	emitted bool
}

// transcriptIdentity keys the per-transcript session-threading state by filesystem identity
// (device+inode) — the same identity the watcher's cursor tracks, so a rename keeps the session id
// while a rotation to a new inode starts fresh from its own session record.
type transcriptIdentity struct {
	device uint64
	inode  uint64
}

// SinkConfig configures a CandidateSinkAdapter. Client and a valid Policy are required; the
// provenance identity fields are stamped onto every observation before the transform.
type SinkConfig struct {
	// Client is the durable-append seam into the daemon (required).
	Client *local.Client
	// Policy is the daemon-constant capture policy every candidate is transformed under (required,
	// validated at construction).
	Policy evidence.Policy
	// Provider is the provenance provider stamped on each observation (e.g. "codex").
	Provider string
	// ParserVersion is the transcript-parser identity stamped into provenance (codex.ParserVersion).
	ParserVersion string
	// TransformVersion is the transform identity stamped into provenance.
	TransformVersion string
	// Now supplies the endpoint capture timestamp; nil selects time.Now.
	Now func() time.Time
	// RunResolver maps a native session id to a wrapper-bound run so the sink can stamp run_context.
	// Optional: nil captures passively (no run binding).
	RunResolver sessionRunResolver
}

// NewCandidateSinkAdapter validates cfg and returns a ready sink. The Policy is validated once here
// so every transform can guarantee a content-free fail-closed diagnostic.
func NewCandidateSinkAdapter(cfg SinkConfig) (*CandidateSinkAdapter, error) {
	if cfg.Client == nil {
		return nil, errors.New("observer daemon: candidate sink requires a client")
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("observer daemon: candidate sink policy: %w", err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CandidateSinkAdapter{
		client:           cfg.Client,
		policy:           cfg.Policy,
		provider:         cfg.Provider,
		parserVersion:    cfg.ParserVersion,
		transformVersion: cfg.TransformVersion,
		now:              now,
		runResolver:      cfg.RunResolver,
		sessions:         map[transcriptIdentity]*transcriptSession{},
	}, nil
}

// CandidateSinkAdapter satisfies the watcher's candidate sink.
var _ codex.CandidateSink = (*CandidateSinkAdapter)(nil)

// DeliverCandidates transforms each candidate through the committed Policy and durably appends the
// result, in transcript order. A per-ref-kind extraction toggle that gates a reference out is a
// consent-recorded drop and is skipped (not a failure). A transform that could not even build its
// fail-closed diagnostic, or a durable append that fails, returns a non-nil error immediately so
// the watcher does not advance its cursor past this batch.
func (a *CandidateSinkAdapter) DeliverCandidates(ctx context.Context, ref codex.TranscriptRef, cands []*codex.Candidate) error {
	for _, cand := range cands {
		if cand == nil {
			continue
		}
		native, provider, suppress := a.resolveSession(ref, cand)
		if suppress {
			// A duplicate SESSION_LIFECYCLE re-synthesized for an already-recorded native session
			// (Claude emits its session record on every poll). It is threaded but not re-appended;
			// re-reading the batch would only re-suppress it, so it is safely treated as delivered.
			continue
		}
		if provider == "" {
			provider = a.provider
		}
		env := evidence.PolicyEnvelope{
			CapturedAt: a.now(),
			Provenance: evidence.RawProvenance{
				Provider:            provider,
				NativeSessionID:     native,
				ParserVersion:       a.parserVersion,
				TransformVersion:    a.transformVersion,
				RootRelativeLocator: ref.Locator,
			},
			RunContext: a.runContextFor(native),
		}
		res := cand.Transform(a.policy, env)
		if res.Dropped {
			// A consent-recorded extraction-toggle drop: nothing to append, and re-reading the batch
			// would only re-drop it, so it is safe to treat as delivered.
			continue
		}
		if !res.HasObservation() {
			// The transform could not even build a content-free diagnostic (invalid policy or absent
			// timestamps). Fail closed: do not advance the cursor.
			return fmt.Errorf("observer daemon: candidate transform produced no durable observation: %w", res.Cause)
		}
		if _, err := a.client.CaptureObservation(ctx, res.Observation); err != nil {
			return fmt.Errorf("observer daemon: deliver candidate to daemon: %w", err)
		}
	}
	return nil
}

// resolveSession resolves the native session id and provider to stamp onto one candidate, and
// reports whether the candidate is a duplicate SESSION_LIFECYCLE to suppress. A SESSION_LIFECYCLE
// candidate carries its own id and provider: they are recorded for the transcript and returned so
// the session observation itself is stamped — unless the same native id was already appended for
// this transcript, in which case suppress is true (a re-synthesized STARTED, e.g. Claude's per-poll
// session record). Every other candidate from the same transcript inherits the recorded id and
// provider, so a USAGE record (which has neither field) resolves to the same SyntheticRunID as the
// session and its tokens sum into that run's totals. A candidate delivered before the transcript's
// session record has been seen — or a watcher-scoped diagnostic on a zero-value ref — resolves to
// empty strings and is stamped unchanged (provider then falls back to the sink default).
func (a *CandidateSinkAdapter) resolveSession(ref codex.TranscriptRef, cand *codex.Candidate) (native, provider string, suppress bool) {
	key := transcriptIdentity{device: ref.Device, inode: ref.Inode}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	s := a.sessions[key]
	if s == nil {
		s = &transcriptSession{}
		a.sessions[key] = s
	}
	if cand.Kind == codex.KindSessionLifecycle && cand.SessionLifecycle != nil && cand.SessionLifecycle.NativeSessionID != "" {
		id := cand.SessionLifecycle.NativeSessionID
		prov := cand.SessionLifecycle.Provider
		if s.emitted && s.nativeID == id {
			// Same session, already appended: thread the recorded values but suppress the re-append.
			return id, orString(prov, s.provider), true
		}
		s.nativeID = id
		if prov != "" {
			s.provider = prov
		}
		s.emitted = true
		return id, s.provider, false
	}
	return s.nativeID, s.provider, false
}

// SessionFor returns the native session id and provider threaded for the transcript identified by
// (device, inode) — the same identity the watcher's cursor and the content side channel key on — or
// ok=false when no SESSION_LIFECYCLE record has yet been observed for it. It lets the content
// uploader key a whole-transcript snapshot by the exact native session id the metadata observations
// carry, without re-parsing. A session whose own record omitted the provider falls back to the sink
// default provider, matching how DeliverCandidates stamps provenance.
func (a *CandidateSinkAdapter) SessionFor(device, inode uint64) (nativeID, provider string, ok bool) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	s := a.sessions[transcriptIdentity{device: device, inode: inode}]
	if s == nil || s.nativeID == "" {
		return "", "", false
	}
	prov := s.provider
	if prov == "" {
		prov = a.provider
	}
	return s.nativeID, prov, true
}

// Forget drops the threaded session state for a transcript identity. The watcher calls it (via the
// content side channel's ForgetContent) when a transcript has fully rotated away, so a later file
// that reuses the same (device,inode) cannot inherit the previous transcript's native session id.
func (a *CandidateSinkAdapter) Forget(device, inode uint64) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	delete(a.sessions, transcriptIdentity{device: device, inode: inode})
}

// runContextFor returns the run context to stamp onto a session's observation, or nil when the
// session has no wrapper binding (passive capture). A bound session's USAGE/SESSION observation
// carries the explicit run id under DECLARED_BOUNDARY membership — the wrapper declared the run and
// bound this child session to it — so the explicit run carries its child agent's real cost natively.
func (a *CandidateSinkAdapter) runContextFor(native string) *wire.RunContext {
	if native == "" || a.runResolver == nil {
		return nil
	}
	runID, ok := a.runResolver.LookupSessionRun(native)
	if !ok {
		return nil
	}
	return &wire.RunContext{
		RunId:              runID,
		MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY,
	}
}

// orString returns a when non-empty, else b.
func orString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
