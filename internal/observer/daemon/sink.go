//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
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

// transcriptSession is the per-transcript session-threading state, and what this sink already
// appended for the transcript. The watcher re-delivers a whole transcript line after a delivery
// failure part way through it, so the line's leading candidates arrive twice; the appended records
// let the sink recognize a start or a usage it already made durable, and skip it.
type transcriptSession struct {
	nativeID string
	provider string
	// started holds the sessions whose SESSION_LIFECYCLE this sink appended for the transcript. It
	// is set only once the append succeeded, so a start whose append failed is appended on the retry
	// — the start is the only record that carries the session's model.
	started map[string]bool
	// usage holds the message ids of the last usageMemory USAGE observations this sink appended for
	// the transcript, as hashes. A message id names one response, which the parser counts once per
	// transcript, so a second USAGE with the same id is that response re-delivered.
	usage []uint64
}

// usageMemory bounds the appended usage message ids kept per transcript. A re-delivery repeats at
// most one transcript line's candidates, which never hold more than a few usage atoms.
const usageMemory = 32

// usageKey hashes a USAGE candidate's message id; ok is false for usage without one (a legacy
// Codex token_count, a record without an id), which can never be recognized as re-delivered.
func usageKey(cand *codex.Candidate) (key uint64, ok bool) {
	if cand.Kind != codex.KindUsage || cand.Usage == nil || cand.Usage.MessageID == "" {
		return 0, false
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(cand.Usage.MessageID))
	return h.Sum64(), true
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
		if _, err := a.deliverOne(ctx, ref, cand); err != nil {
			return err
		}
	}
	return nil
}

// deliverOne transforms one candidate and durably appends the result, returning the WAL sequence
// it was appended at. The sequence is 0 when nothing was appended: a nil candidate, a start or usage
// this sink already made durable, or a consent-recorded extraction drop — each safely treated as
// delivered.
func (a *CandidateSinkAdapter) deliverOne(ctx context.Context, ref codex.TranscriptRef, cand *codex.Candidate) (int64, error) {
	if cand == nil {
		return 0, nil
	}
	native, provider, appended := a.resolveSession(ref, cand)
	if appended {
		// A start or usage this sink already made durable, re-delivered with a line re-read after a
		// partial delivery failure. Re-reading the batch would only skip it again, so it is safely
		// treated as delivered.
		return 0, nil
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
		return 0, nil
	}
	if !res.HasObservation() {
		// The transform could not even build a content-free diagnostic (invalid policy or absent
		// timestamps). Fail closed: do not advance the cursor.
		return 0, fmt.Errorf("observer daemon: candidate transform produced no durable observation: %w", res.Cause)
	}
	ack, err := a.client.CaptureObservation(ctx, res.Observation)
	if err != nil {
		return 0, fmt.Errorf("observer daemon: deliver candidate to daemon: %w", err)
	}
	a.recordAppended(ref, cand, native)
	return ack.Sequence, nil
}

// recordAppended remembers a start or a usage that was just made durable for the transcript (see
// transcriptSession).
func (a *CandidateSinkAdapter) recordAppended(ref codex.TranscriptRef, cand *codex.Candidate, native string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	s := a.sessions[transcriptIdentity{device: ref.Device, inode: ref.Inode}]
	if s == nil {
		return
	}
	if cand.Kind == codex.KindSessionLifecycle && native != "" {
		if s.started == nil {
			s.started = map[string]bool{}
		}
		s.started[native] = true
	}
	if key, ok := usageKey(cand); ok {
		s.usage = append(s.usage, key)
		if len(s.usage) > usageMemory {
			s.usage = s.usage[len(s.usage)-usageMemory:]
		}
	}
}

// resolveSession resolves the native session id and provider to stamp onto one candidate, and
// reports whether the candidate was already appended (see transcriptSession). A SESSION_LIFECYCLE
// candidate carries its own id and provider: they are recorded for the transcript and returned so
// the session observation itself is stamped. A candidate the parser attributed to a session
// (codex.Candidate.Session, from the transcript's persisted parse state) is stamped with it and
// records it for the transcript, so attribution holds after a daemon restart, when this threading
// starts empty while the cursor resumes past the session's start. Every other candidate from the
// same transcript inherits the recorded id and provider, so a USAGE record without a session of its
// own resolves to the same SyntheticRunID as the session and its tokens sum into that run's totals.
// A candidate delivered before the transcript's session record has been seen — or a
// watcher-scoped diagnostic on a zero-value ref — resolves to empty strings and is stamped
// unchanged (provider then falls back to the sink default).
func (a *CandidateSinkAdapter) resolveSession(ref codex.TranscriptRef, cand *codex.Candidate) (native, provider string, appended bool) {
	key := transcriptIdentity{device: ref.Device, inode: ref.Inode}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	s := a.sessions[key]
	if s == nil {
		s = &transcriptSession{}
		a.sessions[key] = s
	}
	if h, ok := usageKey(cand); ok && slices.Contains(s.usage, h) {
		return s.nativeID, s.provider, true
	}
	if cand.Kind == codex.KindSessionLifecycle && cand.SessionLifecycle != nil && cand.SessionLifecycle.NativeSessionID != "" {
		id := cand.SessionLifecycle.NativeSessionID
		s.nativeID = id
		if prov := cand.SessionLifecycle.Provider; prov != "" {
			s.provider = prov
		}
		return id, s.provider, s.started[id]
	}
	if attributed := cand.Session; attributed != nil && attributed.NativeID != "" {
		if s.nativeID != attributed.NativeID {
			s.nativeID, s.provider = attributed.NativeID, attributed.Provider
		}
		return attributed.NativeID, orString(attributed.Provider, s.provider), false
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
