//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
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
		env := evidence.PolicyEnvelope{
			CapturedAt: a.now(),
			Provenance: evidence.RawProvenance{
				Provider:            a.provider,
				ParserVersion:       a.parserVersion,
				TransformVersion:    a.transformVersion,
				RootRelativeLocator: ref.Locator,
			},
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
