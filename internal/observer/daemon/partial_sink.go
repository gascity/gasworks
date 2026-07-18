//go:build linux

package daemon

import (
	"context"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
)

// PartialCandidateSinkAdapter refines the committed CandidateSinkAdapter with the delivered-count
// contract the watcher's partial-commit path (E1.10b) needs to avoid the mid-batch double-append
// (E1.10a red-team finding 2). It reuses the committed adapter's ordered, policy-transforming,
// stop-on-first-failure delivery unchanged — it only makes the count of durably-delivered leading
// candidates observable. The committed adapter already appends candidates one at a time, so
// delivering a single candidate per inner call is behaviorally identical; it simply lets this
// wrapper count the successes that preceded a failure.
type PartialCandidateSinkAdapter struct {
	inner *CandidateSinkAdapter
}

// NewPartialCandidateSinkAdapter wraps a committed CandidateSinkAdapter as a
// codex.PartialCandidateSink.
func NewPartialCandidateSinkAdapter(inner *CandidateSinkAdapter) *PartialCandidateSinkAdapter {
	return &PartialCandidateSinkAdapter{inner: inner}
}

// PartialCandidateSinkAdapter satisfies both the plain and the partial watcher sink.
var _ codex.PartialCandidateSink = (*PartialCandidateSinkAdapter)(nil)

// DeliverCandidates delivers the whole batch, discarding the delivered count. It exists so the
// wrapper still satisfies the plain CandidateSink contract; the watcher prefers the partial method.
func (a *PartialCandidateSinkAdapter) DeliverCandidates(ctx context.Context, ref codex.TranscriptRef, cands []*codex.Candidate) error {
	_, err := a.DeliverCandidatesPartial(ctx, ref, cands)
	return err
}

// DeliverCandidatesPartial delivers cands in transcript order, one at a time, through the committed
// adapter and returns how many leading candidates were durably delivered (or safely dropped)
// before the first failure. A nil error means every candidate was delivered.
func (a *PartialCandidateSinkAdapter) DeliverCandidatesPartial(ctx context.Context, ref codex.TranscriptRef, cands []*codex.Candidate) (int, error) {
	for i := range cands {
		if err := a.inner.DeliverCandidates(ctx, ref, cands[i:i+1]); err != nil {
			return i, err
		}
	}
	return len(cands), nil
}
