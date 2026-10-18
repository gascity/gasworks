//go:build linux || darwin

package daemon

import (
	"context"
	"fmt"
	"sort"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// watchShape is everything the transcript watcher is built from under a live consent policy: the
// capturable consent records (active roots and tombstones) and whether transcript content is
// observed for upload. A policy change that leaves the shape alone — a rewrite with identical
// consent, the same records in another order, a fail-closed report while content was already off —
// keeps the running watcher.
type watchShape struct {
	// records are in document order: the order a static configuration hands the watcher its roots.
	records []rootpolicy.Record
	content bool
}

// shapeOf derives the watcher shape a policy calls for. contentWired reports whether this daemon
// can upload content at all (it has a collector).
func shapeOf(p consent.Policy, contentWired bool) watchShape {
	return watchShape{records: append([]rootpolicy.Record(nil), p.Roots...), content: p.ContentUpload && contentWired}
}

// equal reports whether two shapes build the same watcher; record order does not matter.
func (a watchShape) equal(b watchShape) bool {
	if a.content != b.content || len(a.records) != len(b.records) {
		return false
	}
	x, y := sortedByPath(a.records), sortedByPath(b.records)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// sortedByPath returns a copy of records ordered by path.
func sortedByPath(records []rootpolicy.Record) []rootpolicy.Record {
	out := append([]rootpolicy.Record(nil), records...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// generations maps every active consent root to its generation.
func (a watchShape) generations() map[string]uint64 {
	out := make(map[string]uint64, len(a.records))
	for _, r := range a.records {
		if r.Active {
			out[r.Path] = r.Generation
		}
	}
	return out
}

// applyWatchConsentLocked brings the watcher in line with p, rebuilding it when p changed its shape.
// A shape the watcher cannot be built for leaves NO watcher — capture pauses rather than continue
// under consent that was withdrawn — and is retried on every pass, logged once per distinct error.
// Called with s.watchMu held (or before the service starts).
func (s *Service) applyWatchConsentLocked(p consent.Policy) error {
	shape := shapeOf(p, s.content != nil)
	if s.watchShapeSet && shape.equal(s.watchShape) {
		s.noteUnavailableContentLocked(p)
		return nil
	}
	if err := s.rebuildWatcherLocked(p, shape); err != nil {
		if msg := err.Error(); msg != s.watchBuildErr {
			s.watchBuildErr = msg
			s.logf("consent policy version %d cannot be applied to the transcript watcher: %v; transcript capture is paused until a policy that can be applied is written", p.Version, err)
		}
		return err
	}
	s.watchBuildErr = ""
	return nil
}

// rebuildWatcherLocked replaces the watcher with one built for shape. The previous watcher is
// dropped first, so a failure leaves none. Queued content is dropped as well: the new watcher
// re-observes every transcript it still tails, under the consent it now holds.
func (s *Service) rebuildWatcherLocked(p consent.Policy, shape watchShape) error {
	s.watcher, s.watchShapeSet = nil, false
	if s.content != nil {
		s.content.dropAll()
	}
	if len(shape.records) == 0 {
		s.watchShape, s.watchShapeSet = shape, true
		s.logf("consent policy version %d consents to no transcript root; transcript capture is idle", p.Version)
		return nil
	}
	gens := shape.generations()
	sink := &consentSink{inner: s.sink, fence: s.fence, generations: gens}
	var obs codex.ContentObserver
	if shape.content {
		obs = consentContentObserver{u: s.content, generations: gens}
	}
	cfg := *s.watchCfg
	cfg.RootPolicies = shape.records
	w, err := s.buildWatcher(&cfg, sink, obs)
	if err != nil {
		return err
	}
	s.watcher, s.watchShape, s.watchShapeSet = w, shape, true
	s.logf("transcript watcher applied consent policy version %d: tailing %d consented roots; content upload %s", p.Version, len(gens), onOff(shape.content))
	s.noteUnavailableContentLocked(p)
	return nil
}

// noteUnavailableContentLocked logs, once per grant, that the policy consents to content upload but
// this daemon was started without a collector, so nothing will be uploaded.
func (s *Service) noteUnavailableContentLocked(p consent.Policy) {
	granted := p.ContentUpload && s.content == nil
	if granted && !s.contentUnavailableNoted {
		s.logf("consent policy version %d consents to content upload, but this daemon has no -collector: content upload stays off", p.Version)
	}
	s.contentUnavailableNoted = granted
}

// recordShutdownConsent writes (or rewrites) the consent fence's shutdown record against the spool's
// durable ceiling.
func (s *Service) recordShutdownConsent() error {
	snap, err := s.spool.Health()
	if err != nil {
		return fmt.Errorf("spool health: %w", err)
	}
	return s.fence.recordShutdown(snap.HighestDurable)
}

// consentContentObserver is the watcher's content observer under a live consent policy. Each
// watcher build gets its own, stamping every observation with the consent generation its root had
// when the watcher was built, so content observed under consent that is later withdrawn or
// re-registered is never uploaded under the new consent.
type consentContentObserver struct {
	u           *contentUploader
	generations map[string]uint64
}

var _ codex.ContentObserver = consentContentObserver{}

// ObserveContent records an observation under its consent origin.
func (o consentContentObserver) ObserveContent(_ context.Context, obs codex.ContentObservation) {
	gen, ok := o.generations[obs.ConsentRoot]
	if !ok {
		return
	}
	o.u.observe(consentOrigin{root: obs.ConsentRoot, generation: gen}, obs)
}

// ForgetContent releases a transcript the watcher dropped.
func (o consentContentObserver) ForgetContent(device, inode uint64) {
	o.u.ForgetContent(device, inode)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
