//go:build linux

// Package daemon is the endpoint's wiring layer above the owner-only local socket (E1.5) and the
// vendored evidence/wire/codex contracts. It owns the daemon-side boundary/ancestry projection
// (Registry) and the two seam adapters that let the committed Codex hook (E1.7) and transcript
// watcher (E1.8) reach the local daemon: a DaemonSeamAdapter (codex.DaemonSeam over a
// local.Client) and a CandidateSinkAdapter (codex.CandidateSink over a local.Client).
//
// It sits ABOVE the closure boundary the codex adapter deliberately keeps: the codex package
// depends only on stdlib plus the vendored evidence/wire contract and never imports
// internal/observer/local. The daemon package is allowed to import both, so it is the single place
// the hook/watcher seams are wired onto the socket client.
package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// walSubdirName and segmentExt mirror the local spool's on-disk layout: durable segments live
// under <dir>/wal as ascending zero-padded .seg files. ReplayWAL reads them to rebuild the
// projection on boot.
const (
	walSubdirName = "wal"
	segmentExt    = ".seg"
)

// Registry is the daemon's in-memory projection of two indexes, folded from observations as they
// are durably appended and rebuilt by replaying the WAL on boot:
//
//   - the registered-ancestor index: a map from a wrapper-registered OS process identity
//     (boot_id, pid, process_start_time) to the run it opened, folded from
//     PROCESS_LIFECYCLE{REGISTERED};
//   - the run-boundary index: a per-run {open|closed, workspace, source} record, folded from
//     RUN_STARTED (opens) and RUN_ENDED (closes); closure is terminal, so a later RUN_STARTED
//     never reopens a run that RUN_ENDED already closed.
//
// It is judgment-free: a pure fold plus two total lookups, with no role logic and no heuristics.
// source and workspace are the daemon's installation scope, injected once at construction and
// stamped onto every run boundary it folds. The whole registry belongs to one source, so a run
// present in the boundary index is same-source by construction, and a run id authored by another
// source is simply absent (classified InheritedRunUnknown) — matching the endpoint's rule that an
// inherited id from another source/workspace is quarantined.
//
// It is safe for concurrent use: the socket server folds appends and answers queries from bounded
// goroutines, so every method takes the same mutex.
type Registry struct {
	mu         sync.Mutex
	source     string
	workspace  string
	registered map[wire.ProcessIdentity]string
	boundaries map[string]runBoundary
}

// runBoundary is one run's folded boundary record: its open/closed state plus the workspace and
// source scope in effect when it was folded.
type runBoundary struct {
	open      bool
	workspace string
	source    string
}

// NewRegistry returns an empty registry scoped to one installation source and workspace. The scope
// is stamped onto every run boundary it folds and is what a later ResolveInherited compares a
// caller's workspace against.
func NewRegistry(source, workspace string) *Registry {
	return &Registry{
		source:     source,
		workspace:  workspace,
		registered: make(map[wire.ProcessIdentity]string),
		boundaries: make(map[string]runBoundary),
	}
}

// Fold projects one observation into the two indexes. It recognizes exactly
// PROCESS_LIFECYCLE{REGISTERED}, RUN_STARTED, and RUN_ENDED; every other observation is ignored.
// It ignores the observation's sequence and observation id — which the single-writer spool
// re-stamps — so folding a producer's pre-seal observation on the append path and replaying the
// WAL's re-stamped frame on boot converge on the same registry. A structurally malformed union is
// returned as an error so the boot-replay path can surface it; the live append path treats a fold
// error as a projection bug, not an append failure.
func (r *Registry) Fold(obs wire.Observation) error {
	kind, err := obs.Discriminator()
	if err != nil {
		return fmt.Errorf("observer daemon: registry read observation kind: %w", err)
	}
	switch kind {
	case string(wire.ObservationEnvelopeKindPROCESSLIFECYCLE):
		return r.foldProcessLifecycle(obs)
	case string(wire.ObservationEnvelopeKindRUNBOUNDARY):
		return r.foldRunBoundary(obs)
	default:
		return nil
	}
}

// foldProcessLifecycle indexes a REGISTERED frame's process identity to the run the wrapper
// stamped on it. Any other process transition (PROCESS_EXITED / PROCESS_LAUNCH_FAILED) is not an
// ancestry registration and is ignored. A REGISTERED frame with no stamped run context has no run
// to map to, so its identity is not indexed.
func (r *Registry) foldProcessLifecycle(obs wire.Observation) error {
	pl, err := obs.AsProcessLifecycleObservation()
	if err != nil {
		return fmt.Errorf("observer daemon: registry decode process lifecycle: %w", err)
	}
	if pl.ProcessLifecycle.Transition != wire.ProcessLifecyclePayloadTransitionREGISTERED {
		return nil
	}
	if pl.RunContext == nil || pl.RunContext.RunId == "" {
		return nil
	}
	r.mu.Lock()
	r.registered[pl.ProcessLifecycle.ProcessIdentity] = pl.RunContext.RunId
	r.mu.Unlock()
	return nil
}

// foldRunBoundary opens a run's boundary on RUN_STARTED and closes it on RUN_ENDED. Closure is
// TERMINAL: once a run is closed it can never reopen, so a later (stale, duplicate, or reordered)
// RUN_STARTED for a closed run id is ignored rather than resurrecting it. A RUN_ENDED that arrives
// without a folded RUN_STARTED (a compacted or partial WAL) records a closed boundary under the
// registry scope rather than inventing an open one. The two guards are symmetric: neither a
// late RUN_STARTED nor a torn-WAL RUN_ENDED can produce a false OPEN.
func (r *Registry) foldRunBoundary(obs wire.Observation) error {
	rb, err := obs.AsRunBoundaryObservation()
	if err != nil {
		return fmt.Errorf("observer daemon: registry decode run boundary: %w", err)
	}
	transition, err := rb.RunBoundary.Discriminator()
	if err != nil {
		return fmt.Errorf("observer daemon: registry read boundary transition: %w", err)
	}
	switch transition {
	case string(wire.RunStartedBoundaryTransitionRUNSTARTED):
		started, err := rb.RunBoundary.AsRunStartedBoundary()
		if err != nil {
			return fmt.Errorf("observer daemon: registry decode run started: %w", err)
		}
		if started.RunId == "" {
			return nil
		}
		r.mu.Lock()
		// Latch closure: a RUN_STARTED for a run whose boundary is already CLOSED must not reopen it.
		// Otherwise a stale/reused inherited GASWORKS_RUN_ID (or an at-least-once duplicate
		// RUN_STARTED re-appended after RUN_ENDED, which folds after the close on replay) would flip
		// the run back to OPEN and let an inheriting session attach HIGH to a run the spec says was
		// permanently closed — the worst false-merge. An already-OPEN run may idempotently re-open.
		if b, ok := r.boundaries[started.RunId]; ok && !b.open {
			r.mu.Unlock()
			return nil
		}
		r.boundaries[started.RunId] = runBoundary{open: true, workspace: r.workspace, source: r.source}
		r.mu.Unlock()
	case string(wire.RunEndedBoundaryTransitionRUNENDED):
		ended, err := rb.RunBoundary.AsRunEndedBoundary()
		if err != nil {
			return fmt.Errorf("observer daemon: registry decode run ended: %w", err)
		}
		if ended.RunId == "" {
			return nil
		}
		r.mu.Lock()
		b, ok := r.boundaries[ended.RunId]
		if !ok {
			b = runBoundary{workspace: r.workspace, source: r.source}
		}
		b.open = false
		r.boundaries[ended.RunId] = b
		r.mu.Unlock()
	}
	return nil
}

// LookupRegistered reports whether id was registered by a wrapper (folded from a
// PROCESS_LIFECYCLE{REGISTERED}) and, if so, the run it opened. A miss returns found=false, never
// an error — a queried process that is not a registered wrapper is the ordinary case.
func (r *Registry) LookupRegistered(id wire.ProcessIdentity) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	runID, found := r.registered[id]
	return runID, found
}

// ResolveInherited classifies how runID resolves against this source's boundary index:
//
//   - absent from the index          -> InheritedRunUnknown (also covers a run id from another
//     source, which is simply not folded here);
//   - present but closed             -> InheritedRunClosed;
//   - present, open, same workspace  -> InheritedRunOpenSameScope (the only trustworthy proof);
//   - present, open, other workspace -> InheritedRunCrossWorkspace.
//
// Source scoping is implicit: the registry is one source, so a present run is same-source and an
// absent one is unknown. The workspace comparison is exact against the run's recorded scope.
func (r *Registry) ResolveInherited(runID, workspace string) local.InheritedRunStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.boundaries[runID]
	if !ok {
		return local.InheritedRunUnknown
	}
	if !b.open {
		return local.InheritedRunClosed
	}
	if b.workspace == workspace {
		return local.InheritedRunOpenSameScope
	}
	return local.InheritedRunCrossWorkspace
}

// Registry satisfies the socket server's projection seam.
var _ local.Registry = (*Registry)(nil)

// ReplayWAL rebuilds reg by folding every observation durably recorded in the WAL under dir, in
// segment (sequence) order, so a daemon restart reconstructs the same boundary/ancestry projection
// it held before. It is the boot path: run it once, before the socket server starts folding live
// appends. An un-created WAL is an empty projection, not an error.
func ReplayWAL(dir string, reg *Registry) error {
	walDir := filepath.Join(dir, walSubdirName)
	entries, err := os.ReadDir(walDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("observer daemon: list wal dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == segmentExt {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if err := replaySegment(filepath.Join(walDir, name), reg); err != nil {
			return err
		}
	}
	return nil
}

// replaySegment opens one WAL segment, decodes each canonical frame payload back into a typed
// observation, and folds it. The segment is closed before returning.
func replaySegment(path string, reg *Registry) error {
	seg, err := spool.OpenSegment(path, spool.SegmentOptions{})
	if err != nil {
		return fmt.Errorf("observer daemon: open wal segment: %w", err)
	}
	frames, err := seg.ReadAll()
	if cerr := seg.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("observer daemon: read wal segment: %w", err)
	}
	for _, fr := range frames {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			return fmt.Errorf("observer daemon: decode wal frame: %w", err)
		}
		if err := reg.Fold(obs); err != nil {
			return err
		}
	}
	return nil
}
