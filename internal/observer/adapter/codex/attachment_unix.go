//go:build unix

// Package codex implements the first Observer capture adapter: the Codex SessionStart hook
// decoder and its attachment ledger (E1.7). The adapter turns a Codex SessionStart hook event
// into exactly one durable SESSION_LIFECYCLE observation, and decides — from causal evidence
// only — which run that native session attaches to.
//
// The adapter depends on the endpoint daemon through a narrow DaemonSeam interface, never on
// internal/observer/local directly: E1.10 wires local.Client into the seam, and tests use a
// fake. The adapter's whole dependency closure is the standard library plus the vendored,
// self-contained internal/observer/{evidence,wire} contract — no Gas City, no telemetry axes.
//
// This file owns the membership decision. It maps a decoded SessionStart onto the spec's
// "Boundary and membership rules" table (docs/design/gasworks-observer-mvp.md): the two
// HIGH-confidence attachment proofs (a resolvable inherited run id, or exact process lineage),
// the QUARANTINE cases that take precedence over any attachment, and the passive INFERRED run
// derived deterministically from the native session identity.
package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// ---- daemon seam ----

// CaptureAck is the daemon's durable acknowledgement of an appended observation: the sequence
// the single-writer WAL assigned, returned only after the fsync. The adapter needs no more of
// the ack than proof that capture is durable.
type CaptureAck struct {
	Sequence int64
}

// RegisteredAncestor is a wrapper-registered process identity and the run it opened. The E1.6
// wrapper publishes it with a durable PROCESS_LIFECYCLE{REGISTERED} append; the ancestry index
// returns it when a queried (boot_id, pid, process_start_time) matches.
type RegisteredAncestor struct {
	Identity wire.ProcessIdentity
	RunID    string
}

// InheritedStatus classifies how an inherited GASWORKS_RUN_ID resolves against THIS source's
// durable boundary index. Only InheritedOpenSameScope is trustworthy; every other status is a
// quarantine input (the spec: "An inherited run ID is unknown, closed, belongs to another
// source/workspace ... Quarantine").
type InheritedStatus int

const (
	// InheritedUnknown means the run id is not present in this source's boundary index. A run id
	// authored by another Observer source/installation is simply unknown here, so this status
	// also covers the cross-source case.
	InheritedUnknown InheritedStatus = iota
	// InheritedOpenSameScope means the run id resolves to a durable OPEN boundary from the same
	// source AND the same workspace as the hook — the only trustworthy inherited-id status.
	InheritedOpenSameScope
	// InheritedClosed means the run id is known but its boundary was already closed by RUN_ENDED.
	InheritedClosed
	// InheritedCrossWorkspace means the run id resolves to an OPEN boundary in this source but a
	// different workspace than the hook's.
	InheritedCrossWorkspace
)

// InheritedResolution is the boundary index's answer for an inherited run id. The daemon owns
// the boundary index and the source/workspace scoping, so it performs the same-source and
// same-workspace comparison and returns the classified status.
type InheritedResolution struct {
	Status InheritedStatus
}

// DaemonSeam is the narrow dependency the Codex adapter has on the endpoint daemon (the E1.5
// owner-only socket and the E1.6 wrapper's process-ancestry / boundary indexes). E1.10 wires
// internal/observer/local.Client to it; tests use a fake. The adapter never imports
// internal/observer/local, which keeps its dependency closure to stdlib + evidence/wire.
type DaemonSeam interface {
	// CaptureSessionLifecycle durably appends the SESSION_LIFECYCLE observation and returns only
	// after the local WAL fsync ack. A non-nil error means capture is NOT durable, and the hook
	// must surface its bounded capture-failure systemMessage rather than pretend success.
	CaptureSessionLifecycle(ctx context.Context, obs PendingObservation) (CaptureAck, error)

	// LookupRegisteredProcess reports whether id was registered by a wrapper (E1.6
	// PROCESS_LIFECYCLE{REGISTERED}) and, if so, the run it opened. found=false is the ordinary
	// "not a wrapper" answer, not an error; err is reserved for a transport/query failure.
	LookupRegisteredProcess(ctx context.Context, id wire.ProcessIdentity) (ancestor RegisteredAncestor, found bool, err error)

	// ResolveInheritedRun classifies how runID resolves in THIS source's boundary index, using
	// workspace to perform the same-workspace comparison against the boundary's recorded
	// workspace. A transport/query failure returns err; a definite classification returns a
	// status with a nil error.
	ResolveInheritedRun(ctx context.Context, runID, workspace string) (InheritedResolution, error)
}

// PendingObservation is the pre-sequence observation the daemon seals and appends. It aliases
// the evidence constructor's type through a package-local name so callers reading this file see
// the seam surface without reaching into the evidence package name. See attachment/hook code
// for how it is produced (evidence.Policy.TransformSessionLifecycle).
//
// It is declared in hook_unix.go via a type alias to evidence.PendingObservation.

// ---- decision model ----

// Disposition is the attachment-interval outcome for a decoded SessionStart.
type Disposition int

const (
	// DispositionWithinSession is a clear/compact event: lifecycle evidence within the current
	// native session that does NOT open an interval or reassign run membership.
	DispositionWithinSession Disposition = iota
	// DispositionAttachHigh is a startup/resume that attached to an explicit run with a
	// HIGH-confidence proof (a resolvable inherited run id or exact process lineage).
	DispositionAttachHigh
	// DispositionInferred is a startup/resume with neither proof: a passive session that belongs
	// to its own deterministic synthetic run. The durable observation carries NO run context;
	// the Builder re-derives the same synthetic id from (source_id, provider, native_session_id).
	DispositionInferred
	// DispositionQuarantine is a startup/resume whose inherited run id was refused. The
	// association is never trusted; it surfaces only as a projection diagnostic and the durable
	// observation carries no run context.
	DispositionQuarantine
)

// QuarantineReason classifies why an inherited run id was refused. It drives the projection
// diagnostic; it never authorizes a merge.
type QuarantineReason int

const (
	// QuarantineNone is the zero value: no quarantine.
	QuarantineNone QuarantineReason = iota
	// QuarantineUnknownRunID: the run id is not in this source's index (covers cross-source).
	QuarantineUnknownRunID
	// QuarantineClosedRun: the run id resolves to a boundary already closed by RUN_ENDED.
	QuarantineClosedRun
	// QuarantineCrossWorkspace: the run id resolves to an OPEN boundary in a different workspace.
	QuarantineCrossWorkspace
	// QuarantineLineageConflict: the inherited run id disagrees with the nearest proven process
	// ancestor's run id.
	QuarantineLineageConflict
)

// Decision is the membership decision for one SessionStart. For AttachHigh it carries the run
// id and the membership evidence the daemon stamps onto the observation; for Inferred it
// carries the derived synthetic run id (observable for diagnostics and tests, though the
// passive observation itself stays run-context-free); for Quarantine it carries the reason.
type Decision struct {
	Disposition   Disposition
	Transition    wire.SessionLifecyclePayloadTransition
	OpensInterval bool
	// RunID is the attached run (AttachHigh) or the derived synthetic run (Inferred). It is
	// empty for Quarantine (never trusted) and WithinSession.
	RunID string
	// Membership is the evidence stamped on the run context; set only for AttachHigh.
	Membership wire.RunContextMembershipEvidence
	// Quarantine is the refusal reason; set only for Quarantine.
	Quarantine QuarantineReason
	// ProofUnavailable records that a HIGH proof could not be evaluated because a seam query
	// failed, so the session degraded to Inferred. It is surfaced (not swallowed) so the
	// projection can distinguish a transient degrade from a genuinely passive session.
	ProofUnavailable bool
}

// AttachInput is the causal evidence the decision consumes for one SessionStart.
type AttachInput struct {
	SourceID        string
	Provider        string
	NativeSessionID string
	// Workspace is the hook's workspace token (a configured id or root-relative value), used
	// only for the same-workspace comparison at the daemon; it is never emitted on the wire.
	Workspace   string
	StartSource wire.SessionLifecyclePayloadStartSource
	// InheritedRunID is the resolved GASWORKS_RUN_ID, or "" when the hook inherited none.
	InheritedRunID string
	// HookPID is the pid whose ancestry proves (or fails to prove) exact process lineage.
	HookPID int
}

// Decide applies the spec's boundary-and-membership rules to one SessionStart. It is total: a
// seam query failure never fails the decision, it degrades to a separate INFERRED run (the
// spec: "membership falls back to a separate inferred run when proof is unavailable"), with
// ProofUnavailable set so the degrade is observable. Quarantine outcomes take precedence over
// attachment, matching the table's "Quarantine/no-merge rows take precedence" rule.
func Decide(ctx context.Context, seam DaemonSeam, in AttachInput) Decision {
	transition, opens := classifySource(in.StartSource)
	if !opens {
		// clear/compact: within-session lifecycle only; membership is unchanged.
		return Decision{Disposition: DispositionWithinSession, Transition: transition, OpensInterval: false}
	}

	if in.InheritedRunID != "" {
		res, err := seam.ResolveInheritedRun(ctx, in.InheritedRunID, in.Workspace)
		if err != nil {
			// The inherited id could not be validated. A transport failure is not proof that the
			// id is bad, so we neither trust nor quarantine it — we degrade to a separate inferred
			// run and surface the unavailability.
			return inferred(in, transition, true)
		}
		switch res.Status {
		case InheritedOpenSameScope:
			// The inherited id is trustworthy on its own. Quarantine only on POSITIVE proof of a
			// conflicting nearest ancestor; an unavailable lineage query cannot manufacture a
			// conflict, so the inherited proof stands.
			lineage, lerr := proveLineage(ctx, seam, in.HookPID)
			if lerr == nil && lineage.Attached && lineage.Nearest.RunID != in.InheritedRunID {
				return quarantine(transition, QuarantineLineageConflict)
			}
			return attach(transition, in.InheritedRunID, wire.RunContextMembershipEvidenceINHERITEDRUNID)
		case InheritedClosed:
			return quarantine(transition, QuarantineClosedRun)
		case InheritedCrossWorkspace:
			return quarantine(transition, QuarantineCrossWorkspace)
		default: // InheritedUnknown
			return quarantine(transition, QuarantineUnknownRunID)
		}
	}

	// No inherited run id: the only remaining HIGH proof is exact process lineage.
	lineage, lerr := proveLineage(ctx, seam, in.HookPID)
	if lerr != nil {
		return inferred(in, transition, true)
	}
	if lineage.Attached {
		return attach(transition, lineage.Nearest.RunID, wire.RunContextMembershipEvidencePROVENPROCESSLINEAGE)
	}
	return inferred(in, transition, false)
}

func attach(transition wire.SessionLifecyclePayloadTransition, runID string, ev wire.RunContextMembershipEvidence) Decision {
	return Decision{
		Disposition:   DispositionAttachHigh,
		Transition:    transition,
		OpensInterval: true,
		RunID:         runID,
		Membership:    ev,
	}
}

func inferred(in AttachInput, transition wire.SessionLifecyclePayloadTransition, proofUnavailable bool) Decision {
	return Decision{
		Disposition:      DispositionInferred,
		Transition:       transition,
		OpensInterval:    true,
		RunID:            SyntheticRunID(in.SourceID, in.Provider, in.NativeSessionID),
		ProofUnavailable: proofUnavailable,
	}
}

func quarantine(transition wire.SessionLifecyclePayloadTransition, reason QuarantineReason) Decision {
	return Decision{
		Disposition:   DispositionQuarantine,
		Transition:    transition,
		OpensInterval: true,
		Quarantine:    reason,
	}
}

// classifySource maps a Codex start source onto its wire transition and whether it opens an
// attachment interval. startup/resume open intervals; clear/compact are within-session
// lifecycle evidence that never reassigns membership (spec "Codex adapter").
func classifySource(s wire.SessionLifecyclePayloadStartSource) (wire.SessionLifecyclePayloadTransition, bool) {
	switch s {
	case wire.SessionLifecyclePayloadStartSourceSTARTUP:
		return wire.SessionLifecyclePayloadTransitionSTARTED, true
	case wire.SessionLifecyclePayloadStartSourceRESUME:
		return wire.SessionLifecyclePayloadTransitionRESUMED, true
	case wire.SessionLifecyclePayloadStartSourceCLEAR:
		return wire.SessionLifecyclePayloadTransitionCLEARED, false
	case wire.SessionLifecyclePayloadStartSourceCOMPACT:
		return wire.SessionLifecyclePayloadTransitionCOMPACTED, false
	default:
		// An unvalidated source should never reach here; the hook validates the enum before
		// deciding. Treat an unknown source conservatively as a non-opening lifecycle event.
		return wire.SessionLifecyclePayloadTransitionSTARTED, false
	}
}

// ---- deterministic synthetic run id ----

// SyntheticRunVersion tags the deterministic synthetic run-id derivation. It is embedded in
// BOTH the hashed personalization and the id prefix, so bumping it re-partitions synthetic runs
// and a future derivation change can never alias an old synthetic id.
const SyntheticRunVersion = "1"

// SyntheticRunID derives the deterministic, versioned run id for a passive Codex session that
// carries no daemon-stamped run id. Two passive sessions with distinct native session ids map
// to distinct runs; the same passive session always maps to the same run across replay and
// unwrapped resume.
//
// NOTE ON THE BYTE LAYOUT: this is a byte-for-byte re-derivation of the platform's canonical
// apigen.SyntheticRunID (gasworks-platform internal/observercontract/apigen). That function is
// NOT exposed through this repo's vendored wire/evidence surface, so per the task it is derived
// identically here and pinned by a golden test (TestSyntheticRunIDGolden). The S2.6 RunBuilder
// derives the same id from the evidence's (source_id, provider, native_session_id) columns; a
// drift on either side silently orphans every passive run, which the shared golden literal
// catches loudly.
func SyntheticRunID(sourceID, provider, nativeSessionID string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "observer/synthetic-run/v"+SyntheticRunVersion)
	writeSyntheticField(h, sourceID)
	writeSyntheticField(h, provider)
	writeSyntheticField(h, nativeSessionID)
	return "gwr_syn" + SyntheticRunVersion + "_" + hex.EncodeToString(h.Sum(nil))
}

// writeSyntheticField appends a little-endian 8-byte length prefix and then the field bytes, so
// no two distinct field boundaries can hash alike. This byte layout is load-bearing and pinned
// by TestSyntheticRunIDGolden.
func writeSyntheticField(h io.Writer, s string) {
	var lenbuf [8]byte
	n := len(s)
	for i := 0; i < 8; i++ {
		lenbuf[i] = byte(n >> (8 * i))
	}
	_, _ = h.Write(lenbuf[:])
	_, _ = io.WriteString(h, s)
}
