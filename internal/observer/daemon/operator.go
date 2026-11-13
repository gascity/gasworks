//go:build linux || darwin

package daemon

import (
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/operatorfile"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// S10 M3: the sink stamps the bd-login operator (gasworks-platform attribution.md r2 §2.1) on the
// SESSION_LIFECYCLE starts it delivers.
//
//   - Only a LIVE start is stamped: one captured within operatorLiveWindow of the session's first
//     record. A start the watcher reaches later (a backlog, a daemon that was down) is of a session
//     whose login at the time nobody knows, so it carries no operator.
//   - A STARTED carries the operator only when the login began no later than the session's first
//     record (principal_since). A login that began after it is reported as {principal_id:"",
//     not_at_start:true}: the session was not started by that login.
//   - A logout reads principal_id "".
//   - The first operator per native session wins: a later STARTED of the same session (a subagent
//     transcript, a re-read) carries none. A RESUMED carries the then-current operator.
//   - No file (or a malformed one) is no operator member at all: the run's human is "not reported".

// operatorLiveWindow bounds how long after a session's first record its start still counts as live.
const operatorLiveWindow = 5 * time.Minute

// OperatorSource supplies the current bd-login operator reading (satisfied by *operatorfile.File).
type OperatorSource interface {
	Current() (operatorfile.Snapshot, bool)
}

// operatorFor returns the operator to stamp on a SESSION_LIFECYCLE start of native whose first record
// is at firstRecord, captured at capturedAt; nil stamps none.
func (a *CandidateSinkAdapter) operatorFor(native string, transition wire.SessionLifecyclePayloadTransition, firstRecord, capturedAt time.Time) *wire.SessionOperator {
	if a.operator == nil || native == "" {
		return nil
	}
	if transition != wire.SessionLifecyclePayloadTransitionSTARTED && transition != wire.SessionLifecyclePayloadTransitionRESUMED {
		return nil
	}
	if age := capturedAt.Sub(firstRecord); age > operatorLiveWindow || age < -operatorLiveWindow {
		return nil
	}
	if transition == wire.SessionLifecyclePayloadTransitionSTARTED {
		a.sessionMu.Lock()
		stamped := a.operatorStamped[native]
		a.sessionMu.Unlock()
		if stamped {
			return nil
		}
	}
	snap, ok := a.operator.Current()
	if !ok {
		return nil
	}
	op := &wire.SessionOperator{ReportedBy: wire.SessionOperatorReportedByBDLOGINFILE}
	switch {
	case snap.LoggedOut():
		op.PrincipalId = ""
	case transition == wire.SessionLifecyclePayloadTransitionSTARTED && snap.PrincipalSince.After(firstRecord):
		notAtStart := true
		op.PrincipalId, op.NotAtStart = "", &notAtStart
	default:
		class := wire.SessionOperatorPrincipalClass(snap.PrincipalClass)
		since := snap.PrincipalSince
		op.PrincipalId, op.PrincipalClass, op.PrincipalSince = snap.PrincipalID, &class, &since
	}
	return op
}

// stampOperator sets the operator on a SESSION_LIFECYCLE candidate about to be delivered.
func (a *CandidateSinkAdapter) stampOperator(native string, cand *codex.Candidate, capturedAt time.Time) {
	if cand.Kind != codex.KindSessionLifecycle || cand.SessionLifecycle == nil {
		return
	}
	cand.SessionLifecycle.Operator = a.operatorFor(native, cand.SessionLifecycle.Transition, cand.OccurredAt, capturedAt)
}

// recordOperatorStamped remembers that native's start carried an operator (first one wins).
func (a *CandidateSinkAdapter) recordOperatorStamped(native string, cand *codex.Candidate) {
	if cand.Kind != codex.KindSessionLifecycle || cand.SessionLifecycle == nil || cand.SessionLifecycle.Operator == nil {
		return
	}
	if cand.SessionLifecycle.Transition != wire.SessionLifecyclePayloadTransitionSTARTED {
		return
	}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	a.operatorStamped[native] = true
}
