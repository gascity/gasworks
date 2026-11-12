//go:build linux

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/operatorfile"
	"github.com/gascity/gasworks/internal/observer/wire"
)

const opUser = "usr_01a19b2a-9bbb-79e6-b877-0f48ad23f928"

// fakeOperator is a fixed operator-file reading.
type fakeOperator struct {
	snap operatorfile.Snapshot
	ok   bool
}

func (f *fakeOperator) Current() (operatorfile.Snapshot, bool) { return f.snap, f.ok }

func operatorSink(t *testing.T, client *local.Client, src OperatorSource, now *time.Time) *CandidateSinkAdapter {
	t.Helper()
	sink, err := NewCandidateSinkAdapter(SinkConfig{
		Client:           client,
		Policy:           metadataOnlyPolicy(),
		Provider:         "claude",
		ParserVersion:    codex.ParserVersion,
		TransformVersion: "codex-transform-v1",
		Now:              func() time.Time { return *now },
		Operator:         src,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sink
}

func startCandidate(native string, transition wire.SessionLifecyclePayloadTransition, firstRecord time.Time) *codex.Candidate {
	source := wire.SessionLifecyclePayloadStartSourceSTARTUP
	if transition == wire.SessionLifecyclePayloadTransitionRESUMED {
		source = wire.SessionLifecyclePayloadStartSourceRESUME
	}
	return &codex.Candidate{
		Kind:       codex.KindSessionLifecycle,
		OccurredAt: firstRecord,
		SessionLifecycle: &evidence.SessionLifecycleCandidate{
			NativeSessionID: native, Provider: "claude", StartSource: source, Transition: transition,
		},
	}
}

// lastOperator delivers cand and returns the operator on the SESSION_LIFECYCLE observation it
// appended (nil when none).
func lastOperator(t *testing.T, sink *CandidateSinkAdapter, dir string, ref codex.TranscriptRef, cand *codex.Candidate) *wire.SessionOperator {
	t.Helper()
	if err := sink.DeliverCandidates(context.Background(), ref, []*codex.Candidate{cand}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	frames := readWAL(t, dir)
	var obs wire.Observation
	if err := obs.UnmarshalJSON(frames[len(frames)-1].Payload); err != nil {
		t.Fatal(err)
	}
	sl, err := obs.AsSessionLifecycleObservation()
	if err != nil {
		t.Fatal(err)
	}
	return sl.SessionLifecycle.Operator
}

// TestSinkStampsTheOperatorOnLiveStarts (S10 M3 acceptance 4, fixed clock): a live STARTED carries the
// login whose principal_since is not after the session's first record; a newer login reads
// not_at_start; a start captured past the live window carries none; the first operator per native
// session wins; a RESUMED carries the then-current login; a logout reads "".
func TestSinkStampsTheOperatorOnLiveStarts(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	first := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	now := first.Add(30 * time.Second)
	src := &fakeOperator{ok: true, snap: operatorfile.Snapshot{PrincipalID: opUser, PrincipalClass: "USER", PrincipalSince: first.Add(-time.Hour)}}
	sink := operatorSink(t, client, src, &now)
	ref := codex.TranscriptRef{Locator: "claude/a.jsonl", Device: 1, Inode: 1}

	op := lastOperator(t, sink, dir, ref, startCandidate("sess-1", wire.SessionLifecyclePayloadTransitionSTARTED, first))
	if op == nil || op.PrincipalId != opUser || op.PrincipalClass == nil || *op.PrincipalClass != wire.SessionOperatorPrincipalClassUSER ||
		op.ReportedBy != wire.SessionOperatorReportedByBDLOGINFILE || op.PrincipalSince == nil || op.NotAtStart != nil {
		t.Fatalf("live start operator = %+v", op)
	}
	// First wins: the same session's second STARTED (a subagent transcript) carries none.
	ref2 := codex.TranscriptRef{Locator: "claude/a-sub.jsonl", Device: 1, Inode: 2}
	if op := lastOperator(t, sink, dir, ref2, startCandidate("sess-1", wire.SessionLifecyclePayloadTransitionSTARTED, first)); op != nil {
		t.Fatalf("second start of the session carried %+v", op)
	}

	// A login newer than the session's first record: not_at_start.
	src.snap.PrincipalSince = first.Add(time.Minute)
	op = lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "b", Device: 1, Inode: 3}, startCandidate("sess-2", wire.SessionLifecyclePayloadTransitionSTARTED, first))
	if op == nil || op.PrincipalId != "" || op.NotAtStart == nil || !*op.NotAtStart || op.PrincipalClass != nil {
		t.Fatalf("not-at-start operator = %+v", op)
	}

	// A RESUMED carries the then-current login, whenever it began.
	op = lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "c", Device: 1, Inode: 4}, startCandidate("sess-2", wire.SessionLifecyclePayloadTransitionRESUMED, first))
	if op == nil || op.PrincipalId != opUser || op.NotAtStart != nil {
		t.Fatalf("resumed operator = %+v", op)
	}

	// A start captured past the live window (a backlog) carries none.
	now = first.Add(6 * time.Minute)
	if op := lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "d", Device: 1, Inode: 5}, startCandidate("sess-3", wire.SessionLifecyclePayloadTransitionSTARTED, first)); op != nil {
		t.Fatalf("backlog start carried %+v", op)
	}

	// A logout reads "".
	now = first.Add(time.Minute)
	src.snap = operatorfile.Snapshot{}
	op = lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "e", Device: 1, Inode: 6}, startCandidate("sess-4", wire.SessionLifecyclePayloadTransitionSTARTED, first))
	if op == nil || op.PrincipalId != "" || op.NotAtStart != nil {
		t.Fatalf("logged-out operator = %+v", op)
	}

	// No file: no operator member at all.
	src.ok = false
	if op := lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "f", Device: 1, Inode: 7}, startCandidate("sess-5", wire.SessionLifecyclePayloadTransitionSTARTED, first)); op != nil {
		t.Fatalf("no file stamped %+v", op)
	}
}

// TestSinkWithoutOperatorSourceStampsNothing: a daemon without -operator-file captures as before.
func TestSinkWithoutOperatorSourceStampsNothing(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	sink := operatorSink(t, local.NewClient(srv.SocketPath()), nil, &now)
	if op := lastOperator(t, sink, dir, codex.TranscriptRef{Locator: "a", Device: 1, Inode: 1}, startCandidate("sess-1", wire.SessionLifecyclePayloadTransitionSTARTED, now)); op != nil {
		t.Fatalf("stamped %+v without a source", op)
	}
}
