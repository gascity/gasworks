//go:build linux

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// sessionCandidateProvider is a SESSION_LIFECYCLE candidate carrying an explicit provider, so the
// provider-threading and multi-provider tests can drive a Claude session through a Codex-default sink.
func sessionCandidateProvider(nativeID, provider, model string) *codex.Candidate {
	return &codex.Candidate{
		Kind:       codex.KindSessionLifecycle,
		OccurredAt: testBase,
		SessionLifecycle: &evidence.SessionLifecycleCandidate{
			NativeSessionID: nativeID,
			Provider:        provider,
			StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
			Transition:      wire.SessionLifecyclePayloadTransitionSTARTED,
			Model:           model,
		},
	}
}

func newSinkWithResolver(t *testing.T, client *local.Client, resolver sessionRunResolver) *CandidateSinkAdapter {
	t.Helper()
	sink, err := NewCandidateSinkAdapter(SinkConfig{
		Client:           client,
		Policy:           metadataOnlyPolicy(),
		Provider:         "codex",
		ParserVersion:    codex.ParserVersion,
		TransformVersion: "codex-transform-v1",
		Now:              func() time.Time { return testBase },
		RunResolver:      resolver,
	})
	if err != nil {
		t.Fatalf("NewCandidateSinkAdapter: %v", err)
	}
	return sink
}

// TestSinkStampsRunContextForBoundSession is the explicit-run usage-binding guard: once a native
// session is bound to a run (the wrapper's BindSession), the sink must stamp run_context.run_id onto
// that session's USAGE (and SESSION) observations, so the explicit `run -work-item <bead>` carries
// the child agent session's real cost on the bead's run — natively, no manual attach step. An
// UNBOUND session's USAGE must carry NO run_context (passive capture is unchanged).
func TestSinkStampsRunContextForBoundSession(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	reg := NewRegistry("src_test", "ws_main")
	srv := startDaemonServer(t, dir, w, reg)
	client := local.NewClient(srv.SocketPath())
	sink := newSinkWithResolver(t, client, reg)

	const nativeID = "019f8229-42ff-72c1-8c28-45f6936bf0d2"
	const runID = "run_boundbead01"
	reg.BindSession(nativeID, runID)

	ref := codex.TranscriptRef{Locator: "sessions/rollout.jsonl", Device: 7, Inode: 71}
	deliver(t, sink, ref, sessionCandidate(nativeID, "gpt-5.6-sol"))
	deliver(t, sink, ref, usageCandidate(1200, 340))

	// The unbound co-resident session must stay run-context-free.
	const otherNative = "019f8229-ffff-72c1-8c28-45f6936bf0d2"
	otherRef := codex.TranscriptRef{Locator: "sessions/other.jsonl", Device: 7, Inode: 72}
	deliver(t, sink, otherRef, sessionCandidate(otherNative, "gpt-5.6-sol"))
	deliver(t, sink, otherRef, usageCandidate(10, 20))

	boundUsage, unboundUsage := 0, 0
	for _, obs := range decodeUsageObservations(t, dir) {
		switch nativeOf(obs) {
		case nativeID:
			boundUsage++
			if obs.RunContext == nil {
				t.Fatalf("bound session USAGE has no run_context; the run cannot carry its usage")
			}
			if obs.RunContext.RunId != runID {
				t.Fatalf("run_context.run_id = %q, want %q", obs.RunContext.RunId, runID)
			}
			if obs.RunContext.MembershipEvidence != wire.RunContextMembershipEvidenceDECLAREDBOUNDARY {
				t.Fatalf("membership = %q, want DECLARED_BOUNDARY", obs.RunContext.MembershipEvidence)
			}
		case otherNative:
			unboundUsage++
			if obs.RunContext != nil {
				t.Fatalf("unbound session USAGE carries a run_context %q; passive capture must not", obs.RunContext.RunId)
			}
		}
	}
	if boundUsage != 1 || unboundUsage != 1 {
		t.Fatalf("usage counts: bound=%d unbound=%d, want 1 and 1", boundUsage, unboundUsage)
	}
}

// TestSinkThreadsProviderPerTranscript proves one watcher can tail Codex and Claude roots together:
// a session's provider (from its SESSION_LIFECYCLE) is threaded onto its later session-free USAGE,
// so a Claude session's USAGE carries provider=claude even though the sink's default provider is
// codex — the platform then derives a distinct per-provider synthetic run.
func TestSinkThreadsProviderPerTranscript(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client) // default provider "codex", no resolver

	ref := codex.TranscriptRef{Locator: "projects/claude.jsonl", Device: 8, Inode: 81}
	deliver(t, sink, ref, sessionCandidateProvider("claude-sess-01", "claude", "claude-opus-4-8"))
	deliver(t, sink, ref, usageCandidate(500, 60))

	var sawUsage bool
	for _, obs := range decodeUsageObservations(t, dir) {
		sawUsage = true
		if obs.Provenance.Provider == nil || *obs.Provenance.Provider != "claude" {
			t.Fatalf("USAGE provenance.provider = %v, want claude (threaded from the session record)", obs.Provenance.Provider)
		}
	}
	if !sawUsage {
		t.Fatalf("no USAGE observation found")
	}
}

// TestSinkDeDupsSessionLifecycle proves the sink appends a transcript's SESSION_LIFECYCLE exactly
// once even when the parser re-synthesizes it every poll (Claude's session id recurs on every
// envelope, so its STARTED record is re-emitted). Duplicates are threaded but not re-appended.
func TestSinkDeDupsSessionLifecycle(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client)

	const nativeID = "claude-sess-dedup"
	ref := codex.TranscriptRef{Locator: "projects/claude.jsonl", Device: 9, Inode: 91}
	// The same STARTED session record delivered across three "polls".
	deliver(t, sink, ref, sessionCandidateProvider(nativeID, "claude", "claude-opus-4-8"))
	deliver(t, sink, ref, sessionCandidateProvider(nativeID, "claude", "claude-opus-4-8"))
	deliver(t, sink, ref, sessionCandidateProvider(nativeID, "claude", "claude-opus-4-8"))
	// A usage record must still be threaded onto the (de-duplicated) session.
	deliver(t, sink, ref, usageCandidate(1, 1))

	sessions, usages := 0, 0
	for _, fr := range readWAL(t, dir) {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			t.Fatalf("decode observation: %v", err)
		}
		kind, err := obs.Discriminator()
		if err != nil {
			t.Fatalf("discriminator: %v", err)
		}
		switch kind {
		case string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE):
			sessions++
		case string(wire.ObservationEnvelopeKindUSAGE):
			usages++
		}
	}
	if sessions != 1 {
		t.Fatalf("SESSION_LIFECYCLE observations = %d, want 1 (de-duplicated across polls)", sessions)
	}
	if usages != 1 {
		t.Fatalf("USAGE observations = %d, want 1", usages)
	}
}

func deliver(t *testing.T, sink *CandidateSinkAdapter, ref codex.TranscriptRef, cand *codex.Candidate) {
	t.Helper()
	if err := sink.DeliverCandidates(context.Background(), ref, []*codex.Candidate{cand}); err != nil {
		t.Fatalf("DeliverCandidates: %v", err)
	}
}

func decodeUsageObservations(t *testing.T, dir string) []wire.UsageObservation {
	t.Helper()
	var out []wire.UsageObservation
	for _, fr := range readWAL(t, dir) {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			t.Fatalf("decode observation: %v", err)
		}
		kind, err := obs.Discriminator()
		if err != nil {
			t.Fatalf("discriminator: %v", err)
		}
		if kind != string(wire.ObservationEnvelopeKindUSAGE) {
			continue
		}
		u, err := obs.AsUsageObservation()
		if err != nil {
			t.Fatalf("AsUsageObservation: %v", err)
		}
		out = append(out, u)
	}
	return out
}

func nativeOf(obs wire.UsageObservation) string {
	if obs.Provenance.NativeSessionId == nil {
		return ""
	}
	return *obs.Provenance.NativeSessionId
}

// TestRegistryBindSessionLookup covers the session→run index directly: an unbound session is a
// clean miss, a bound one resolves to its run, a rebind wins, and empty ids are ignored.
func TestRegistryBindSessionLookup(t *testing.T) {
	reg := NewRegistry("src_test", "ws_main")

	if _, ok := reg.LookupSessionRun("sess-a"); ok {
		t.Fatalf("unbound session resolved; want miss")
	}
	reg.BindSession("sess-a", "run_1")
	if runID, ok := reg.LookupSessionRun("sess-a"); !ok || runID != "run_1" {
		t.Fatalf("LookupSessionRun(sess-a) = (%q, %v), want (run_1, true)", runID, ok)
	}
	// A rebind (a session id reused, or a later wrapper association) wins.
	reg.BindSession("sess-a", "run_2")
	if runID, _ := reg.LookupSessionRun("sess-a"); runID != "run_2" {
		t.Fatalf("after rebind LookupSessionRun(sess-a) = %q, want run_2", runID)
	}
	// Empty ids are no-ops.
	reg.BindSession("", "run_x")
	reg.BindSession("sess-b", "")
	if _, ok := reg.LookupSessionRun("sess-b"); ok {
		t.Fatalf("empty run bound a session; want ignored")
	}
}
