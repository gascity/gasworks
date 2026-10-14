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
// once even when the same STARTED record is delivered again (a batch re-read after a partial
// delivery failure re-delivers its line's start). Duplicates are threaded but not re-appended.
func TestSinkDeDupsSessionLifecycle(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client)

	const nativeID = "claude-sess-dedup"
	ref := codex.TranscriptRef{Locator: "projects/claude.jsonl", Device: 9, Inode: 91}
	// The same STARTED session record delivered three times.
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

// TestSinkStampsTheParsersSessionWithoutThreading is the restart half of the attribution fix: after a
// daemon restart the sink's in-memory threading is empty while the cursor resumes mid-transcript,
// past the session's start. The parser stamps each candidate with the session from the cursor's
// persisted state, and the sink must take it as provenance — and record it for the content side
// channel — without having appended that session's start itself.
func TestSinkStampsTheParsersSessionWithoutThreading(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	sink := newSink(t, local.NewClient(srv.SocketPath())) // fresh: nothing threaded, default provider codex

	ref := codex.TranscriptRef{Locator: "projects/p/agent.jsonl", Device: 8, Inode: 82}
	usage := usageCandidate(700, 90)
	usage.Session = &codex.SessionRef{NativeID: "claude-sess-resumed", Provider: "claude"}
	deliver(t, sink, ref, usage)

	usages := decodeUsageObservations(t, dir)
	if len(usages) != 1 {
		t.Fatalf("USAGE observations = %d, want 1", len(usages))
	}
	if nativeOf(usages[0]) != "claude-sess-resumed" || usages[0].Provenance.Provider == nil || *usages[0].Provenance.Provider != "claude" {
		t.Fatalf("usage provenance = %q/%v, want claude-sess-resumed/claude", nativeOf(usages[0]), usages[0].Provenance.Provider)
	}
	if native, provider, ok := sink.SessionFor(8, 82); !ok || native != "claude-sess-resumed" || provider != "claude" {
		t.Fatalf("SessionFor = %q/%q/%v, want the parser's session for the content side channel", native, provider, ok)
	}

	// The sink never appended this session's start, so a start it is later handed is appended.
	deliver(t, sink, ref, sessionCandidateProvider("claude-sess-resumed", "claude", "claude-opus-5-5"))
	starts := 0
	for _, fr := range readWAL(t, dir) {
		var obs wire.Observation
		if err := obs.UnmarshalJSON(fr.Payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if kind, _ := obs.Discriminator(); kind == string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE) {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("SESSION_LIFECYCLE observations = %d, want 1", starts)
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

// TestSinkRedeliveredLineAppendsEachRecordOnce covers the watcher's retry after a delivery failure
// part way through one transcript line: it re-delivers the whole line, so the line's leading
// candidates arrive twice. Each start and each usage must end up durable exactly once — including a
// start whose own append failed, which carries the session's model and must not be lost.
func TestSinkRedeliveredLineAppendsEachRecordOnce(t *testing.T) {
	usage := func(session, messageID string, input int64) *codex.Candidate {
		c := usageCandidate(input, 1)
		c.Usage.MessageID = messageID
		c.Session = &codex.SessionRef{NativeID: session, Provider: "claude"}
		return c
	}
	cases := map[string]struct {
		line                   []*codex.Candidate
		failAppend             int
		wantStarts, wantUsages int
	}{
		"the start's own append failed": {
			line:       []*codex.Candidate{sessionCandidateProvider("sess-S", "claude", "claude-opus-5-5"), usage("sess-S", "msg_1", 10)},
			failAppend: 1, wantStarts: 1, wantUsages: 1,
		},
		"failure between two usage atoms of one line": {
			line:       []*codex.Candidate{usage("sess-S", "msg_A", 10), usage("sess-S", "msg_B", 20)},
			failAppend: 2, wantStarts: 0, wantUsages: 2,
		},
		"a session switch line": {
			line:       []*codex.Candidate{usage("sess-X", "msg_X", 10), sessionCandidateProvider("sess-Y", "claude", "claude-opus-5-5"), usage("sess-Y", "msg_Y", 20)},
			failAppend: 3, wantStarts: 1, wantUsages: 2,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			spool := &failOnNthSpool{inner: newSpoolWriter(t, dir), n: tc.failAppend}
			srv := startDaemonServer(t, dir, spool, NewRegistry("src_test", "ws_main"))
			sink := NewPartialCandidateSinkAdapter(newSink(t, local.NewClient(srv.SocketPath())))
			ref := codex.TranscriptRef{Locator: "projects/p/s.jsonl", Device: 5, Inode: 55}
			if _, err := sink.DeliverCandidatesPartial(context.Background(), ref, tc.line); err == nil {
				t.Fatal("the injected append failure was not reported")
			}
			if n, err := sink.DeliverCandidatesPartial(context.Background(), ref, tc.line); err != nil || n != len(tc.line) {
				t.Fatalf("re-delivery = %d, %v; want the whole line delivered", n, err)
			}
			starts, usages := 0, map[string]int{}
			for _, fr := range readWAL(t, dir) {
				var obs wire.Observation
				if err := obs.UnmarshalJSON(fr.Payload); err != nil {
					t.Fatalf("decode: %v", err)
				}
				switch kind, _ := obs.Discriminator(); kind {
				case string(wire.ObservationEnvelopeKindSESSIONLIFECYCLE):
					starts++
				case string(wire.ObservationEnvelopeKindUSAGE):
					u, _ := obs.AsUsageObservation()
					usages[*u.Usage.MessageId]++
				}
			}
			if starts != tc.wantStarts || len(usages) != tc.wantUsages {
				t.Fatalf("durable: %d starts, usages %v; want %d starts and %d distinct usages", starts, usages, tc.wantStarts, tc.wantUsages)
			}
			for id, n := range usages {
				if n != 1 {
					t.Fatalf("usage %s appended %d times", id, n)
				}
			}
		})
	}
}
