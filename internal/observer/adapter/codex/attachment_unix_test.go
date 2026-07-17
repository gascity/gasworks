//go:build unix

package codex

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestSyntheticRunIDGolden pins the EXACT output bytes of the synthetic run-id derivation with a
// hardcoded literal that is byte-identical to the platform's canonical apigen.SyntheticRunID.
// It is deliberately NOT computed by calling SyntheticRunID (that would be tautological). Any
// drift in the version tag, personalization, little-endian length-prefix layout, field order,
// prefix, or hex encoding changes this literal and fails loudly — which is the whole point,
// because the S2.6 RunBuilder derives the same id and a drift silently orphans passive runs.
func TestSyntheticRunIDGolden(t *testing.T) {
	const want = "gwr_syn1_6f13c5807ba673120596d6ebccf56d2e25906d1b2a4247022f8b78f46caa6be9"
	if got := SyntheticRunID("src_fixed", "codex", "019f5500-passive-7a"); got != want {
		t.Fatalf("SyntheticRunID drift:\n got  %s\n want %s\n"+
			"The synthetic run-id wire bytes diverged from platform apigen.SyntheticRunID; passive "+
			"runs would no longer join across the endpoint and the Builder.", got, want)
	}
}

// TestSyntheticRunIDDeterministicAndDistinct proves the derivation is a pure function of its
// inputs and that each input participates (the length-prefix framing actually separates fields).
func TestSyntheticRunIDDeterministicAndDistinct(t *testing.T) {
	base := SyntheticRunID("src_a", "codex", "sess-1")
	if again := SyntheticRunID("src_a", "codex", "sess-1"); again != base {
		t.Fatalf("not deterministic: %s != %s", again, base)
	}
	if shifted := SyntheticRunID("src_ac", "odex", "sess-1"); shifted == base {
		t.Fatalf("field boundary collision: length prefix is not separating fields (%s)", shifted)
	}
	for _, tc := range []struct{ s, p, n string }{
		{"src_b", "codex", "sess-1"},
		{"src_a", "claude", "sess-1"},
		{"src_a", "codex", "sess-2"},
	} {
		if got := SyntheticRunID(tc.s, tc.p, tc.n); got == base {
			t.Fatalf("input %v collided with base", tc)
		}
	}
}

// TestDecideClearCompactWithinSession proves clear and compact are within-session lifecycle
// evidence that never opens an interval or reassigns membership — even when an inherited run id
// is present and would otherwise attach HIGH.
func TestDecideClearCompactWithinSession(t *testing.T) {
	for _, tc := range []struct {
		source     wire.SessionLifecyclePayloadStartSource
		transition wire.SessionLifecyclePayloadTransition
	}{
		{wire.SessionLifecyclePayloadStartSourceCLEAR, wire.SessionLifecyclePayloadTransitionCLEARED},
		{wire.SessionLifecyclePayloadStartSourceCOMPACT, wire.SessionLifecyclePayloadTransitionCOMPACTED},
	} {
		seam := newFakeSeam()
		seam.resolve("gwr_open", InheritedOpenSameScope) // would attach on startup/resume
		d := Decide(context.Background(), seam, AttachInput{
			SourceID:        "src_1",
			Provider:        Provider,
			NativeSessionID: "sess-1",
			StartSource:     tc.source,
			InheritedRunID:  "gwr_open",
			HookPID:         os.Getpid(),
		})
		if d.Disposition != DispositionWithinSession {
			t.Fatalf("%s: disposition = %v, want WithinSession", tc.source, d.Disposition)
		}
		if d.OpensInterval {
			t.Fatalf("%s: OpensInterval = true, want false", tc.source)
		}
		if d.RunID != "" || d.Membership != "" {
			t.Fatalf("%s: within-session must not stamp membership; got run=%q ev=%q", tc.source, d.RunID, d.Membership)
		}
		if d.Transition != tc.transition {
			t.Fatalf("%s: transition = %q, want %q", tc.source, d.Transition, tc.transition)
		}
	}
}

// TestDecidePassiveSessionsAreDistinctInferredRuns proves two unwrapped sessions in the same
// directory at the same time become two separate INFERRED runs, keyed by native session id.
func TestDecidePassiveSessionsAreDistinctInferredRuns(t *testing.T) {
	seam := newFakeSeam() // no registered ancestors, no inherited id
	mk := func(sid string) Decision {
		return Decide(context.Background(), seam, AttachInput{
			SourceID:        "src_1",
			Provider:        Provider,
			NativeSessionID: sid,
			Workspace:       "/same/dir",
			StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
			HookPID:         os.Getpid(),
		})
	}
	a := mk("sess-a")
	b := mk("sess-b")
	for _, d := range []Decision{a, b} {
		if d.Disposition != DispositionInferred {
			t.Fatalf("disposition = %v, want Inferred", d.Disposition)
		}
		if d.Membership != "" {
			t.Fatalf("inferred run must carry no membership evidence, got %q", d.Membership)
		}
	}
	if a.RunID == b.RunID {
		t.Fatalf("two passive sessions collided on one inferred run: %s", a.RunID)
	}
	if a.RunID != SyntheticRunID("src_1", Provider, "sess-a") {
		t.Fatalf("inferred run id = %q, want deterministic synthetic id", a.RunID)
	}
}

// TestDecideInheritedOpenAttachesHigh proves an inherited run id that resolves to an OPEN
// same-source/workspace boundary attaches HIGH via INHERITED_RUN_ID.
func TestDecideInheritedOpenAttachesHigh(t *testing.T) {
	seam := newFakeSeam()
	seam.resolve("gwr_wrapped", InheritedOpenSameScope)
	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		InheritedRunID:  "gwr_wrapped",
		HookPID:         os.Getpid(),
	})
	if d.Disposition != DispositionAttachHigh {
		t.Fatalf("disposition = %v, want AttachHigh", d.Disposition)
	}
	if d.RunID != "gwr_wrapped" {
		t.Fatalf("run id = %q, want gwr_wrapped", d.RunID)
	}
	if d.Membership != wire.RunContextMembershipEvidenceINHERITEDRUNID {
		t.Fatalf("membership = %q, want INHERITED_RUN_ID", d.Membership)
	}
}

// TestDecideInheritedBadStatusQuarantined proves that unknown, closed, and cross-workspace
// inherited ids quarantine (never trust, never attach). Quarantine leaves no trusted run id.
func TestDecideInheritedBadStatusQuarantined(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status InheritedStatus
		reason QuarantineReason
	}{
		{"unknown/cross-source", InheritedUnknown, QuarantineUnknownRunID},
		{"closed", InheritedClosed, QuarantineClosedRun},
		{"cross-workspace", InheritedCrossWorkspace, QuarantineCrossWorkspace},
	} {
		seam := newFakeSeam()
		seam.resolve("gwr_bad", tc.status)
		d := Decide(context.Background(), seam, AttachInput{
			SourceID:        "src_1",
			Provider:        Provider,
			NativeSessionID: "sess-1",
			StartSource:     wire.SessionLifecyclePayloadStartSourceRESUME,
			InheritedRunID:  "gwr_bad",
			HookPID:         os.Getpid(),
		})
		if d.Disposition != DispositionQuarantine {
			t.Fatalf("%s: disposition = %v, want Quarantine", tc.name, d.Disposition)
		}
		if d.Quarantine != tc.reason {
			t.Fatalf("%s: reason = %v, want %v", tc.name, d.Quarantine, tc.reason)
		}
		if d.RunID != "" || d.Membership != "" {
			t.Fatalf("%s: quarantine must not stamp a trusted run; got run=%q ev=%q", tc.name, d.RunID, d.Membership)
		}
	}
}

// TestDecideResolveErrorDegradesToInferred proves a transport failure resolving an inherited id
// neither trusts nor quarantines it: it degrades to a separate inferred run with the degrade
// surfaced (ProofUnavailable), not swallowed.
func TestDecideResolveErrorDegradesToInferred(t *testing.T) {
	seam := newFakeSeam()
	seam.resolveErr = errors.New("daemon unreachable")
	d := Decide(context.Background(), seam, AttachInput{
		SourceID:        "src_1",
		Provider:        Provider,
		NativeSessionID: "sess-1",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		InheritedRunID:  "gwr_x",
		HookPID:         os.Getpid(),
	})
	if d.Disposition != DispositionInferred {
		t.Fatalf("disposition = %v, want Inferred", d.Disposition)
	}
	if !d.ProofUnavailable {
		t.Fatal("ProofUnavailable = false, want true (degrade must be surfaced)")
	}
}
