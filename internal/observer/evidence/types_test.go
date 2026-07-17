package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func testTimes() (time.Time, time.Time) {
	occurred := time.Date(2026, 7, 16, 10, 1, 0, 0, time.UTC)
	return occurred, occurred.Add(80 * time.Millisecond)
}

// metadataProvenance is a minimal policy-clean METADATA_ONLY provenance for constructor
// tests. It deliberately carries no source_hash and no content locators.
func metadataProvenance() wire.Provenance {
	return wire.Provenance{
		Adapter:        "codex-hook",
		AdapterVersion: "1.0.0",
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
	}
}

func testCommon() Common {
	occ, cap := testTimes()
	return Common{OccurredAt: occ, CapturedAt: cap, Provenance: metadataProvenance()}
}

func sealOne(t *testing.T, p PendingObservation, seq int64, id string) wire.Observation {
	t.Helper()
	o, err := p.Seal(seq, id)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return o
}

// TestSealAssignsIdentityAndKind proves Seal stamps the spool-assigned sequence/id and that
// the sealed union decodes to the constructor's kind.
func TestSealAssignsIdentityAndKind(t *testing.T) {
	p, err := NewMessage(testCommon(), MessageInput{Role: wire.MessagePayloadRoleUSER})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if p.Kind() != "MESSAGE" {
		t.Fatalf("kind = %q, want MESSAGE", p.Kind())
	}
	o := sealOne(t, p, 7, "obs_msg_1")
	disc, err := o.Discriminator()
	if err != nil {
		t.Fatalf("discriminator: %v", err)
	}
	if disc != "MESSAGE" {
		t.Fatalf("discriminator = %q, want MESSAGE", disc)
	}
	msg, err := o.AsMessageObservation()
	if err != nil {
		t.Fatalf("as message: %v", err)
	}
	if msg.Sequence != 7 || msg.ObservationId != "obs_msg_1" {
		t.Fatalf("identity not stamped: seq=%d id=%q", msg.Sequence, msg.ObservationId)
	}
}

// TestSealRejectsBadIdentity proves Seal fails closed on an out-of-range sequence or an
// empty/over-long observation id — identity generation is the spool's job and must be sound.
func TestSealRejectsBadIdentity(t *testing.T) {
	p, err := NewMessage(testCommon(), MessageInput{Role: wire.MessagePayloadRoleUSER})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	cases := []struct {
		name string
		seq  int64
		id   string
	}{
		{"zero sequence", 0, "obs_1"},
		{"negative sequence", -1, "obs_1"},
		{"empty id", 5, ""},
		{"overlong id", 5, strings.Repeat("x", maxObservationID+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Seal(tc.seq, tc.id); err == nil {
				t.Fatalf("expected seal error for %s", tc.name)
			}
		})
	}
}

// TestRunStartedHasNoDrainFields proves a RUN_STARTED boundary decodes as a
// RunStartedBoundary and carries no drain evidence. The input type has no drain field at
// all, so the coupling is unrepresentable by construction; this asserts the wire result.
func TestRunStartedHasNoDrainFields(t *testing.T) {
	p, err := NewRunStarted(testCommon(), RunStartedInput{
		RunID:          "gwr_1",
		BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	if err != nil {
		t.Fatalf("NewRunStarted: %v", err)
	}
	o := sealOne(t, p, 1, "obs_1")
	rb, err := o.AsRunBoundaryObservation()
	if err != nil {
		t.Fatalf("as run boundary: %v", err)
	}
	transition, err := rb.RunBoundary.Discriminator()
	if err != nil {
		t.Fatalf("boundary discriminator: %v", err)
	}
	if transition != "RUN_STARTED" {
		t.Fatalf("transition = %q, want RUN_STARTED", transition)
	}
	// The canonical bytes must not carry any drain vocabulary.
	assertNoSubstrings(t, canonicalOf(t, o), "drain_status", "covered_watermark")
}

// TestRunEndedShapesSatisfyDrainPair proves both legal RUN_ENDED shapes: a drained end
// carries both fields, a launch-failure end carries neither, and both pass the drain-pair
// validator. The two-constructor split makes a half-populated pair impossible to build.
func TestRunEndedShapesSatisfyDrainPair(t *testing.T) {
	locator := "codex/2026/07/16/rollout.jsonl"
	drained, err := NewRunEndedDrain(testCommon(), RunEndedDrainInput{
		RunID:            "gwr_1",
		BoundarySource:   wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		DrainStatus:      wire.RunEndedBoundaryDrainStatusCOMPLETE,
		CoveredWatermark: wire.Watermark{ByteOffset: 4096, SourceLocator: &locator},
	})
	if err != nil {
		t.Fatalf("NewRunEndedDrain: %v", err)
	}
	launchFail, err := NewRunEndedLaunchFailure(testCommon(), RunEndedLaunchFailureInput{
		RunID:          "gwr_1",
		BoundarySource: wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
	})
	if err != nil {
		t.Fatalf("NewRunEndedLaunchFailure: %v", err)
	}
	assertBatchValid(t, "drained", sealOne(t, drained, 1, "obs_1"))
	assertBatchValid(t, "launch-failure", sealOne(t, launchFail, 1, "obs_1"))

	rb, _ := sealOne(t, launchFail, 1, "obs_1").AsRunBoundaryObservation()
	ended, err := rb.RunBoundary.AsRunEndedBoundary()
	if err != nil {
		t.Fatalf("as run ended: %v", err)
	}
	if ended.DrainStatus != nil || ended.CoveredWatermark != nil {
		t.Fatalf("launch-failure RUN_ENDED must carry neither drain field")
	}
}

// TestUsageEstimatedRequiresPriceTable proves the ESTIMATED price-table coupling at
// construction: an ESTIMATED usage without a price table is unbuildable; with one it builds.
func TestUsageEstimatedRequiresPriceTable(t *testing.T) {
	if _, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityESTIMATED}); err == nil {
		t.Fatal("ESTIMATED usage without price_table_version must fail to build")
	}
	pt := "pt_2026_07"
	if _, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityESTIMATED, PriceTableVersion: pt}); err != nil {
		t.Fatalf("ESTIMATED usage with price table must build, got: %v", err)
	}
	// A non-ESTIMATED usage needs no price table.
	if _, err := NewUsage(testCommon(), UsageInput{Quality: wire.UsagePayloadQualityPROVIDERREPORTED}); err != nil {
		t.Fatalf("provider-reported usage must build, got: %v", err)
	}
}

// TestExtractedWorkReferenceResolution proves the project-resolution rule: stamped context
// or configured default resolves and builds an EXTRACTED reference; neither yields a
// content-free drop diagnostic (never a partial reference).
func TestExtractedWorkReferenceResolution(t *testing.T) {
	t.Run("stamped_wins", func(t *testing.T) {
		res, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: "bd-9"},
			ProjectResolver{StampedProjectID: "btsproj_stamped", DefaultProjectID: "btsproj_default"})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if res.Dropped() {
			t.Fatal("expected resolved reference")
		}
		wr, _ := sealOne(t, *res.Resolved, 1, "obs_1").AsWorkReferenceObservation()
		if wr.WorkReference.TeamServerProjectId != "btsproj_stamped" {
			t.Fatalf("project = %q, want stamped precedence", wr.WorkReference.TeamServerProjectId)
		}
		if wr.WorkReference.Origin != wire.WorkReferenceOriginEXTRACTED {
			t.Fatalf("origin = %q, want EXTRACTED", wr.WorkReference.Origin)
		}
	})
	t.Run("default_fallback", func(t *testing.T) {
		res, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: "bd-9"},
			ProjectResolver{DefaultProjectID: "btsproj_default"})
		if err != nil || res.Dropped() {
			t.Fatalf("expected default-resolved reference, err=%v dropped=%v", err, res.Dropped())
		}
	})
	t.Run("unresolvable_drops_with_diagnostic", func(t *testing.T) {
		res, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: "bd-9"}, ProjectResolver{})
		if err != nil {
			t.Fatalf("drop should not be an error: %v", err)
		}
		if !res.Dropped() {
			t.Fatal("expected drop")
		}
		if res.DropReason != RefDropUnresolvableProject {
			t.Fatalf("drop reason = %q", res.DropReason)
		}
		if res.Drop == nil || res.Drop.Kind() != "CAPTURE_DIAGNOSTIC" {
			t.Fatalf("expected a CAPTURE_DIAGNOSTIC drop observation")
		}
		// The drop diagnostic must be content-free: no bead id or project leaks.
		assertNoSubstrings(t, canonicalOf(t, sealOne(t, *res.Drop, 1, "obs_1")), "bd-9", "btsproj")
	})
}

// TestConstructorBoundsRejected proves the field-length and reference-cap guards fire.
func TestConstructorBoundsRejected(t *testing.T) {
	t.Run("overlong_run_id", func(t *testing.T) {
		_, err := NewRunStarted(testCommon(), RunStartedInput{
			RunID:          strings.Repeat("r", maxRunID+1),
			BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
		})
		if err == nil {
			t.Fatal("expected overlong run_id rejection")
		}
	})
	t.Run("overlong_commit_identifier", func(t *testing.T) {
		_, err := NewCommitReference(testCommon(), CommitReferenceInput{
			Identifier: strings.Repeat("a", maxCommitIdentifier+1),
			Extraction: wire.ExtractionProvenance{Surface: wire.ExtractionProvenanceSurfaceTOOLRESULT, PatternId: "p", ExtractorVersion: "1"},
		})
		if err == nil {
			t.Fatal("expected overlong identifier rejection")
		}
	})
	t.Run("over_cap_refs", func(t *testing.T) {
		refs := make([]wire.WorkReference, MaxReferencesPerObservation+1)
		for i := range refs {
			refs[i] = wire.WorkReference{TeamServerProjectId: "btsproj", BeadId: "bd", Origin: wire.WorkReferenceOriginDECLARED}
		}
		_, err := NewRunStarted(testCommon(), RunStartedInput{
			RunID:          "gwr_1",
			BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
			WorkItemRefs:   refs,
		})
		if err == nil {
			t.Fatal("expected over-cap reference rejection")
		}
	})
	t.Run("bad_enum", func(t *testing.T) {
		_, err := NewMessage(testCommon(), MessageInput{Role: wire.MessagePayloadRole("NOPE")})
		if err == nil {
			t.Fatal("expected out-of-enum role rejection")
		}
	})
}

// TestOptionalModelAbsentNotEmpty proves absent-not-empty: an empty optional model produces
// an absent field, and the canonical bytes carry no model key at all.
func TestOptionalModelAbsentNotEmpty(t *testing.T) {
	p, err := NewSessionLifecycle(testCommon(), SessionLifecycleInput{
		NativeSessionID: "019f-native",
		Provider:        "codex",
		StartSource:     wire.SessionLifecyclePayloadStartSourceSTARTUP,
		Transition:      wire.SessionLifecyclePayloadTransitionSTARTED,
		Model:           "", // empty => absent
	})
	if err != nil {
		t.Fatalf("NewSessionLifecycle: %v", err)
	}
	o := sealOne(t, p, 1, "obs_1")
	sl, _ := o.AsSessionLifecycleObservation()
	if sl.SessionLifecycle.Model != nil {
		t.Fatalf("empty model must be absent, got %q", *sl.SessionLifecycle.Model)
	}
	assertNoSubstrings(t, canonicalOf(t, o), `"model"`)
}

// TestConstructedBatchRoundTrips proves the constructors produce a batch that survives the
// strict wire decoder and the semantic validators — the domain layer and the wire contract
// agree end to end.
func TestConstructedBatchRoundTrips(t *testing.T) {
	c := testCommon()
	rc := &wire.RunContext{RunId: "gwr_1", MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY}
	c.RunContext = rc

	start, err := NewRunStarted(c, RunStartedInput{RunID: "gwr_1", BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	msg, err := NewMessage(c, MessageInput{Role: wire.MessagePayloadRoleASSISTANT, ByteCount: ptrI64(42)})
	if err != nil {
		t.Fatalf("msg: %v", err)
	}
	locator := "codex/2026/07/16/rollout.jsonl"
	end, err := NewRunEndedDrain(c, RunEndedDrainInput{
		RunID:            "gwr_1",
		BoundarySource:   wire.RunEndedBoundaryBoundarySourceEXPLICITWRAPPER,
		DrainStatus:      wire.RunEndedBoundaryDrainStatusCOMPLETE,
		CoveredWatermark: wire.Watermark{ByteOffset: 4096, SourceLocator: &locator},
	})
	if err != nil {
		t.Fatalf("end: %v", err)
	}

	batch := assembleBatch(t, "src_019f7a1000observerpilot0001", 1,
		sealOne(t, start, 1, "obs_1"),
		sealOne(t, msg, 2, "obs_2"),
		sealOne(t, end, 3, "obs_3"),
	)
	decoded, err := wire.DecodeObservationBatch(batch)
	if err != nil {
		t.Fatalf("decode constructed batch: %v", err)
	}
	if err := ValidateBatch(decoded); err != nil {
		t.Fatalf("validate constructed batch: %v", err)
	}
}

// ---- test helpers ----

func ptrI64(v int64) *int64 { return &v }

func canonicalOf(t *testing.T, o wire.Observation) []byte {
	t.Helper()
	b, err := wire.CanonicalBytes(o)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	return b
}

func assertNoSubstrings(t *testing.T, b []byte, banned ...string) {
	t.Helper()
	for _, s := range banned {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("canonical bytes must not contain %q\n%s", s, b)
		}
	}
}

func assembleBatch(t *testing.T, sourceID string, first int64, obs ...wire.Observation) []byte {
	t.Helper()
	b := wire.ObservationBatch{
		SchemaVersion: wire.ObservationBatchSchemaVersionN1,
		SourceId:      sourceID,
		FirstSequence: first,
		LastSequence:  first + int64(len(obs)) - 1,
		Observations:  obs,
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	return raw
}

func assertBatchValid(t *testing.T, name string, obs ...wire.Observation) {
	t.Helper()
	decoded, err := wire.DecodeObservationBatch(assembleBatch(t, "src_019f7a1000observerpilot0001", 1, obs...))
	if err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	if err := ValidateBatch(decoded); err != nil {
		t.Fatalf("%s: validate: %v", name, err)
	}
}

// TestBuildErrorIsTyped keeps the construction failure branchable.
func TestBuildErrorIsTyped(t *testing.T) {
	_, err := NewMessage(Common{}, MessageInput{Role: wire.MessagePayloadRoleUSER})
	var be *BuildError
	if !errors.As(err, &be) {
		t.Fatalf("want *BuildError, got %T (%v)", err, err)
	}
}
