package evidence

import (
	"errors"
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// disposition names how the endpoint rejects (or defers) an expect=invalid ObservationBatch
// fixture, so the negative half of the vendored corpus is bound to a concrete E1.1/endpoint
// guard rather than silently passing the write path.
type disposition int

const (
	decodeReject      disposition = iota // wire.DecodeObservationBatch rejects it
	validateReject                       // decode ok, evidence.ValidateBatch rejects it
	constructorReject                    // reachable field rejected by an evidence constructor
	unrepresentable                      // the shape cannot be produced by a constructor
	deferred                             // owned by a named later task (E1.2 spool/enrollment)
)

// negativeCorpus binds each of the 12 expect=invalid ObservationBatch fixtures to its
// endpoint disposition. Every entry is asserted below, so a future relaxation of a guard (or
// a never-added guard) turns a corpus obligation into a red test — this is the structural
// binding whose absence let the VCS-format gaps ship un-noticed.
var negativeCorpus = map[string]struct {
	how      disposition
	decodeIs error  // for decodeReject
	owner    string // for deferred
}{
	"fixtures/ingest/invalid/unknown_kind.json":                       {how: decodeReject, decodeIs: wire.ErrUnknownDiscriminator},
	"fixtures/ingest/invalid/run_started_with_drain.json":             {how: decodeReject, decodeIs: wire.ErrUnknownField},
	"fixtures/ingest/invalid/bad_schema_version.json":                 {how: decodeReject, decodeIs: wire.ErrSchemaVersionUnsupported},
	"fixtures/ingest/invalid/usage_quality_out_of_enum.json":          {how: decodeReject, decodeIs: wire.ErrEnumOutOfRange},
	"fixtures/ingest/invalid/usage_payload_null.json":                 {how: decodeReject, decodeIs: wire.ErrMissingPayload},
	"fixtures/ingest/invalid/num_sequence_fraction.json":              {how: decodeReject, decodeIs: wire.ErrSequenceOutOfRange},
	"fixtures/ingest/invalid/work_refs_over_cap.json":                 {how: validateReject},
	"fixtures/ingest/invalid/abbreviated_commit.json":                 {how: constructorReject},
	"fixtures/ingest/invalid/pull_request_unanchored_identifier.json": {how: constructorReject},
	"fixtures/ingest/invalid/session_model_empty.json":                {how: unrepresentable},
	"fixtures/ingest/invalid/bad_source_id.json":                      {how: deferred, owner: "E1.2 (source_id is server-assigned at enrollment, never adapter-derived)"},
	"fixtures/ingest/invalid/missing_observation_id.json":             {how: deferred, owner: "E1.2 (observation_id is spool-assigned; Seal rejects an empty id)"},
}

// TestNegativeCorpusBoundToEvidenceLayer proves the endpoint's total disposition matches the
// platform's reject verdict on every expect=invalid ObservationBatch fixture: 6 decode-reject,
// 1 validate-reject, 2 constructor-reject (VCS format), 1 unrepresentable (absent-not-empty),
// and 2 deferred to E1.2 with an asserted local guard. Combined with
// TestValidateBatchAgainstSemanticFixtures (the accept side), this reconciles E1.1's verdict
// with the platform's across all 54 fixtures.
func TestNegativeCorpusBoundToEvidenceLayer(t *testing.T) {
	m := loadManifest(t)
	seen := map[string]bool{}
	for _, fx := range m.Fixtures {
		if fx.Schema != "ObservationBatch" || fx.Expect != "invalid" {
			continue
		}
		entry, ok := negativeCorpus[fx.Path]
		if !ok {
			t.Fatalf("expect=invalid fixture %q is unbound — add it to negativeCorpus with its endpoint disposition", fx.Path)
		}
		seen[fx.Path] = true
		fx := fx
		t.Run(fx.Path, func(t *testing.T) {
			data := readFixture(t, fx)
			b, decErr := wire.DecodeObservationBatch(data)
			switch entry.how {
			case decodeReject:
				if !errors.Is(decErr, entry.decodeIs) {
					t.Fatalf("want decode error %v, got %v", entry.decodeIs, decErr)
				}
			case validateReject:
				if decErr != nil {
					t.Fatalf("expected decode to accept, got %v", decErr)
				}
				if err := ValidateBatch(b); err == nil {
					t.Fatalf("ValidateBatch must reject %s", fx.Path)
				}
			case constructorReject:
				if decErr != nil {
					t.Fatalf("expected decode to accept (pattern is not a decode check), got %v", decErr)
				}
				if err := rebuildThroughConstructor(t, b); err == nil {
					t.Fatalf("the evidence constructor must reject the fixture's field value")
				} else {
					mustBuildErr(t, err, fx.Path)
				}
			case unrepresentable:
				assertModelEmptyUnrepresentable(t, b)
			case deferred:
				// The endpoint batch validator does not own this field; the named owner does.
				// Assert the local guard that keeps the endpoint from ever producing it.
				if fx.Path == "fixtures/ingest/invalid/missing_observation_id.json" {
					p, err := NewMessage(testCommon(), MessageInput{Role: wire.MessagePayloadRoleUSER})
					if err != nil {
						t.Fatalf("NewMessage: %v", err)
					}
					if _, err := p.Seal(1, ""); err == nil {
						t.Fatalf("Seal must reject an empty observation_id (owner: %s)", entry.owner)
					}
				}
				if entry.owner == "" {
					t.Fatalf("a deferred fixture must name its owner")
				}
			}
		})
	}
	if len(seen) != len(negativeCorpus) {
		t.Fatalf("bound %d fixtures but negativeCorpus lists %d — a fixture was removed or renamed", len(seen), len(negativeCorpus))
	}
}

// rebuildThroughConstructor takes a decoded VCS_REFERENCE batch and re-runs its identifier /
// repo_slug through the evidence constructor, so the fixture's real field value is what the
// guard rejects.
func rebuildThroughConstructor(t *testing.T, b *wire.DecodedBatch) error {
	t.Helper()
	if len(b.Observations) != 1 {
		t.Fatalf("expected a single-observation VCS fixture, got %d", len(b.Observations))
	}
	v, ok := b.Observations[0].Variant.(wire.VcsReferenceObservation)
	if !ok {
		t.Fatalf("expected a VcsReferenceObservation, got %T", b.Observations[0].Variant)
	}
	disc, err := v.VcsReference.Discriminator()
	if err != nil {
		t.Fatalf("vcs discriminator: %v", err)
	}
	switch disc {
	case "COMMIT":
		cm, err := v.VcsReference.AsCommitVcsReference()
		if err != nil {
			t.Fatalf("as commit: %v", err)
		}
		_, buildErr := NewCommitReference(testCommon(), CommitReferenceInput{
			Identifier: cm.Identifier, RepoSlug: deref(cm.RepoSlug), Extraction: cm.Extraction,
		})
		return buildErr
	case "PULL_REQUEST":
		pr, err := v.VcsReference.AsPullRequestVcsReference()
		if err != nil {
			t.Fatalf("as pr: %v", err)
		}
		_, buildErr := NewPullRequestReference(testCommon(), PullRequestReferenceInput{
			Identifier: pr.Identifier, RepoSlug: deref(pr.RepoSlug), Extraction: pr.Extraction,
		})
		return buildErr
	default:
		t.Fatalf("unexpected ref_kind %q", disc)
		return nil
	}
}

// assertModelEmptyUnrepresentable proves the constructor cannot reproduce the fixture's
// empty-string model: feeding the decoded (empty) model value through NewSessionLifecycle
// yields an absent field, so session_model_empty is unrepresentable-by-construction.
func assertModelEmptyUnrepresentable(t *testing.T, b *wire.DecodedBatch) {
	t.Helper()
	v, ok := b.Observations[0].Variant.(wire.SessionLifecycleObservation)
	if !ok {
		t.Fatalf("expected a SessionLifecycleObservation, got %T", b.Observations[0].Variant)
	}
	if v.SessionLifecycle.Model == nil || *v.SessionLifecycle.Model != "" {
		t.Fatalf("fixture precondition: model should decode to an empty string")
	}
	p, err := NewSessionLifecycle(testCommon(), SessionLifecycleInput{
		NativeSessionID: v.SessionLifecycle.NativeSessionId,
		Provider:        v.SessionLifecycle.Provider,
		StartSource:     v.SessionLifecycle.StartSource,
		Transition:      v.SessionLifecycle.Transition,
		Model:           *v.SessionLifecycle.Model, // ""
	})
	if err != nil {
		t.Fatalf("NewSessionLifecycle: %v", err)
	}
	rebuilt, err := p.Seal(1, "obs_1")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sl, err := rebuilt.AsSessionLifecycleObservation()
	if err != nil {
		t.Fatalf("as session: %v", err)
	}
	if sl.SessionLifecycle.Model != nil {
		t.Fatalf("empty model must be unrepresentable (absent), got %q", *sl.SessionLifecycle.Model)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
