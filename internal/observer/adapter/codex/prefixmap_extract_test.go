package codex

import (
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// swapSource is a test BeadPrefixMapSource whose snapshot can be replaced (a hot reload).
type swapSource struct {
	mu sync.Mutex
	m  *evidence.BeadPrefixMap
}

func (s *swapSource) Current() *evidence.BeadPrefixMap { s.mu.Lock(); defer s.mu.Unlock(); return s.m }
func (s *swapSource) set(m *evidence.BeadPrefixMap)    { s.mu.Lock(); defer s.mu.Unlock(); s.m = m }

func prefixMapOf(t *testing.T, kv ...string) *evidence.BeadPrefixMap {
	t.Helper()
	var ms []evidence.BeadPrefixMapping
	for i := 0; i+1 < len(kv); i += 2 {
		ms = append(ms, evidence.BeadPrefixMapping{Prefix: kv[i], ProjectID: kv[i+1]})
	}
	m, err := evidence.NewBeadPrefixMap(ms)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// beadProjects extracts from one bd TOOL_CALL and returns bead id -> resolved project (built
// through the real evidence constructor, so the resolver snapshot is what is exercised).
func beadProjects(t *testing.T, text string, cfg ReferenceConfig) map[string]string {
	t.Helper()
	refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL, SurfaceText{Tool: "bd", Text: text}, cfg)
	out := map[string]string{}
	pol := testPolicy()
	for _, r := range refs {
		if r.Kind != RefKindBead {
			continue
		}
		res := pol.TransformExtractedWorkReference(testEnvelope(), *r.Work)
		if res.Diagnostic || res.Dropped {
			out[r.Work.BeadID] = ""
			continue
		}
		obs, err := res.Observation.Seal(1, "obs_1")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		wr, err := obs.AsWorkReferenceObservation()
		if err != nil {
			t.Fatalf("not a work reference: %v", err)
		}
		if wr.WorkReference.Origin != wire.WorkReferenceOriginEXTRACTED {
			t.Fatalf("origin = %q", wr.WorkReference.Origin)
		}
		out[r.Work.BeadID] = wr.WorkReference.TeamServerProjectId
	}
	return out
}

// TestPrefixMapCapturesAndResolvesEveryProject is the multi-project acceptance at the extractor
// seam: a tool call referencing beads of two projects yields EXTRACTED references to both, each
// resolved to its own project (longest prefix wins for nested prefixes), and a prefix added by a
// reload is captured on the next parse with no new config value.
func TestPrefixMapCapturesAndResolvesEveryProject(t *testing.T) {
	src := &swapSource{m: prefixMapOf(t, "acme-", "proj_acme", "beta-", "proj_beta", "acme-ops-", "proj_acmeops")}
	cfg := ReferenceConfig{PrefixMap: src}

	got := beadProjects(t, "bd dep add acme-12 beta-7 && bd show acme-ops-3 gamma-1", cfg)
	want := map[string]string{"acme-12": "proj_acme", "beta-7": "proj_beta", "acme-ops-3": "proj_acmeops"}
	if len(got) != len(want) {
		t.Fatalf("extracted %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %q, want %q", k, got[k], v)
		}
	}

	// Hot reload: a new project's prefix appears; the same cfg value now captures it.
	src.set(prefixMapOf(t, "acme-", "proj_acme", "beta-", "proj_beta", "gamma-", "proj_gamma"))
	got = beadProjects(t, "bd show gamma-1", cfg)
	if got["gamma-1"] != "proj_gamma" {
		t.Fatalf("reloaded prefix not captured/resolved: %v", got)
	}

	// An empty/nil snapshot leaves bead capture off (no static prefixes configured).
	src.set(nil)
	if got := beadProjects(t, "bd show acme-12", cfg); len(got) != 0 {
		t.Fatalf("nil snapshot still extracted: %v", got)
	}
}

// TestPrefixMapAmbiguousPrefixDropsWithDiagnostic: a prefix two projects share is still captured,
// but its references drop with a content-free diagnostic instead of linking to either project or
// falling back to a shorter prefix's project; the rest of the tool call links normally.
func TestPrefixMapAmbiguousPrefixDropsWithDiagnostic(t *testing.T) {
	m, err := evidence.NewBeadPrefixMap([]evidence.BeadPrefixMapping{
		{Prefix: "gas-", ProjectID: "proj_gas"},
		{Prefix: "gas-city-", ProjectID: "proj_city1"},
		{Prefix: "gas-city-", ProjectID: "proj_city2"},
		{Prefix: "acme-", ProjectID: "proj_acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := ReferenceConfig{PrefixMap: &swapSource{m: m}}
	got := beadProjects(t, "bd dep add gas-city-9 gas-4 acme-2", cfg)
	want := map[string]string{"gas-city-9": "", "gas-4": "proj_gas", "acme-2": "proj_acme"}
	if len(got) != len(want) {
		t.Fatalf("extracted %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %q, want %q", k, got[k], v)
		}
	}
}

// TestPrefixMapPatternCompiledOncePerSnapshot: the alternation over every mapped prefix is compiled
// once per snapshot (a reload), not on every bead-surface extraction.
func TestPrefixMapPatternCompiledOncePerSnapshot(t *testing.T) {
	src := &swapSource{m: prefixMapOf(t, "acme-", "proj_acme", "beta-", "proj_beta")}
	cfg := ReferenceConfig{PrefixMap: src}
	beadProjects(t, "bd show acme-1", cfg)
	first := mappedBeadPattern.Load()
	if first == nil || first.snap != src.Current() {
		t.Fatal("snapshot pattern not memoized")
	}
	beadProjects(t, "bd show beta-2", cfg)
	if mappedBeadPattern.Load() != first {
		t.Fatal("unchanged snapshot recompiled its pattern")
	}
	src.set(prefixMapOf(t, "acme-", "proj_acme", "gamma-", "proj_gamma"))
	if got := beadProjects(t, "bd show gamma-3", cfg); got["gamma-3"] != "proj_gamma" {
		t.Fatalf("reloaded snapshot not used: %v", got)
	}
	if c := mappedBeadPattern.Load(); c == first || c.snap != src.Current() {
		t.Fatal("a new snapshot did not get its own pattern")
	}
}
