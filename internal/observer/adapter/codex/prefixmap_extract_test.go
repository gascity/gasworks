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

// fakeBody is a deterministic pseudo-random token body; fixtures are assembled at runtime so no
// literal credential-shaped string lives in the repository.
func fakeBody(n int, alphabet string, seed uint32) string {
	out := make([]byte, n)
	x := seed<<1 | 1 // xorshift32 state: odd so never 0, and distinct for distinct seeds
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = alphabet[int(x%uint32(len(alphabet)))]
	}
	return string(out)
}

// TestPrefixMapDoesNotCaptureSecretShapedTokens (bts-xpw.13.3.6): project prefixes are user-chosen,
// so a project whose prefix is "sk", "xoxb" or "api" turns a credential scheme into a capture
// prefix. A credential passed on a gh/bd/git command line must not be captured as a bead id, while
// real beads of the same project on the same line still are.
func TestPrefixMapDoesNotCaptureSecretShapedTokens(t *testing.T) {
	const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const hex = "0123456789abcdef"
	sk := "s" + "k-"
	xoxb := "xox" + "b-"
	glpat := "glp" + "at-"
	api := "ap" + "i-"
	src := &swapSource{m: prefixMapOf(t, sk, "proj_sk", xoxb, "proj_slack", glpat, "proj_gl", api, "proj_api")}
	cfg := ReferenceConfig{PrefixMap: src}

	anthropic := sk + "ant-api03-" + fakeBody(93, al, 1)
	slack := xoxb + fakeBody(13, "0123456789", 2) + "-" + fakeBody(13, "0123456789", 3) + "-" + fakeBody(24, al, 4)
	gitlab := glpat + fakeBody(20, al, 5)
	// A LaunchDarkly-style api-<uuid> key: every segment is short, so only the UUID run gives it away.
	launchDarkly := api + fakeBody(8, hex, 6) + "-" + fakeBody(4, hex, 7) + "-" + fakeBody(4, hex, 8) + "-" +
		fakeBody(4, hex, 9) + "-" + fakeBody(12, hex, 10)
	for _, tc := range []struct{ tool, text string }{
		{"gh", "gh secret set ANTHROPIC_API_KEY --body " + anthropic + " && bd show " + sk + "a1b2"},
		{"gh", "gh secret set SLACK_TOKEN --body '" + slack + "' ; bd close " + xoxb + "9z.1"},
		{"git", "git remote set-url origin https://oauth2:" + gitlab + "@gitlab.example/x.git && bd update " + glpat + "abc"},
		{"bd", "bd create --notes " + gitlab + " " + sk + "a1b2"},
		{"gh", "gh secret set LD_API_KEY --body " + launchDarkly + " && bd show " + api + "k3x"},
	} {
		refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL, SurfaceText{Tool: tc.tool, Text: tc.text}, cfg)
		var beads []string
		for _, r := range refs {
			if r.Kind != RefKindBead {
				continue
			}
			for _, secret := range []string{anthropic, slack, gitlab, launchDarkly} {
				if r.Work.BeadID == secret {
					t.Fatalf("%s: credential captured as bead id", tc.tool)
				}
			}
			beads = append(beads, r.Work.BeadID)
		}
		if len(beads) != 1 {
			t.Errorf("%s: captured %v, want exactly the one real bead", tc.tool, beads)
		}
	}
}

// TestPrefixMapKeepsBeadsUnderUserChosenPrefixes (bts-xpw.13.3.6): BTS project prefixes may be up
// to 32 mixed-case characters and may begin with a credential scheme. The screen exempts the
// declared prefix the extractor matched, so each such project's real beads are captured and
// resolve through the evidence constructor (which repeats the screen) instead of being dropped.
func TestPrefixMapKeepsBeadsUnderUserChosenPrefixes(t *testing.T) {
	sk := "s" + "k-"
	src := &swapSource{m: prefixMapOf(t,
		"PlatformServices-", "proj_ps",
		"projectphoenix2026-", "proj_pp",
		sk+"team-", "proj_skteam",
		sk, "proj_sk",
	)}
	got := beadProjects(t, "bd dep add PlatformServices-a1b2 projectphoenix2026-q7.2 && bd show "+sk+"team-x9z "+sk+"a1b2", ReferenceConfig{PrefixMap: src})
	want := map[string]string{
		"PlatformServices-a1b2":   "proj_ps",
		"projectphoenix2026-q7.2": "proj_pp",
		sk + "team-x9z":           "proj_skteam",
		sk + "a1b2":               "proj_sk",
	}
	if len(got) != len(want) {
		t.Fatalf("extracted %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %q, want %q", k, got[k], v)
		}
	}

	// The static -bead-prefix form gets the same exemption, alone and alongside a prefix map.
	cfg := ReferenceConfig{BeadPrefixes: []string{"CustomerPortalV2-"}, Resolver: evidence.ProjectResolver{DefaultProjectID: "proj_cp"}}
	if got := beadProjects(t, "bd show CustomerPortalV2-a1b2", cfg); got["CustomerPortalV2-a1b2"] != "proj_cp" {
		t.Errorf("static prefix: extracted %v", got)
	}
	cfg.PrefixMap = src
	if got := beadProjects(t, "bd show CustomerPortalV2-a1b2 PlatformServices-a1b2", cfg); got["CustomerPortalV2-a1b2"] != "proj_cp" || got["PlatformServices-a1b2"] != "proj_ps" {
		t.Errorf("static + mapped prefixes: extracted %v", got)
	}
}
