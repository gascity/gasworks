package evidence

import (
	"fmt"
	"strings"
	"testing"
)

func mustPrefixMap(t *testing.T, m ...BeadPrefixMapping) *BeadPrefixMap {
	t.Helper()
	pm, err := NewBeadPrefixMap(m)
	if err != nil {
		t.Fatalf("NewBeadPrefixMap: %v", err)
	}
	return pm
}

// TestBeadPrefixMapLongestPrefixMatch pins the resolution rule for nested issue prefixes: a bead
// id resolves to the project of the LONGEST declared prefix it begins with, regardless of the
// order the file declares them in.
func TestBeadPrefixMapLongestPrefixMatch(t *testing.T) {
	pm := mustPrefixMap(t,
		BeadPrefixMapping{Prefix: "gas-", ProjectID: "proj_gas"},
		BeadPrefixMapping{Prefix: "gas-city-", ProjectID: "proj_gascity"},
		BeadPrefixMapping{Prefix: "acme-", ProjectID: "proj_acme"},
	)
	cases := []struct {
		bead, want, prefix string
		ok                 bool
	}{
		{"gas-city-12", "proj_gascity", "gas-city-", true},
		{"gas-12", "proj_gas", "gas-", true},
		{"gas-cityx-1", "proj_gas", "gas-", true},
		{"acme-9a", "proj_acme", "acme-", true},
		{"beta-1", "", "", false},
		{"acme", "", "", false},
	}
	for _, c := range cases {
		got, ok := pm.Lookup(c.bead)
		if got != c.want || ok != c.ok {
			t.Errorf("Lookup(%q) = %q,%v want %q,%v", c.bead, got, ok, c.want, c.ok)
		}
		if p := pm.LongestPrefix(c.bead); p != c.prefix {
			t.Errorf("LongestPrefix(%q) = %q, want %q", c.bead, p, c.prefix)
		}
	}
	if got := pm.Prefixes(); len(got) != 3 || got[0] != "gas-city-" {
		t.Errorf("Prefixes() = %v, want longest first", got)
	}
	if p := pm.Problems(); p != "" {
		t.Errorf("clean map reported problems: %s", p)
	}
	var nilMap *BeadPrefixMap
	if _, ok := nilMap.Lookup("gas-1"); ok || nilMap.Len() != 0 || nilMap.Prefixes() != nil || nilMap.Problems() != "" || nilMap.LongestPrefix("gas-1") != "" {
		t.Error("nil map must behave as empty")
	}
}

// TestBeadPrefixMapSkipsMalformedPerEntry proves validation is per declaration: one malformed entry
// (BTS accepts issue prefixes with any interior character) is skipped and reported, and every other
// project still links. Only an oversized map fails as a whole. An exact duplicate is collapsed.
func TestBeadPrefixMapSkipsMalformedPerEntry(t *testing.T) {
	longPrefix := strings.Repeat("x", 300) + "-"
	bad := map[string]BeadPrefixMapping{
		"no_trailing_dash":  {Prefix: "acme", ProjectID: "p"},
		"empty_prefix":      {Prefix: "", ProjectID: "p"},
		"bare_dash":         {Prefix: "-", ProjectID: "p"},
		"regex_meta":        {Prefix: "a.*-", ProjectID: "p"},
		"underscore":        {Prefix: "my_app-", ProjectID: "p"},
		"space":             {Prefix: "ac me-", ProjectID: "p"},
		"double_dash":       {Prefix: "acme--", ProjectID: "p"},
		"too_long":          {Prefix: strings.Repeat("a", maxBeadPrefix) + "-", ProjectID: "p"},
		"very_long":         {Prefix: longPrefix, ProjectID: "p"},
		"empty_project":     {Prefix: "zeta-", ProjectID: ""},
		"oversized_project": {Prefix: "zeta-", ProjectID: strings.Repeat("p", maxTeamServerProject+1)},
	}
	for name, b := range bad {
		pm, err := NewBeadPrefixMap([]BeadPrefixMapping{{Prefix: "good-", ProjectID: "proj_good"}, b})
		if err != nil {
			t.Errorf("%s: one bad entry failed the whole map: %v", name, err)
			continue
		}
		if got, ok := pm.Lookup("good-1"); !ok || got != "proj_good" {
			t.Errorf("%s: the valid entry did not apply: %q,%v", name, got, ok)
		}
		if pm.Len() != 1 {
			t.Errorf("%s: Len = %d, want only the valid entry", name, pm.Len())
		}
		p := pm.Problems()
		if !strings.Contains(p, "skipped 1 malformed entry (first: entry 1:") {
			t.Errorf("%s: problems = %q", name, p)
		}
		if strings.Contains(p, strings.Repeat("x", 100)) || strings.Contains(p, strings.Repeat("p", 100)) {
			t.Errorf("%s: problems carry an unbounded value: %q", name, p)
		}
	}
	tooMany := make([]BeadPrefixMapping, MaxBeadPrefixMappings+1)
	for i := range tooMany {
		tooMany[i] = BeadPrefixMapping{Prefix: fmt.Sprintf("p%d-", i), ProjectID: "p"}
	}
	if _, err := NewBeadPrefixMap(tooMany); err == nil {
		t.Error("oversized map accepted")
	}
	pm := mustPrefixMap(t, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p"}, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p"})
	if pm.Len() != 1 || pm.Problems() != "" {
		t.Errorf("exact duplicate not collapsed: Len=%d problems=%q", pm.Len(), pm.Problems())
	}
	if empty := mustPrefixMap(t); empty.Len() != 0 || empty.Problems() != "" {
		t.Error("empty map should be valid and empty")
	}
}

// TestBeadPrefixMapAmbiguousPrefixNeverLinks: the team server does not forbid two projects sharing
// an issue prefix. Such a prefix resolves to NO project — ambiguous ownership never authorizes a
// link — and a longer ambiguous prefix shadows a shorter unambiguous one rather than falling back
// to it (which would mis-attribute the bead). The rest of the map still applies.
func TestBeadPrefixMapAmbiguousPrefixNeverLinks(t *testing.T) {
	pm := mustPrefixMap(t,
		BeadPrefixMapping{Prefix: "FE-", ProjectID: "proj_fe1"},
		BeadPrefixMapping{Prefix: "gas-", ProjectID: "proj_gas"},
		BeadPrefixMapping{Prefix: "FE-", ProjectID: "proj_fe2"},
		BeadPrefixMapping{Prefix: "gas-city-", ProjectID: "proj_city1"},
		BeadPrefixMapping{Prefix: "gas-city-", ProjectID: "proj_city2"},
		BeadPrefixMapping{Prefix: "FE-", ProjectID: "proj_fe1"}, // a repeat never un-ambiguates
		BeadPrefixMapping{Prefix: "acme-", ProjectID: "proj_acme"},
	)
	for bead, want := range map[string]string{"FE-1": "", "gas-city-12": "", "gas-12": "proj_gas", "acme-3": "proj_acme"} {
		got, ok := pm.Lookup(bead)
		if got != want || ok != (want != "") {
			t.Errorf("Lookup(%q) = %q,%v want %q", bead, got, ok, want)
		}
	}
	if pm.Len() != 4 {
		t.Errorf("Len = %d, want 4 (ambiguous prefixes stay captured)", pm.Len())
	}
	if p := pm.LongestPrefix("gas-city-12"); p != "gas-city-" {
		t.Errorf("LongestPrefix must include ambiguous prefixes (still captured), got %q", p)
	}
	if p := pm.Problems(); p != "2 prefixes declared for more than one project resolve to no project: FE-, gas-city-" {
		t.Errorf("problems = %q", p)
	}
	if strings.Contains(pm.Problems(), "proj_") {
		t.Error("problems must not name project ids")
	}
}

// TestExtractedWorkReferencePrefixMapResolution pins the precedence: the stamped run context wins,
// then the longest matching prefix mapping, then the single default; an id no mapping covers with
// no default drops with a diagnostic, and an ambiguous prefix drops even when a default exists.
func TestExtractedWorkReferencePrefixMapResolution(t *testing.T) {
	pm := mustPrefixMap(t,
		BeadPrefixMapping{Prefix: "acme-", ProjectID: "btsproj_acme"},
		BeadPrefixMapping{Prefix: "beta-", ProjectID: "btsproj_beta"},
		BeadPrefixMapping{Prefix: "dup-", ProjectID: "btsproj_dup1"},
		BeadPrefixMapping{Prefix: "dup-", ProjectID: "btsproj_dup2"},
	)
	build := func(t *testing.T, bead string, r ProjectResolver) ExtractedWorkRefResult {
		t.Helper()
		res, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: bead}, r)
		if err != nil {
			t.Fatalf("NewExtractedWorkReference: %v", err)
		}
		return res
	}
	project := func(t *testing.T, bead string, r ProjectResolver) (string, bool) {
		t.Helper()
		res := build(t, bead, r)
		if res.Dropped() {
			return "", false
		}
		wr, _ := sealOne(t, *res.Resolved, 1, "obs_1").AsWorkReferenceObservation()
		return wr.WorkReference.TeamServerProjectId, true
	}
	if got, _ := project(t, "acme-1", ProjectResolver{StampedProjectID: "btsproj_stamped", Prefixes: pm}); got != "btsproj_stamped" {
		t.Errorf("stamped must win over the prefix map, got %q", got)
	}
	if got, _ := project(t, "acme-1", ProjectResolver{Prefixes: pm, DefaultProjectID: "btsproj_default"}); got != "btsproj_acme" {
		t.Errorf("acme-1 -> %q, want btsproj_acme", got)
	}
	if got, _ := project(t, "beta-7", ProjectResolver{Prefixes: pm}); got != "btsproj_beta" {
		t.Errorf("beta-7 -> %q, want btsproj_beta", got)
	}
	if got, _ := project(t, "zeta-7", ProjectResolver{Prefixes: pm, DefaultProjectID: "btsproj_default"}); got != "btsproj_default" {
		t.Errorf("unmapped id must fall back to the default, got %q", got)
	}
	if res := build(t, "zeta-7", ProjectResolver{Prefixes: pm}); !res.Dropped() || res.DropReason != RefDropUnresolvableProject {
		t.Errorf("unmapped id with no default must drop as unresolvable, got dropped=%v reason=%q", res.Dropped(), res.DropReason)
	}
	res := build(t, "dup-4", ProjectResolver{Prefixes: pm, DefaultProjectID: "btsproj_default"})
	if !res.Dropped() || res.DropReason != RefDropAmbiguousPrefix {
		t.Fatalf("ambiguous prefix must drop (no default fallback), got dropped=%v reason=%q", res.Dropped(), res.DropReason)
	}
	if res.Drop == nil || res.Drop.Kind() != "CAPTURE_DIAGNOSTIC" {
		t.Fatal("expected a CAPTURE_DIAGNOSTIC drop observation")
	}
	canon := canonicalOf(t, sealOne(t, *res.Drop, 1, "obs_1"))
	assertNoSubstrings(t, canon, "dup-4", "btsproj")
	if !strings.Contains(string(canon), "declared for more than one team-server project") {
		t.Errorf("ambiguous drop diagnostic does not say why: %s", canon)
	}
	if got, _ := project(t, "dup-4", ProjectResolver{StampedProjectID: "btsproj_stamped", Prefixes: pm}); got != "btsproj_stamped" {
		t.Errorf("stamped must win over an ambiguous prefix, got %q", got)
	}
}

// TestBeadPrefixMapEqual: Equal compares resolution and reported problems, so a reload of
// identical content can keep the current snapshot.
func TestBeadPrefixMapEqual(t *testing.T) {
	a := mustPrefixMap(t, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p1"}, BeadPrefixMapping{Prefix: "beta-", ProjectID: "p2"})
	b := mustPrefixMap(t, BeadPrefixMapping{Prefix: "beta-", ProjectID: "p2"}, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p1"})
	if !a.Equal(b) || !b.Equal(a) {
		t.Error("declaration order must not matter")
	}
	for name, o := range map[string]*BeadPrefixMap{
		"other_project": mustPrefixMap(t, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p9"}, BeadPrefixMapping{Prefix: "beta-", ProjectID: "p2"}),
		"fewer":         mustPrefixMap(t, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p1"}),
		"problems":      mustPrefixMap(t, BeadPrefixMapping{Prefix: "acme-", ProjectID: "p1"}, BeadPrefixMapping{Prefix: "beta-", ProjectID: "p2"}, BeadPrefixMapping{Prefix: "bad", ProjectID: "p3"}),
		"nil":           nil,
	} {
		if a.Equal(o) {
			t.Errorf("%s: unequal maps compare equal", name)
		}
	}
	var nilMap *BeadPrefixMap
	if !nilMap.Equal(mustPrefixMap(t)) {
		t.Error("nil and empty maps resolve identically")
	}
}
