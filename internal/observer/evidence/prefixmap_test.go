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
		bead, want string
		ok         bool
	}{
		{"gas-city-12", "proj_gascity", true},
		{"gas-12", "proj_gas", true},
		{"gas-cityx-1", "proj_gas", true},
		{"acme-9a", "proj_acme", true},
		{"beta-1", "", false},
		{"acme", "", false},
	}
	for _, c := range cases {
		got, ok := pm.Lookup(c.bead)
		if got != c.want || ok != c.ok {
			t.Errorf("Lookup(%q) = %q,%v want %q,%v", c.bead, got, ok, c.want, c.ok)
		}
	}
	if got := pm.Prefixes(); len(got) != 3 || got[0] != "gas-city-" {
		t.Errorf("Prefixes() = %v, want longest first", got)
	}
	var nilMap *BeadPrefixMap
	if _, ok := nilMap.Lookup("gas-1"); ok || nilMap.Len() != 0 || nilMap.Prefixes() != nil {
		t.Error("nil map must behave as empty")
	}
}

// TestBeadPrefixMapRejectsMalformed proves the map fails closed: a malformed or metacharacter
// prefix, an empty/oversized project id, an ambiguous prefix and an oversized map are refused
// whole, never half-applied. An exact duplicate is collapsed.
func TestBeadPrefixMapRejectsMalformed(t *testing.T) {
	bad := map[string][]BeadPrefixMapping{
		"no_trailing_dash":  {{Prefix: "acme", ProjectID: "p"}},
		"empty_prefix":      {{Prefix: "", ProjectID: "p"}},
		"bare_dash":         {{Prefix: "-", ProjectID: "p"}},
		"regex_meta":        {{Prefix: "a.*-", ProjectID: "p"}},
		"space":             {{Prefix: "ac me-", ProjectID: "p"}},
		"double_dash":       {{Prefix: "acme--", ProjectID: "p"}},
		"too_long":          {{Prefix: strings.Repeat("a", maxBeadPrefix) + "-", ProjectID: "p"}},
		"empty_project":     {{Prefix: "acme-", ProjectID: ""}},
		"oversized_project": {{Prefix: "acme-", ProjectID: strings.Repeat("p", maxTeamServerProject+1)}},
		"ambiguous":         {{Prefix: "acme-", ProjectID: "p1"}, {Prefix: "acme-", ProjectID: "p2"}},
	}
	for name, m := range bad {
		if _, err := NewBeadPrefixMap(m); err == nil {
			t.Errorf("%s: accepted, want error", name)
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
	if pm.Len() != 1 {
		t.Errorf("exact duplicate not collapsed: Len=%d", pm.Len())
	}
	if empty := mustPrefixMap(t); empty.Len() != 0 {
		t.Error("empty map should be valid and empty")
	}
}

// TestExtractedWorkReferencePrefixMapResolution pins the precedence: the stamped run context wins,
// then the longest matching prefix mapping, then the single default; an id no mapping covers with
// no default drops with a diagnostic.
func TestExtractedWorkReferencePrefixMapResolution(t *testing.T) {
	pm := mustPrefixMap(t,
		BeadPrefixMapping{Prefix: "acme-", ProjectID: "btsproj_acme"},
		BeadPrefixMapping{Prefix: "beta-", ProjectID: "btsproj_beta"},
	)
	project := func(t *testing.T, bead string, r ProjectResolver) (string, bool) {
		t.Helper()
		res, err := NewExtractedWorkReference(testCommon(), ExtractedWorkRefInput{BeadID: bead}, r)
		if err != nil {
			t.Fatalf("NewExtractedWorkReference: %v", err)
		}
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
	if _, ok := project(t, "zeta-7", ProjectResolver{Prefixes: pm}); ok {
		t.Error("unmapped id with no default must drop")
	}
}
