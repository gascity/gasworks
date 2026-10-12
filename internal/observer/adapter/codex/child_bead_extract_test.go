package codex

import (
	"testing"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestExtractChildBeadsTruePositives: hierarchical child bead ids (<parent>.<n>[.<n>...]) surfaced
// by bd show/close/update are captured whole, alongside their parent, without truncation to the
// parent id and with trailing sentence punctuation trimmed.
func TestExtractChildBeadsTruePositives(t *testing.T) {
	res := Parse(readFixture(t, "beads_child_truepos.jsonl"), defaultRefConfig())
	got := beadRefs(res.Candidates)
	want := []string{"ga-xpw.13.3", "ga-xpw", "ga-a1b2.1", "ga-5g3her.2.10"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected bead ref %q, got %v", w, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("bead refs = %v, want exactly %v", got, want)
	}
	for _, c := range res.Candidates {
		if c.Kind == KindWorkReference {
			canonicalBytes(t, c)
		}
	}
}

// TestChildBeadPatternBoundaries pins the child-segment grammar: only numeric dot segments extend
// an id, so path/extension tokens remain rejected (spec finding 4) and a trailing '.' is trimmed.
func TestChildBeadPatternBoundaries(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"bd show ga-xpw.13.3", []string{"ga-xpw.13.3"}},
		{"bd close ga-a1b2.1.", []string{"ga-a1b2.1"}},
		{"bd update (ga-a1b2.1)", []string{"ga-a1b2.1"}},
		{"bd show ga-x-repair.4", []string{"ga-x-repair.4"}},
		{"bd export --out ga-pilot.git", nil},
		{"bd export --out ga-1.json", nil},
		{"bd show ga-1.2a", nil},
		{"bd show ga-1..2", nil},
		{"bd show ga-.1", nil},
	}
	for _, c := range cases {
		refs, _ := ExtractReferences(wire.ExtractionProvenanceSurfaceTOOLCALL,
			SurfaceText{Tool: "bd", Text: c.text}, defaultRefConfig())
		var ids []string
		for _, r := range refs {
			if r.Kind == RefKindBead {
				ids = append(ids, r.Work.BeadID)
			}
		}
		if len(ids) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.text, ids, c.want)
			continue
		}
		for i := range ids {
			if ids[i] != c.want[i] {
				t.Errorf("%q: got %v, want %v", c.text, ids, c.want)
			}
		}
	}
}

// TestPrefixMapResolvesChildBeadByPrefix: a child id resolves to the project of its prefix through
// the prefix map (the bts-xpw.13.3 probe from the gasworks#93 review), and nested-prefix longest
// match still applies to child ids.
func TestPrefixMapResolvesChildBeadByPrefix(t *testing.T) {
	src := &swapSource{m: prefixMapOf(t, "bts-", "proj_bts", "bts-ops-", "proj_ops")}
	cfg := ReferenceConfig{PrefixMap: src}

	got := beadProjects(t, "bd show bts-xpw.13.3 bts-xpw && bd close bts-a1b2.1 bts-ops-7.2", cfg)
	want := map[string]string{
		"bts-xpw.13.3": "proj_bts",
		"bts-xpw":      "proj_bts",
		"bts-a1b2.1":   "proj_bts",
		"bts-ops-7.2":  "proj_ops",
	}
	if len(got) != len(want) {
		t.Fatalf("extracted %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %q, want %q", k, got[k], v)
		}
	}
}
