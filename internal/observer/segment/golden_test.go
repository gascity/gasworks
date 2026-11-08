package segment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The golden corpus is shared with gasworks-platform's vendored copy (internal/beadsegment). A
// case is one session: its initial claims, the ids the lane cannot resolve, and its ordered
// events (tool calls with their command, result and error flag; usage records). Both repositories
// run every case through both lane forms and require the same answer.

const goldenProject = "proj"

type goldenCase struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Initial     []string      `json:"initial"`
	Unresolved  []string      `json:"unresolved"`
	Events      []goldenEvent `json:"events"`
	Want        goldenWant    `json:"want"`
}

type goldenEvent struct {
	Ref     string        `json:"ref"`
	Command *string       `json:"command,omitempty"`
	Result  string        `json:"result,omitempty"`
	IsError bool          `json:"is_error,omitempty"`
	Usage   *goldenTokens `json:"usage,omitempty"`
}

type goldenTokens struct {
	Quality string `json:"quality"`
	Tokens
}

type goldenWant struct {
	Segments    []goldenSegment     `json:"segments"`
	Diagnostics int                 `json:"diagnostics"`
	Tokens      []map[string]Tokens `json:"tokens,omitempty"`
}

type goldenSegment struct {
	Bead       *string  `json:"bead"`
	OpenRef    string   `json:"open_ref"`
	CloseRef   string   `json:"close_ref"`
	UsageRefs  []string `json:"usage_refs"`
	MultiClaim bool     `json:"multi_claim"`
}

func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no golden cases")
	}
	sort.Strings(paths)
	cases := make([]goldenCase, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var c goldenCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		cases = append(cases, c)
	}
	return cases
}

// resolveGolden is the corpus's lane resolver: every id resolves to goldenProject except the
// case's unresolved ids, whose effects are dropped (no effect, §5.2).
func resolveGolden(c goldenCase, effects []Effect) []ResolvedEffect {
	out := make([]ResolvedEffect, 0, len(effects))
	for _, e := range effects {
		skip := false
		for _, u := range c.Unresolved {
			if u == e.BeadID {
				skip = true
			}
		}
		if !skip {
			out = append(out, ResolvedEffect{Op: e.Op, Bead: Bead{Project: goldenProject, ID: e.BeadID}})
		}
	}
	return out
}

func initialBeads(c goldenCase) []Bead {
	out := make([]Bead, 0, len(c.Initial))
	for _, id := range c.Initial {
		out = append(out, Bead{Project: goldenProject, ID: id})
	}
	return out
}

// boundaryOf parses one tool-call event; ok is false for a failed call, which has no effect.
func boundaryOf(c goldenCase, e goldenEvent) ([]ResolvedEffect, int, bool) {
	if e.IsError {
		return nil, 0, false
	}
	p := ParseCommand(*e.Command, e.Result)
	return resolveGolden(c, p.Effects), p.Ambiguous, true
}

func TestGoldenCorpusStreamLane(t *testing.T) {
	for _, c := range loadGolden(t) {
		t.Run(c.Name, func(t *testing.T) {
			s := New(initialBeads(c)...)
			for _, e := range c.Events {
				switch {
				case e.Command != nil:
					if effects, ambiguous, ok := boundaryOf(c, e); ok {
						s.Boundary(e.Ref, effects, ambiguous)
					}
				case e.Usage != nil:
					s.Usage(Usage{Ref: e.Ref, Quality: e.Usage.Quality, Tokens: e.Usage.Tokens})
				}
			}
			got := s.Segments()
			want := c.Want.Segments
			if len(got) != len(want) {
				t.Fatalf("segments = %d, want %d: %+v", len(got), len(want), got)
			}
			for i := range got {
				g, w := got[i], want[i]
				var gb *string
				if g.Bead != nil {
					if g.Bead.Project != goldenProject {
						t.Errorf("segment %d project = %q", i, g.Bead.Project)
					}
					id := g.Bead.ID
					gb = &id
				}
				if !reflect.DeepEqual(gb, w.Bead) {
					t.Errorf("segment %d bead = %v, want %v", i, deref(gb), deref(w.Bead))
				}
				if g.Ordinal != i || g.OpenRef != w.OpenRef || g.CloseRef != w.CloseRef ||
					!reflect.DeepEqual(g.UsageRefs, w.UsageRefs) || g.MultiClaim != w.MultiClaim {
					t.Errorf("segment %d = %+v, want %+v", i, g, w)
				}
				if c.Want.Tokens != nil && !reflect.DeepEqual(g.ByQuality, c.Want.Tokens[i]) {
					t.Errorf("segment %d tokens = %+v, want %+v", i, g.ByQuality, c.Want.Tokens[i])
				}
			}
			if s.Diagnostics() != c.Want.Diagnostics {
				t.Errorf("diagnostics = %d, want %d", s.Diagnostics(), c.Want.Diagnostics)
			}
		})
	}
}

// TestGoldenCorpusTimelineLane runs the transcript lane's form: boundaries first (positioned by
// event index), then each usage record assigned to its interval. Every usage record must land on
// the bead the stream lane gave it.
func TestGoldenCorpusTimelineLane(t *testing.T) {
	for _, c := range loadGolden(t) {
		t.Run(c.Name, func(t *testing.T) {
			var boundaries []Boundary
			for i, e := range c.Events {
				if e.Command == nil {
					continue
				}
				if effects, ambiguous, ok := boundaryOf(c, e); ok {
					boundaries = append(boundaries, Boundary{Pos: int64(i), Ref: e.Ref, Effects: effects, Ambiguous: ambiguous})
				}
			}
			intervals, diagnostics := Timeline(initialBeads(c), boundaries)
			if diagnostics != c.Want.Diagnostics {
				t.Errorf("diagnostics = %d, want %d", diagnostics, c.Want.Diagnostics)
			}
			want := map[string]*string{}
			for _, s := range c.Want.Segments {
				for _, ref := range s.UsageRefs {
					want[ref] = s.Bead
				}
			}
			for i, e := range c.Events {
				if e.Usage == nil {
					continue
				}
				iv := intervals[Assign(intervals, int64(i))]
				var got *string
				if iv.Bead != nil {
					id := iv.Bead.ID
					got = &id
				}
				if !reflect.DeepEqual(got, want[e.Ref]) {
					t.Errorf("usage %s on %v, want %v", e.Ref, deref(got), deref(want[e.Ref]))
				}
			}
			for i, iv := range intervals {
				if iv.Ordinal != i {
					t.Errorf("interval %d ordinal %d", i, iv.Ordinal)
				}
				if i > 0 && (iv.Start == nil || intervals[i-1].End == nil || *iv.Start != *intervals[i-1].End || iv.OpenRef != intervals[i-1].CloseRef) {
					t.Errorf("interval %d does not continue interval %d", i, i-1)
				}
			}
			if intervals[0].Start != nil || intervals[len(intervals)-1].End != nil {
				t.Error("timeline must cover the whole session")
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}
