package segment

import "sort"

// Boundary is one successful boundary command at a position in the session. Pos orders it
// against usage records: for the transcript lane it is the tool result's time in Unix
// nanoseconds; for a lane with one ordered stream it is the stream index. Ref identifies it.
type Boundary struct {
	Pos       int64
	Ref       string
	Effects   []ResolvedEffect
	Ambiguous int
}

// Interval is a stretch of a session's positions during which the current bead is constant. It
// covers positions p with Start < p <= End; a nil Start is the session start and a nil End the
// session end. A usage record at exactly a boundary's position belongs to the interval BEFORE
// the boundary: the boundary applies after the tool result, and the record at that position is
// the one that issued the command.
type Interval struct {
	Ordinal int
	// Bead is nil for "not on a bead".
	Bead     *Bead
	OpenRef  string
	CloseRef string
	Start    *int64
	End      *int64
	// MultiClaim is true when more than one claim was open during the interval.
	MultiClaim bool
}

// Timeline cuts a session into intervals at the boundaries that change the current bead. It is
// the transcript lane's form of the segmenter: boundaries are known before usage, and usage is
// assigned afterwards with Assign. Boundaries must be sorted by Pos (ties keep their order). The
// result always has at least one interval; boundaries that do not change the current bead do
// not cut. diagnostics counts ambiguous boundary commands.
func Timeline(initial []Bead, boundaries []Boundary) (intervals []Interval, diagnostics int) {
	stack := NewStack(initial...)
	cur := func() *Bead {
		if b, ok := stack.Current(); ok {
			return &b
		}
		return nil
	}
	open := Interval{Bead: cur(), MultiClaim: stack.Depth() > 1}
	for _, b := range boundaries {
		diagnostics += b.Ambiguous
		if !stack.Apply(b.Effects) {
			if stack.Depth() > 1 {
				open.MultiClaim = true
			}
			continue
		}
		pos := b.Pos
		open.End = &pos
		open.CloseRef = b.Ref
		intervals = append(intervals, open)
		start := b.Pos
		open = Interval{
			Ordinal:    len(intervals),
			Bead:       cur(),
			OpenRef:    b.Ref,
			Start:      &start,
			MultiClaim: stack.Depth() > 1,
		}
	}
	intervals = append(intervals, open)
	return intervals, diagnostics
}

// Assign returns the index of the interval that holds position pos. intervals must be a
// Timeline result (contiguous, in order).
func Assign(intervals []Interval, pos int64) int {
	// The first interval whose End is nil or >= pos.
	return sort.Search(len(intervals), func(i int) bool {
		end := intervals[i].End
		return end == nil || pos <= *end
	})
}
