package segment

// Bead is a resolved bead: the team-server project that owns it and its id. Lanes resolve the
// ids a command names before applying effects; the segmenter compares beads by value.
type Bead struct {
	Project string `json:"project"`
	ID      string `json:"bead_id"`
}

// ResolvedEffect is an Effect whose id a lane resolved to exactly one project.
type ResolvedEffect struct {
	Op   Op
	Bead Bead
}

// Stack is a session's claim stack. The zero value is an empty stack ("none").
type Stack struct {
	beads []Bead
}

// NewStack returns a stack holding initial, bottom first (the last element is current).
func NewStack(initial ...Bead) *Stack {
	s := &Stack{}
	for _, b := range initial {
		s.open(b)
	}
	return s
}

// Current returns the top of the stack, or ok=false for "none".
func (s *Stack) Current() (Bead, bool) {
	if len(s.beads) == 0 {
		return Bead{}, false
	}
	return s.beads[len(s.beads)-1], true
}

// Depth is the number of open claims.
func (s *Stack) Depth() int { return len(s.beads) }

// Apply applies effects in order and reports whether the current bead changed.
func (s *Stack) Apply(effects []ResolvedEffect) bool {
	before, had := s.Current()
	for _, e := range effects {
		switch e.Op {
		case OpOpen:
			s.open(e.Bead)
		case OpClose:
			s.remove(e.Bead)
		}
	}
	after, has := s.Current()
	return had != has || before != after
}

func (s *Stack) open(b Bead) {
	s.remove(b)
	s.beads = append(s.beads, b)
}

func (s *Stack) remove(b Bead) {
	out := s.beads[:0]
	for _, x := range s.beads {
		if x != b {
			out = append(out, x)
		}
	}
	s.beads = out
}

// Tokens are one usage record's token counts. Absent counts are zero.
type Tokens struct {
	Input         int64 `json:"input_tokens,omitempty"`
	Output        int64 `json:"output_tokens,omitempty"`
	CacheCreation int64 `json:"cache_creation_tokens,omitempty"`
	CacheRead     int64 `json:"cache_read_tokens,omitempty"`
}

// Add returns t + u.
func (t Tokens) Add(u Tokens) Tokens {
	return Tokens{
		Input:         t.Input + u.Input,
		Output:        t.Output + u.Output,
		CacheCreation: t.CacheCreation + u.CacheCreation,
		CacheRead:     t.CacheRead + u.CacheRead,
	}
}

// Usage is one usage record of the session's ordered usage stream. Quality keeps the billed and
// estimated bands apart (§5.5): segment sums are kept per quality, never added across.
type Usage struct {
	Ref     string
	Quality string
	Tokens  Tokens
}

// Segment is a maximal stretch of a session's usage stream with a constant current bead.
type Segment struct {
	Ordinal int
	// Bead is nil for "not on a bead".
	Bead *Bead
	// OpenRef is the boundary that made Bead current ("" when it was current from the session
	// start). CloseRef is the boundary that ended the segment ("" for the session's last).
	OpenRef  string
	CloseRef string
	// UsageRefs are the refs of the segment's usage records, in stream order.
	UsageRefs []string
	// ByQuality sums the segment's tokens per usage quality.
	ByQuality map[string]Tokens
	// MultiClaim is true when more than one claim was open while the segment was current, the
	// known weakness of last-claimed-wins (§5.3).
	MultiClaim bool
}

// Segmenter cuts one session's ordered stream of boundaries and usage records into segments.
// Feed it in source order: Boundary after each successful boundary command's tool result, Usage
// for each usage record.
type Segmenter struct {
	stack       *Stack
	lastChange  string
	segments    []Segment
	open        *Segment
	diagnostics int
}

// New starts a session with the given initial claims (bottom first); none for an empty stack.
func New(initial ...Bead) *Segmenter {
	return &Segmenter{stack: NewStack(initial...)}
}

// Boundary applies a successful boundary command's resolved effects. ref identifies the command
// (an evidence id, a tool call id or a fragment ordinal). ambiguous counts boundary commands
// that named no readable bead; they have no effect and are only counted.
func (s *Segmenter) Boundary(ref string, effects []ResolvedEffect, ambiguous int) {
	s.diagnostics += ambiguous
	if s.stack.Apply(effects) {
		s.lastChange = ref
	}
}

// Usage attributes one usage record to the current bead.
func (s *Segmenter) Usage(u Usage) {
	cur, ok := s.stack.Current()
	var bead *Bead
	if ok {
		b := cur
		bead = &b
	}
	if s.open == nil || !sameBead(s.open.Bead, bead) {
		if s.open != nil {
			s.open.CloseRef = s.lastChange
			s.segments = append(s.segments, *s.open)
		}
		s.open = &Segment{
			Ordinal:   len(s.segments),
			Bead:      bead,
			OpenRef:   s.lastChange,
			ByQuality: map[string]Tokens{},
		}
	}
	s.open.UsageRefs = append(s.open.UsageRefs, u.Ref)
	s.open.ByQuality[u.Quality] = s.open.ByQuality[u.Quality].Add(u.Tokens)
	if s.stack.Depth() > 1 {
		s.open.MultiClaim = true
	}
}

// Segments returns the session's segments so far. The last one has an empty CloseRef.
func (s *Segmenter) Segments() []Segment {
	out := append([]Segment(nil), s.segments...)
	if s.open != nil {
		out = append(out, *s.open)
	}
	return out
}

// Diagnostics is the number of ambiguous boundary commands seen.
func (s *Segmenter) Diagnostics() int { return s.diagnostics }

func sameBead(a, b *Bead) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
