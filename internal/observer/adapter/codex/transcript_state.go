package codex

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"time"
)

// transcriptCarry is everything the parse of one transcript FILE carries from one buffer to the
// next. Parse state is otherwise per buffer, but these facts belong to the file: which source its
// usage comes from, which session it is in and whether that session's start went out, and which
// Claude responses are still waiting for their final record or were already counted. The durable
// cursor commits the carry with the consumed offset, persists it, and hands it to the next
// buffer's parse, so a poll split or a daemon restart resumes the file in exactly the state its
// consumed bytes left. It holds counts, ids and times — never transcript content.
type transcriptCarry struct {
	// rollout is the Codex usage source (record mode, legacy repeat total, upgrade pending).
	rollout rolloutCarry
	// session is the native session the transcript is in.
	session sessionCarry
	// claude is the per-message Claude usage state.
	claude claudeCarry
}

// clone returns a copy that shares no mutable memory with c. A parse works on a clone: the
// cursor's committed carry must stay untouched until the parse's candidates are durably delivered
// and its commit runs.
func (c transcriptCarry) clone() transcriptCarry {
	c.claude = c.claude.clone()
	c.session.Sessions = slices.Clone(c.session.Sessions)
	return c
}

// sessionCarry is the native session of one transcript file as its parse has seen it so far.
type sessionCarry struct {
	// NativeID is the session the transcript is in: a Codex rollout's own (first) session_meta id,
	// or the sessionId of the latest Claude record. Empty until a record names one.
	NativeID string `json:"native_session_id,omitempty"`
	// Provider is NativeID's provider: codex or claude.
	Provider string `json:"provider,omitempty"`
	// StartedAt is when the session's transcript started: a rollout's session_meta time, or the
	// earliest record time of a Claude session before its start went out. Zero when no record of the
	// session carried a time.
	StartedAt time.Time `json:"started_at,omitzero"`
	// Started is set once the session's SESSION_LIFECYCLE start was emitted.
	Started bool `json:"started,omitempty"`
	// Sessions are the sessions whose start this transcript emitted, NativeID's included, oldest
	// first: a transcript that moves to another session and back does not start the first again.
	Sessions []string `json:"started_sessions,omitempty"`
}

// maxStartedSessions bounds sessionCarry.Sessions. A transcript names more than two sessions only
// when a conversation is resumed into it repeatedly.
const maxStartedSessions = 16

// enter moves the transcript to session id of provider. A session it started before resumes
// started; any other waits for its own start.
func (s *sessionCarry) enter(id, provider string) {
	*s = sessionCarry{NativeID: id, Provider: provider, Started: slices.Contains(s.Sessions, id), Sessions: s.Sessions}
}

// markStarted records that the current session's start went out.
func (s *sessionCarry) markStarted() {
	s.Started = true
	if slices.Contains(s.Sessions, s.NativeID) {
		return
	}
	s.Sessions = append(s.Sessions, s.NativeID)
	if len(s.Sessions) > maxStartedSessions {
		s.Sessions = slices.Delete(s.Sessions, 0, len(s.Sessions)-maxStartedSessions)
	}
}

// SessionRef names the native session a candidate belongs to.
type SessionRef struct {
	NativeID string
	Provider string
}

// ref returns the session for stamping onto candidates, nil until the session's start is out.
func (s sessionCarry) ref() *SessionRef {
	if !s.Started || s.NativeID == "" {
		return nil
	}
	return &SessionRef{NativeID: s.NativeID, Provider: s.Provider}
}

// Bounds on the per-transcript Claude state the cursor persists.
const (
	// maxOpenClaudeMessages bounds the responses waiting for their final record. Claude Code
	// streams at most a handful of responses into one transcript at once (5 in a sample of 40k
	// transcripts); past the bound the oldest is counted with the usage it has.
	maxOpenClaudeMessages = 32
	// maxResponseLineage bounds the record uuids kept per open response. A record names the record
	// it follows, which is always one of the latest of its branch, so only the newest are needed.
	maxResponseLineage = 64
)

// claudeCarry is the Claude usage state of one transcript.
type claudeCarry struct {
	// Open are the responses whose usage waits for their final record, in the order they began.
	Open []claudeMessage `json:"open,omitempty"`
	// Counted holds every message id the transcript has already counted, so no later record of a
	// counted response — a trailing content block, or a copy of the whole history that a resumed
	// agent writes back into its transcript — is counted again. It grows with the transcript, so the
	// cursor keeps it out of its state file, in an append-only sidecar (see Cursor.Save).
	Counted messageIDSet `json:"-"`
	// Unsaved are the ids Counted gained since the cursor last saved, in the order they were
	// counted: what the next save appends to the sidecar.
	Unsaved []uint64 `json:"-"`
}

func (c claudeCarry) clone() claudeCarry {
	open := make([]claudeMessage, len(c.Open))
	for i, m := range c.Open {
		m.Lineage = slices.Clone(m.Lineage)
		open[i] = m
	}
	if len(open) == 0 {
		open = nil
	}
	return claudeCarry{Open: open, Counted: slices.Clone(c.Counted), Unsaved: slices.Clone(c.Unsaved)}
}

// count records a response as counted, reporting whether it was not yet.
func (c *claudeCarry) count(key uint64) bool {
	if !c.Counted.add(key) {
		return false
	}
	c.Unsaved = append(c.Unsaved, key)
	return true
}

// claudeMessage is one Claude response (one message.id) whose usage is not counted yet.
type claudeMessage struct {
	// Key is the hash of the response's message.id, its identity. Any non-empty id collapses the
	// response's records, even one too long or malformed to be carried as the spend-join key.
	Key uint64 `json:"key"`
	// ID is the message.id the USAGE carries as its message_id: empty when the id is not a usable
	// join key (see joinKeyID).
	ID string `json:"id,omitempty"`
	// Usage is the usage on the response's latest record.
	Usage claudeUsage `json:"usage"`
	// OccurredAt is the latest record's time, the time its usage is reported at.
	OccurredAt time.Time `json:"occurred_at,omitzero"`
	// Lineage is the response's branch of the transcript's record tree: the uuids of its own
	// records and of every record that follows from them (its tool results, attachments, ...),
	// newest last. A new response or a user turn that follows from one of them continues this
	// response's branch, which Claude Code does only once this response finished.
	Lineage recordTrail `json:"lineage,omitempty"`
}

// idHash is the 64-bit FNV-1a hash the Claude state keeps in place of a message id or record uuid:
// eight bytes whatever the id's length. A collision between two ids of one transcript (around
// n²/2⁶⁵) could drop a response's usage or count one early; for a million ids that is a 3·10⁻⁸
// chance.
func idHash(id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}

// messageIDSet is a set of message ids, kept as their sorted hashes.
type messageIDSet []uint64

func (s messageIDSet) has(key uint64) bool {
	_, found := slices.BinarySearch(s, key)
	return found
}

// add inserts key, reporting whether it was not in the set yet.
func (s *messageIDSet) add(key uint64) bool {
	i, found := slices.BinarySearch(*s, key)
	if !found {
		*s = slices.Insert(*s, i, key)
	}
	return !found
}

// recordTrail is a bounded list of record uuids, kept as their hashes, newest last.
type recordTrail []uint64

func (t recordTrail) has(uuid string) bool { return slices.Contains(t, idHash(uuid)) }

func (t *recordTrail) add(uuid string) {
	h := idHash(uuid)
	if slices.Contains(*t, h) {
		return
	}
	*t = append(*t, h)
	if len(*t) > maxResponseLineage {
		*t = slices.Delete(*t, 0, len(*t)-maxResponseLineage)
	}
}

// MarshalJSON persists the trail as base64 of its big-endian hashes.
func (t recordTrail) MarshalJSON() ([]byte, error) { return marshalHashes(t) }

// UnmarshalJSON restores a trail persisted by MarshalJSON.
func (t *recordTrail) UnmarshalJSON(data []byte) error {
	trail, err := unmarshalHashes(data)
	if err != nil {
		return fmt.Errorf("response lineage: %w", err)
	}
	*t = trail
	return nil
}

func marshalHashes(hashes []uint64) ([]byte, error) {
	b := make([]byte, 8*len(hashes))
	for i, h := range hashes {
		binary.BigEndian.PutUint64(b[8*i:], h)
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func unmarshalHashes(data []byte) ([]uint64, error) {
	var enc string
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b)%8 != 0 {
		return nil, fmt.Errorf("not a whole number of base64 hashes")
	}
	if len(b) == 0 {
		return nil, nil
	}
	hashes := make([]uint64, len(b)/8)
	for i := range hashes {
		hashes[i] = binary.BigEndian.Uint64(b[8*i:])
	}
	return hashes, nil
}

// startSession emits the transcript session's start, once: with the model when a record named it,
// at the time the transcript started (the triggering record's time when no earlier record carried
// one). It emits nothing before a record named the session or after the start went out.
func (st *parseState) startSession(model string, ts time.Time, lineNo int) []*Candidate {
	s := &st.carry.session
	if s.Started || s.NativeID == "" {
		return nil
	}
	s.markStarted()
	at := s.StartedAt
	if at.IsZero() {
		at = ts
	}
	return []*Candidate{sessionLifecycleCandidate(s.NativeID, s.Provider, model, at, lineNo)}
}

// attribute ties a native dialect's candidates to the transcript's session. Usage that arrives
// before any record named the model still needs its session, so the start goes out first, without
// a model — the platform withholds a price for that, rather than pricing the usage at a model it
// cannot know. Every candidate parsed after the start carries the session (see Candidate.Session).
func (st *parseState) attribute(cands []*Candidate) []*Candidate {
	if len(cands) == 0 {
		return cands
	}
	out := make([]*Candidate, 0, len(cands)+1)
	for _, c := range cands {
		if c.Kind == KindUsage {
			out = append(out, st.startSession("", c.OccurredAt, c.LineNumber)...)
		}
		if c.Session == nil {
			c.Session = st.carry.session.ref()
		}
		out = append(out, c)
	}
	return out
}

// stamp gives a line's candidates that carry no session yet — its diagnostics — the session the
// transcript is in, once that session's start is out.
func (st *parseState) stamp(cands []*Candidate) []*Candidate {
	ref := st.carry.session.ref()
	if ref == nil {
		return cands
	}
	for _, c := range cands {
		if c.Session == nil && c.Kind != KindSessionLifecycle {
			c.Session = &SessionRef{NativeID: ref.NativeID, Provider: ref.Provider}
		}
	}
	return cands
}
