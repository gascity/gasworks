package usageaxis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Cursor is the per-source resume point. Offset is the byte position in the ledger
// up to which every fact has been confirmed-forwarded. NextSeq is the seq to assign
// to the NEXT new fact — it is GLOBALLY monotonic per source and NEVER resets, even
// across a ledger rotation, so usage-ingest's per-(org|source) seq high-water-mark
// can drop a forwarder replay without dropping a genuinely new fact. FileID is the
// ledger's filesystem identity (inode on unix; 0 when unsupported) used to detect a
// rename-and-recreate rotation that a size check alone would miss.
type Cursor struct {
	Offset  int64  `json:"offset"`
	NextSeq uint64 `json:"next_seq"`
	FileID  uint64 `json:"file_id,omitempty"`
}

// State maps source_id -> Cursor. One forwarder instance tails one ledger today, but
// the map shape matches the events cursors.json so multi-source is a later add.
type State struct {
	cursors map[string]Cursor
}

// NewState returns an empty State.
func NewState() *State { return &State{cursors: map[string]Cursor{}} }

// Get returns the cursor for a source (zero Cursor + false if unseen).
func (s *State) Get(source string) (Cursor, bool) {
	c, ok := s.cursors[source]
	return c, ok
}

// Put stores the cursor for a source.
func (s *State) Put(source string, c Cursor) { s.cursors[source] = c }

// LoadState reads the JSON cursor file. A missing or malformed file yields an empty
// State and a nil error (start from the top of the ledger).
func LoadState(path string) (*State, error) {
	st := NewState()
	raw, err := os.ReadFile(path)
	if err != nil {
		return st, nil
	}
	_ = json.Unmarshal(raw, &st.cursors) // malformed => stay empty
	if st.cursors == nil {
		st.cursors = map[string]Cursor{}
	}
	return st, nil
}

// SaveState atomically writes the JSON cursor file (temp sibling + rename). The
// parent dir is 0700 and the temp file 0600 — the cursor file lists no secrets, but
// keep it owner-only for consistency with the other axes.
func SaveState(path string, st *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(st.cursors))
	for k := range st.cursors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]Cursor, len(keys))
	for _, k := range keys {
		ordered[k] = st.cursors[k]
	}
	data, err := json.Marshal(ordered)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cursors-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
