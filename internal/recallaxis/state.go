package recallaxis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Status is a per-file dedup outcome.
type Status string

const (
	StatusSent     Status = "sent"
	StatusRejected Status = "rejected"
)

// FileState is the persisted dedup record for one transcript file. blake3 keys the "same
// content => don't re-send" check; mtime_ns + size are the cheap unchanged short-circuit;
// status records whether the content was sent or terminally rejected (so a rejection is
// never retried until the content changes).
type FileState struct {
	Status  Status `json:"status"`
	Blake3  string `json:"blake3"`
	MtimeNS int64  `json:"mtime_ns"`
	Size    int64  `json:"size"`
	Code    int    `json:"code,omitempty"`
}

// State is the dedup map keyed by resolved file path.
type State struct {
	files map[string]FileState
}

// NewState returns an empty State.
func NewState() *State { return &State{files: map[string]FileState{}} }

// Get returns the stored record for path.
func (s *State) Get(path string) (FileState, bool) {
	fs, ok := s.files[path]
	return fs, ok
}

// Put stores a record for path.
func (s *State) Put(path string, fs FileState) { s.files[path] = fs }

// Len reports how many files are tracked.
func (s *State) Len() int { return len(s.files) }

// LoadState reads the JSON state file. A missing or malformed file yields an empty
// State and a nil error (the Python treats both as "{}").
func LoadState(path string) (*State, error) {
	st := NewState()
	raw, err := os.ReadFile(path)
	if err != nil {
		return st, nil
	}
	_ = json.Unmarshal(raw, &st.files) // malformed => stay empty, mirror Python
	if st.files == nil {
		st.files = map[string]FileState{}
	}
	return st, nil
}

// SaveState atomically writes the JSON state file (write to a temp sibling, then
// rename), mirroring the Python mkstemp + os.replace. The parent dir is created 0700 and
// the temp file 0600 so the dedup record (which lists transcript paths) is owner-only.
func SaveState(path string, st *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Marshal with sorted keys for a stable, diffable file.
	keys := make([]string, 0, len(st.files))
	for k := range st.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]FileState, len(keys))
	for _, k := range keys {
		ordered[k] = st.files[k]
	}
	data, err := json.Marshal(ordered)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
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
