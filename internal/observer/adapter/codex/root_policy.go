//go:build unix

package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

const rootPolicyControlVersion = 1

// rootPolicyControl is the durable high-water record for one canonical root. Baselines are kept
// in the committed control record (as well as in individual cursors) so losing one cursor cannot
// turn a pre-consent identity into a byte-zero capture after restart.
type rootPolicyControl struct {
	Version    int              `json:"version"`
	Root       string           `json:"root"`
	Generation uint64           `json:"generation"`
	Active     bool             `json:"active"`
	Mode       rootpolicy.Mode  `json:"mode,omitempty"`
	Committed  bool             `json:"committed"`
	Baselines  map[string]int64 `json:"baselines,omitempty"`
}

type rootPolicyState struct {
	record  rootpolicy.Record
	id      string
	scope   string
	control rootPolicyControl
	path    string
	// dirty marks in-memory control changes a poll has made but not yet written. The watcher flushes
	// them once per root per poll rather than once per changed identity.
	dirty bool
}

func rootPolicyID(root string) string {
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:16])
}

func identityString(dev, ino uint64) string { return fmt.Sprintf("%d:%d", dev, ino) }

func newRootPolicyState(stateDir string, r rootpolicy.Record) (*rootPolicyState, error) {
	id := rootPolicyID(r.Path)
	path := filepath.Join(stateDir, "root-policy-"+id+".json")
	st := &rootPolicyState{record: r, id: id, scope: fmt.Sprintf("%s-g%d", id, r.Generation), path: path}
	data, err := osReadFile(path)
	if err != nil {
		if !isNotExist(err) {
			return nil, fmt.Errorf("read root-policy control: %w", err)
		}
		st.control = rootPolicyControl{Version: rootPolicyControlVersion, Root: r.Path, Generation: r.Generation, Active: r.Active, Mode: r.Mode}
		if err := st.persistControl(); err != nil {
			return nil, err
		}
		return st, nil
	}
	if err := json.Unmarshal(data, &st.control); err != nil {
		return nil, fmt.Errorf("decode root-policy control: %w", err)
	}
	if st.control.Version != rootPolicyControlVersion || st.control.Root != r.Path || st.control.Generation == 0 {
		return nil, fmt.Errorf("invalid root-policy control for %q", r.Path)
	}
	if r.Generation < st.control.Generation {
		return nil, fmt.Errorf("stale root-policy generation %d for %q (high-water is %d)", r.Generation, r.Path, st.control.Generation)
	}
	if r.Generation == st.control.Generation {
		if r.Active != st.control.Active || r.Mode != st.control.Mode {
			return nil, fmt.Errorf("non-idempotent root-policy generation %d for %q", r.Generation, r.Path)
		}
		return st, nil
	}
	// A higher generation fences all prior state. Persist the new high-water record before any
	// activation scan; its uncommitted marker makes a crash retry metadata-only sealing.
	st.control = rootPolicyControl{Version: rootPolicyControlVersion, Root: r.Path, Generation: r.Generation, Active: r.Active, Mode: r.Mode}
	if err := st.persistControl(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *rootPolicyState) persistControl() error {
	b, err := json.Marshal(s.control)
	if err != nil {
		return fmt.Errorf("encode root-policy control: %w", err)
	}
	if err := atomicWriteCursorFile(s.path, b); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

func (s *rootPolicyState) baseline(dev, ino uint64) (int64, bool) {
	if !s.control.Committed || s.record.Mode != rootpolicy.ForwardOnly {
		return 0, false
	}
	v, ok := s.control.Baselines[identityString(dev, ino)]
	return v, ok
}

// The indirections keep the policy state small and give tests a narrow seam without exposing it.
var osReadFile = os.ReadFile
var isNotExist = os.IsNotExist
