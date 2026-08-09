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

const (
	// rootPolicyControlVersion is the on-disk schema version of a root's control record. v2 stores a
	// fingerprint of the bytes ending at each floor beside the floor itself; v1 stored the floor
	// alone, as a bare integer.
	rootPolicyControlVersion = 2
	// rootPolicyControlMinVersion is the oldest schema this build reads. An older record keeps every
	// floor it carries and is re-stamped at the next write.
	rootPolicyControlMinVersion = 1

	// floorFingerprintLen is how many bytes ending at a sealed floor are fingerprinted. It matches the
	// cursor's anchor window: wide enough that a rewritten prefix cannot land on the same hash by
	// coincidence, narrow enough that corroborating a floor stays one bounded pread per drain.
	floorFingerprintLen = 64
)

// baselineRecord is one identity's durable forward-only seal: the floor no delivery may reach below,
// plus a fingerprint of the bytes immediately preceding it. The fingerprint is recorded lazily, on
// the first drain after the seal (the seal pass itself is stat-only and never opens a transcript),
// and re-checked before every read past the floor, which is what turns an in-place rewrite of the
// sealed prefix into a detected reseal instead of a tail parsed mid-record.
type baselineRecord struct {
	Floor           int64  `json:"floor"`
	FingerprintHash uint64 `json:"fingerprint_hash,omitempty"`
	FingerprintLen  int    `json:"fingerprint_len,omitempty"`
}

func (b baselineRecord) hasFingerprint() bool { return b.FingerprintLen > 0 }

// UnmarshalJSON accepts both the v2 object form and the v1 form, where a baseline was written as
// the bare floor integer. Losing a floor on upgrade would republish a whole pre-consent prefix on
// the next poll, so an unreadable baseline is never silently dropped.
func (b *baselineRecord) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '{' {
		type record baselineRecord
		var r record
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		*b = baselineRecord(r)
		return nil
	}
	return json.Unmarshal(data, &b.Floor)
}

// rootPolicyControl is the durable high-water record for one canonical root. Baselines are kept
// in the committed control record (as well as in individual cursors) so losing one cursor cannot
// turn a pre-consent identity into a byte-zero capture after restart.
type rootPolicyControl struct {
	Version    int                       `json:"version"`
	Root       string                    `json:"root"`
	Generation uint64                    `json:"generation"`
	Active     bool                      `json:"active"`
	Mode       rootpolicy.Mode           `json:"mode,omitempty"`
	Committed  bool                      `json:"committed"`
	Baselines  map[string]baselineRecord `json:"baselines,omitempty"`
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
	if st.control.Version < rootPolicyControlMinVersion || st.control.Version > rootPolicyControlVersion || st.control.Root != r.Path || st.control.Generation == 0 {
		return nil, fmt.Errorf("invalid root-policy control for %q", r.Path)
	}
	if st.control.Version < rootPolicyControlVersion {
		// Upgrade in place: every floor decoded above is kept as-is, and the fingerprints the older
		// schema never held are recorded on each file's next drain. The re-stamped record reaches disk
		// with the next flush.
		st.control.Version = rootPolicyControlVersion
		st.dirty = true
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

func (s *rootPolicyState) baseline(dev, ino uint64) (baselineRecord, bool) {
	if !s.control.Committed || s.record.Mode != rootpolicy.ForwardOnly {
		return baselineRecord{}, false
	}
	v, ok := s.control.Baselines[identityString(dev, ino)]
	return v, ok
}

// setBaseline records one identity's floor (and whatever fingerprint accompanies it) in memory and
// marks the root for this poll's single control write. A caller that must not lose the change across
// a crash (a reseal onto a diverged file) persists the control itself right after.
func (s *rootPolicyState) setBaseline(dev, ino uint64, b baselineRecord) {
	if s.control.Baselines == nil {
		s.control.Baselines = map[string]baselineRecord{}
	}
	s.control.Baselines[identityString(dev, ino)] = b
	s.dirty = true
}

// The indirections keep the policy state small and give tests a narrow seam without exposing it.
var osReadFile = os.ReadFile
var isNotExist = os.IsNotExist
