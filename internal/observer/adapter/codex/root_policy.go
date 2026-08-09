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

	// maxSealLineages is a backstop on how many per-locator seal lineages one root retains. It is not
	// the operative bound: an entry exists only for a locator that is occupied in the current
	// generation and is dropped the moment a complete walk finds that locator empty, so the steady
	// state is one entry per sealed transcript - the cardinality the baseline map already carries.
	// Past the cap new locators are simply not admitted, which degrades toward capture for files
	// discovered later rather than trading away a fence that is already established.
	maxSealLineages = 65536
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

// sealLineage is a locator's memory of the floor sealed over whatever file occupies it, kept so a
// NEW inode appearing at the path of a sealed transcript can inherit that floor instead of being
// captured from byte zero. That is the rewrite-via-rename hole: sed -i, an editor save, and most
// sync tools write a temp file and rename it over the original, which leaves the path the owner was
// told is sealed untouched while the inode - the identity every cursor and baseline keys on - is
// brand new.
type sealLineage struct {
	Floor           int64  `json:"floor"`
	FingerprintHash uint64 `json:"fingerprint_hash,omitempty"`
	FingerprintLen  int    `json:"fingerprint_len,omitempty"`
	// Generation fences a lineage to the consent interval that sealed it. The control record is
	// rewritten from scratch when the generation advances, so this is defence in depth: an entry that
	// somehow survived a re-registration still cannot fence the new generation's files.
	Generation uint64 `json:"generation"`
	// Device / Inode name the identity that last held this locator, so a rename moves only the entry
	// that identity actually owns.
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (l sealLineage) baseline() baselineRecord {
	return baselineRecord{Floor: l.Floor, FingerprintHash: l.FingerprintHash, FingerprintLen: l.FingerprintLen}
}

// rootPolicyControl is the durable high-water record for one canonical root. Baselines are kept
// in the committed control record (as well as in individual cursors) so losing one cursor cannot
// turn a pre-consent identity into a byte-zero capture after restart. Lineages index the same
// floors by locator, which is what survives the one thing an identity cannot: being replaced.
// Lineages is a v2 addition rather than a schema bump - it is optional, an older build ignores it,
// and a control record without it loses only the cross-rename fence, never a floor.
type rootPolicyControl struct {
	Version    int                       `json:"version"`
	Root       string                    `json:"root"`
	Generation uint64                    `json:"generation"`
	Active     bool                      `json:"active"`
	Mode       rootpolicy.Mode           `json:"mode,omitempty"`
	Committed  bool                      `json:"committed"`
	Baselines  map[string]baselineRecord `json:"baselines,omitempty"`
	Lineages   map[string]sealLineage    `json:"lineages,omitempty"`
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
	// absentLineagePolls counts, per locator, the consecutive complete and error-free walks that have
	// positively found that locator empty. It is deliberately in-memory only: the count is evidence
	// this process gathered, and a restart re-gathers it rather than retiring a fence on a
	// predecessor's word.
	absentLineagePolls map[string]int
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

// setBaseline records one identity's floor (and whatever fingerprint accompanies it) in memory,
// carries it into the locator's seal lineage, and marks the root for this poll's single control
// write. A caller that must not lose the change across a crash (a reseal onto a diverged file)
// persists the control itself right after.
func (s *rootPolicyState) setBaseline(locator string, dev, ino uint64, b baselineRecord) {
	if s.control.Baselines == nil {
		s.control.Baselines = map[string]baselineRecord{}
	}
	s.control.Baselines[identityString(dev, ino)] = b
	s.setLineage(locator, dev, ino, b)
	s.dirty = true
}

// setLineage points a locator at the floor the identity now sitting there is sealed over. A floor at
// byte zero has no pre-consent prefix beneath it and so carries nothing worth inheriting: it drops
// the entry instead, which is also how a truncation all the way to zero lowers a lineage - but only
// for the identity the fence names, because fenceHolds turns every other write into a ratchet.
func (s *rootPolicyState) setLineage(locator string, dev, ino uint64, b baselineRecord) {
	if locator == "" {
		return
	}
	if s.fenceHolds(locator, dev, ino, b.Floor) {
		return
	}
	if b.Floor <= 0 {
		delete(s.control.Lineages, locator)
		return
	}
	if _, known := s.control.Lineages[locator]; !known && len(s.control.Lineages) >= maxSealLineages {
		return
	}
	if s.control.Lineages == nil {
		s.control.Lineages = map[string]sealLineage{}
	}
	s.control.Lineages[locator] = sealLineage{
		Floor:           b.Floor,
		FingerprintHash: b.FingerprintHash,
		FingerprintLen:  b.FingerprintLen,
		Generation:      s.control.Generation,
		Device:          dev,
		Inode:           ino,
	}
}

// liveFence returns the fence standing at a locator right now, which is the only kind of entry that
// fences anything: one recorded in the CURRENT consent generation (a re-registration mints a new
// generation, and consent given again is consent to reseal) over a floor above byte zero (a floor at
// zero has no pre-consent prefix beneath it).
func (s *rootPolicyState) liveFence(locator string) (sealLineage, bool) {
	lin, ok := s.control.Lineages[locator]
	if !ok || lin.Generation != s.control.Generation || lin.Floor <= 0 {
		return sealLineage{}, false
	}
	return lin, true
}

// fenceHolds reports that a live fence at locator must NOT be written down to floor on behalf of
// (dev,ino), and it is the whole of the ratchet: a live fence is lowered - or, at a floor of zero,
// deleted - only by the very identity it names.
//
// The identity is the distinction, because it is what says where the sealed bytes are (bd-main-9xl).
// A sealed file that shrinks its OWN floor really did destroy the bytes above it: an in-place
// truncation or a rewrite beneath the floor leaves nothing anywhere for the fence to protect, and
// lowering there is honest bookkeeping that the reseal diagnostic reports (A22). Any OTHER identity
// at that locator is a replacement standing where a sealed transcript used to be, and its own end of
// file says nothing about the sealed bytes: those are alive in the file that rotated away, which is
// the whole reason the name it left keeps a fence through its retirement window. Resealing at the
// replacement's size cut that floor down to the interposed file's length - or deleted the fence
// outright when the interposition held no bytes at all - and the next copy of the owner's pre-consent
// history put back at the name inherited the cut floor and published everything above it. So a
// replacement may RAISE a fence or hold it, never cut beneath it, and absence still un-fences a
// locator through retireAbsentLineages alone.
func (s *rootPolicyState) fenceHolds(locator string, dev, ino uint64, floor int64) bool {
	cur, fenced := s.liveFence(locator)
	if !fenced || (cur.Device == dev && cur.Inode == ino) {
		return false
	}
	return floor < cur.Floor
}

// dropBaseline releases one identity's floor while deliberately LEAVING the locator's lineage in
// place. An identity that leaves a path something else already occupies has been REPLACED, and the
// replacement inherits through exactly that lineage; a lineage whose locator is genuinely empty is
// dropped by retireAbsentLineages instead, on the evidence of consecutive complete walks.
func (s *rootPolicyState) dropBaseline(dev, ino uint64) {
	delete(s.control.Baselines, identityString(dev, ino))
	s.dirty = true
}

// holdLineage fences the locator a sealed identity occupies, and is the only way a locator's fence is
// established outside the seal walk itself. Nothing is released in exchange, which is what makes it
// safe to apply the moment it is discovered:
//
//   - A hard link gives ONE identity two live locators at once, and treating the second as a rename of
//     the first retired the fence at a path that still holds the sealed bytes (bd-main-x6u F2).
//   - A rename is a COPY of the fence, not a move (bd-main-37y). The name a sealed file leaves keeps
//     its own lineage, fingerprint and all, and clears through ordinary retirement once corroborated
//     walks find it empty — so a file put back at that name inside the window still answers to the
//     fingerprint fence instead of being published from byte zero.
//
// Holding only ever ADDS a fence, so it needs no evidence beyond having seen the identity here, and no
// two holds in one walk can contend: each names the locator its own file occupies. That is what the
// deferred staging this replaced was for — with no vacates left there is nothing to order, nothing to
// hold back from a walk that ended early, and nothing left in memory by a panic mid-walk.
//
// "Only ever adds" is an invariant, so it is checked rather than assumed: one sealed transcript can
// arrive at a name ANOTHER one's fence still covers (a swap, or a rename onto a name inside its
// retirement window), and writing its own lower floor there would cut a live fence down on behalf of
// an identity that is not the one it names — the same lowering bd-main-9xl closed everywhere else. The
// arriving file is fenced by its own identity-keyed floor either way; the locator keeps the higher
// fence until retirement clears it.
func (s *rootPolicyState) holdLineage(locator string, dev, ino uint64) {
	if locator == "" {
		return
	}
	base, sealed := s.baseline(dev, ino)
	if !sealed || base.Floor <= 0 {
		return
	}
	if s.fenceHolds(locator, dev, ino, base.Floor) {
		return
	}
	lin := sealLineage{
		Floor:           base.Floor,
		FingerprintHash: base.FingerprintHash,
		FingerprintLen:  base.FingerprintLen,
		Generation:      s.control.Generation,
		Device:          dev,
		Inode:           ino,
	}
	if cur, known := s.control.Lineages[locator]; known && cur == lin {
		return
	}
	if s.control.Lineages == nil {
		s.control.Lineages = map[string]sealLineage{}
	}
	// Deliberately not subject to maxSealLineages: the cap declines to admit fences for locators
	// nothing has fenced yet, and must never drop one that is already established.
	s.control.Lineages[locator] = lin
	s.dirty = true
}

// lineage returns the sealed floor a new identity discovered at locator may inherit. Like baseline
// it is available only on a committed forward-only root, and only within the generation that sealed
// it: a re-registration mints a new generation, and consent given again is consent to fence again.
func (s *rootPolicyState) lineage(locator string) (sealLineage, bool) {
	if !s.control.Committed || s.record.Mode != rootpolicy.ForwardOnly || locator == "" {
		return sealLineage{}, false
	}
	return s.liveFence(locator)
}

// retireAbsentLineages drops the lineage of every locator that absenceEvictionPolls consecutive
// COMPLETE, error-free walks of the root have found empty, and is what keeps the inheritance narrow.
// An unlinked path with nothing put back in its place is a deleted transcript, not a rewritten one,
// so the next file created there is a genuinely new transcript and is captured in full; only a
// replacement the walks never saw the path empty for - which is precisely what an atomic
// temp-write+rename produces - inherits a floor.
//
// Retirement is the ONLY step that un-fences a locator - no rename, no replacement and no walk-order
// accident releases one (bd-main-37y) - so it is held to the same corroboration
// standard as cursor-state GC (A1-v2): one walk finding a path empty is indistinguishable from a
// rotation caught in flight, and retiring on that evidence would republish a sealed prefix to the
// very next file created there. Callers must pass the locators of a walk that enumerated the whole
// root and lost nothing under it; anything less is not evidence and belongs in forgetLineageAbsence.
func (s *rootPolicyState) retireAbsentLineages(seen map[string]struct{}) {
	if s.absentLineagePolls == nil {
		s.absentLineagePolls = map[string]int{}
	}
	for locator := range s.control.Lineages {
		if _, ok := seen[locator]; ok {
			delete(s.absentLineagePolls, locator)
			continue
		}
		s.absentLineagePolls[locator]++
		if s.absentLineagePolls[locator] < absenceEvictionPolls {
			continue
		}
		delete(s.control.Lineages, locator)
		delete(s.absentLineagePolls, locator)
		s.dirty = true
	}
	for locator := range s.absentLineagePolls {
		if _, ok := s.control.Lineages[locator]; !ok {
			delete(s.absentLineagePolls, locator)
		}
	}
}

// forgetLineageAbsence discards the retirement evidence gathered so far, because the walk that just
// finished cannot extend it: the run of consecutive empty observations a retirement rests on has to
// be unbroken, and a walk that hit an error, never read the root, or lost an entry to a rename in
// flight breaks it.
func (s *rootPolicyState) forgetLineageAbsence() {
	clear(s.absentLineagePolls)
}

// The indirections keep the policy state small and give tests a narrow seam without exposing it.
var osReadFile = os.ReadFile
var isNotExist = os.IsNotExist
