//go:build unix

package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	// Orphaned marks a fence whose named identity was RELEASED while the fence still stood, which frees
	// that identity's inode NUMBER for the allocator to hand to an unrelated file. The incumbent
	// exemption is a pure (Device,Inode) comparison, so a file that reuses the freed number would
	// otherwise meet it and be allowed to lower or clear a fence it is not the sealed transcript of
	// (bd-main-fpj). An orphaned fence is foreign to EVERY writer, including that reused number:
	// reconcileLineage may only ratchet its floor up or hold it, never lower, rebind or delete it, and
	// retirement stays the sole un-fencing path. omitempty keeps an ordinary fence byte-identical on
	// disk, so an older build still reads the record unchanged.
	Orphaned bool `json:"orphaned,omitempty"`
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
	// absentBaselinePolls is the identity-keyed twin of absentLineagePolls: it counts, per sealed
	// identity, the consecutive corroborated walks that have found NO file carrying that identity under
	// the root. It gates the eviction of a dead ACTIVATION baseline — a floor a forward-activation seal
	// gave a file that was never tracked, so the per-identity release sweep never GCs it — on the same
	// N>=2 corroborated-absence discipline retirement uses. In-memory only, for the same reason.
	absentBaselinePolls map[string]int
}

func rootPolicyID(root string) string {
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:16])
}

func identityString(dev, ino uint64) string { return fmt.Sprintf("%d:%d", dev, ino) }

// parseIdentityString reverses identityString, recovering the (device,inode) a Baselines key names so a
// dead identity's floor can be evicted by the identity it belongs to. A key that does not parse is left
// untouched — the fail-closed direction, since an unparseable key can only cause a floor to be HELD.
func parseIdentityString(s string) (dev, ino uint64, ok bool) {
	d, i, found := strings.Cut(s, ":")
	if !found {
		return 0, 0, false
	}
	dev, err := strconv.ParseUint(d, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	ino, err = strconv.ParseUint(i, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return dev, ino, true
}

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

// setLineage points a locator at the floor the identity now sitting there is sealed over, through the
// reconcileLineage choke point. A floor at byte zero has no pre-consent prefix beneath it and so
// carries nothing worth inheriting: reconcileLineage drops the entry, which is also how a truncation
// all the way to zero lowers a lineage - but only for the identity the fence names, because a foreign
// write is ratcheted up or held there instead, never rebound and never lowered.
func (s *rootPolicyState) setLineage(locator string, dev, ino uint64, b baselineRecord) {
	if locator == "" {
		return
	}
	next, keep := s.reconcileLineage(locator, dev, ino, b)
	if !keep {
		delete(s.control.Lineages, locator)
		return
	}
	if _, known := s.control.Lineages[locator]; !known && len(s.control.Lineages) >= maxSealLineages {
		return
	}
	if s.control.Lineages == nil {
		s.control.Lineages = map[string]sealLineage{}
	}
	s.control.Lineages[locator] = next
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

// reconcileLineage returns the lineage entry that must stand at locator after identity (dev,ino) with
// baseline b writes there, and whether an entry should exist at all. It is the whole of the ratchet,
// and the single choke point both setLineage and holdLineage route through, so no write path can
// rebind or lower a live fence by taking a different door.
//
// A live fence carries not just a floor but the IDENTITY that last legitimately held the locator, and
// that identity is what says where the sealed bytes are (bd-main-9xl). It is IMMUTABLE to every writer
// but the one it names:
//
//   - The incumbent (writer identity == the fence's), or a locator with no live fence, is an honest
//     write and stands exactly as given. A file that shrinks its OWN floor really did destroy the
//     bytes above it - an in-place truncation or a rewrite beneath the floor leaves nothing anywhere
//     for the fence to protect - so it lowers, and a floor at zero clears the entry (A22); the reseal
//     diagnostic reports it.
//   - A foreign identity is a replacement standing where a sealed transcript used to be, and its own
//     end of file says nothing about the sealed bytes: those are alive in the file that rotated away,
//     which is the whole reason the name it left keeps a fence through its retirement window. It may
//     RATCHET the fence up (a strictly higher floor, keeping the incumbent identity) or hold it, but
//     it NEVER lowers and NEVER rebinds the identity. Guarding only the floor let a foreign write at
//     or above it rebind the fence to the writer; the writer then met its own same-identity exemption
//     and could lower the floor to zero, delete the fence, and have the owner's pre-consent prefix
//     republished from byte zero by the next copy put back at the name (bd-main-dyc).
//
// Incumbency is a pure comparison of the writer's (dev,ino) against the LIVE FENCE's (Device,Inode).
// It must never be re-derived from s.control.Baselines: setBaseline writes the baseline BEFORE calling
// setLineage, so a baseline-keyed test would see the just-written foreign entry and be defeated.
// Absence still un-fences a locator through retireAbsentLineages alone.
//
// One case has no incumbent at all: an ORPHANED fence, whose named identity was released while the
// fence stood (orphanLineagesNaming, from releaseTracked). Releasing an identity frees its inode
// NUMBER, so the number the fence names can be reused by an unrelated file; the pure (dev,ino) test
// would then hand that reused number the incumbent's own exemption to lower the floor to zero and
// delete the fence (bd-main-fpj). An orphaned fence is therefore treated as foreign to EVERY writer -
// it may only ratchet up or hold, never lower, rebind or delete - and the orphaned marker rides
// through a ratchet so a reused number cannot launder it off by first raising the floor.
func (s *rootPolicyState) reconcileLineage(locator string, dev, ino uint64, b baselineRecord) (sealLineage, bool) {
	cur, fenced := s.liveFence(locator)
	if fenced && (cur.Orphaned || cur.Device != dev || cur.Inode != ino) {
		if b.Floor <= cur.Floor {
			return cur, true // hold: a foreign writer never lowers and never rebinds
		}
		return sealLineage{ // ratchet up, keeping the incumbent identity (and its orphaned marker)
			Floor:           b.Floor,
			FingerprintHash: b.FingerprintHash,
			FingerprintLen:  b.FingerprintLen,
			Generation:      s.control.Generation,
			Device:          cur.Device,
			Inode:           cur.Inode,
			Orphaned:        cur.Orphaned,
		}, true
	}
	if b.Floor <= 0 { // incumbent, or no live fence: an honest write; a floor at zero clears the entry
		return sealLineage{}, false
	}
	return sealLineage{
		Floor:           b.Floor,
		FingerprintHash: b.FingerprintHash,
		FingerprintLen:  b.FingerprintLen,
		Generation:      s.control.Generation,
		Device:          dev,
		Inode:           ino,
	}, true
}

// dropBaseline releases one identity's floor while deliberately LEAVING the locator's lineage in
// place. An identity that leaves a path something else already occupies has been REPLACED, and the
// replacement inherits through exactly that lineage; a lineage whose locator is genuinely empty is
// dropped by retireAbsentLineages instead, on the evidence of consecutive complete walks.
func (s *rootPolicyState) dropBaseline(dev, ino uint64) {
	delete(s.control.Baselines, identityString(dev, ino))
	s.dirty = true
}

// orphanLineagesNaming marks every LIVE fence whose named identity is (dev,ino) as orphaned, and is
// called from releaseTracked at the moment that identity's durable floor is dropped. Releasing an
// identity frees its inode NUMBER for the allocator to hand to an unrelated file; a fence still naming
// that number would otherwise grant the reused number reconcileLineage's incumbent exemption and let
// it lower or clear a fence it is not the sealed transcript of (bd-main-fpj). Orphaning forces the
// foreign branch for every later writer instead.
//
// This mutates the fence map directly, on the same footing as retirement, because it only ever RAISES
// protection: it never lowers a floor, never rebinds an identity and never deletes an entry - it flips
// one marker that can only make reconcileLineage stricter. It touches only a live fence (current
// generation, floor above zero) that names the departing identity; a fence at another identity, an
// already-orphaned one, or a cleared entry is left exactly as it stands.
//
// An identity renamed to another path UNDER THE ROOT is found alive by the walk and so is never
// released, so a genuine rename-back within the root is still correctly the incumbent. An identity
// that leaves the root - unlinked, or moved outside it - is released once corroborated absent, and its
// fence is orphaned; that is the conservative direction whether or not the inode itself was freed,
// since a reused number is a different file and a true return re-inherits its own floor by fingerprint
// through inheritSealLineage without ever publishing below it.
func (s *rootPolicyState) orphanLineagesNaming(dev, ino uint64) {
	for locator := range s.control.Lineages {
		lin, live := s.liveFence(locator)
		if !live || lin.Orphaned || lin.Device != dev || lin.Inode != ino {
			continue
		}
		lin.Orphaned = true
		s.control.Lineages[locator] = lin
		s.dirty = true
	}
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
	lin, keep := s.reconcileLineage(locator, dev, ino, base)
	if !keep {
		// A foreign write that would lower is refused here rather than deleting: holding only ever adds
		// or raises a fence, and un-fencing is retireAbsentLineages' alone.
		return
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

// retireAbsentActivationBaselines is the identity-keyed twin of retireAbsentLineages, and closes the
// one lifecycle gap the per-identity release sweep leaves open (bd-main-1qh facet A). A forward-only
// activation seals EVERY regular file standing under the root, transcript-named or not, so a file the
// Match filter never admits still gets a durable identity floor — and, never being entered into
// w.tracked, is never reached by the release sweep that drops a tracked file's floor on corroborated
// absence. That floor then outlives its file; once the inode NUMBER is handed to a genuinely new
// transcript, cursorFor reads the dead floor as that file's own and fences its leading bytes.
//
// It rests on exactly the evidence retirement and release rest on. `occupied` names every identity a
// corroborated walk of the whole root found still standing — matching or not, since a present but
// non-transcript file is as real an occupant as a member — together with every identity this watcher
// is still tailing into this root, so a rename the walk raced is never mistaken for a departure. Only a
// baseline whose identity is absent from that set for absenceEvictionPolls consecutive corroborated
// walks is a dead activation floor; a present-but-untracked file is NOT absent and its floor is held.
//
// It never deletes or lowers a lineage. Before dropping the dead floor it orphans any live fence still
// naming the freed inode NUMBER — exactly as releaseTracked does — which only RAISES protection, so a
// number the allocator later reuses can at most ratchet a fence up or hold it, never lower or clear it;
// retireAbsentLineages stays the sole lineage-deletion path. It returns the evicted identities so the
// caller can drop their durable cursors on the same evidence.
func (s *rootPolicyState) retireAbsentActivationBaselines(occupied map[string]struct{}) []identityKey {
	if s.absentBaselinePolls == nil {
		s.absentBaselinePolls = map[string]int{}
	}
	var evicted []identityKey
	for id := range s.control.Baselines {
		if _, ok := occupied[id]; ok {
			delete(s.absentBaselinePolls, id)
			continue
		}
		s.absentBaselinePolls[id]++
		if s.absentBaselinePolls[id] < absenceEvictionPolls {
			continue
		}
		dev, ino, ok := parseIdentityString(id)
		if !ok {
			delete(s.absentBaselinePolls, id)
			continue
		}
		s.orphanLineagesNaming(dev, ino)
		s.dropBaseline(dev, ino)
		delete(s.absentBaselinePolls, id)
		evicted = append(evicted, identityKey{dev: dev, ino: ino})
	}
	// A baseline that vanished by any other path (a release, a re-registration) drops its stale streak
	// with it, exactly as retireAbsentLineages prunes a locator's.
	for id := range s.absentBaselinePolls {
		if _, ok := s.control.Baselines[id]; !ok {
			delete(s.absentBaselinePolls, id)
		}
	}
	return evicted
}

// forgetBaselineAbsence discards the activation-baseline eviction evidence, for the same reason
// forgetLineageAbsence discards the retirement evidence: an absence streak is a run of consecutive
// corroborated walks, and a walk that could not corroborate breaks it.
func (s *rootPolicyState) forgetBaselineAbsence() {
	clear(s.absentBaselinePolls)
}

// The indirections keep the policy state small and give tests a narrow seam without exposing it.
var osReadFile = os.ReadFile
var isNotExist = os.IsNotExist
