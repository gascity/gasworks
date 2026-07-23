package spool

// capacity.go (E1.3) owns the byte-ceiling accounting and the open-run terminal reserves.
//
// Two responsibilities:
//
//  1. The `reserves` sidecar — the AUTHORITATIVE open-run terminal-reserve state (S2.1
//     finding-10). It is checksummed and written with the same temp→fsync→rename→dir-fsync
//     discipline as identity/ack. A terminal reserve is preallocated on RUN_STARTED and
//     released on RUN_ENDED / PROCESS_EXITED / PROCESS_LAUNCH_FAILED or capacity reclamation.
//     The durable RUN_STARTED frame is a RECOVERY CROSS-CHECK: acknowledging and compacting a
//     still-open run's RUN_STARTED segment removes the frame, but the sidecar still holds the
//     reserve, so the reserve survives (this is the "ack + compact + restart + hard pressure"
//     case). A corrupt/oversized reserves sidecar surfaces unhealthy — it is never silently
//     reset to empty.
//
//  2. The byte ceiling and pressure signals. The ceiling accounts for offline-normalized
//     bytes, compaction/migration scratch, the sum of open-run reserves, at least a 25% safety
//     margin, and one maximum segment/snapshot held in reserve. Soft pressure (a configurable
//     threshold below the ceiling) signals "pause passive capture"; hard pressure signals
//     "reject new explicit runs before RUN_STARTED" while already-started runs keep their
//     preallocated terminal reserve. E1.6 (wrapper lifecycle) consumes AdmitNewExplicitRun and
//     the release API; E1.10 (doctor/status) consumes Evaluate and RequiredCeiling.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// reservesFilename is the open-run reserve sidecar name under the observer state root.
const reservesFilename = "reserves"

// reservesMagic ("ORS1") marks the reserves sidecar.
const reservesMagic uint32 = 0x4F525331

// reserves sidecar bounds. A sidecar claiming more entries or a longer run id than these is
// corruption, not a value to trust.
const (
	maxReserveEntries = 1 << 16 // 65536 concurrently open runs is far past any real endpoint.
	maxRunIDLen       = 256     // bounds an embedded run id length.
)

// MinSafetyMarginRatio is the floor the spec fixes for the byte-ceiling safety margin (25%).
const MinSafetyMarginRatio = 0.25

// Typed capacity errors.
var (
	// ErrReserveRunID is an empty or oversized run id offered to the reserve ledger.
	ErrReserveRunID = errors.New("observer spool: reserve run id empty or too long")
	// ErrCapacityConfig is an invalid capacity configuration (non-positive ceiling, a soft
	// threshold not below the hard floor, a sub-25% margin, or no room for one max segment).
	ErrCapacityConfig = errors.New("observer spool: invalid capacity configuration")
)

// ---- reserves sidecar ----

// Reserves is the in-memory projection of the authoritative open-run reserve sidecar. Each
// entry is a run id mapped to the byte size reserved for its terminal evidence. It is safe for
// concurrent use.
type Reserves struct {
	mu           sync.Mutex
	dir          string
	fixedReserve int64
	open         map[string]int64
}

// LoadReserves reads and validates the reserves sidecar. An absent sidecar is an empty open
// set (a clean fresh-install state, not a reset). A present-but-corrupt/oversized sidecar
// returns ErrChecksumMismatch so the caller surfaces unhealthy and holds — it is never treated
// as empty. fixedReserve is the per-run terminal reserve granted to a run whose RUN_STARTED
// frame is rediscovered during recovery reconciliation.
func LoadReserves(dir string, fixedReserve int64) (*Reserves, error) {
	open, err := readReserves(dir)
	if err != nil {
		return nil, err
	}
	if open == nil {
		open = make(map[string]int64)
	}
	return &Reserves{dir: dir, fixedReserve: fixedReserve, open: open}, nil
}

// Reserve preallocates the fixed terminal reserve for a run on RUN_STARTED and durably updates
// the sidecar. It is idempotent: re-reserving an already-open run keeps its existing reserve
// and does not rewrite the sidecar.
func (r *Reserves) Reserve(runID string) error {
	if runID == "" || len(runID) > maxRunIDLen {
		return fmt.Errorf("%w: %q", ErrReserveRunID, runID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.open[runID]; ok {
		return nil
	}
	r.open[runID] = r.fixedReserve
	return r.persistLocked()
}

// Release frees a run's terminal reserve on RUN_ENDED / PROCESS_EXITED / PROCESS_LAUNCH_FAILED
// or after capacity reclamation (E1.6 verifies the wrapper process identity is gone before
// calling this). It durably updates the sidecar and is idempotent: releasing an unknown run is
// a no-op.
func (r *Reserves) Release(runID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.open[runID]; !ok {
		return nil
	}
	delete(r.open, runID)
	return r.persistLocked()
}

// OpenReserveBytes is the sum of all open-run terminal reserves — the byte count that must
// stay available so every started run can always append its terminal evidence.
func (r *Reserves) OpenReserveBytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var total int64
	for _, n := range r.open {
		total += n
	}
	return total
}

// IsOpen reports whether a run currently holds a terminal reserve.
func (r *Reserves) IsOpen(runID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.open[runID]
	return ok
}

// OpenRuns returns the open run ids in sorted order (a stable snapshot).
func (r *Reserves) OpenRuns() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.open))
	for id := range r.open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// persistLocked writes the current open set to the sidecar atomically. The caller holds r.mu.
func (r *Reserves) persistLocked() error {
	return atomicWriteFile(filepath.Join(r.dir, reservesFilename), encodeReserves(r.open))
}

// encodeReserves serializes the open-run reserve set with a trailing CRC32C:
//
//	magic(4) entry_count(4) [reserve_bytes(8) run_id_length(2) run_id(n)]... crc32c(4)
//
// Entries are emitted in sorted run-id order so the encoding is deterministic.
func encodeReserves(open map[string]int64) []byte {
	ids := make([]string, 0, len(open))
	for id := range open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	size := 8
	for _, id := range ids {
		size += 8 + 2 + len(id)
	}
	size += 4
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:], reservesMagic)
	binary.BigEndian.PutUint32(buf[4:], uint32(len(ids)))
	off := 8
	for _, id := range ids {
		binary.BigEndian.PutUint64(buf[off:], uint64(open[id]))
		off += 8
		binary.BigEndian.PutUint16(buf[off:], uint16(len(id)))
		off += 2
		copy(buf[off:], id)
		off += len(id)
	}
	crc := crc32.Checksum(buf[:off], castagnoli)
	binary.BigEndian.PutUint32(buf[off:], crc)
	return buf
}

// decodeReserves validates and decodes the reserves sidecar. Any structural inconsistency
// (bad magic, over-count, oversized/short run id, or CRC mismatch) is ErrChecksumMismatch: the
// store is unhealthy and recovery does not guess past a corrupt control file.
func decodeReserves(data []byte) (map[string]int64, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("%w: reserves too short", ErrChecksumMismatch)
	}
	if binary.BigEndian.Uint32(data[0:]) != reservesMagic {
		return nil, fmt.Errorf("%w: reserves bad magic", ErrChecksumMismatch)
	}
	count := int(binary.BigEndian.Uint32(data[4:]))
	if count > maxReserveEntries {
		return nil, fmt.Errorf("%w: reserves entry count %d over bound", ErrChecksumMismatch, count)
	}
	off := 8
	open := make(map[string]int64, count)
	for i := 0; i < count; i++ {
		if off+10 > len(data)-4 {
			return nil, fmt.Errorf("%w: reserves truncated at entry %d", ErrChecksumMismatch, i)
		}
		reserve := int64(binary.BigEndian.Uint64(data[off:]))
		off += 8
		idLen := int(binary.BigEndian.Uint16(data[off:]))
		off += 2
		if reserve < 0 || idLen == 0 || idLen > maxRunIDLen || off+idLen > len(data)-4 {
			return nil, fmt.Errorf("%w: reserves entry %d inconsistent", ErrChecksumMismatch, i)
		}
		id := string(data[off : off+idLen])
		if _, dup := open[id]; dup {
			return nil, fmt.Errorf("%w: reserves duplicate run id", ErrChecksumMismatch)
		}
		open[id] = reserve
		off += idLen
	}
	if off != len(data)-4 {
		return nil, fmt.Errorf("%w: reserves trailing bytes", ErrChecksumMismatch)
	}
	stored := binary.BigEndian.Uint32(data[off:])
	if crc32.Checksum(data[:off], castagnoli) != stored {
		return nil, ErrChecksumMismatch
	}
	return open, nil
}

// readReserves reads and validates the reserves sidecar. The map is nil when the file is
// absent (nothing reserved); a present-but-corrupt file is ErrChecksumMismatch.
func readReserves(dir string) (map[string]int64, error) {
	data, err := os.ReadFile(filepath.Join(dir, reservesFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("observer spool: read reserves: %w", err)
	}
	return decodeReserves(data)
}

// ---- recovery reconciliation ----

// RunEventKind classifies a durable frame's effect on open-run reserve state.
type RunEventKind int

const (
	// RunEventOther is any frame that neither opens nor closes a run.
	RunEventOther RunEventKind = iota
	// RunEventStarted is a RUN_STARTED boundary that opens a run and preallocates its reserve.
	RunEventStarted
	// RunEventTerminated is a terminal frame (RUN_ENDED, PROCESS_EXITED, PROCESS_LAUNCH_FAILED)
	// that consumes/releases a run's reserve.
	RunEventTerminated
)

// RunEvent is one run-lifecycle-relevant durable frame, in WAL sequence order.
type RunEvent struct {
	Sequence int64
	RunID    string
	Kind     RunEventKind
}

// ScanRunEvents walks every durable frame under wal/ in sequence order and returns the
// run-lifecycle events (RUN_STARTED / RUN_ENDED / PROCESS_EXITED / PROCESS_LAUNCH_FAILED). It
// runs after startup Recover (see the boot-order contract on ReconcileReserves), so the WAL is
// already validated: any interior corruption or non-final unclean frame was rejected by Recover
// before this runs, and an unclean frame here is therefore an error (recover first).
//
// The one segment Recover leaves in place without a decodable header is a benign
// interrupted-create trailing segment (OutcomeInterruptedCreate) — a crash during CreateSegment
// left a zero/sub-header-length file that holds no durable frame. ScanRunEvents tolerates that
// trailing segment exactly as Recover does: a last segment whose header does not decode is
// skipped (it contributes no run event), rather than hard-failing and stranding reconciliation.
// Frames with no run id are skipped — they cannot participate in reserve reconciliation.
func ScanRunEvents(dir string) ([]RunEvent, error) {
	walDir := filepath.Join(dir, walDirName)
	segPaths, err := listSegments(walDir)
	if err != nil {
		return nil, err
	}
	var events []RunEvent
	for i, path := range segPaths {
		isLast := i == len(segPaths)-1
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("observer spool: read segment %s: %w", filepath.Base(path), err)
		}
		_, hdrLen, err := decodeSegmentHeader(data)
		if err != nil {
			if isLast {
				// The benign interrupted-create tail Recover already tolerated. Recover is the
				// corruption gate: a non-final or oversized-corrupt-header segment would have made
				// Recover return before we reached reconciliation, so a header that fails to decode
				// here, on the last segment, is the interrupted create — skip it.
				continue
			}
			return nil, err
		}
		off := hdrLen
		for off < len(data) {
			fr, n, status := DecodeFrame(data[off:])
			if status != FrameOK {
				return nil, fmt.Errorf("observer spool: scan segment %s: unclean frame at offset %d (recover first)",
					filepath.Base(path), off)
			}
			kind, runID := classifyRunFrame(fr.Payload)
			if kind != RunEventOther && runID != "" {
				events = append(events, RunEvent{Sequence: fr.Sequence, RunID: runID, Kind: kind})
			}
			off += n
		}
	}
	return events, nil
}

// runFrameEnvelope is the minimal projection of a canonical observation needed to classify its
// effect on reserve state, decoded without depending on the wire union's unexported shape.
type runFrameEnvelope struct {
	Kind       string `json:"kind"`
	RunContext *struct {
		RunID string `json:"run_id"`
	} `json:"run_context"`
	RunBoundary *struct {
		Transition string `json:"transition"`
		RunID      string `json:"run_id"`
	} `json:"run_boundary"`
	ProcessLifecycle *struct {
		Transition string `json:"transition"`
	} `json:"process_lifecycle"`
}

// classifyRunFrame decodes a canonical observation payload and reports whether it opens or
// closes a run and the run id it affects. A RUN_STARTED/RUN_ENDED boundary carries its own
// run_id; a PROCESS_EXITED/PROCESS_LAUNCH_FAILED lifecycle takes the run id from the stamped
// run_context.
func classifyRunFrame(payload []byte) (RunEventKind, string) {
	var env runFrameEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return RunEventOther, ""
	}
	switch env.Kind {
	case string(wire.ObservationEnvelopeKindRUNBOUNDARY):
		if env.RunBoundary == nil {
			return RunEventOther, ""
		}
		switch env.RunBoundary.Transition {
		case string(wire.RunStartedBoundaryTransitionRUNSTARTED):
			return RunEventStarted, env.RunBoundary.RunID
		case string(wire.RunEndedBoundaryTransitionRUNENDED):
			return RunEventTerminated, env.RunBoundary.RunID
		}
	case string(wire.ProcessLifecycleObservationKindPROCESSLIFECYCLE):
		if env.ProcessLifecycle == nil || env.RunContext == nil {
			return RunEventOther, ""
		}
		switch env.ProcessLifecycle.Transition {
		case string(wire.ProcessLifecyclePayloadTransitionPROCESSEXITED),
			string(wire.ProcessLifecyclePayloadTransitionPROCESSLAUNCHFAILED):
			return RunEventTerminated, env.RunContext.RunID
		}
	}
	return RunEventOther, ""
}

// Boot-order contract (load-bearing; E1.10 owns enforcing it at daemon start): at every
// startup, run Recover → ScanRunEvents → ReconcileReserves BEFORE any Compact. Reconciliation's
// "a run present only in the sidecar is still-open, keep it" inference (the finding-10 case) is
// sound ONLY because the cross-check frames have not yet been erased by a compaction in this
// process. Two failure modes if the order is violated:
//
//   - Compact before ReconcileReserves in the same boot could remove the RUN_STARTED frame of a
//     run whose reserve was released-but-not-yet-persisted (a crash-window run), so reconciliation
//     would no longer see the terminal cross-check and would wrongly KEEP a closed run's reserve;
//   - more dangerously, never compact a RUN_STARTED whose reserve is not yet durably recorded in
//     the sidecar — otherwise a crash after compaction but before the sidecar write loses the
//     only record of a still-open run's reserve, STRANDING the run without terminal capacity.
//
// The safe rule enforced by ordering: reserve durability (sidecar write) and RUN_STARTED
// durability both precede any compaction that could remove that RUN_STARTED, and reconciliation
// always runs against the pre-compaction frame set.
//
// ReconcileReserves re-derives open-run reserve state at startup: the authoritative reserves
// sidecar reconciled against the durable RUN_STARTED-without-terminal frames. The sidecar is
// the base; the durable frames are the cross-check:
//
//   - a RUN_STARTED with a matching durable terminal frame is proven closed → released (covers
//     a crash between the terminal append and the sidecar release);
//   - a RUN_STARTED with no durable terminal frame is proven still-open → reserved (covers a
//     crash between the RUN_STARTED append and the sidecar preallocation);
//   - a terminal frame whose RUN_STARTED is gone (compacted) is proven closed → released;
//   - a run present only in the sidecar — its RUN_STARTED acknowledged and compacted while it
//     is still open — is KEPT, because the sidecar is authoritative and no frame contradicts it
//     (the S2.1 finding-10 case).
//
// A corrupt sidecar surfaces unhealthy via LoadReserves; reconciliation persists the sidecar
// only when the reconciled state differs from what was read.
func ReconcileReserves(dir string, fixedReserve int64, events []RunEvent) (*Reserves, error) {
	r, err := LoadReserves(dir, fixedReserve)
	if err != nil {
		return nil, err
	}
	started := make(map[string]bool)
	terminated := make(map[string]bool)
	for _, e := range events {
		switch e.Kind {
		case RunEventStarted:
			started[e.RunID] = true
		case RunEventTerminated:
			terminated[e.RunID] = true
		}
	}
	r.mu.Lock()
	changed := false
	for id := range started {
		if terminated[id] {
			if _, ok := r.open[id]; ok {
				delete(r.open, id)
				changed = true
			}
		} else if _, ok := r.open[id]; !ok {
			r.open[id] = fixedReserve
			changed = true
		}
	}
	for id := range terminated {
		if started[id] {
			continue
		}
		if _, ok := r.open[id]; ok {
			delete(r.open, id)
			changed = true
		}
	}
	var perr error
	if changed {
		perr = r.persistLocked()
	}
	r.mu.Unlock()
	if perr != nil {
		return nil, perr
	}
	return r, nil
}

// ---- byte-ceiling accounting ----

// CapacityConfig is the byte-ceiling model input. All byte fields are non-negative.
type CapacityConfig struct {
	// CeilingBytes is the total hard cap on spool bytes (bounded by the configured disk budget).
	CeilingBytes int64
	// SoftThresholdBytes is the pressure threshold below the ceiling that pauses passive
	// capture. 0 derives a default fraction of the usable hard floor (ceiling minus the
	// one-max-segment and scratch reserves), which keeps the default strictly below the floor.
	SoftThresholdBytes int64
	// TerminalReserveBytes is the fixed per-run terminal reserve preallocated on RUN_STARTED.
	TerminalReserveBytes int64
	// MaxSegmentBytes is the one maximum segment/snapshot held in reserve so a terminal append
	// can always rotate into fresh space.
	MaxSegmentBytes int64
	// ScratchBytes is the compaction/migration scratch held out of the usable budget.
	ScratchBytes int64
	// OfflineNormalizedBytes is the projected offline backlog the ceiling must be able to hold.
	OfflineNormalizedBytes int64
	// SafetyMarginRatio is the safety margin over the accounted bytes; it must be at least
	// MinSafetyMarginRatio. 0 selects MinSafetyMarginRatio.
	SafetyMarginRatio float64
}

// defaultSoftFraction is the fraction of the usable HARD FLOOR (not the raw ceiling) used for
// the soft-pressure threshold when SoftThresholdBytes is unset. Anchoring it to the hard floor
// keeps the default strictly below the floor by construction, so it never collides with the
// floor when the one-max-segment + scratch reserve is a large fraction of a small ceiling (the
// realistic default-64-MiB-segment case).
const defaultSoftFraction = 0.75

// CapacityModel is the validated byte-ceiling accounting: derived hard floor and soft
// threshold plus the reserve/scratch geometry. Evaluate reports pressure and admission given
// the current used bytes and open-run reserves.
type CapacityModel struct {
	cfg           CapacityConfig
	safetyMargin  float64
	hardFloor     int64 // ceiling - one-max-segment - scratch; committed bytes past this are hard pressure.
	softThreshold int64
}

// Pressure is the capacity-pressure signal E1.6/E1.10 consume.
type Pressure int

const (
	// PressureNone means normal operation: passive capture and new explicit runs are admitted.
	PressureNone Pressure = iota
	// PressureSoft signals "pause passive capture" — explicit runs and terminal evidence still
	// proceed, but passive session/tool/usage observations are paused visibly.
	PressureSoft
	// PressureHard signals "reject new explicit runs before RUN_STARTED". Already-started runs
	// keep their preallocated terminal reserve and can always append terminal evidence.
	PressureHard
)

// String renders the pressure signal for status/logs.
func (p Pressure) String() string {
	switch p {
	case PressureNone:
		return "none"
	case PressureSoft:
		return "soft"
	case PressureHard:
		return "hard"
	default:
		return "unknown"
	}
}

// CapacityStatus is a full snapshot of a capacity evaluation.
type CapacityStatus struct {
	UsedBytes           int64
	OpenReserveBytes    int64
	CommittedBytes      int64 // used + open reserves
	CeilingBytes        int64
	HardFloorBytes      int64
	SoftThresholdBytes  int64
	Pressure            Pressure
	AdmitPassiveCapture bool
	AdmitNewExplicitRun bool
}

// NewCapacityModel validates the configuration and derives the hard floor and soft threshold.
// It rejects a non-positive ceiling, a sub-25% margin, a hard floor that leaves no usable
// space once the one-max-segment reserve and scratch are held out, and a soft threshold that
// is not strictly below the hard floor.
func NewCapacityModel(cfg CapacityConfig) (CapacityModel, error) {
	if cfg.CeilingBytes <= 0 {
		return CapacityModel{}, fmt.Errorf("%w: ceiling %d must be positive", ErrCapacityConfig, cfg.CeilingBytes)
	}
	if cfg.MaxSegmentBytes < 0 || cfg.ScratchBytes < 0 || cfg.TerminalReserveBytes < 0 || cfg.OfflineNormalizedBytes < 0 {
		return CapacityModel{}, fmt.Errorf("%w: byte fields must be non-negative", ErrCapacityConfig)
	}
	margin := cfg.SafetyMarginRatio
	if margin == 0 {
		margin = MinSafetyMarginRatio
	}
	if margin < MinSafetyMarginRatio {
		return CapacityModel{}, fmt.Errorf("%w: safety margin %.3f below floor %.2f", ErrCapacityConfig, margin, MinSafetyMarginRatio)
	}
	hardFloor := cfg.CeilingBytes - cfg.MaxSegmentBytes - cfg.ScratchBytes
	if hardFloor <= 0 {
		return CapacityModel{}, fmt.Errorf("%w: ceiling %d leaves no room after one max segment (%d) + scratch (%d)",
			ErrCapacityConfig, cfg.CeilingBytes, cfg.MaxSegmentBytes, cfg.ScratchBytes)
	}
	soft := cfg.SoftThresholdBytes
	if soft == 0 {
		// Derive the default from the usable hard floor so it is always strictly below it,
		// regardless of how large the one-max-segment + scratch reserve is relative to the
		// ceiling.
		soft = int64(math.Floor(float64(hardFloor) * defaultSoftFraction))
	}
	if soft <= 0 || soft >= hardFloor {
		return CapacityModel{}, fmt.Errorf("%w: soft threshold %d must be in (0, hard floor %d)", ErrCapacityConfig, soft, hardFloor)
	}
	return CapacityModel{cfg: cfg, safetyMargin: margin, hardFloor: hardFloor, softThreshold: soft}, nil
}

// Evaluate reports the pressure signal and admission decisions for the current used bytes and
// open-run reserves. Committed bytes are used + open reserves. Hard pressure is committed at or
// past the hard floor (one max segment + scratch of slack is exhausted); soft pressure is
// committed at or past the soft threshold. Passive capture is admitted only with no pressure;
// a new explicit run is admitted only when granting one more full terminal reserve still leaves
// the one-max-segment + scratch slack below the ceiling.
func (m CapacityModel) Evaluate(usedBytes, openReserveBytes int64) CapacityStatus {
	committed := usedBytes + openReserveBytes
	st := CapacityStatus{
		UsedBytes:          usedBytes,
		OpenReserveBytes:   openReserveBytes,
		CommittedBytes:     committed,
		CeilingBytes:       m.cfg.CeilingBytes,
		HardFloorBytes:     m.hardFloor,
		SoftThresholdBytes: m.softThreshold,
	}
	switch {
	case committed >= m.hardFloor:
		st.Pressure = PressureHard
	case committed >= m.softThreshold:
		st.Pressure = PressureSoft
	default:
		st.Pressure = PressureNone
	}
	st.AdmitPassiveCapture = st.Pressure == PressureNone
	st.AdmitNewExplicitRun = st.Pressure != PressureHard &&
		committed+m.cfg.TerminalReserveBytes <= m.hardFloor
	return st
}

// RequiredCeiling computes the minimum byte ceiling the spec formula demands for the given open
// reserves: (offline-normalized + scratch + open reserves) grown by the safety margin, plus one
// maximum segment/snapshot held in reserve. setup/doctor (E1.10) compare the configured ceiling
// against this to prove the budget is sufficient.
func (m CapacityModel) RequiredCeiling(openReserveBytes int64) int64 {
	base := m.cfg.OfflineNormalizedBytes + m.cfg.ScratchBytes + openReserveBytes
	withMargin := base + int64(math.Ceil(float64(base)*m.safetyMargin))
	return withMargin + m.cfg.MaxSegmentBytes
}

// WALBytes sums the on-disk size of every segment under wal/ — the used-bytes input to
// Evaluate. Compaction reduces it by removing whole acknowledged segments.
//
// By design it counts wal/*.seg only. Quarantine bytes (frozen corrupt segments under
// quarantine/, E1.4) and recovery diagnostics (torn-tail forensics under recovery/) are
// deliberately excluded from this ceiling input: they are bounded, out-of-band forensic state
// governed by the corruption/quarantine path, not live spool pressure the passive/explicit
// admission decisions should throttle on. E1.4/E1.10 account for that fixed forensic budget
// separately.
func WALBytes(dir string) (int64, error) {
	walDir := filepath.Join(dir, walDirName)
	entries, err := os.ReadDir(walDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("observer spool: list wal dir: %w", err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".seg" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, fmt.Errorf("observer spool: stat segment %s: %w", e.Name(), err)
		}
		total += info.Size()
	}
	return total, nil
}
