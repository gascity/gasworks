//go:build unix

package codex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// maxAncestryDepth bounds the PPID walk so a pathological or racing /proc can never spin the
// lineage proof. A real ancestry chain is a handful deep; 256 is generous headroom.
const maxAncestryDepth = 256

// procStartTimeFieldAfterComm is the index of the starttime field (proc(5) field 22) counting
// from the first field AFTER the comm ')' — field 22 minus field 3 == 19. It matches the
// wrapper's own /proc stat parser (internal/observer/runwrap).
const procStartTimeFieldAfterComm = 19

// procPPIDFieldAfterComm is the index of the ppid field (proc(5) field 4) counting from the
// first field after the comm ')' — field 4 minus field 3 == 1.
const procPPIDFieldAfterComm = 1

// LineageProof is the outcome of the exact-descendant proof: whether THIS hook process is an
// exact descendant of any wrapper-registered process, the nearest such ancestor (which wins),
// and any farther registered ancestors retained as correlation evidence only.
type LineageProof struct {
	Attached bool
	// Nearest is the closest registered ancestor; valid only when Attached.
	Nearest RegisteredAncestor
	// Outer are farther registered ancestors, nearest-first. They are correlation evidence only
	// (spec: "retain outer run IDs only as correlation evidence"); membership never uses them.
	Outer []RegisteredAncestor
}

// proveLineage walks the hook process's /proc ancestry nearest-first and asks the daemon's
// REGISTERED index about each ancestor identity. The FIRST registered ancestor wins
// (nearest-ancestor precedence); farther registered ancestors are retained only as correlation.
//
// It returns an error ONLY when a seam query fails (a genuine "proof unavailable" the caller
// degrades to an inferred run). A truncated /proc walk — a vanished ancestor, an unreadable
// stat — is best-effort and simply ends the walk: exact lineage is causal launch evidence, and
// the absence of it is a legitimate "not proven", not an error.
func proveLineage(ctx context.Context, seam DaemonSeam, hookPID int) (LineageProof, error) {
	if hookPID <= 0 {
		hookPID = os.Getpid()
	}
	bootID, err := hostBootID()
	if err != nil {
		// Without a boot id we cannot form a comparable process identity, so lineage is simply
		// unproven. This is not a seam failure; it degrades to a legitimate "not attached".
		return LineageProof{}, nil
	}
	ancestors := processAncestry(hookPID, bootID)

	var proof LineageProof
	for _, id := range ancestors {
		reg, found, qerr := seam.LookupRegisteredProcess(ctx, id)
		if qerr != nil {
			return LineageProof{}, fmt.Errorf("codex lineage: ancestry query failed: %w", qerr)
		}
		if !found {
			continue
		}
		if !proof.Attached {
			proof.Attached = true
			proof.Nearest = reg
			continue
		}
		proof.Outer = append(proof.Outer, reg)
	}
	return proof, nil
}

// statFunc reads (ppid, process_start_time) for a pid. procStatReader is the production reader;
// tests override it (or call walkAncestry directly) to simulate a pid-reuse chain deterministically.
type statFunc func(pid int) (ppid int, startTime int64, err error)

var procStatReader statFunc = readProcStat

// processAncestry returns the /proc ancestor identities of startPID, nearest-first (its parent,
// then grandparent, ...). The starting process itself is excluded: an exact-descendant proof
// requires a strict ancestor, and init (pid 1) and below are excluded — a wrapper-registered work
// process is never init.
//
// It defends against pid-reuse across generations with a process_start_time MONOTONICITY gate. A
// single read per pid only guarantees intra-pid ppid/starttime consistency; it does NOT stop a
// TOCTOU pid-reuse false merge: between reading child C (ppid=P) and reading /proc/P/stat, the
// registered wrapper at pid P could exit and pid P be recycled by a concurrently-launched wrapper
// W2 that registers its OWN (boot_id, P, start_W2) — so the full-tuple seam match would succeed on
// W2 and attach C to a run it is not a descendant of. Because a true parent must have started no
// later than its child, and W2 started AFTER C, W2's start_time exceeds the child generation's
// start_time. The gate rejects any ancestor whose start_time is greater than the previous
// (child) generation's start_time and stops the walk there, so the impostor never enters the
// chain and the session falls through to a separate inferred run. The gate sits ON TOP of the
// full-tuple seam match; it does not weaken it. The walk is otherwise best-effort: it stops at
// the first unreadable /proc entry rather than failing.
func processAncestry(startPID int, bootID string) []wire.ProcessIdentity {
	return walkAncestry(startPID, bootID, procStatReader)
}

// walkAncestry is the pure walk with the start_time monotonicity gate, parameterized on its stat
// reader so the gate is unit-testable without racing real pid reuse.
func walkAncestry(startPID int, bootID string, stat statFunc) []wire.ProcessIdentity {
	var chain []wire.ProcessIdentity
	seen := make(map[int]bool, maxAncestryDepth)
	cur := startPID
	// prevStart is the start_time of the generation BELOW the ancestor being examined, seeded
	// with the starting process itself. A true parent starts no later than its child, so an
	// ancestor whose start_time exceeds prevStart is a recycled-pid impostor: reject it and stop.
	var prevStart int64 = -1
	for depth := 0; depth < maxAncestryDepth; depth++ {
		if cur <= 1 || seen[cur] {
			break
		}
		seen[cur] = true
		ppid, startTime, err := stat(cur)
		if err != nil {
			break
		}
		if cur == startPID {
			// The starting process anchors the gate; it is not itself a recorded ancestor.
			prevStart = startTime
			cur = ppid
			continue
		}
		if prevStart >= 0 && startTime > prevStart {
			// cur started after the generation below it — pid reuse. Everything above is
			// unreachable through a proven causal chain, so stop.
			break
		}
		chain = append(chain, wire.ProcessIdentity{
			BootId:           bootID,
			Pid:              int64(cur),
			ProcessStartTime: startTime,
		})
		prevStart = startTime
		cur = ppid
	}
	return chain
}

// hostBootID reads the host boot identifier that scopes every process identity. It mirrors the
// wrapper's own read so a registered identity and a walked ancestor identity share the same
// boot_id string byte-for-byte.
func hostBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("codex lineage: read boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if bootID == "" {
		return "", errors.New("codex lineage: empty boot id")
	}
	return bootID, nil
}

// readProcStat parses the ppid (proc(5) field 4) and starttime (field 22) from /proc/<pid>/stat
// in a single read. The comm field (field 2) may contain spaces and parentheses, so parsing
// resumes after the LAST ')': the fields after it begin at field 3. It matches the wrapper's
// parser so identities are comparable.
func readProcStat(pid int) (ppid int, startTime int64, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: read stat: %w", err)
	}
	lastParen := bytes.LastIndexByte(data, ')')
	if lastParen < 0 || lastParen+2 >= len(data) {
		return 0, 0, fmt.Errorf("codex lineage: malformed stat for pid %d", pid)
	}
	fields := strings.Fields(string(data[lastParen+2:]))
	if len(fields) <= procStartTimeFieldAfterComm {
		return 0, 0, fmt.Errorf("codex lineage: stat for pid %d has too few fields", pid)
	}
	ppid, err = strconv.Atoi(fields[procPPIDFieldAfterComm])
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: parse ppid for pid %d: %w", pid, err)
	}
	startTime, err = strconv.ParseInt(fields[procStartTimeFieldAfterComm], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("codex lineage: parse start time for pid %d: %w", pid, err)
	}
	if ppid < 0 || startTime < 0 {
		return 0, 0, fmt.Errorf("codex lineage: negative field in stat for pid %d", pid)
	}
	return ppid, startTime, nil
}
