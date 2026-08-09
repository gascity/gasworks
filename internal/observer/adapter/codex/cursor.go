//go:build unix

package codex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"syscall"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// The durable cursor makes incremental transcript tailing crash-safe and O(new bytes). It records
// the file's filesystem IDENTITY (device+inode, corroborated by size+mtime) plus the byte offset
// through which complete newline-terminated lines have been parsed, and persists that state
// atomically so a restart resumes at exactly the last line boundary — never re-parsing consumed
// bytes and never skipping an appended record. Identity, not path, is authoritative: a new inode
// at the same path is a REPLACEMENT (restart at 0), a shrunken same-inode file is a TRUNCATION
// (restart at 0 with a diagnostic), and a renamed-but-same-inode file is the SAME cursor. The
// unconsumed trailing partial line is buffered in memory and re-presented ahead of the next read,
// so a record split across two reads parses exactly once; that buffer is bounded, and a
// pathologically long partial line overflows to a content-free diagnostic rather than unbounded
// memory.

const (
	// cursorStateVersion is the on-disk cursor schema version. It is stamped into every persisted
	// cursor so a future format change can be detected on load rather than silently misread.
	cursorStateVersion = 1

	// cursorFileMode / cursorDirMode keep cursor state owner-only, matching the spool's discipline
	// (evidence-adjacent state must not be world-readable even under a permissive umask).
	cursorFileMode os.FileMode = 0o600
	cursorDirMode  os.FileMode = 0o700

	// DefaultMaxPartialLine bounds the in-memory unconsumed remainder. A single transcript record
	// far larger than this without a terminating newline is pathological (the format is one JSON
	// object per line); the cursor overflows it to a diagnostic and re-synchronizes at the next
	// newline instead of growing memory without bound.
	DefaultMaxPartialLine = 1 << 20

	// anchorLen is the number of bytes immediately preceding the consumed offset whose FNV hash is
	// persisted as a content fingerprint. Before trusting a resumed/continued offset, the watcher
	// re-reads these bytes from the live file and compares the hash: a match proves the file is the
	// same content up to the offset (a pure append continuation), while a mismatch — an in-place
	// rewrite, or a different file at a reused inode — forces a safe re-read from 0. A multi-byte
	// window (not a single newline byte) is what defeats a one-byte boundary coincidence. It is a
	// suffix fingerprint, not a full-prefix hash (which would break the O(new bytes) guarantee): an
	// in-place edit that preserves both the file size and these trailing bytes while altering
	// earlier already-consumed content is not detected — an acceptable residual, since that content
	// was already delivered once and at-least-once holds relative to the original stream, and it
	// requires a surgical size-preserving editor rather than any operational transcript behavior.
	anchorLen = 64
)

// Cursor is the durable per-file tail position for one Codex transcript. It is not safe for
// concurrent use; the watcher owns exactly one Cursor per tracked file identity and drives it
// single-threaded.
type Cursor struct {
	statePath string // absolute path of this cursor's atomic state file
	scope     string // empty for legacy roots; canonical-root + generation for policy roots

	dev, ino uint64 // filesystem identity: authoritative for replacement/rotation
	size     int64  // last observed size (corroborating change signal, not authoritative)
	modNanos int64  // last observed mtime in Unix nanoseconds (corroborating)

	consumed  int64  // durable: bytes fully parsed (at a newline boundary, except mid-overflow-skip)
	remainder []byte // in-memory: unconsumed trailing partial line (len <= maxPartialLine)
	skip      bool   // true after a remainder-cap overflow: discard bytes until the next newline

	anchor     []byte // in-memory: last <=anchorLen consumed bytes (nil after a resume until a commit)
	anchorHash uint64 // FNV hash of the anchor window ending at consumed (persisted fingerprint)
	anchorSize int    // length of the anchor window the hash covers (<= anchorLen)
	sealed     bool   // forward-only baseline; never corroborate pre-consent bytes

	maxPartialLine int
}

// persistedCursor is the atomic on-disk projection of a Cursor. The in-memory remainder is
// deliberately NOT persisted: consumed is newline-aligned, so on reload the unconsumed partial
// line is simply re-read from the file starting at consumed. The skip flag IS persisted so a
// mid-overflow resynchronization survives a restart.
type persistedCursor struct {
	Version    int    `json:"version"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Consumed   int64  `json:"consumed_offset"`
	Size       int64  `json:"observed_size"`
	ModNanos   int64  `json:"observed_mtime_nanos"`
	Skip       bool   `json:"skipping_partial"`
	AnchorHash uint64 `json:"anchor_hash"` // FNV of the anchorSize bytes ending at consumed
	AnchorSize int    `json:"anchor_size"` // length of the fingerprinted window (0 = none)
	Scope      string `json:"scope,omitempty"`
	Sealed     bool   `json:"sealed,omitempty"`
}

// fileIdentityOf extracts the device and inode of a stat result. ok is false only when the
// platform does not expose a *syscall.Stat_t (never on the //go:build unix targets this file
// compiles for), in which case identity-based reconciliation degrades to size/mtime and the
// caller must treat the file conservatively.
func fileIdentityOf(info os.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}

// cursorStatePath is the deterministic state-file path for one file identity beneath stateDir.
// Keying by device+inode (not path) is what lets a renamed transcript keep its cursor and a
// reused path with a new inode get a fresh one.
func cursorStatePath(stateDir string, dev, ino uint64) string {
	return filepath.Join(stateDir, fmt.Sprintf("codex-cursor-%d-%d.json", dev, ino))
}

// LoadCursor returns the durable cursor for the file identified by (dev, ino) beneath stateDir,
// resuming a persisted state ONLY when it is corroborated as a same-file append continuation and
// starting fresh at offset 0 otherwise. Keying the state file by (dev, ino) alone is not enough:
// Unix reuses inode numbers, so a deleted transcript's state file can be found for a brand-new file
// that reused its inode. The recorded Size/ModNanos are therefore checked against the live file's:
// the persisted offset is trusted only when the live file is a pure forward continuation
// (live size >= persisted size, live mtime not older than persisted, and the offset is within the
// live file). On any inconsistency the cursor starts fresh at 0 — a re-read is at-least-once-safe
// (the endpoint deduplicates), whereas resuming the wrong file would silently skip its leading
// records. liveSize/liveModNanos come from the caller's stat of the live file.
func LoadCursor(stateDir string, dev, ino uint64, liveSize, liveModNanos int64, maxPartialLine int) (*Cursor, error) {
	return loadCursor(stateDir, dev, ino, liveSize, liveModNanos, maxPartialLine, "")
}

// LoadScopedCursor is the consent-policy variant of LoadCursor. The supplied scope is a stable
// canonical-root and generation identity, so a cursor from one consent interval can never be
// resumed by another root or generation.
func LoadScopedCursor(stateDir string, dev, ino uint64, liveSize, liveModNanos int64, maxPartialLine int, scope string) (*Cursor, error) {
	if scope == "" {
		return nil, fmt.Errorf("codex cursor scope is required")
	}
	return loadCursor(filepath.Join(stateDir, "root-cursors", scope), dev, ino, liveSize, liveModNanos, maxPartialLine, scope)
}

func loadCursor(stateDir string, dev, ino uint64, liveSize, liveModNanos int64, maxPartialLine int, scope string) (*Cursor, error) {
	if maxPartialLine <= 0 {
		maxPartialLine = DefaultMaxPartialLine
	}
	c := &Cursor{
		statePath:      cursorStatePath(stateDir, dev, ino),
		dev:            dev,
		ino:            ino,
		size:           liveSize,
		modNanos:       liveModNanos,
		maxPartialLine: maxPartialLine,
		scope:          scope,
	}
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // fresh cursor at offset 0
		}
		return nil, fmt.Errorf("reading codex cursor state %s: %w", c.statePath, err)
	}
	var p persistedCursor
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decoding codex cursor state %s: %w", c.statePath, err)
	}
	if p.Version != cursorStateVersion || p.Device != dev || p.Inode != ino || p.Scope != scope {
		return c, nil // stale/foreign record: start fresh rather than resume the wrong file
	}
	// Corroborate the persisted offset against the live file. A reused inode (or an in-place
	// rewrite that happened while we were not watching) fails one of these checks, so we default to
	// a full re-read from 0 rather than a resume that could skip the new file's leading bytes.
	if p.Consumed > liveSize || liveSize < p.Size || liveModNanos < p.ModNanos {
		return c, nil // not a clean append continuation: start fresh at 0
	}
	c.consumed = p.Consumed
	c.size = p.Size
	c.modNanos = p.ModNanos
	c.skip = p.Skip
	// The anchor bytes themselves are not persisted (they are transcript content); only their hash
	// and length are. On resume the in-memory anchor is nil and the watcher verifies the persisted
	// hash against a fresh read of the file before trusting the offset.
	c.anchorHash = p.AnchorHash
	c.anchorSize = p.AnchorSize
	c.sealed = p.Sealed
	return c, nil
}

// AnchorFingerprint returns the FNV hash and byte length of the content window ending at the
// consumed offset. The watcher re-reads that many bytes from the live file and compares the hash to
// corroborate that the offset is still a valid append point (defeating a one-byte boundary
// coincidence). A zero length means no fingerprint is available (a fresh cursor, or a legacy
// persisted state), in which case the watcher falls back to the single-byte newline boundary check.
func (c *Cursor) AnchorFingerprint() (hash uint64, length int) { return c.anchorHash, c.anchorSize }

// SeedAnchor populates the in-memory anchor window from bytes the watcher has just read and
// validated against the persisted fingerprint (the anchorLen bytes ending at consumed). It is a
// no-op once the anchor is already populated. This is what makes a resumed cursor durable: after a
// restart LoadCursor restores only the persisted hash (not the raw bytes), so without re-seeding
// the first commit would rebuild the window from only post-restart bytes and persist a degraded or
// empty fingerprint — silently downgrading the corroboration. Seeding from the validated read keeps
// the full window intact across the restart.
func (c *Cursor) SeedAnchor(window []byte) {
	if len(c.anchor) > 0 || len(window) == 0 {
		return
	}
	w := window
	if len(w) > anchorLen {
		w = w[len(w)-anchorLen:]
	}
	c.anchor = append([]byte(nil), w...)
	c.anchorSize = len(c.anchor)
	c.anchorHash = hashBytes(c.anchor)
}

// updateAnchor folds the just-consumed bytes into the rolling anchor window (the last anchorLen
// bytes ending at the new consumed offset) and recomputes the persisted fingerprint.
func (c *Cursor) updateAnchor(consumedBytes []byte) {
	buf := append(c.anchor, consumedBytes...)
	if len(buf) > anchorLen {
		buf = buf[len(buf)-anchorLen:]
	}
	c.anchor = append(c.anchor[:0], buf...)
	c.anchorSize = len(c.anchor)
	c.anchorHash = hashBytes(c.anchor)
}

// hashBytes is the FNV-1a 64-bit hash used for the anchor fingerprint.
func hashBytes(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

// Identity reports the device and inode this cursor is bound to.
func (c *Cursor) Identity() (dev, ino uint64) { return c.dev, c.ino }

// Consumed is the durable, newline-aligned byte offset through which records have been parsed.
func (c *Cursor) Consumed() int64 { return c.consumed }

// ReadOffset is the byte offset the next read should start from: the consumed offset plus the
// length of the in-memory unconsumed remainder. The watcher reads [ReadOffset, size) so it only
// ever touches bytes appended since the last read — the O(new bytes) guarantee.
func (c *Cursor) ReadOffset() int64 { return c.consumed + int64(len(c.remainder)) }

// StatePath is the absolute path of this cursor's atomic state file, exposed for tests and for
// the watcher's bounded state directory management.
func (c *Cursor) StatePath() string { return c.statePath }

// observe records the latest stat metadata (size/mtime) so persisted state carries a corroborating
// change signal alongside the authoritative identity+offset.
func (c *Cursor) observe(size, modNanos int64) {
	c.size = size
	c.modNanos = modNanos
}

// Reset returns the cursor to offset 0 with an empty remainder and no pending skip, for a
// same-identity file that was truncated or rewritten in place. The caller is responsible for
// emitting the truncation diagnostic; Reset only moves the position.
func (c *Cursor) Reset() {
	c.consumed = 0
	c.remainder = nil
	c.skip = false
	c.anchor = nil
	c.anchorHash = 0
	c.anchorSize = 0
	c.sealed = false
}

// SealAt advances a forward-only baseline cursor to the raw EOF observed by stat. It deliberately
// has no anchor: validating an anchor would read pre-consent transcript content. A later shrink or
// rewrite is sealed again by stat rather than ever falling back to byte zero.
func (c *Cursor) SealAt(eof int64) {
	if eof < 0 {
		eof = 0
	}
	c.consumed = eof
	c.remainder = nil
	c.skip = false
	c.anchor = nil
	c.anchorHash = 0
	c.anchorSize = 0
	c.sealed = true
}

func (c *Cursor) IsSealed() bool { return c.sealed }

// Ingest folds newBytes (the freshly appended tail) into the cursor. It prepends the buffered
// remainder, parses only complete newline-terminated lines via the committed Parse, and returns
// the parsed candidates in transcript order. When an unterminated line grows past the remainder
// cap, a content-free CAPTURE_DIAGNOSTIC is appended and the cursor enters a re-synchronizing
// skip state that discards bytes up to the next newline.
//
// Ingest does NOT mutate the cursor's durable position. Instead it returns a commit closure the
// caller invokes only AFTER the candidates are durably accepted downstream; on a delivery failure
// the caller drops the closure and re-reads the same bytes next poll (at-least-once, deduplicated
// downstream). This ordering is what guarantees a crash between parse and delivery re-delivers
// rather than skips.
func (c *Cursor) Ingest(newBytes []byte, cfg ReferenceConfig) (cands []*Candidate, commit func()) {
	// Re-synchronizing after a remainder overflow: discard bytes until the next newline before
	// resuming normal line parsing. This keeps memory bounded when a single line is pathological.
	if c.skip {
		nl := bytes.IndexByte(newBytes, '\n')
		if nl < 0 {
			// Still no line boundary: account for the discarded bytes and stay in skip mode.
			discarded := append([]byte(nil), newBytes...)
			return nil, func() {
				c.consumed += int64(len(discarded))
				c.updateAnchor(discarded)
			}
		}
		discarded := append([]byte(nil), newBytes[:nl+1]...)
		rest := newBytes[nl+1:]
		cands, restCommit := c.ingestNormal(nil, rest, cfg)
		return cands, func() {
			c.consumed += int64(len(discarded))
			c.updateAnchor(discarded)
			c.skip = false
			restCommit()
		}
	}
	return c.ingestNormal(c.remainder, newBytes, cfg)
}

// ingestNormal parses buf = prefix + newBytes (prefix is the currently buffered remainder, or nil
// when the caller has already cleared it), and computes the resulting position mutation as a
// deferred commit. It never mutates the cursor directly.
func (c *Cursor) ingestNormal(prefix, newBytes []byte, cfg ReferenceConfig) (cands []*Candidate, commit func()) {
	buf := make([]byte, 0, len(prefix)+len(newBytes))
	buf = append(buf, prefix...)
	buf = append(buf, newBytes...)

	res := Parse(buf, cfg)
	rem := buf[res.Consumed:]

	if len(rem) > c.maxPartialLine {
		// A single unterminated line has outgrown the cap. Emit a bounded diagnostic, discard the
		// partial (advance past it), and enter skip mode so its eventual continuation is dropped
		// up to the next newline. Memory stays bounded; no future record is silently lost — the
		// tail after the next newline re-enters clean parsing. consumed lands mid-line here, so the
		// anchor (not a newline-boundary assumption) is what lets the next poll corroborate it.
		diag := overflowDiagnostic(len(rem), c.maxPartialLine)
		out := append(res.Candidates, diag)
		consumed := append([]byte(nil), buf...) // all of buf is consumed (parsed prefix + discarded partial)
		return out, func() {
			c.consumed += int64(len(consumed))
			c.updateAnchor(consumed)
			c.remainder = nil
			c.skip = true
		}
	}

	// Copy the remainder out of buf so the caller's newBytes slice can be reused/freed.
	nextRem := append([]byte(nil), rem...)
	consumed := append([]byte(nil), buf[:res.Consumed]...)
	return res.Candidates, func() {
		c.consumed += int64(len(consumed))
		c.updateAnchor(consumed)
		c.remainder = nextRem
	}
}

// Save atomically persists the cursor's durable state (identity + consumed offset + skip flag +
// corroborating size/mtime) using temp-file → fsync → rename → directory-fsync, so the state file
// is left either fully old or fully new across a crash. It never persists the in-memory remainder;
// the consumed offset is newline-aligned and the remainder is re-derived from the file on reload.
func (c *Cursor) Save() error {
	p := persistedCursor{
		Version:    cursorStateVersion,
		Device:     c.dev,
		Inode:      c.ino,
		Consumed:   c.consumed,
		Size:       c.size,
		ModNanos:   c.modNanos,
		Skip:       c.skip,
		AnchorHash: c.anchorHash,
		AnchorSize: c.anchorSize,
		Scope:      c.scope,
		Sealed:     c.sealed,
	}
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encoding codex cursor state: %w", err)
	}
	return atomicWriteCursorFile(c.statePath, data)
}

// overflowDiagnostic builds the content-free diagnostic emitted when an unterminated transcript
// line exceeds the remainder cap. It names byte counts only — never any transcript content.
func overflowDiagnostic(got, cap int) *Candidate {
	d := evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodePARTIALCAPTURE,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            fmt.Sprintf("transcript line exceeded the %d-byte partial-line cap (%d bytes buffered without a newline); resynchronizing at the next line boundary", cap, got),
	}
	return &Candidate{Kind: KindDiagnostic, Diagnostic: &d}
}

// ---- atomic cursor-state persistence (mirrors internal/observer/spool's discipline) ----

// atomicWriteCursorFile writes data to path via a temp file, file fsync, rename, and directory
// fsync, leaving path either fully old or fully new across a crash. Files are owner-only.
func atomicWriteCursorFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensureCursorDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("creating temp for cursor state %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(cursorFileMode); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp for cursor state %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("writing temp for cursor state %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp for cursor state %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing temp for cursor state %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming temp for cursor state %s: %w", path, err)
	}
	return fsyncCursorDir(dir)
}

// ensureCursorDir creates dir (and parents) owner-only, fsyncing the parent when it creates the
// leaf so the new directory entry is durable before any state file is renamed into it.
func ensureCursorDir(dir string) error {
	created := false
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		created = true
	}
	if err := os.MkdirAll(dir, cursorDirMode); err != nil {
		return fmt.Errorf("creating cursor state dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, cursorDirMode); err != nil {
		return fmt.Errorf("chmod cursor state dir %s: %w", dir, err)
	}
	if created {
		parent := filepath.Dir(dir)
		if _, err := os.Stat(parent); err == nil {
			if err := fsyncCursorDir(parent); err != nil {
				return err
			}
		}
	}
	return nil
}

// fsyncCursorDir fsyncs a directory so a rename/create in it is durable (the directory entry,
// not just the file contents).
func fsyncCursorDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening cursor state dir for fsync %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync cursor state dir %s: %w", dir, err)
	}
	return nil
}
