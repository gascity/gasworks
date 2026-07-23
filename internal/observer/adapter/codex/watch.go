//go:build unix

package codex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// errIdentityMismatch, errNotRegular, and errRefusedResolve mark a validated-open that did not
// resolve to the tracked regular file — a rotation that replaced the inode mid-poll, a non-regular
// file swapped in, or a symlink encountered while resolving under the approved root. All are
// treated like a vanished file: the poll skips the file and the next reconcile re-binds the correct
// one, so the watcher never reads a wrong file under a tracked cursor.
var (
	errIdentityMismatch = errors.New("codex watcher: transcript identity changed since discovery")
	errNotRegular       = errors.New("codex watcher: transcript is not a regular file")
	errRefusedResolve   = errors.New("codex watcher: transcript path resolution crossed a symlink")
)

// KNOWN mc-SCALE CAPTURE GAP — symlinked transcripts are refused, so aimux-multiplexed sessions are
// not captured. aimux exposes each agent/workflow's transcript as a SYMLINK into the real
// rollout/session file; this watcher refuses a symlinked final path component at BOTH layers — at
// discovery (canonicalizeTranscript -> refusalSymlink, via os.Lstat) and at read
// (openValidatedTranscript's openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH, and the O_NOFOLLOW
// fallback). At mc scale, where most agent transcripts are aimux symlinks, this is a systematic
// capture gap: a symlinked transcript emits a one-shot refusal diagnostic and is never tailed.
//
// This is deliberately NOT relaxed inline, because following symlinks safely is a change to the
// security core, not a flag flip:
//   - Both refusal layers must change in lockstep, and the race-free-open guarantee (openat2 under a
//     fixed root fd with no path re-resolution between validate and read) is the property reworked.
//   - RESOLVE_BENEATH rejects absolute symlink targets, which aimux links typically are; only
//     RESOLVE_IN_ROOT (treat the approved root as "/") both follows the link AND contains it, which
//     changes the containment model (an absolute link resolves relative to the root).
//   - Identity keys on (device,inode); a followed symlink tracks the TARGET's identity, so the
//     locator/cursor bookkeeping and the state-dir disjointness proof need re-derivation.
//
// RECOMMENDED APPROACH (behind a -follow-contained-symlinks flag, default off):
//  1. Discovery: replace the refusalSymlink refusal with EvalSymlinks(path), then verify the fully
//     resolved real path is beneath a fully resolved approved root (reject any escape). Track the
//     resolved TARGET's (device,inode) and a locator relative to the root.
//  2. Read: open the resolved real path with openat2 RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS relative to
//     the root fd (containment preserved; no symlink followed at read time because the path is
//     already resolved), then fstat-validate the tracked identity exactly as today.
//  3. Tests: a contained symlink IS captured; a symlink whose target escapes the root is refused; a
//     target swapped after discovery is caught by the identity fstat (skipped, never misread).
//
// Until that lands, capture aimux-multiplexed sessions by pointing an approved root at the REAL
// transcript directory (the symlink targets), not at the aimux symlink view.

// The watcher is the file-tailing mechanic that feeds the committed Parse. Codex does not publish
// a transcript-append hook, and fsnotify is not vendored, so change detection is a bounded poll:
// on each tick the watcher re-scans the approved root(s) (stat only — never a content rehash),
// reads ONLY the bytes appended since each file's durable cursor offset (O(new bytes)), parses
// complete lines, and hands the resulting candidates to a narrow CandidateSink seam. Files are
// tracked by filesystem IDENTITY (device+inode), so a rotation (active transcript renamed, a new
// one created) is picked up as a new identity while a rename keeps its cursor, and a replacement
// or in-place truncation restarts cleanly. Every read re-canonicalizes the path and refuses a
// symlink swap or a root escape before touching a byte, mirroring the hook's canonicalizeTranscript.

// TranscriptRef identifies the transcript a batch of candidates came from, using the same
// never-absolute discipline as the hook: Locator is the path relative to the matched approved
// root, and Device/Inode carry the filesystem identity the cursor keys on. A zero-value ref
// (empty Locator) marks a watcher-scoped diagnostic not attributable to a single tracked file
// (for example, a refused symlink swap).
type TranscriptRef struct {
	Locator string
	Device  uint64
	Inode   uint64
}

// CandidateSink is the narrow seam the watcher hands parsed candidates to, mirroring how the hook
// depends on the daemon only through DaemonSeam. E1.10 wires the endpoint's attachment/append
// path behind it; tests use a fake. The watcher never imports internal/observer/local, keeping its
// dependency closure to the standard library plus the vendored evidence/wire/parser contract.
type CandidateSink interface {
	// DeliverCandidates hands one poll's ordered candidates for a single transcript to the
	// endpoint. A non-nil error means delivery is NOT durable: the watcher does not advance the
	// cursor past these bytes and re-reads them on the next poll (at-least-once; the endpoint
	// deduplicates by observation identity). Candidates arrive in transcript order.
	DeliverCandidates(ctx context.Context, ref TranscriptRef, cands []*Candidate) error
}

// PartialCandidateSink is an optional refinement of CandidateSink whose DeliverCandidatesPartial
// reports how many leading candidates were durably delivered before any failure. The watcher uses
// that count to advance its cursor over the fully-delivered leading transcript LINES (a partial
// commit) instead of re-reading — and re-delivering — the whole batch on the next poll, which is
// what stops a mid-batch failure from double-appending the already-durable leading records
// (E1.10a red-team finding 2: an at-least-once re-append gets a fresh daemon sequence/observation
// id, so a re-read of an already-durable record is NOT collapsed by logical dedup). Delivery stays
// ordered and stop-on-first-failure; a sink that does not implement this keeps the all-or-nothing
// behavior, so existing sinks are unaffected.
//
// SCOPE — the double-append is eliminated across LINE boundaries only. The cursor advances a whole
// transcript line at a time, so when a single line emits MULTIPLE candidates (a tool_call plus its
// extracted git/gh reference candidates) and delivery fails PART-WAY through that one line, the
// line is not committed and the retry re-appends the line's already-durable leading candidates.
// That residual is a bounded at-least-once duplicate the platform's observation-id dedup tolerates
// — never a loss and never a cross-line duplicate; the common one-candidate-per-line case (message,
// usage, session records) is exact.
type PartialCandidateSink interface {
	CandidateSink
	// DeliverCandidatesPartial delivers cands in transcript order, stopping at the first failure,
	// and returns the number of leading candidates durably delivered (or safely dropped) before
	// it. A nil error means the whole batch was delivered (delivered == len(cands)).
	DeliverCandidatesPartial(ctx context.Context, ref TranscriptRef, cands []*Candidate) (delivered int, err error)
}

// ReadRangeFunc reads length bytes starting at off from an already-opened, identity-validated file
// handle, returning the bytes actually available (a short read at EOF is not an error). Reading
// from the handle the watcher opened and fstat-validated — never re-resolving the path — is what
// closes the symlink-swap window between canonicalization and read. It is injectable so tests can
// prove the watcher only ever reads O(new bytes); the default is readRangeAt.
type ReadRangeFunc func(f *os.File, off, length int64) ([]byte, error)

// ContentObservation reports one tracked transcript's current filesystem identity, path, and stat
// after a poll drained its tail. It is the input to an optional whole-file side channel (Phase 1b
// content upload): the identity + root + locator let the consumer re-open the same file through the
// watcher's race-free validated open, and Size/ModNanos are the cheap debounce signal (a file that
// has stopped growing is stable). It carries no transcript content — the consumer reads that itself,
// on demand, only when it decides to upload.
type ContentObservation struct {
	// Root is the approved root the file was discovered beneath (the openat2 anchor).
	Root string
	// Locator is the file path relative to Root (never absolute), for the validated re-open.
	Locator string
	// Path is the current absolute path, for provenance (the content endpoint's source-path header).
	Path string
	// Device / Inode are the filesystem identity the cursor and session-threading key on.
	Device uint64
	Inode  uint64
	// Size / ModNanos are the current stat, the debounce (stability) signal.
	Size     int64
	ModNanos int64
}

// ContentObserver is an optional seam the watcher notifies once per tracked file per poll, right
// after the file's tail has been drained, with the file's current identity/path/stat. It is a
// fire-and-forget side channel: the watcher ignores whatever it does, so a slow or failing content
// consumer can never stall or fail the metadata poll. Implementations MUST return promptly (record
// cheap state; do network I/O elsewhere).
type ContentObserver interface {
	ObserveContent(ctx context.Context, obs ContentObservation)
}

const (
	// DefaultPollInterval is the steady-state poll cadence when WatchConfig.Interval is unset. It
	// is a substitute for the absent filesystem-notification signal; the endpoint budget tunes it.
	DefaultPollInterval = 500 * time.Millisecond

	// DefaultMaxReadChunk bounds how many appended bytes a single poll reads for one file, so a
	// burst of appends drains across polls with bounded per-read memory while remaining O(new
	// bytes) overall.
	DefaultMaxReadChunk int64 = 1 << 22 // 4 MiB
)

// WatchConfig is the endpoint-owned configuration a Watcher runs under. Everything the watcher
// touches is injected so Poll is a deterministic function of the filesystem plus config.
type WatchConfig struct {
	// ApprovedRoots are the absolute directory roots whose transcripts may be tailed. A file is
	// refused unless it canonicalizes (no symlink, regular file, no parent-symlink escape) beneath
	// one of these roots — the same rule the hook enforces.
	ApprovedRoots []string
	// StateDir is the owner-only directory where per-file durable cursor state is persisted. It
	// must be OUTSIDE the transcript roots so cursor files are never themselves treated as
	// transcripts.
	StateDir string
	// References is the extraction configuration passed to every Parse call.
	References ReferenceConfig
	// Sink receives parsed candidates. Required.
	Sink CandidateSink
	// Match, when non-nil, selects which regular-file names under a root are transcripts. Nil
	// tracks every regular file beneath the roots.
	Match func(name string) bool
	// Interval overrides DefaultPollInterval for Run's ticker; 0 uses the default.
	Interval time.Duration
	// MaxPartialLine overrides the cursor remainder cap; 0 uses DefaultMaxPartialLine.
	MaxPartialLine int
	// MaxReadChunk overrides the per-poll per-file read ceiling; 0 uses DefaultMaxReadChunk.
	MaxReadChunk int64
	// ReadRange overrides the file-tail reader; nil uses readRangeAt.
	ReadRange ReadRangeFunc
	// ContentObserver, when non-nil, is notified once per tracked file per poll (after its tail is
	// drained) with the file's current identity/path/stat, driving the optional whole-file content
	// side channel. It never affects the metadata poll's success or cursor advancement.
	ContentObserver ContentObserver
	// Now overrides the clock (unused by Poll; Run's ticker uses Interval). nil uses time.Now.
	Now func() time.Time
}

type identityKey struct {
	dev uint64
	ino uint64
}

// trackedFile is one transcript the watcher is tailing, its durable cursor, and its current
// approved root, path, and locator (path/locator/root updated when the file is renamed but keeps
// its identity). root + locator drive the race-free openat2 read: the file is re-opened relative
// to a fd on the trusted root, refusing any symlink within the subtree, so drain never re-resolves
// an absolute path whose parent components an attacker could swap after discovery.
type trackedFile struct {
	cursor   *Cursor
	root     string
	path     string
	locator  string
	dev, ino uint64
}

func (tf *trackedFile) ref() TranscriptRef {
	return TranscriptRef{Locator: tf.locator, Device: tf.dev, Inode: tf.ino}
}

// Watcher tails the approved transcript roots by bounded polling. It is not safe for concurrent
// use; Poll and Run must be driven from a single goroutine.
type Watcher struct {
	cfg          WatchConfig
	readRange    ReadRangeFunc
	maxReadChunk int64
	tracked      map[identityKey]*trackedFile
	refused      map[string]bool
}

// NewWatcher validates cfg and returns a Watcher ready to Poll. It requires at least one absolute
// approved root, a state directory outside those roots, and a sink.
func NewWatcher(cfg WatchConfig) (*Watcher, error) {
	if len(cfg.ApprovedRoots) == 0 {
		return nil, errors.New("codex watcher: at least one approved root is required")
	}
	for _, root := range cfg.ApprovedRoots {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("codex watcher: approved root %q must be absolute", root)
		}
	}
	if cfg.StateDir == "" {
		return nil, errors.New("codex watcher: a cursor state directory is required")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, fmt.Errorf("codex watcher: state dir %q must be absolute", cfg.StateDir)
	}
	// The state dir must be disjoint from every approved root: if it nested inside a root the
	// watcher would discover and ingest its own cursor files as transcripts (unbounded self-feed),
	// and if a root nested inside the state dir a transcript could masquerade as cursor state. The
	// comparison resolves symlinks first, so a StateDir that is a symlink whose target lands inside
	// a root is rejected too (a textual-only check would miss the indirection).
	stateReal := resolvePathForCheck(cfg.StateDir)
	for _, root := range cfg.ApprovedRoots {
		rootReal := resolvePathForCheck(root)
		if pathContains(rootReal, stateReal) || pathContains(stateReal, rootReal) {
			return nil, fmt.Errorf("codex watcher: state dir %q must be outside approved root %q", cfg.StateDir, root)
		}
	}
	if cfg.Sink == nil {
		return nil, errors.New("codex watcher: a candidate sink is required")
	}
	rr := cfg.ReadRange
	if rr == nil {
		rr = readRangeAt
	}
	chunk := cfg.MaxReadChunk
	if chunk <= 0 {
		chunk = DefaultMaxReadChunk
	}
	return &Watcher{
		cfg:          cfg,
		readRange:    rr,
		maxReadChunk: chunk,
		tracked:      map[identityKey]*trackedFile{},
		refused:      map[string]bool{},
	}, nil
}

// Run polls at the configured interval until ctx is cancelled, returning ctx.Err(). A per-poll
// error is surfaced immediately; a transient sink failure is better handled by the caller's
// restart policy than swallowed here.
func (w *Watcher) Run(ctx context.Context) error {
	interval := w.cfg.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.Poll(ctx); err != nil {
				return err
			}
		}
	}
}

// Poll performs one reconcile-then-drain cycle: it re-scans the roots for new/rotated files
// (stat only), then reads and parses the newly appended bytes of every tracked file, delivering
// candidates to the sink. It is the deterministic unit the tests drive directly.
func (w *Watcher) Poll(ctx context.Context) error {
	files, err := w.reconcile(ctx)
	if err != nil {
		return err
	}
	for _, tf := range files {
		if err := w.drain(ctx, tf); err != nil {
			return err
		}
	}
	return nil
}

// reconcile re-scans every approved root, tracking newly appeared identities, carrying a renamed
// file's cursor to its new path, and dropping identities that are gone. It walks with WalkDir,
// which never follows a symlinked directory, so a parent directory swapped to a symlink is not
// descended and its would-be transcript is simply never discovered (refused by absence). It
// performs only readdir and stat — never a content read — so steady-state discovery is bounded by
// the directory tree size, not transcript size. It returns the tracked files in a deterministic
// order.
func (w *Watcher) reconcile(ctx context.Context) ([]*trackedFile, error) {
	present := map[identityKey]struct{}{}
	for _, root := range w.cfg.ApprovedRoots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // skip an unreadable entry; keep walking the rest of the tree
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			info, err := os.Stat(path)
			if err != nil {
				return nil // vanished mid-walk; a later poll re-discovers it
			}
			dev, ino, ok := fileIdentityOf(info)
			if !ok {
				return nil
			}
			key := identityKey{dev: dev, ino: ino}
			tf, isTracked := w.tracked[key]
			// Match gates DISCOVERY only. An already-tracked file whose name stops matching after a
			// rename must stay tracked so its unread tail is still drained — dropping it by name
			// would silently lose that tail. New (untracked) non-matching files are skipped.
			if !isTracked && w.cfg.Match != nil && !w.cfg.Match(name) {
				return nil
			}
			// Fast path: a file already tracked at this EXACT path needs no re-canonicalization. The
			// discovery-time symlink/escape check (an Lstat plus an EvalSymlinks over every parent
			// component) is the dominant per-poll cost at scale — with tens of thousands of tracked
			// transcripts it runs on every one, every poll — yet it is redundant for a stable tracked
			// file: the path and locator are unchanged, and drain re-validates the open on every read
			// with openat2 (RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) plus an fstat identity check, so a
			// parent-symlink swap or inode replacement after discovery is still refused at read time.
			// Only NEW or MOVED (renamed) files pay the canonicalize cost, making steady-state
			// discovery O(new/moved matched files) rather than O(all tracked files) per poll.
			if isTracked && tf.path == path {
				tf.root = root
				present[key] = struct{}{}
				return nil
			}
			// Refuse a symlinked final component, a non-regular file, or a parent-symlink escape
			// before trusting the path — the same rule the hook enforces on a supplied transcript.
			// (drain re-validates with O_NOFOLLOW at read time; this refusal is discovery-time.)
			locator, ok, refusal := canonicalizeTranscript(path, w.cfg.ApprovedRoots)
			if !ok {
				w.reportRefusal(ctx, refusal, path)
				return nil
			}
			delete(w.refused, path)
			present[key] = struct{}{}
			if isTracked {
				// A rename kept the identity and the cursor; only path/root/locator move.
				tf.root = root
				tf.path = path
				tf.locator = locator
				return nil
			}
			cur, err := LoadCursor(w.cfg.StateDir, dev, ino, info.Size(), info.ModTime().UnixNano(), w.cfg.MaxPartialLine)
			if err != nil {
				return err
			}
			w.tracked[key] = &trackedFile{cursor: cur, root: root, path: path, locator: locator, dev: dev, ino: ino}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("scanning transcript root %s: %w", root, err)
		}
	}
	for key := range w.tracked {
		if _, ok := present[key]; !ok {
			// Fully rotated away / deleted. GC the durable state file so a later file that reuses
			// this (device,inode) cannot resurrect a stale cursor and skip its own leading bytes.
			_ = os.Remove(cursorStatePath(w.cfg.StateDir, key.dev, key.ino))
			delete(w.tracked, key)
		}
	}
	out := make([]*trackedFile, 0, len(w.tracked))
	for _, tf := range w.tracked {
		out = append(out, tf)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].locator != out[j].locator {
			return out[i].locator < out[j].locator
		}
		if out[i].dev != out[j].dev {
			return out[i].dev < out[j].dev
		}
		return out[i].ino < out[j].ino
	})
	return out, nil
}

// drain reads and parses the bytes appended to one tracked file since its cursor offset and
// delivers the candidates. It opens the file ONCE relative to a fd on the trusted approved root,
// refusing any symlink within the subtree (openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH), and
// fstat-validates that the handle is the tracked (device,inode) regular file, then reads only from
// that handle — so neither a final-component NOR a parent-component symlink swapped in after
// discovery can redirect the read, and a mid-poll rotation that replaced the inode is skipped
// rather than misread. It detects an in-place truncation (the file shrank below the read watermark)
// and an in-place rewrite (the byte preceding the consumed offset is no longer the newline that
// ended the last consumed line), emitting a CAPTURE_LOSS diagnostic and restarting at 0 — a re-read
// is at-least-once-safe, whereas trusting the offset after a rewrite would silently skip the new
// leading content. It never re-reads consumed bytes.
func (w *Watcher) drain(ctx context.Context, tf *trackedFile) error {
	f, size, mod, err := openValidatedTranscript(tf.root, tf.locator, tf.dev, tf.ino)
	if err != nil {
		// Vanished, symlink-swapped, non-regular, or rotated to a different inode since discovery:
		// skip this file for the poll (matching Poll's tolerance) and let the next reconcile
		// re-bind the correct identity. Never a hard error that would terminate Run.
		if isSkippableDrainErr(err) {
			return nil
		}
		return fmt.Errorf("opening transcript tail %s: %w", tf.locator, err)
	}
	defer f.Close()

	// Corroborate that the cursor offset is still a valid append point in THIS file. A shrink below
	// the read watermark is an obvious truncation; a same-or-larger size whose byte before the
	// consumed offset is not a newline is an in-place rewrite (e.g. compaction/clear that grew past
	// the old offset) or a wrong file at a reused inode. Either way, reset to 0 and re-read.
	rewrite, err := w.offsetInvalidated(f, tf.cursor, size)
	if err != nil {
		return fmt.Errorf("corroborating transcript offset %s: %w", tf.locator, err)
	}
	if rewrite {
		diag := truncationDiagnostic(tf.cursor.ReadOffset(), size)
		if derr := w.cfg.Sink.DeliverCandidates(ctx, tf.ref(), []*Candidate{diag}); derr != nil {
			return derr
		}
		tf.cursor.Reset()
		if serr := tf.cursor.Save(); serr != nil {
			return serr
		}
	}

	// The file is open and its identity is corroborated: size/mod are the current stat. Notify the
	// optional content side channel before touching the tail. This is a cheap, fire-and-forget hook
	// (it must not block); it never affects the tail read or cursor advancement below.
	w.observeContent(ctx, tf, size, mod)

	readOff := tf.cursor.ReadOffset()
	if size <= readOff {
		tf.cursor.observe(size, mod)
		return nil
	}
	length := size - readOff
	if length > w.maxReadChunk {
		length = w.maxReadChunk
	}
	newBytes, err := w.readRange(f, readOff, length)
	if err != nil {
		return fmt.Errorf("reading transcript tail %s: %w", tf.locator, err)
	}
	if len(newBytes) == 0 {
		return nil
	}
	cands, commit := tf.cursor.Ingest(newBytes, w.cfg.References)
	if len(cands) == 0 {
		commit()
		tf.cursor.observe(size, mod)
		return tf.cursor.Save()
	}
	delivered, derr := deliverCandidates(ctx, w.cfg.Sink, tf.ref(), cands)
	if derr == nil {
		commit()
		tf.cursor.observe(size, mod)
		return tf.cursor.Save()
	}
	// A mid-batch delivery failure. Advance the cursor over only the leading transcript LINES whose
	// every candidate was durably delivered (a partial commit), so the next poll re-reads from the
	// first undelivered record rather than re-delivering — and re-appending — the already-durable
	// leading records. A line is committed only when all of its candidates were delivered, so no
	// candidate is ever skipped. When no whole leading line was fully delivered, or a partial commit
	// is unsafe (a mid-overflow resync accounts bytes mid-line), nothing is committed and the whole
	// tail is re-read next poll — the original all-or-nothing behavior. The re-Ingest of the
	// fully-delivered prefix mutates the cursor only through the same commit path; its re-parsed
	// candidates are already durable and are discarded, never re-delivered.
	if !tf.cursor.skip {
		if p, ok := deliveredLinePrefix(cands, delivered, newBytes); ok {
			_, commitPrefix := tf.cursor.Ingest(newBytes[:p], w.cfg.References)
			commitPrefix()
			tf.cursor.observe(size, mod)
			if serr := tf.cursor.Save(); serr != nil {
				return serr
			}
		}
	}
	return derr
}

// observeContent fires the optional content side channel for one tracked file with its current
// stat. It is a no-op when no observer is configured, and the observer's contract forbids blocking,
// so this never delays the poll.
func (w *Watcher) observeContent(ctx context.Context, tf *trackedFile, size, modNanos int64) {
	if w.cfg.ContentObserver == nil {
		return
	}
	w.cfg.ContentObserver.ObserveContent(ctx, ContentObservation{
		Root:     tf.root,
		Locator:  tf.locator,
		Path:     tf.path,
		Device:   tf.dev,
		Inode:    tf.ino,
		Size:     size,
		ModNanos: modNanos,
	})
}

// ErrTranscriptTooLarge reports that a transcript exceeds the caller's whole-file content ceiling.
// ReadValidatedTranscript returns it (with the file's true size) instead of reading the file, so a
// pathologically large transcript is skipped by the content side channel rather than buffered.
var ErrTranscriptTooLarge = errors.New("codex watcher: transcript exceeds the maximum content size")

// ReadValidatedTranscript reads the whole current content of the transcript identified by
// (root, locator, dev, ino) through the SAME race-free validated open the tail reader uses: the file
// is opened relative to a fd on the trusted approved root (RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) and
// fstat-validated against the tracked (device,inode) regular-file identity, so no symlink swap or
// inode reuse after discovery can redirect the read. It refuses a file larger than maxBytes,
// returning ErrTranscriptTooLarge and the true size without reading any content (maxBytes<=0 disables
// the ceiling). A file that vanished, was symlink-swapped, went non-regular, or rotated to a new
// inode returns the same skippable errors openValidatedTranscript reports, which the content side
// channel treats as "skip this file, retry next poll". This is the accessor the daemon's content
// upload reads whole snapshots through, keeping the symlink-safe open logic in one place.
func ReadValidatedTranscript(root, locator string, dev, ino uint64, maxBytes int64) (content []byte, size, modNanos int64, err error) {
	f, size, modNanos, err := openValidatedTranscript(root, locator, dev, ino)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()
	if maxBytes > 0 && size > maxBytes {
		return nil, size, modNanos, ErrTranscriptTooLarge
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	// A file that shrank between the fstat and the read yields a short read (ErrUnexpectedEOF); a file
	// that grew is snapshot at the fstat size (the extra tail is captured on a later poll). Neither is
	// an error — the content endpoint dedups by hash and a later, larger snapshot supersedes.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, size, modNanos, err
	}
	return buf[:n], size, modNanos, nil
}

// deliverCandidates delivers one poll's candidates and reports how many leading candidates were
// durably delivered. A sink that implements PartialCandidateSink reports the exact count so a
// mid-batch failure can partial-commit; a plain CandidateSink reports all-or-nothing (a failure is
// treated as zero delivered, preserving the original re-read-the-whole-batch behavior).
func deliverCandidates(ctx context.Context, sink CandidateSink, ref TranscriptRef, cands []*Candidate) (int, error) {
	if ps, ok := sink.(PartialCandidateSink); ok {
		return ps.DeliverCandidatesPartial(ctx, ref, cands)
	}
	if err := sink.DeliverCandidates(ctx, ref, cands); err != nil {
		return 0, err
	}
	return len(cands), nil
}

// deliveredLinePrefix returns the byte length of the leading newBytes whose transcript lines were
// fully delivered, given that `delivered` leading candidates were durably delivered. It is the
// offset just past the newline of the last line before the first undelivered candidate's source
// line, so every candidate on a committed line was delivered (no candidate is skipped) and no
// committed line is re-read (no already-durable record is re-appended). ok is false when no whole
// leading line was fully delivered or when the first undelivered candidate carries no source line.
func deliveredLinePrefix(cands []*Candidate, delivered int, newBytes []byte) (int, bool) {
	if delivered <= 0 || delivered >= len(cands) {
		return 0, false
	}
	nextLine := cands[delivered].LineNumber
	if nextLine <= 1 {
		// The first undelivered record is on the first parsed line (or carries no line number):
		// there is no whole leading line to commit.
		return 0, false
	}
	p := offsetAfterNthNewline(newBytes, nextLine-1)
	if p <= 0 {
		return 0, false
	}
	return p, true
}

// offsetAfterNthNewline returns the byte offset just past the n-th '\n' in b (1-based), or -1 when
// b holds fewer than n newlines. Because the cursor's in-memory remainder never contains a newline,
// the n-th newline in the freshly-read newBytes is the n-th line boundary of the parse buffer, so
// this maps a delivered line count to the exact prefix the cursor must advance over.
func offsetAfterNthNewline(b []byte, n int) int {
	if n <= 0 {
		return -1
	}
	count := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			count++
			if count == n {
				return i + 1
			}
		}
	}
	return -1
}

// offsetInvalidated reports whether the cursor's consumed offset can no longer be trusted as an
// append point in the file behind f. It is true when the file shrank below the read watermark
// (truncation) or when the content window ending at the consumed offset no longer matches the
// cursor's persisted anchor fingerprint (an in-place rewrite — even one that grew past the offset
// with a coincidental newline at the boundary — or a reused-inode file whose content differs). The
// multi-byte anchor is what defeats a single-byte newline coincidence and works even when consumed
// sits mid-line (during an overflow resync). A fresh cursor (consumed 0) is always valid; a legacy
// cursor with no persisted anchor falls back to the single-byte newline check.
func (w *Watcher) offsetInvalidated(f *os.File, cur *Cursor, size int64) (bool, error) {
	if size < cur.ReadOffset() {
		return true, nil
	}
	consumed := cur.Consumed()
	if consumed <= 0 {
		return false, nil
	}
	if consumed > size {
		return true, nil
	}
	hash, alen := cur.AnchorFingerprint()
	if alen <= 0 {
		// Legacy/hand-seeded cursor without an anchor: fall back to the newline-boundary check.
		b := make([]byte, 1)
		if _, err := f.ReadAt(b, consumed-1); err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil
			}
			return false, err
		}
		return b[0] != '\n', nil
	}
	if int64(alen) > consumed {
		alen = int(consumed)
	}
	buf := make([]byte, alen)
	n, err := f.ReadAt(buf, consumed-int64(alen))
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if n < alen {
		return true, nil // could not read the full fingerprint window: not a valid continuation
	}
	if hashBytes(buf) != hash {
		return true, nil
	}
	// The offset is a valid continuation. Re-seed the in-memory anchor from the validated window so
	// a post-restart commit (LoadCursor left the raw bytes nil) extends the full fingerprint rather
	// than rebuilding a degraded one from only post-restart bytes.
	cur.SeedAnchor(buf)
	return false, nil
}

// reportRefusal emits a bounded, content-free diagnostic the first time a given full path is
// refused, so a symlink swap or root escape is observable without leaking the path and without
// flooding on every poll. The dedup is keyed by the full path (not the basename) so per-day /
// per-session transcripts that share a basename across subdirectories track refusals independently
// and one clean file cannot clear another directory's refusal audit signal. The dedup is cleared
// when that same path later canonicalizes cleanly. Delivery is best-effort: the security guarantee
// is that the refused file is never read, which has already happened by this point.
func (w *Watcher) reportRefusal(ctx context.Context, refusal transcriptRefusal, path string) {
	if refusal == refusalNone || refusal == refusalNotAbsolute {
		return
	}
	if w.refused[path] {
		return
	}
	w.refused[path] = true
	diag := refusalDiagnostic(refusal)
	_ = w.cfg.Sink.DeliverCandidates(ctx, TranscriptRef{}, []*Candidate{diag})
}

// openValidatedTranscript opens the transcript identified by (root, locator) and fstat-validates
// the handle is the tracked (device,inode) regular file. The open resolves locator RELATIVE to a
// fd on the trusted approved root with RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH, so no symlink anywhere
// within the subtree — final component OR any parent directory — can redirect it, and it cannot
// escape the root. This is race-free: unlike re-resolving an absolute path (where O_NOFOLLOW guards
// only the final component and a parent-directory swap after discovery could redirect the open even
// under inode reuse), the kernel resolves the whole path under the fixed root fd in one refusing
// step. Reading from the returned handle — never re-resolving the path — is what lets drain trust
// the bytes. On a kernel without openat2 (ENOSYS) it degrades to the O_NOFOLLOW final-component
// guard, which still refuses a final-component symlink and validates identity. The caller Closes f.
func openValidatedTranscript(root, locator string, dev, ino uint64) (f *os.File, size, modNanos int64, err error) {
	rootFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	defer unix.Close(rootFd)
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	}
	fd, err := unix.Openat2(rootFd, locator, how)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS):
			return openValidatedFallback(filepath.Join(root, locator), dev, ino)
		case errors.Is(err, unix.ENOENT):
			return nil, 0, 0, os.ErrNotExist // vanished mid-poll
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV):
			return nil, 0, 0, errRefusedResolve // a symlink under the root / an escape attempt
		default:
			return nil, 0, 0, err
		}
	}
	return validateOpenFile(os.NewFile(uintptr(fd), locator), dev, ino)
}

// openValidatedFallback is the pre-openat2 (ENOSYS) path: open the absolute path refusing only a
// final-component symlink (O_NOFOLLOW) and validate identity. It leaves the parent-component swap
// window open, but only runs on kernels older than 5.6 that lack openat2.
func openValidatedFallback(path string, dev, ino uint64) (*os.File, int64, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, 0, err
	}
	return validateOpenFile(f, dev, ino)
}

// validateOpenFile fstats an already-open handle and confirms it is a regular file whose
// (device,inode) equals the tracked identity, closing it and returning a typed error otherwise.
func validateOpenFile(f *os.File, dev, ino uint64) (*os.File, int64, int64, error) {
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, 0, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, 0, 0, errNotRegular
	}
	fdev, fino, ok := fileIdentityOf(info)
	if !ok || fdev != dev || fino != ino {
		f.Close()
		return nil, 0, 0, errIdentityMismatch
	}
	return f, info.Size(), info.ModTime().UnixNano(), nil
}

// isSkippableDrainErr reports whether a validated-open error means "skip this file this poll" rather
// than "fail the poll". A vanished file (ENOENT), a symlink refused during resolution (ELOOP via the
// O_NOFOLLOW fallback, or errRefusedResolve from openat2), a non-regular replacement, or a rotated
// inode are all routine mid-poll races that the next reconcile resolves; none should terminate Run.
func isSkippableDrainErr(err error) bool {
	return os.IsNotExist(err) ||
		errors.Is(err, errIdentityMismatch) ||
		errors.Is(err, errNotRegular) ||
		errors.Is(err, errRefusedResolve) ||
		errors.Is(err, syscall.ELOOP) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM)
}

// readRangeAt is the default file-tail reader: it reads length bytes at off from the already-open,
// identity-validated handle via ReadAt and tolerates a short read at EOF. It reads exactly the
// requested window and nothing before off, which is what keeps the watcher O(new bytes).
func readRangeAt(f *os.File, off, length int64) ([]byte, error) {
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// resolvePathForCheck returns the symlink-resolved absolute form of p when it (or its nearest
// existing ancestor) can be resolved, falling back to the lexically cleaned path otherwise. It lets
// the state-dir/root disjointness check see through a symlinked directory without requiring either
// path to exist yet.
func resolvePathForCheck(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	// p does not fully exist yet: resolve the longest existing ancestor and re-attach the remainder,
	// so a symlinked existing parent is still seen through.
	dir, rest := filepath.Split(filepath.Clean(p))
	dir = filepath.Clean(dir)
	if dir == p || dir == "" || rest == "" {
		return filepath.Clean(p)
	}
	return filepath.Join(resolvePathForCheck(dir), rest)
}

// pathContains reports whether child is outer itself or lies beneath outer, after cleaning both.
// It is used to keep the state directory disjoint from the transcript roots.
func pathContains(outer, child string) bool {
	outer = filepath.Clean(outer)
	child = filepath.Clean(child)
	if outer == child {
		return true
	}
	rel, err := filepath.Rel(outer, child)
	if err != nil {
		return false
	}
	return rel != ".." && !hasDotDotPrefix(rel) && !filepath.IsAbs(rel)
}

// hasDotDotPrefix reports whether rel starts with a ".." path segment (i.e. child escapes outer).
func hasDotDotPrefix(rel string) bool {
	return rel == ".." || (len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && os.IsPathSeparator(rel[2]))
}

// truncationDiagnostic reports that a same-identity transcript shrank below the read watermark
// (an in-place rewrite): bytes between the new size and the old offset are unrecoverable, so
// capture of that interval is partial. It names byte offsets only — never transcript content.
func truncationDiagnostic(oldOffset, newSize int64) *Candidate {
	d := evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            fmt.Sprintf("transcript truncated to %d bytes below the read offset %d; restarting capture at 0", newSize, oldOffset),
	}
	return &Candidate{Kind: KindDiagnostic, Diagnostic: &d}
}

// refusalDiagnostic reports that a candidate transcript path was refused for a safety reason. It
// names the refusal class only — never the path — so a symlink swap or a root escape is auditable
// without leaking a local filesystem path onto the wire.
func refusalDiagnostic(refusal transcriptRefusal) *Candidate {
	d := evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            "refused a transcript path (" + refusalReason(refusal) + "); it was not read",
	}
	return &Candidate{Kind: KindDiagnostic, Diagnostic: &d}
}

func refusalReason(refusal transcriptRefusal) string {
	switch refusal {
	case refusalSymlink:
		return "symlinked final component"
	case refusalNonRegular:
		return "non-regular file"
	case refusalRootEscape:
		return "path escapes every approved root"
	case refusalUnreadable:
		return "unreadable"
	case refusalNotAbsolute:
		return "non-absolute path"
	default:
		return "unspecified"
	}
}
