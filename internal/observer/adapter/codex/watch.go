//go:build unix

package codex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/rootpolicy"
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
	// errDeferTracking marks a newly discovered identity whose seal lineage could not be evaluated
	// this poll, because the file vanished or was swapped again between the walk and the validated
	// open. Tracking waits for the next reconcile rather than starting at byte zero, which would
	// drain a prefix the locator's lineage may still fence.
	errDeferTracking = errors.New("codex watcher: deferring tracking until the seal lineage can be read")
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
	// GCSessionID is the authoritative Gas City session binding from the adjacent .gcmeta sidecar.
	// It is empty when no valid sidecar is present; it is never inferred from the native session id.
	GCSessionID string
}

// ContentObserver is an optional seam the watcher notifies once per tracked file per poll, right
// after the file's tail has been drained, with the file's current identity/path/stat. It is a
// fire-and-forget side channel: the watcher ignores whatever it does, so a slow or failing content
// consumer can never stall or fail the metadata poll. Implementations MUST return promptly (record
// cheap state; do network I/O elsewhere).
type ContentObserver interface {
	ObserveContent(ctx context.Context, obs ContentObservation)
	// ForgetContent is called once when the watcher drops a transcript identity that has fully
	// rotated away / been deleted (the same point it GCs the durable cursor state). The consumer
	// must release any per-identity in-memory state and durable marker for that (device,inode) so a
	// later file that reuses the identity starts fresh and cannot be resurrected by a stale marker,
	// and so a long-lived daemon does not accumulate state for transcripts that no longer exist.
	ForgetContent(device, inode uint64)
}

const (
	// DefaultPollInterval is the steady-state poll cadence when WatchConfig.Interval is unset. It
	// is a substitute for the absent filesystem-notification signal; the endpoint budget tunes it.
	DefaultPollInterval = 500 * time.Millisecond

	// DefaultMaxReadChunk bounds how many appended bytes a single poll reads for one file, so a
	// burst of appends drains across polls with bounded per-read memory while remaining O(new
	// bytes) overall.
	DefaultMaxReadChunk int64 = 1 << 22 // 4 MiB
	// gcMetaCheckInterval bounds sidecar I/O for an unchanged transcript while still making a
	// late-written authoritative binding visible promptly. The watcher keeps polling transcript
	// metadata at its normal cadence; this only limits the small adjacent sidecar read.
	gcMetaCheckInterval = 5 * time.Second
	maxGCSessionIDBytes = 256
	// Gas City's transcriptmeta writer stores the opaque id followed by one LF record delimiter.
	maxGCSessionMetaBytes = maxGCSessionIDBytes + 1
	// absenceEvictionPolls is how many consecutive CORROBORATED absent polls an identity must
	// accumulate before its durable state is released. One empty walk is not evidence a transcript is
	// gone: a store subdirectory that momentarily cannot be read (a chmod, an NFS blip) produces
	// exactly the same absence as a deletion, and releasing a forward-only floor there would
	// republish the whole pre-consent prefix the moment the directory came back.
	absenceEvictionPolls = 2

	// storePeekHotHorizon is how recently a store transcript must have been written to stay in the HOT
	// classification tier, where it is eligible for a membership peek on every poll. A provider store
	// is date-sharded and grows forever, and an undetermined verdict is deliberately never cached, so
	// without a horizon every ancient shard would re-enter the undetermined set on each poll and spend
	// the budget this poll's live sessions need. 90 days is far past any session still being appended
	// to, so a transcript below the horizon has nothing left to say that a slow cadence would miss.
	storePeekHotHorizon = 90 * 24 * time.Hour
	// defaultStorePeekBudget caps how many membership peeks ONE poll spends classifying store
	// transcripts the watcher is not already tailing. A peek reads a bounded head — a few KB for the
	// overwhelming majority of transcripts, maxPeekBytes at the very worst — so 64 of them is a few
	// hundred KB of reads in the common case and stays an order of magnitude inside the 500ms default
	// poll interval even at the tail. It drains a 10k-transcript store in ~157 polls (~80s at the
	// default cadence), which is well inside the window after a registration, while the tail of a
	// transcript already being tailed is never charged against it.
	defaultStorePeekBudget = 64
	// defaultStorePeekColdPeriod is how many polls apart one COLD-tier transcript is reconsidered. At
	// the default cadence that is one reconsideration per ~32s per pre-horizon file instead of two per
	// second, which is what stops a store's accumulated history from crowding out its live sessions.
	defaultStorePeekColdPeriod = 64
)

// WatchConfig is the endpoint-owned configuration a Watcher runs under. Everything the watcher
// touches is injected so Poll is a deterministic function of the filesystem plus config.
type WatchConfig struct {
	// ApprovedRoots are the absolute directory roots whose transcripts may be tailed. A file is
	// refused unless it canonicalizes (no symlink, regular file, no parent-symlink escape) beneath
	// one of these roots — the same rule the hook enforces.
	ApprovedRoots []string
	// RootPolicies are explicit, canonical companion consent records. They are mutually exclusive
	// with ApprovedRoots; the legacy field remains unchanged for existing deployments.
	RootPolicies []rootpolicy.Record
	// Stores are the absolute provider store directories (the Claude projects dir, the Codex sessions
	// dir) that kind=project consent roots draw their sessions from. A store holds every session on the
	// machine, so it is never itself an approved root: a transcript beneath a store is captured only
	// once membership classifies it into an active project root, and every other session is left
	// untouched. Stores are meaningful only alongside kind=project RootPolicies.
	Stores []string
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
	// Now overrides the clock: the store scan reads it to tier a transcript by mtime, and Run's ticker
	// uses Interval. nil uses time.Now.
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
	cursor          *Cursor
	root            string
	path            string
	locator         string
	dev, ino        uint64
	gcSessionID     string
	gcMetaCheckedAt time.Time
	policy          *rootPolicyState
	forwardBaseline bool
	// member marks a transcript admitted by project membership rather than by direct root containment.
	// It is what the content gate reads to require the A5 seal-completion conditions of a project
	// session while leaving a legacy transcripts-root file's gate on forwardBaseline alone.
	member bool
	// absentPolls counts consecutive polls whose walk positively established that this identity is
	// no longer under its root (a clean walk plus a readable parent directory). Walk errors leave it
	// untouched, so an unreadable directory never counts as evidence of absence.
	absentPolls int
}

func (tf *trackedFile) ref() TranscriptRef {
	return TranscriptRef{Locator: tf.locator, Device: tf.dev, Inode: tf.ino}
}

// discovered is one regular file a walk just canonicalized, before it becomes a trackedFile: where
// it lives, which identity it carries, and the stat the walk read. It travels together because the
// baseline decision needs all of it: the locator to look up a seal lineage, the root and identity
// to re-open the file through the same validated open a drain uses, and the stat to seal.
type discovered struct {
	root    string
	path    string
	locator string
	dev     uint64
	ino     uint64
	size    int64
	mod     int64
}

func (d discovered) ref() TranscriptRef {
	return TranscriptRef{Locator: d.locator, Device: d.dev, Inode: d.ino}
}

// Watcher tails the approved transcript roots by bounded polling. It is not safe for concurrent
// use; Poll and Run must be driven from a single goroutine.
type Watcher struct {
	cfg          WatchConfig
	readRange    ReadRangeFunc
	maxReadChunk int64
	tracked      map[identityKey]*trackedFile
	refused      map[string]bool
	rootPolicies map[string]*rootPolicyState
	// stores are the provider store directories walked for kind=project consent. They are disjoint from
	// ApprovedRoots: a store file reaches tracking through membership, never through root containment.
	stores []string
	// projectPolicies indexes the kind=project policy states by their ProjectRootID (the same id
	// membership stamps on a positive verdict), so a member transcript is routed to the root it belongs
	// to rather than the directory it was found under.
	projectPolicies map[string]*rootPolicyState
	// membership and membershipIndex are the peek engine and its corroborated verdict cache, built once
	// when there is at least one active kind=project root. Both are nil in a legacy or transcripts-only
	// deployment, which is the flag reconcileStores checks before doing any store work.
	membership      *MembershipPeeker
	membershipIndex *MembershipIndex
	// peekMembership is the classification call the store scan spends its per-poll budget on. It is a
	// field rather than a direct w.membership.Peek so a test can count the peeks one poll makes;
	// production always holds the peeker's own method.
	peekMembership func(store, locator string, dev, ino uint64) (Membership, TranscriptStat, error)
	// storePeekBudget is how many peeks one poll may spend classifying store transcripts that are not
	// already tracked, and storePeekColdPeriod is how many polls apart one cold-tier transcript is
	// reconsidered. Both are fields, seeded from the package defaults, so a test can drive the
	// scheduler without a config surface nobody deploying this would set.
	storePeekBudget     int
	storePeekColdPeriod uint64
	// peekDeferred is the queue of identities the previous poll ran out of budget before classifying,
	// IN THE ORDER they were deferred. It is the round-robin state: they are reconsidered ahead of the
	// rest of the walk on the next poll, so no transcript is starved behind the same head of a store's
	// enumeration. The order is load-bearing — an unordered set re-sorts into walk order on every poll,
	// which hands the allowance back to the same low-sorting names and starves the tail just as badly.
	peekDeferred []identityKey
	// coldPeekDue is the poll each pre-horizon transcript may next be reconsidered on, so a store's
	// accumulated history is re-read on a cadence instead of on every poll. Both maps are rebuilt from
	// what each poll actually walked, so neither outlives the transcripts in it.
	coldPeekDue map[identityKey]uint64
	// pollSeq counts the store polls this watcher has run. It is the clock the cold tier's cadence is
	// measured in.
	pollSeq uint64
}

// NewWatcher validates cfg and returns a Watcher ready to Poll. It requires at least one absolute
// approved root, a state directory outside those roots, and a sink.
func NewWatcher(cfg WatchConfig) (*Watcher, error) {
	if len(cfg.RootPolicies) > 0 && len(cfg.ApprovedRoots) > 0 {
		return nil, errors.New("codex watcher: root policies and approved roots are mutually exclusive")
	}
	policyStates := map[string]*rootPolicyState{}
	if len(cfg.RootPolicies) > 0 {
		for _, p := range cfg.RootPolicies {
			if !filepath.IsAbs(p.Path) || p.Generation == 0 || (p.Active && p.Mode != rootpolicy.ForwardOnly && p.Mode != rootpolicy.Backfill) || (!p.Active && p.Mode != "") {
				return nil, fmt.Errorf("codex watcher: invalid root policy for %q", p.Path)
			}
			// Only a transcripts-kind root is a directory to tail directly. A kind=project root's path is
			// the owner's project folder, whose sessions live in the recorded stores and are selected by
			// membership, so it is never added to the tailed roots — walking it would seal and capture the
			// project's own files.
			if p.Active && !p.IsProject() {
				cfg.ApprovedRoots = append(cfg.ApprovedRoots, p.Path)
			}
		}
	}
	if len(cfg.ApprovedRoots) == 0 && len(cfg.RootPolicies) == 0 {
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
	if len(cfg.RootPolicies) > 0 {
		for _, p := range cfg.RootPolicies {
			if _, exists := policyStates[p.Path]; exists {
				return nil, fmt.Errorf("codex watcher: duplicate root policy %q", p.Path)
			}
			st, err := newRootPolicyState(cfg.StateDir, p)
			if err != nil {
				return nil, err
			}
			policyStates[p.Path] = st
		}
	}
	// A kind=project root draws its sessions from the recorded stores, indexed here by the id membership
	// stamps on a member so a verdict routes straight to the root's state. The peek engine is built only
	// when at least one such root is active; a legacy or transcripts-only deployment leaves it nil and
	// reconcileStores stays a no-op.
	projectPolicies := map[string]*rootPolicyState{}
	hasProject := false
	for _, p := range cfg.RootPolicies {
		if p.Active && p.IsProject() {
			hasProject = true
			projectPolicies[rootPolicyID(p.Path)] = policyStates[p.Path]
		}
	}
	for _, store := range cfg.Stores {
		if !filepath.IsAbs(store) {
			return nil, fmt.Errorf("codex watcher: store %q must be absolute", store)
		}
		// A store is walked like a root, so the same self-feed hazard applies: cursor state must not sit
		// inside it, nor a store inside the state dir.
		storeReal := resolvePathForCheck(store)
		if pathContains(storeReal, stateReal) || pathContains(stateReal, storeReal) {
			return nil, fmt.Errorf("codex watcher: state dir %q must be outside store %q", cfg.StateDir, store)
		}
	}
	if hasProject && len(cfg.Stores) == 0 {
		return nil, errors.New("codex watcher: a project root requires at least one recorded store")
	}
	var (
		membership      *MembershipPeeker
		membershipIndex *MembershipIndex
	)
	if hasProject {
		membership = NewMembershipPeeker(rootpolicy.Policy{Roots: cfg.RootPolicies, Stores: cfg.Stores})
		membershipIndex = NewMembershipIndex()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	rr := cfg.ReadRange
	if rr == nil {
		rr = readRangeAt
	}
	chunk := cfg.MaxReadChunk
	if chunk <= 0 {
		chunk = DefaultMaxReadChunk
	}
	w := &Watcher{
		cfg:                 cfg,
		readRange:           rr,
		maxReadChunk:        chunk,
		tracked:             map[identityKey]*trackedFile{},
		refused:             map[string]bool{},
		rootPolicies:        policyStates,
		stores:              append([]string(nil), cfg.Stores...),
		projectPolicies:     projectPolicies,
		membership:          membership,
		membershipIndex:     membershipIndex,
		storePeekBudget:     defaultStorePeekBudget,
		storePeekColdPeriod: defaultStorePeekColdPeriod,
		coldPeekDue:         map[identityKey]uint64{},
	}
	if membership != nil {
		w.peekMembership = membership.Peek
	}
	return w, nil
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
	// Drains record floor fingerprints lazily, the first time a sealed file is corroborated. Flushing
	// here makes them durable in the poll that computed them while still costing one write per
	// changed root, not one per file.
	return w.flushPolicyControls()
}

// reconcile re-scans every approved root, tracking newly appeared identities, carrying a renamed
// file's cursor to its new path, and dropping identities that are gone. It walks with WalkDir,
// which never follows a symlinked directory, so a parent directory swapped to a symlink is not
// descended and its would-be transcript is simply never discovered (refused by absence). It
// performs only readdir and stat — never a content read — so steady-state discovery is bounded by
// the directory tree size, not transcript size. It returns the tracked files in a deterministic
// order. A forward-only activation fails closed on every traversal or stat uncertainty (except a
// root that does not yet exist, which defers the activation commit rather than failing), because
// its durable baseline is valid only after the entire explicitly registered root was seen.
func (w *Watcher) reconcile(ctx context.Context) ([]*trackedFile, error) {
	files, err := w.reconcileRoots(ctx)
	if err != nil {
		// A reconcile that ended part way through establishes nothing, and it is not consecutive with
		// the polls on either side of it. Both absence streaks are runs of CORROBORATED observations,
		// so an errored poll has to break them rather than be stepped over (bd-main-x6u F4).
		w.forgetAbsenceEvidence()
		return nil, err
	}
	return files, nil
}

// forgetAbsenceEvidence discards every consecutive-absence count this process has accumulated: the
// per-identity release streak and every root's per-locator retirement streak.
func (w *Watcher) forgetAbsenceEvidence() {
	for _, tf := range w.tracked {
		tf.absentPolls = 0
	}
	for _, policy := range w.rootPolicies {
		policy.forgetLineageAbsence()
		policy.forgetBaselineAbsence()
	}
}

// reconcileRoots is reconcile's body: everything above is the contract, and everything an early
// return here leaves half-established is the caller's to discard.
func (w *Watcher) reconcileRoots(ctx context.Context) ([]*trackedFile, error) {
	present := map[identityKey]struct{}{}
	// dirsRead holds every directory this poll actually enumerated, and rootCorroborated marks a root
	// whose walk was complete, error-free, and lost nothing under it. Together they are what turns
	// "missing from the walk" into positive evidence of absence rather than an unreadable-directory or
	// rename-in-flight artifact.
	dirsRead := map[string]struct{}{}
	rootCorroborated := map[string]bool{}
	for _, root := range w.cfg.ApprovedRoots {
		policy := w.rootPolicies[root]
		forwardActivating := policy != nil && policy.record.Mode == rootpolicy.ForwardOnly && !policy.control.Committed
		scan, err := w.scanRoot(root, forwardActivating, dirsRead)
		if err != nil {
			// A walk that ended early enumerated only part of the root, so nothing below may read
			// this poll as evidence of what is missing under it — whether the error is fatal here or
			// tolerated as a root that does not exist yet.
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("scanning transcript root %s: %w", root, err)
			}
			continue
		}
		// Releasing a tracked identity and retiring a locator's fence both un-fence sealed bytes, so
		// they run on the same evidence: a walk that read the whole root, hit no error, and lost no
		// entry between readdir and stat. Anything less is what a rotation in flight looks like from
		// the outside, and counting it toward a release is what let two rename-racing polls evict a
		// live floor (bd-main-x6u F3).
		rootCorroborated[root] = scan.corroborated()
		// A reconcile error leaves this root's evidence partial, so it returns before any of the
		// clean-walk consumers below can read it.
		seenLocators, err := w.reconcileScan(ctx, root, policy, forwardActivating, scan, present)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			continue
		}
		// Activation commits only over a walk that actually saw the root: a missing or unreadable
		// root enumerates nothing, and committing there would record zero baselines and hand every
		// pre-existing file a byte-zero cursor once the root appeared. Leaving the marker uncommitted
		// retries the metadata-only seal on the next poll, which is the fail-closed direction.
		if scan.enumerated && !scan.failed && !policy.control.Committed {
			policy.control.Committed = true
			if err := policy.persistControl(); err != nil {
				return nil, fmt.Errorf("commit root-policy activation %q: %w", root, err)
			}
		}
		// Retiring a locator's seal lineage needs more evidence than committing the activation does,
		// because retirement is the one step that un-fences a path: it takes the corroborated walk, and
		// the locator must have been found empty by absenceEvictionPolls consecutive such walks
		// (A1-v2). A single empty walk is what an in-flight rotation looks like from the outside.
		if rootCorroborated[root] {
			policy.retireAbsentLineages(seenLocators)
			// A dead activation baseline un-fences nothing when it is dropped, but a reused inode number
			// inheriting it fences a genuinely new file's leading bytes, so its eviction takes the same
			// corroborated-walk evidence retirement does and runs only here.
			w.sweepActivationBaselines(policy, scan)
			continue
		}
		policy.forgetLineageAbsence()
		policy.forgetBaselineAbsence()
	}
	// Project roots draw their sessions from the shared stores rather than from a directory of their
	// own, so they are reconciled in a separate membership-routed pass over those stores. It populates
	// present and w.tracked (and rootCorroborated for each store) exactly as the loop above does for
	// transcripts roots, so the absence GC below governs members on the same evidence.
	if err := w.reconcileStores(ctx, present, dirsRead, rootCorroborated); err != nil {
		return nil, err
	}
	for key := range present {
		if tf := w.tracked[key]; tf != nil {
			tf.absentPolls = 0
		}
	}
	for key, tf := range w.tracked {
		if _, ok := present[key]; ok {
			continue
		}
		// Absence alone is not a departure. An uncorroborated walk proves nothing about what lives
		// under the root, and neither does a parent directory this poll could not enumerate — both
		// produce the same empty result as a deletion. Releasing the durable state on that evidence
		// destroys the generation-local floor, and the committed root then treats the reappearing
		// file as brand new.
		if !rootCorroborated[tf.root] {
			continue
		}
		if _, ok := dirsRead[filepath.Clean(filepath.Dir(tf.path))]; !ok {
			continue
		}
		tf.absentPolls++
		if tf.absentPolls < absenceEvictionPolls {
			continue
		}
		// Corroborated: fully rotated away / deleted.
		w.releaseTracked(key, tf)
	}
	if err := w.flushPolicyControls(); err != nil {
		return nil, err
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

// scannedFile is one non-directory entry a walk found, with the identity and stat it read. Nothing is
// decided here: the walk's job is to say what is under the root, and only that.
type scannedFile struct {
	path     string
	name     string
	dev, ino uint64
	size     int64
	mod      int64
	regular  bool
}

// rootScan is one walk's complete account of a root, and what it could not establish. Enumerating the
// whole root before reconciling any single file is what makes the answer independent of walk order: a
// new file at a sealed locator can be told apart from a rename of the file that used to be there only
// by knowing whether that identity is still living somewhere else under the root, and a walk that
// decides as it goes does not know that when it reaches the first of the two paths.
type rootScan struct {
	files []scannedFile
	// byIdentity locates each regular identity the walk found, so a seal lineage can be matched to the
	// file carrying it wherever that file moved to. It is MULTI-VALUED because an identity can occupy
	// several locators at once: hard links are one file under two names, and keeping only one of them
	// both hid the second from the fence bookkeeping and made an ambiguous identity look like an
	// unambiguous move (bd-main-x6u F2). Paths arrive in the walk's lexical order.
	byIdentity map[identityKey][]string
	// enumerated is set when the root directory itself was read.
	enumerated bool
	// failed marks a walk that hit any error: absence under it is evidence of nothing.
	failed bool
	// vanished marks an entry that was gone by the time the walk statted it — a rename in flight. The
	// rest of the tree is still enumerated, but this walk did not positively observe any locator empty,
	// which is the evidence lineage retirement runs on.
	vanished bool
}

// scanRoot walks one approved root and records what it finds. It performs only readdir and stat —
// never a content read, never a canonicalization — so the cost of the enumeration pass is the cost
// the walk already paid. A forward-only activation fails closed on every traversal or stat
// uncertainty, because its durable baseline is valid only over the entire registered root.
func (w *Watcher) scanRoot(root string, forwardActivating bool, dirsRead map[string]struct{}) (*rootScan, error) {
	scan := &rootScan{byIdentity: map[identityKey][]string{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// The lone carve-out is a root that does not yet exist: defer the activation to a later
			// poll instead of failing the whole reconcile. The fmt.Errorf wrap is load-bearing -
			// reconcile's post-walk check is os.IsNotExist, which does NOT unwrap, so even an ENOENT
			// here still propagates.
			if forwardActivating && !(path == root && os.IsNotExist(walkErr)) {
				return fmt.Errorf("walk %s: %w", path, walkErr)
			}
			// Skip the unreadable entry and keep walking the rest of the tree, but remember that this
			// walk saw less than the whole root. WalkDir reports a failed readdir as a second callback
			// for the directory itself, so this is also where a directory loses the enumerated mark it
			// was given below.
			scan.failed = true
			if d != nil && d.IsDir() {
				delete(dirsRead, filepath.Clean(path))
			}
			if path == root {
				scan.enumerated = false
			}
			return nil
		}
		if d.IsDir() {
			// Provisional: a readdir failure on this directory arrives as a second callback and takes
			// the entry back out above.
			dirsRead[filepath.Clean(path)] = struct{}{}
			if path == root {
				scan.enumerated = true
			}
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			if forwardActivating {
				return fmt.Errorf("stat %s: %w", path, err)
			}
			if !os.IsNotExist(err) {
				// An entry that cannot be statted is not an entry that is gone.
				scan.failed = true
			} else {
				scan.vanished = true
			}
			return nil // vanished mid-walk; a later poll re-discovers it
		}
		dev, ino, ok := fileIdentityOf(info)
		if !ok {
			return nil
		}
		f := scannedFile{
			path: path, name: d.Name(), dev: dev, ino: ino,
			size: info.Size(), mod: info.ModTime().UnixNano(), regular: info.Mode().IsRegular(),
		}
		scan.files = append(scan.files, f)
		if f.regular {
			key := identityKey{dev: dev, ino: ino}
			scan.byIdentity[key] = append(scan.byIdentity[key], path)
		}
		return nil
	})
	return scan, err
}

// corroborated reports a walk that read the whole root, hit no error, and lost no entry between
// readdir and stat. It is the evidence standard both un-fencing steps run on: releasing a tracked
// identity and retiring a locator's lineage. Anything less is what a rotation in flight looks like
// from the outside, so a walk below this bar may add fences and observations but must never remove
// one (bd-main-ikh).
func (s *rootScan) corroborated() bool {
	return s.enumerated && !s.failed && !s.vanished
}

// locatorsOf returns every path this walk found one identity living at. Two or more means hard links:
// the identity did not move away from any of them, and no single one of them is where it went.
func (s *rootScan) locatorsOf(dev, ino uint64) []string {
	if s == nil {
		return nil
	}
	return s.byIdentity[identityKey{dev: dev, ino: ino}]
}

// reconcileScan turns one root's enumeration into tracking decisions, in the walk's own lexical
// order, and returns the locators it found occupied. Every error it returns ends the poll, because a
// reconcile that stopped part way through leaves an account of the root that nothing may treat as
// complete.
func (w *Watcher) reconcileScan(ctx context.Context, root string, policy *rootPolicyState, forwardActivating bool, scan *rootScan, present map[identityKey]struct{}) (map[string]struct{}, error) {
	// seenLocators records every locator under this root the walk found occupied. It is the evidence
	// retireAbsentLineages needs to tell a deleted transcript (path left empty) from a replaced one
	// (path never empty), and it is collected for refused files too: a path holding something the
	// watcher declines to read is still an occupied path.
	seenLocators := map[string]struct{}{}
	for _, f := range scan.files {
		key := identityKey{dev: f.dev, ino: f.ino}
		// A tracked identity that is here again after being missed by an earlier walk RESUMES from its
		// existing cursor and floor. One clean-walk miss is not evidence the transcript left: a rename
		// racing the walk (the listing holds the old name, the stat of it finds nothing) and a file
		// moved out of the root and back both produce exactly that, and releasing the state there
		// re-tracks the file at byte zero and drains its sealed, pre-consent prefix. Release stays
		// gated on the corroborated absenceEvictionPolls evidence; a file that really was replaced by
		// an inode-reusing new one is caught where it always was, by the drain's fingerprint
		// corroboration, which reseals rather than publishes.
		tf, isTracked := w.tracked[key]
		if forwardActivating && f.regular {
			lstat, lerr := os.Lstat(f.path)
			if lerr != nil {
				return nil, fmt.Errorf("lstat %s: %w", f.path, lerr)
			}
			if lstat.Mode().IsRegular() {
				// Seal every regular identity under the root before the Match gate, so a file that is
				// not (yet) named like a transcript still gets a durable floor while activation is
				// uncommitted. Passing the canonical locator seeds seal lineage for the sealed
				// non-matching file; seenLocators must include it or retireAbsentLineages retires the
				// lineage after the commit poll. cursorFor's !Committed branch returns before
				// inheritSealLineage, so this stays stat-only.
				locator, ok, _ := canonicalizeTranscript(f.path, w.cfg.ApprovedRoots)
				if !ok {
					locator = "" // baseline still recorded by identity; setLineage no-ops on ""
				} else {
					seenLocators[locator] = struct{}{}
				}
				cur, forwardBaseline, err := w.cursorFor(ctx, policy, discovered{
					root: root, path: f.path, locator: locator, dev: f.dev, ino: f.ino, size: f.size, mod: f.mod,
				}, scan)
				if err != nil {
					return nil, fmt.Errorf("sealing %s: %w", f.path, err)
				}
				if isTracked {
					tf.cursor = cur
					tf.forwardBaseline = forwardBaseline
				}
			}
		}
		// Match gates DISCOVERY only. An already-tracked file whose name stops matching after a rename
		// must stay tracked so its unread tail is still drained — dropping it by name would silently
		// lose that tail. New (untracked) non-matching files are skipped, except that an uncommitted
		// forward-only activation seals every regular identity above so a later rename cannot expose
		// bytes that existed before consent.
		if !isTracked && w.cfg.Match != nil && !w.cfg.Match(f.name) {
			continue
		}
		// Fast path: a file already tracked at this EXACT path needs no re-canonicalization. The
		// discovery-time symlink/escape check (an Lstat plus an EvalSymlinks over every parent
		// component) is the dominant per-poll cost at scale — with tens of thousands of tracked
		// transcripts it runs on every one, every poll — yet it is redundant for a stable tracked
		// file: the path and locator are unchanged, and drain re-validates the open on every read with
		// openat2 (RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH) plus an fstat identity check, so a
		// parent-symlink swap or inode replacement after discovery is still refused at read time. Only
		// NEW or MOVED (renamed) files pay the canonicalize cost, making steady-state discovery
		// O(new/moved matched files) rather than O(all tracked files) per poll.
		if isTracked && tf.path == f.path {
			tf.root = root
			seenLocators[tf.locator] = struct{}{}
			present[key] = struct{}{}
			continue
		}
		// Refuse a symlinked final component, a non-regular file, or a parent-symlink escape before
		// trusting the path — the same rule the hook enforces on a supplied transcript. (drain
		// re-validates with O_NOFOLLOW at read time; this refusal is discovery-time.)
		locator, ok, refusal := canonicalizeTranscript(f.path, w.cfg.ApprovedRoots)
		if !ok {
			if rel, relErr := filepath.Rel(root, f.path); relErr == nil {
				seenLocators[rel] = struct{}{}
			}
			w.reportRefusal(ctx, refusal, f.path)
			continue
		}
		delete(w.refused, f.path)
		seenLocators[locator] = struct{}{}
		present[key] = struct{}{}
		if isTracked {
			// A rename kept the identity and the cursor; only path/root/locator move, and the fence is
			// COPIED to the path the sealed bytes are now at rather than moved off the one they left.
			// Releasing a locator is retirement's job alone: vacating on the strength of one walk left
			// the old name unfenced AND deleted the fingerprint that would have caught an edited copy
			// put back there, so the whole edited history published from byte zero (bd-main-37y). The
			// hold is also the right answer for a file living at several locators at once - a hard link
			// is not a rename, and the name it is seen at second is as real as the first.
			if policy != nil {
				policy.holdLineage(locator, f.dev, f.ino)
			}
			tf.root = root
			tf.path = f.path
			tf.locator = locator
			continue
		}
		found := discovered{root: root, path: f.path, locator: locator, dev: f.dev, ino: f.ino, size: f.size, mod: f.mod}
		cur, forwardBaseline, err := w.cursorFor(ctx, policy, found, scan)
		if err != nil {
			if errors.Is(err, errDeferTracking) {
				continue
			}
			return nil, fmt.Errorf("tracking %s: %w", f.path, err)
		}
		w.tracked[key] = &trackedFile{cursor: cur, root: root, path: f.path, locator: locator, dev: f.dev, ino: f.ino, policy: policy, forwardBaseline: forwardBaseline}
	}
	return seenLocators, nil
}

// releaseTracked drops every trace of one tracked identity: its durable cursor file, its
// generation-local floor, and the content side channel's per-identity state. It is the single point
// both the corroborated-absence GC and the reused-inode path go through, so a later file that lands
// on this (device,inode) can neither resurrect a stale cursor nor be mistaken for a pre-consent
// baseline. What it does NOT drop is the locator's seal lineage: an identity can leave a path that
// another file has already taken, and that replacement is exactly the case the lineage exists for.
// The floor removal is only marked dirty here; flushPolicyControls persists it once per root per
// poll instead of once per identity.
func (w *Watcher) releaseTracked(key identityKey, tf *trackedFile) {
	_ = os.Remove(tf.cursor.StatePath())
	if tf.policy != nil && tf.forwardBaseline {
		// Orphan any live fence still NAMING this identity before its floor is dropped. Releasing the
		// identity frees its inode number, and a fence that kept naming that number would grant a later,
		// unrelated file that reuses it reconcileLineage's incumbent exemption to lower or clear the
		// fence (bd-main-fpj). Orphaning only forces the foreign branch for every later writer - it
		// never lowers or deletes - so the reused number can at most ratchet the floor up or hold it;
		// retirement stays the sole un-fencing path.
		tf.policy.orphanLineagesNaming(key.dev, key.ino)
		tf.policy.dropBaseline(key.dev, key.ino)
	}
	delete(w.tracked, key)
	if w.cfg.ContentObserver != nil {
		w.cfg.ContentObserver.ForgetContent(key.dev, key.ino)
	}
}

// sweepActivationBaselines GCs the activation baselines whose files are gone (bd-main-1qh facet A). A
// forward-only activation seals every regular identity under the root before the Match gate, so a
// non-transcript file gets a durable floor it is never tracked through; releaseTracked, which drops a
// tracked identity's floor once it is corroborated absent, therefore never reaches it, and the dead
// floor lingers to fence a later file that reuses its inode NUMBER. This is that floor's release sweep,
// held to the same corroborated-absence evidence: it runs only when the caller has corroborated the
// walk, and occupancy counts every regular identity the walk found (scan.byIdentity includes the
// non-matching files) plus every identity still tracked into this root, so a present or rename-raced
// file is never read as absent. The floor and its durable cursor are dropped together, mirroring
// releaseTracked, so a reused inode number neither inherits the dead floor nor resumes its cursor.
func (w *Watcher) sweepActivationBaselines(policy *rootPolicyState, scan *rootScan) {
	if policy == nil {
		return
	}
	if len(policy.control.Baselines) == 0 {
		policy.forgetBaselineAbsence()
		return
	}
	occupied := make(map[string]struct{}, len(scan.byIdentity)+len(w.tracked))
	for key := range scan.byIdentity {
		occupied[identityString(key.dev, key.ino)] = struct{}{}
	}
	for key, tf := range w.tracked {
		if tf.policy == policy {
			occupied[identityString(key.dev, key.ino)] = struct{}{}
		}
	}
	scopedDir := filepath.Join(w.cfg.StateDir, "root-cursors", policy.scope)
	for _, id := range policy.retireAbsentActivationBaselines(occupied) {
		// The evicted identity is corroborated gone, so nothing live loses a cursor here; dropping it on
		// the same evidence as the floor keeps a reused inode number from resuming a stranger's sealed
		// position instead of being captured from its own byte zero.
		_ = os.Remove(cursorStatePath(scopedDir, id.dev, id.ino))
	}
}

// flushPolicyControls writes every root-policy control record a poll changed, at most once per root.
// Batching matters at store scale: a rotation sweep that retires hundreds of identities would
// otherwise rewrite (and fsync) the same control file once per identity.
func (w *Watcher) flushPolicyControls() error {
	for root, policy := range w.rootPolicies {
		if !policy.dirty {
			continue
		}
		if err := policy.persistControl(); err != nil {
			return fmt.Errorf("persist root-policy control %q: %w", root, err)
		}
	}
	return nil
}

// sealFloor computes the byte floor a forward-only seal fences a discovered file at. A transcripts-
// root seal stays stat-only — the floor is exactly the size the walk observed, taken without opening
// the file — preserving the activation pass's no-read guarantee. A project member's floor is aligned
// to the last complete record boundary at or before that size instead (A6), so a drain resuming at
// the floor never begins mid-record and never splits one across the fence; the bytes of a partial
// tail line still being written at seal time fall above the floor and count as post-seal. Locating
// the boundary reads a bounded window ending at the size through the same validated open the tail
// reader uses — it inspects bytes to find a newline, never delivers one — which is admissible for a
// member whose head the peek has already read.
func (w *Watcher) sealFloor(policy *rootPolicyState, d discovered) (int64, error) {
	if !policy.record.IsProject() || d.size <= 0 {
		return d.size, nil
	}
	f, _, _, err := openValidatedTranscript(d.root, d.locator, d.dev, d.ino)
	if err != nil {
		if isSkippableDrainErr(err) {
			return 0, errDeferTracking
		}
		return 0, fmt.Errorf("aligning the seal floor for %s: %w", d.locator, err)
	}
	defer f.Close()
	start := int64(0)
	if d.size > w.maxReadChunk {
		start = d.size - w.maxReadChunk
	}
	window, err := w.readRange(f, start, d.size-start)
	if err != nil {
		return 0, fmt.Errorf("aligning the seal floor for %s: %w", d.locator, err)
	}
	nl := bytes.LastIndexByte(window, '\n')
	if nl < 0 {
		// No record boundary within the bounded window (a single line longer than the read chunk):
		// fence the whole partial at the observed size rather than split a record — the conservative
		// direction, an over-fence that is backfillable rather than a mid-record publish.
		return d.size, nil
	}
	return start + int64(nl) + 1, nil
}

// cursorFor returns a cursor constrained to the root's policy generation. During a transcripts-root
// forward-only activation it performs only stat-derived sealing and durable writes; it never opens or
// reads the transcript. The committed baseline map is the fail-closed recovery path when one cursor
// file is lost after the activation marker has been written, and the committed lineage map is the same
// recovery for the case no identity-keyed record can cover: the sealed file was replaced.
func (w *Watcher) cursorFor(ctx context.Context, policy *rootPolicyState, d discovered, scan *rootScan) (*Cursor, bool, error) {
	if policy == nil {
		cur, err := LoadCursor(w.cfg.StateDir, d.dev, d.ino, d.size, d.mod, w.cfg.MaxPartialLine)
		return cur, false, err
	}
	cur, err := LoadScopedCursor(w.cfg.StateDir, d.dev, d.ino, d.size, d.mod, w.cfg.MaxPartialLine, policy.scope)
	if err != nil {
		return nil, false, fmt.Errorf("loading the scoped cursor for %s: %w", d.locator, err)
	}
	if policy.record.Mode != rootpolicy.ForwardOnly {
		return cur, false, nil
	}
	if !policy.control.Committed {
		floor, err := w.sealFloor(policy, d)
		if err != nil {
			return nil, false, err
		}
		policy.setBaseline(d.locator, d.dev, d.ino, baselineRecord{Floor: floor})
		cur.SealAt(floor)
		cur.observe(d.size, d.mod)
		if err := cur.Save(); err != nil {
			return nil, false, fmt.Errorf("saving the activation seal for %s: %w", d.locator, err)
		}
		return cur, true, nil
	}
	base, baseline := policy.baseline(d.dev, d.ino)
	fromLineage := false
	if !baseline {
		// No floor for THIS identity, but the PATH may still be sealed. An atomic rewrite (temp
		// file + rename) leaves the locator the owner was told is sealed exactly where it was and
		// makes the inode brand new, so every identity-keyed record misses while the transcript is,
		// to the owner, the same file.
		inherited, ok, err := w.inheritSealLineage(ctx, policy, d, scan)
		if err != nil {
			return nil, false, err
		}
		base, baseline, fromLineage = inherited, ok, ok
	}
	if !baseline && policy.record.IsProject() {
		// Late-member rule (A3/A5). A store transcript first classified a member AFTER the seal pass
		// committed has neither a durable baseline nor a seal lineage to inherit: it was undetermined or
		// non-member when the pass ran, so its identity was never sealed. The committed branch below
		// would hand it a byte-zero cursor and publish everything it wrote before it became a member, so
		// it is sealed here at its size at classification time instead — its pre-classification bytes are
		// fenced as pre-consent and only what it appends afterward is captured. A transcripts-root file
		// takes no such seal: a new file under a consented directory is post-consent in full.
		floor, err := w.sealFloor(policy, d)
		if err != nil {
			return nil, false, err
		}
		policy.setBaseline(d.locator, d.dev, d.ino, baselineRecord{Floor: floor})
		cur.SealAt(floor)
		cur.observe(d.size, d.mod)
		if err := cur.Save(); err != nil {
			return nil, false, fmt.Errorf("saving the late-member seal for %s: %w", d.locator, err)
		}
		return cur, true, nil
	}
	// A missing/corrupt individual cursor must not reopen a baseline at byte zero, and neither must a
	// cursor left behind a raised floor by a crash between the control write and the cursor write:
	// the committed floor is authoritative whenever the cursor sits below it.
	if baseline && (!cur.IsSealed() || cur.Consumed() < base.Floor) {
		floor := base.Floor
		// A22 reconciles a floor recovered from durable state against the walk's stat. An INHERITED
		// floor needs no such reconciliation: it was just derived from this file through the
		// validated handle and never sits above the bytes that handle saw. Lowering it back to a
		// stat a concurrent rewrite has already outgrown would deliver bytes the floor was chosen
		// to fence.
		if !fromLineage && d.size < floor {
			// The lowered floor is flushed with the rest of this poll's control changes; the cursor
			// saved just below already fences the same bytes, so a crash in between reseals no lower.
			// The recorded fingerprint described bytes that no longer exist, so it is dropped with the
			// floor and recorded again, from the new floor, on this file's next drain.
			floor = d.size
			policy.setBaseline(d.locator, d.dev, d.ino, baselineRecord{Floor: floor})
		}
		cur.SealAt(floor)
		cur.observe(d.size, d.mod)
		if err := cur.Save(); err != nil {
			return nil, false, fmt.Errorf("saving the recovered floor for %s: %w", d.locator, err)
		}
	}
	return cur, baseline, nil
}

// inheritSealLineage decides what a brand-new identity discovered at the locator of a sealed
// transcript inherits (A1). It is the cross-inode twin of drain's corroboration and uses the same
// evidence: one bounded pread of the window ending at the recorded floor, through the same
// race-free validated open a drain reads through, hashed and dropped - never parsed, never
// delivered. A byte-identical window means the sealed history is still there under a new inode, so
// the floor and its fingerprint carry over untouched and the replacement is silent.
//
// The two ways of being wrong are not symmetric, so the ambiguous cases do not split the
// difference. Capturing from byte zero publishes a prefix the owner was told was sealed and can
// never be taken back; inheriting a floor loses capture of a file that may be genuinely new, which
// costs history the owner can still choose to backfill. So only a DEMONSTRABLE divergence - a
// window that is there to read and does not match - treats the file as unrelated content, and even
// then it reseals at the current EOF rather than draining from zero, because a diverged prefix is a
// rewrite of the sealed range, not a new session. A floor that was never fingerprinted (sealed and
// replaced before any drain recorded the window) is inherited with a diagnostic naming the
// ambiguity, and a replacement too short to hold the window is fenced at its own EOF.
//
// ok is false only when the locator carries no lineage at all, which is the ordinary case: a new
// transcript at a path no sealed file has occupied in this generation is captured in full — and the
// displacement check below is what makes a rotated-away transcript's path one of those paths again.
func (w *Watcher) inheritSealLineage(ctx context.Context, policy *rootPolicyState, d discovered, scan *rootScan) (baselineRecord, bool, error) {
	lin, ok := policy.lineage(d.locator)
	if !ok {
		return baselineRecord{}, false, nil
	}
	f, size, _, err := openValidatedTranscript(d.root, d.locator, d.dev, d.ino)
	if err != nil {
		if isSkippableDrainErr(err) {
			return baselineRecord{}, false, errDeferTracking
		}
		return baselineRecord{}, false, fmt.Errorf("opening replaced transcript %s: %w", d.locator, err)
	}
	defer f.Close()

	rec := lin.baseline()
	window, readable, err := readFloorWindow(f, rec.Floor)
	if err != nil {
		return baselineRecord{}, false, fmt.Errorf("corroborating replaced transcript %s: %w", d.locator, err)
	}
	corroborated := readable && rec.hasFingerprint() && rec.FingerprintLen == len(window) && rec.FingerprintHash == hashBytes(window)
	// The sealed transcript may not have been replaced at all. Rotation renames it out of the way and
	// starts a new session at the path it left, which reaches here looking exactly like a rewrite —
	// except that the identity the lineage names is still alive elsewhere under the root. The sealed
	// bytes went with it, so the fence follows them there.
	//
	// What that does NOT establish is that the file standing at the locator they left is new. `sed
	// -i.bak` produces this exact picture — the untouched original moves to the .bak name and the
	// EDITED history takes its place — and so does any rotation the watcher was not running for. So
	// the locator they left is resealed at its own EOF: displacement ADDS a fence where the bytes went
	// and lifts none from where they were (A1-v2, bd-main-x6u F1, bd-main-37y). A file whose own bytes
	// demonstrably ARE the sealed prefix never reaches the question: the corroborated window inherits
	// the floor where it is found.
	//
	// A genuinely new session at that locator is captured in full once the one step that un-fences a
	// locator at all has run: retirement, after absenceEvictionPolls consecutive corroborated walks
	// have found it empty. Deciding it here on a SINGLE empty observation was the one-walk standard
	// retirement itself refuses, and one empty walk was all a redact-and-restore needed to have the
	// owner's edited pre-consent history published from byte zero (bd-main-ikh). Resealing the head of
	// a rotated-into session instead is bounded, diagnosed and backfillable.
	//
	// An identity found alive at SEVERAL locators names no single place the sealed bytes went, so it
	// is not usable as displacement evidence at all; it takes the same reseal, holding nothing.
	if to, displaced, ambiguous := w.displacedLineageLocator(scan, lin, d); (displaced || ambiguous) && !corroborated {
		if displaced {
			policy.holdLineage(to, lin.Device, lin.Inode)
		}
		return w.resealReplacement(ctx, policy, d, size, sealReplacedDisplaced, rec.Floor)
	}
	switch {
	case !readable:
		// The replacement does not even reach the floor, so the window that would corroborate it is
		// not there to read. Fence everything that exists, which is A22's lowered floor applied
		// across the replacement.
		return w.resealReplacement(ctx, policy, d, size, sealReplacedShort, rec.Floor)
	case !rec.hasFingerprint():
		// Sealed and replaced before any drain recorded the window: the prefix can be neither
		// confirmed nor refuted. Prefer privacy: inherit the floor, and say so.
		if err := w.reportSealReplacement(ctx, d, sealReplacedUnverifiable, rec.Floor, size); err != nil {
			return baselineRecord{}, false, err
		}
		policy.setBaseline(d.locator, d.dev, d.ino, rec)
		return rec, true, nil
	case rec.FingerprintLen == len(window) && rec.FingerprintHash == hashBytes(window):
		policy.setBaseline(d.locator, d.dev, d.ino, rec)
		return rec, true, nil
	default:
		return w.resealReplacement(ctx, policy, d, size, sealReplacedDiverged, rec.Floor)
	}
}

// displacedLineageLocator reports where the identity a seal lineage names is living now, when this
// walk found it under the root at exactly one locator other than the one the lineage is recorded at.
// That is positive evidence, and it is only ever read as such: not finding the identity says nothing
// (the walk may have been partial, and the sealed file may simply be gone), so the caller falls
// through to the fail-closed inheritance path.
//
// ambiguous reports the separate case of an identity found at SEVERAL locators - hard links, one file
// under more than one name. It is still proof that the sealed file is alive and so that the file at
// this locator is not it, but it names no single place the bytes went, so nothing may be moved on it.
//
// The locator is derived the same way discovery derives one, with the walk-relative path as the
// fallback for a file the watcher would refuse to read — the sealed bytes are still there either way,
// and the fence has to name where.
func (w *Watcher) displacedLineageLocator(scan *rootScan, lin sealLineage, d discovered) (to string, displaced, ambiguous bool) {
	paths := scan.locatorsOf(lin.Device, lin.Inode)
	if len(paths) == 0 {
		return "", false, false
	}
	if len(paths) > 1 {
		return "", false, true
	}
	locator, ok, _ := canonicalizeTranscript(paths[0], w.cfg.ApprovedRoots)
	if !ok {
		rel, err := filepath.Rel(d.root, paths[0])
		if err != nil {
			return "", false, false
		}
		locator = filepath.ToSlash(rel)
	}
	if locator == "" || locator == d.locator {
		return "", false, false
	}
	return locator, true, false
}

// resealReplacement fences everything a replaced locator currently holds and reports the capture
// gap, exactly as an in-place rewrite of the same inode does: no byte that exists now is delivered
// on either channel, and capture resumes at the first byte appended after this poll. The new floor's
// fingerprint is left to the first drain, the same way the activation seal leaves it, so discovery
// stays one pread per replaced file.
func (w *Watcher) resealReplacement(ctx context.Context, policy *rootPolicyState, d discovered, size int64, outcome sealReplacement, floor int64) (baselineRecord, bool, error) {
	if err := w.reportSealReplacement(ctx, d, outcome, floor, size); err != nil {
		return baselineRecord{}, false, err
	}
	rec := baselineRecord{Floor: size}
	policy.setBaseline(d.locator, d.dev, d.ino, rec)
	return rec, true, nil
}

// reportSealReplacement delivers the replacement diagnostic BEFORE the floor it describes is
// recorded, matching drain's ordering: a delivery failure fails the poll with nothing yet committed,
// and the next poll re-derives the same decision from the same lineage. The failure is wrapped where
// it is raised: a sink error is an arbitrary error value, and one that happens to look like ENOENT
// must not be mistaken for a filesystem answer by anything it passes through on the way out.
func (w *Watcher) reportSealReplacement(ctx context.Context, d discovered, outcome sealReplacement, floor, size int64) error {
	if err := w.cfg.Sink.DeliverCandidates(ctx, d.ref(), []*Candidate{sealReplacementDiagnostic(outcome, floor, size)}); err != nil {
		return fmt.Errorf("reporting the replacement of sealed transcript %s: %w", d.locator, err)
	}
	return nil
}

// drain reads and parses the bytes appended to one tracked file since its cursor offset and
// delivers the candidates. It opens the file ONCE relative to a fd on the trusted approved root,
// refusing any symlink within the subtree (openat2 RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH), and
// fstat-validates that the handle is the tracked (device,inode) regular file, then reads only from
// that handle — so neither a final-component NOR a parent-component symlink swapped in after
// discovery can redirect the read, and a mid-poll rotation that replaced the inode is skipped
// rather than misread. It detects an in-place truncation (the file shrank below the read watermark)
// and an in-place rewrite (the content window ending at the cursor's position, or at a sealed
// forward-only floor, no longer matches its recorded fingerprint), emitting a CAPTURE_LOSS
// diagnostic and recovering: an ordinary cursor restarts at 0, which is at-least-once-safe, while a
// sealed floor reseals at the current EOF, because re-reading there would publish the pre-consent
// prefix. Either way the tail is never parsed mid-record against a file that changed underneath it.
// It never re-reads consumed bytes.
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

	// Corroborate that the cursor offset is still a valid append point in THIS file before reading
	// anything past it, and act on what the corroboration found: an ordinary cursor restarts at 0,
	// while a sealed forward-only floor reseals at the current EOF (it must never fall back to byte
	// zero, which would publish the pre-consent prefix).
	divergence, err := w.corroborateOffset(f, tf, size)
	if err != nil {
		return fmt.Errorf("corroborating transcript offset %s: %w", tf.locator, err)
	}
	if divergence != sealIntact {
		diag := divergenceDiagnostic(divergence, tf.cursor.ReadOffset(), size)
		if derr := w.cfg.Sink.DeliverCandidates(ctx, tf.ref(), []*Candidate{diag}); derr != nil {
			return derr
		}
		if tf.forwardBaseline {
			tf.cursor.SealAt(size)
			if err := w.resealFloor(f, tf, size); err != nil {
				return err
			}
		} else {
			tf.cursor.Reset()
		}
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
	if w.cfg.ContentObserver == nil || !w.contentGateOpen(tf) {
		return
	}
	// The sidecar uses the same anchored, no-symlink open discipline as transcript reads. Cache
	// both a missing and a valid result so an unchanged transcript cannot turn the metadata sidecar
	// into unbounded I/O at the watcher poll cadence.
	if tf.gcSessionID == "" && (tf.gcMetaCheckedAt.IsZero() || w.cfg.Now().Sub(tf.gcMetaCheckedAt) >= gcMetaCheckInterval) {
		tf.gcSessionID = readGCSessionIDSidecar(tf.root, tf.locator)
		tf.gcMetaCheckedAt = w.cfg.Now()
	}
	w.cfg.ContentObserver.ObserveContent(ctx, ContentObservation{
		Root:        tf.root,
		Locator:     tf.locator,
		Path:        tf.path,
		Device:      tf.dev,
		Inode:       tf.ino,
		Size:        size,
		ModNanos:    modNanos,
		GCSessionID: tf.gcSessionID,
	})
}

// readGCSessionIDSidecar reads the exact binding emitted by Gas City beside a transcript. It is
// intentionally tiny and conservative: a missing, replaced, non-regular, symlinked, oversized, or
// malformed sidecar simply means no authoritative binding for this observation. The raw value is
// never trimmed or normalized, because either operation could bind content to a different session.
func readGCSessionIDSidecar(root, locator string) string {
	f, err := openGCMetaSidecar(root, locator+".gcmeta")
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 1 || info.Size() > maxGCSessionMetaBytes {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(f, maxGCSessionMetaBytes+1))
	if err != nil || len(b) <= 1 || len(b) > maxGCSessionMetaBytes || b[len(b)-1] != '\n' {
		return ""
	}
	id := string(b[:len(b)-1])
	if !validGCSessionID(id) {
		return ""
	}
	return id
}

func validGCSessionID(id string) bool {
	if id == "" || len(id) > maxGCSessionIDBytes || !utf8.ValidString(id) || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
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

// sealDivergence classifies what a drain's corroboration found, and therefore how the watcher
// recovers: an ordinary cursor whose anchor no longer matches restarts at 0, while a sealed
// forward-only file that was truncated below its floor, or rewritten in place beneath it, reseals at
// the current EOF and re-delivers nothing.
type sealDivergence int

const (
	sealIntact sealDivergence = iota
	sealRestart
	sealTruncated
	sealRewritten
)

// corroborateOffset checks that a tracked file's cursor position is still a valid continuation point
// in the file behind f. An ordinary cursor is corroborated by its own anchor. A forward-only cursor
// has no anchor over its sealed prefix (building one at seal time would read pre-consent bytes), so
// its floor is corroborated instead by a fingerprint of the bytes ending at it, recorded here on the
// first drain after the seal and re-checked with one bounded pread on every drain after that. Only
// the bytes below the floor are read for the fingerprint, and they are hashed and dropped, never
// parsed and never delivered.
//
// The check covers the sealed prefix, which is the boundary that matters: a rewrite there both
// unseals history and leaves the tail being parsed mid-record. A rewrite confined to the range
// between the floor and the cursor's current position is not detected (the same bounded-window
// residual the anchor accepts), and it can only over-deliver already-consented bytes, never publish
// anything below the floor.
func (w *Watcher) corroborateOffset(f *os.File, tf *trackedFile, size int64) (sealDivergence, error) {
	if !tf.forwardBaseline {
		invalidated, err := w.offsetInvalidated(f, tf.cursor, size)
		if err != nil || !invalidated {
			return sealIntact, err
		}
		return sealRestart, nil
	}
	if size < tf.cursor.ReadOffset() {
		return sealTruncated, nil
	}
	if tf.policy == nil {
		return sealIntact, nil
	}
	base, sealed := tf.policy.baseline(tf.dev, tf.ino)
	if !sealed || base.Floor <= 0 {
		// No committed floor yet (a root whose activation has not committed), or a file sealed at byte
		// zero: there is no sealed prefix for a rewrite to hide beneath.
		return sealIntact, nil
	}
	window, readable, err := readFloorWindow(f, base.Floor)
	if err != nil {
		return sealIntact, err
	}
	if !readable {
		// The floor bytes are gone: the file shrank below the fingerprint window between the walk's
		// stat and this read. That is the shrink path, resealed at the current EOF.
		return sealTruncated, nil
	}
	if !base.hasFingerprint() {
		base.FingerprintHash, base.FingerprintLen = hashBytes(window), len(window)
		tf.policy.setBaseline(tf.locator, tf.dev, tf.ino, base)
		return sealIntact, nil
	}
	if base.FingerprintLen != len(window) || base.FingerprintHash != hashBytes(window) {
		return sealRewritten, nil
	}
	return sealIntact, nil
}

// resealFloor moves one identity's durable floor to the EOF its cursor was just resealed at and
// refreshes the fingerprint from the bytes ending there, so the stale window (which described
// content that no longer exists) is never checked again. It writes the control record immediately
// rather than leaving it to the poll's batched flush: a crash between a saved cursor and an unwritten
// floor would leave the lower, stale floor to recover from, and the range above it has already been
// declared uncaptured.
func (w *Watcher) resealFloor(f *os.File, tf *trackedFile, eof int64) error {
	if tf.policy == nil {
		return nil
	}
	rec := baselineRecord{Floor: eof}
	window, readable, err := readFloorWindow(f, eof)
	if err != nil {
		return err
	}
	if readable {
		rec.FingerprintHash, rec.FingerprintLen = hashBytes(window), len(window)
	}
	tf.policy.setBaseline(tf.locator, tf.dev, tf.ino, rec)
	return tf.policy.persistControl()
}

// readFloorWindow reads the up-to-floorFingerprintLen bytes ending at floor from the already-open,
// identity-validated handle: one bounded pread, never a whole-file rehash, so corroborating a sealed
// prefix stays O(1) per drain. readable is false when the file no longer holds that window (it
// shrank below the floor), which the caller treats as a truncation.
func readFloorWindow(f *os.File, floor int64) (window []byte, readable bool, err error) {
	n := int64(floorFingerprintLen)
	if floor < n {
		n = floor
	}
	if n <= 0 {
		return nil, false, nil
	}
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, floor-n)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if int64(got) < n {
		return nil, false, nil
	}
	return buf, true, nil
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

// divergenceDiagnostic reports that a same-identity transcript no longer corroborates the cursor
// position it was being tailed from, and states what the watcher actually did about it. The
// recovery differs per cursor, so the text does too: an ordinary cursor really does restart at 0,
// while a sealed forward-only cursor reseals at the current EOF and re-delivers nothing (claiming a
// restart at 0 there would describe a replay that never happens, and would hide the capture gap
// between the old floor and the new one). It names byte offsets only, never transcript content.
func divergenceDiagnostic(d sealDivergence, oldOffset, newSize int64) *Candidate {
	var reason string
	switch d {
	case sealTruncated:
		reason = fmt.Sprintf("transcript truncated to %d bytes below the sealed read offset %d; resealing capture at the new end of file; the truncated interval is unrecoverable and no bytes are re-delivered", newSize, oldOffset)
	case sealRewritten:
		reason = fmt.Sprintf("transcript prefix below the sealed read offset %d diverged from the bytes it was sealed over (file is now %d bytes); resealing capture at the current end of file; the rewritten interval is not captured and no bytes are re-delivered", oldOffset, newSize)
	default:
		reason = fmt.Sprintf("transcript truncated to %d bytes below the read offset %d; restarting capture at 0", newSize, oldOffset)
	}
	diag := evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            reason,
	}
	return &Candidate{Kind: KindDiagnostic, Diagnostic: &diag}
}

// sealReplacement classifies what a new inode found at a sealed locator turned out to be, and so
// what the watcher did with the floor it inherited there.
type sealReplacement int

const (
	// sealReplacedDiverged: the window ending at the floor was readable and did not match the bytes
	// that were sealed over. The path was rewritten, and the floor describes no boundary in this
	// file.
	sealReplacedDiverged sealReplacement = iota
	// sealReplacedShort: the replacement is too small to hold the window, so nothing corroborates it.
	sealReplacedShort
	// sealReplacedUnverifiable: the floor was never fingerprinted, so there is nothing to compare.
	sealReplacedUnverifiable
	// sealReplacedDisplaced: the sealed transcript itself is alive elsewhere under the root, so the
	// file at this locator is definitely a different one — but no walk ever saw this locator standing
	// empty, so it cannot be shown to have arrived after the sealed file left. `sed -i.bak` produces
	// exactly this and leaves the owner's edited pre-consent history here.
	sealReplacedDisplaced
)

// sealReplacementDiagnostic reports that the file at a sealed path was replaced by a new one and
// states which floor capture is now standing on and why. It names byte offsets only, never
// transcript content and never the path. The three texts are deliberately distinct: two of them
// describe a capture gap (the replaced file's current content is fenced and never delivered) while
// the unverifiable one describes an inherited floor that may be fencing bytes written after consent
// and the owner can tell those apart only if the diagnostic does.
func sealReplacementDiagnostic(outcome sealReplacement, floor, size int64) *Candidate {
	var reason string
	switch outcome {
	case sealReplacedShort:
		reason = fmt.Sprintf("a new file replaced the transcript sealed at offset %d at this path and holds only %d bytes, too few to corroborate the sealed prefix; resealing capture at the current end of file; no bytes below it are delivered", floor, size)
	case sealReplacedUnverifiable:
		reason = fmt.Sprintf("a new file replaced the transcript sealed at offset %d at this path before that prefix was ever fingerprinted (the file is now %d bytes), so the replacement can be neither confirmed nor refuted; inheriting the sealed floor and capturing only the bytes above it", floor, size)
	case sealReplacedDisplaced:
		reason = fmt.Sprintf("the transcript sealed at offset %d at this path is still present elsewhere under its root, and this path was never observed empty in between, so the file now holding it (%d bytes) cannot be shown to be a new one; resealing capture at the current end of file; nothing below it is delivered", floor, size)
	default:
		reason = fmt.Sprintf("a new file replaced the transcript sealed at offset %d at this path and its prefix diverged from the bytes that were sealed (the file is now %d bytes); resealing capture at the current end of file; the replaced interval is not captured and no bytes are re-delivered", floor, size)
	}
	d := evidence.DiagnosticCandidate{
		Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
		Severity:           wire.CaptureDiagnosticPayloadSeverityWARNING,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectPARTIAL,
		Context:            reason,
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
