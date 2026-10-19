//go:build linux || darwin

package daemon

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/contentguard"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Content-upload side-channel defaults and bounds.
const (
	// DefaultContentDebounce is how long a transcript's size+mtime must hold steady before its whole
	// content is snapshotted and uploaded. It stops a still-growing transcript from being re-shipped
	// on every poll; the final, stable snapshot is what lands.
	DefaultContentDebounce = 30 * time.Second
	// DefaultContentInterval is the content-loop ticker cadence when unset.
	DefaultContentInterval = 5 * time.Second
	// DefaultMaxContentBytes bounds a single whole-file upload (200 MiB). A larger transcript is
	// skipped with one diagnostic rather than buffered into memory.
	DefaultMaxContentBytes = int64(200) << 20
	// contentTransientHold is the global back-off applied after a transport/5xx failure or a 429 with
	// no Retry-After, so a persistent server problem does not hot-loop the content POST.
	contentTransientHold = 15 * time.Second
	// maxContentHold caps how long a single server-supplied Retry-After can shed content upload, so a
	// malformed or absurd value cannot silently disable content upload for the whole process lifetime.
	// It caps the refusal back-off (contentRefusal) the same way.
	maxContentHold = 5 * time.Minute
	// maxContentPostAttempts bounds how many times a single stable snapshot is re-read + re-hashed +
	// re-POSTed after transport/retryable failures before the uploader gives up on THAT snapshot (until
	// its content changes). Without it, a within-cap transcript that cannot finish within the content
	// timeout (a slow link) would re-read+re-hash the whole file every backoff forever.
	maxContentPostAttempts = 5
	// contentMarkerVersion is the on-disk last-uploaded marker schema version.
	contentMarkerVersion = 2
	// legacyContentMarkerVersion is accepted so an existing plain-upload marker remains a dedup
	// hit until a sidecar binding actually arrives.
	legacyContentMarkerVersion = 1
	// contentMarkerTempPrefix names the temporary file a marker write renames over the marker.
	contentMarkerTempPrefix = ".tmp-content-marker-"
	// maxNativeSessionIDLen / maxSourcePathLen mirror the Phase 1a server header-validation limits,
	// enforced client-side so a structurally invalid transcript never triggers a server 422 loop.
	maxNativeSessionIDLen = 256
	maxSourcePathLen      = 1024
)

// nativeSessionIDPattern mirrors the Phase 1a server's X-Observer-Native-Session-Id contract.
var nativeSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// validContentHeaders reports whether the resolved provenance values satisfy the server's Phase 1a
// header contract. A transcript that fails this can never produce an accepted upload, so the caller
// skips it (logging once) instead of POSTing bytes the server will reject with 422.
func validContentHeaders(nativeID, provider, sourcePath string) bool {
	if nativeID == "" || len(nativeID) > maxNativeSessionIDLen || !nativeSessionIDPattern.MatchString(nativeID) {
		return false
	}
	if provider != "claude" && provider != "codex" {
		return false
	}
	if len(sourcePath) > maxSourcePathLen || !isPrintableASCII(sourcePath) {
		return false
	}
	return true
}

// isPrintableASCII reports whether s is entirely printable ASCII (a safe, header-legal value).
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ContentSender POSTs one whole-transcript snapshot to the collector's content route. *upload.Client
// satisfies it; tests substitute a scripted double. It is the ONLY collector seam the content side
// channel uses — it reuses the same authenticated client (base URL + source-bound bearer) as the
// observation-batch uploader, never a second credential.
type ContentSender interface {
	PostContent(ctx context.Context, r upload.ContentRequest) (*upload.ContentResult, error)
}

// sessionLookup resolves the native session id and provider threaded for a transcript identity
// (satisfied by the daemon's CandidateSinkAdapter). It lets the content uploader key a snapshot by
// the same native session id the metadata pipeline stamps, without re-parsing the transcript.
type sessionLookup interface {
	SessionFor(device, inode uint64) (nativeID, provider string, ok bool)
	// Forget drops any threaded session state for a transcript identity, so a reused (device,inode)
	// cannot inherit the previous transcript's native session id.
	Forget(device, inode uint64)
}

// transcriptReader reads a whole validated transcript snapshot, refusing an oversize file with
// codex.ErrTranscriptTooLarge. The default is codex.ReadValidatedTranscript; tests inject an
// in-memory reader so the content logic can be exercised without real transcript files.
type transcriptReader func(root, locator string, dev, ino uint64, maxBytes int64) (content []byte, size, modNanos int64, err error)

// contentUploaderConfig wires a contentUploader. Sender, Sessions, and StateDir are required.
type contentUploaderConfig struct {
	sender   ContentSender
	sessions sessionLookup
	stateDir string
	maxBytes int64
	debounce time.Duration
	read     transcriptReader
	now      func() time.Time
	log      func(string)
	// consent, when non-nil, is the live consent policy every observation and upload is checked
	// against (see contentUploader.consent).
	consent *consent.Source
	// tokenFile is the bearer token file the sender reads its credential from ("" when unknown).
	tokenFile string
	// interval is the content loop's cadence; 0 selects DefaultContentInterval.
	interval time.Duration
}

// contentUploader ships whole-transcript snapshots to the collector's content endpoint as a side
// channel. The watcher feeds it each tracked transcript's identity/path/stat per poll via
// ObserveContent (cheap, non-blocking); on its own ticker it uploads a transcript's current full
// content once its size+mtime have been STABLE for the debounce window AND the content changed since
// the last successful upload. A per-transcript last-uploaded marker persisted in the state dir makes
// dedup survive a restart. It never blocks the watcher: ObserveContent only records state, and all
// file reads and network I/O run on the content loop with u.mu released.
type contentUploader struct {
	sender   ContentSender
	sessions sessionLookup
	stateDir string
	maxBytes int64
	debounce time.Duration
	read     transcriptReader
	now      func() time.Time
	log      func(string)
	// consent, when non-nil, gates every observation and every upload on the live consent policy:
	// content upload must be consented and the transcript's consent root still consented at the
	// generation it was observed under. The policy is re-checked before every upload; a narrowing
	// drops the queued state it no longer covers and cancels an in-flight upload it no longer
	// covers. nil (no -root-policy-file) keeps the static -content-upload behavior.
	consent *consent.Source
	// tokenFile is the bearer token file the sender reads its credential from ("" when unknown).
	// While the collector refuses content upload, a renewal of it retries at once (contentRefusal).
	tokenFile string
	// interval is the content loop's cadence, which also paces recordOwedIfStale.
	interval time.Duration

	// tickMu serializes ticks, so the content loop and an on-demand tick never upload the same
	// snapshot twice.
	tickMu sync.Mutex

	// pendingMu serializes the pending records' file operations (content_pending.go): a record is
	// written, deleted, or swept under it, never under u.mu. Lock order: pendingMu before u.mu.
	pendingMu sync.Mutex
	// pendingDeleteFailing latches the log of a pending-record delete failure until a delete succeeds
	// again, so a read-only disk is reported once, not on every acceptance. Guarded by pendingMu.
	pendingDeleteFailing bool

	mu    sync.Mutex
	files map[transcriptIdentity]*contentState
	// inflight is the upload being sent right now, if any, so a consent narrowing can cancel it.
	// Guarded by u.mu.
	inflight *contentFlight
	// guardRefusals counts transcripts dropped by an always-on content guard (denylist / allowlist /
	// PEM sniff), keyed by reason, so a refused credential/config/key file is visible and testable —
	// counted + logged, never silent. Guarded by u.mu.
	guardRefusals map[contentguard.Reason]int
	// refusal is the back-off the collector armed by refusing content upload (401/403/404/501); nil
	// while it accepts content upload. It never affects the metadata pipeline. Guarded by u.mu.
	refusal *contentRefusal
	// lastPlanned is when plan last ran (recordOwedIfStale). Guarded by u.mu.
	lastPlanned time.Time
	// holdUntil shed-backs off ALL content uploads until this time, set on a 429 Retry-After or a
	// transient/5xx failure. It is a coarse global gate because the shed is a server-wide signal.
	holdUntil time.Time
}

// contentFlight is one upload being sent: its consent origin, the cancel for its request, and
// whether a consent narrowing withdrew it.
type contentFlight struct {
	origin    consentOrigin
	cancel    context.CancelFunc
	withdrawn bool
}

// contentState is the per-transcript upload bookkeeping, keyed by filesystem identity.
type contentState struct {
	root, locator, path string
	// origin is the consent the transcript was observed under (zero without a live consent policy).
	origin         consentOrigin
	size, modNanos int64
	// stableSince is when the current (size,modNanos) was first observed; the file is "stable" once
	// now-stableSince >= debounce. Any size/mtime change resets it.
	stableSince time.Time
	observed    bool

	// marker* mirror the persisted last-uploaded marker (loaded lazily). markerHash=="" means nothing
	// has been uploaded for this identity yet. markerNative/markerProvider carry the native session id
	// and provider of the last upload so a transcript uploaded at least once can still be keyed after a
	// daemon restart, when the sink's in-memory session threading is empty (the codex head
	// SESSION_LIFECYCLE line sits behind the durable cursor and is never re-parsed).
	markerLoaded      bool
	markerHash        string
	markerSize        int64
	markerMod         int64
	markerNative      string
	markerProvider    string
	markerGCSessionID string
	gcSessionID       string

	// pending mirrors the transcript's durable pending record when one keys it: the session its owed,
	// never-accepted content was queued under (content_pending.go). pendingLoaded marks that the
	// record on disk was looked for; pendingWriteLogged latches the log of a failure to write it until
	// a write succeeds.
	pending            *contentPending
	pendingLoaded      bool
	pendingWriteLogged bool

	// eval* is the (size,modNanos,gcSessionID) of the snapshot last EVALUATED to a non-upload-needed
	// outcome (uploaded, unchanged, oversize, invalid, or permanently-rejected). A file whose current
	// stat AND gc session id equal eval* is skipped without a re-read. It is seeded from the marker on
	// load so an unchanged file is not re-read after restart. Always advance it through
	// markEvaluated — the skip predicate compares all three fields, so a site that records the stat
	// but not the gc session id leaves the snapshot permanently re-armed.
	evalSize        int64
	evalMod         int64
	evalSet         bool
	evalGCSessionID string

	// gcBindingRefused latches that the collector rejected this transcript's GC session binding as
	// conflicting with one the content store already holds for the same path. The GC binding is
	// write-once upstream, so re-sending it can only ever conflict again; the bytes still belong to
	// the bound transcript, so subsequent uploads carry the provider-native identity alone.
	gcBindingRefused bool
	// gcRefusedLogged latches the once-per-transcript log of that refusal.
	gcRefusedLogged bool

	// uploaded records whether markerHash came from a real acceptance (2xx / 409) rather than a
	// permanent-4xx rejection. Only a real acceptance may be durably persisted; a rejected hash is kept
	// as in-memory dedup only, so a restart re-probes it (the 400/413/422 intent).
	uploaded bool

	// postFail* count consecutive failed POSTs against a single (size,mod) snapshot so a snapshot that
	// keeps failing (e.g. a file too slow to finish within the content timeout) is eventually given up
	// on instead of re-read/re-hashed/re-POSTed forever; a stat change or a success resets them.
	postFailSize  int64
	postFailMod   int64
	postFailCount int

	oversizeLogged  bool
	invalidLogged   bool
	readErrLogged   bool
	permanentLogged bool
	giveUpLogged    bool
	// guardLogged latches the once-per-transcript log + count of an always-on content-guard refusal,
	// so a persistently-refused file does not re-log or re-count on every tick.
	guardLogged bool
}

// newContentUploader validates cfg and returns a ready uploader.
func newContentUploader(cfg contentUploaderConfig) (*contentUploader, error) {
	if cfg.sender == nil {
		return nil, errors.New("observer daemon: content uploader requires a sender")
	}
	if cfg.sessions == nil {
		return nil, errors.New("observer daemon: content uploader requires a session lookup")
	}
	if cfg.stateDir == "" {
		return nil, errors.New("observer daemon: content uploader requires a state dir")
	}
	read := cfg.read
	if read == nil {
		read = codex.ReadValidatedTranscript
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	maxBytes := cfg.maxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxContentBytes
	}
	debounce := cfg.debounce
	if debounce <= 0 {
		debounce = DefaultContentDebounce
	}
	interval := cfg.interval
	if interval <= 0 {
		interval = DefaultContentInterval
	}
	// Sweep any orphaned marker temp files left by a crash mid-persist, so they cannot accumulate
	// across restarts. The state dir is shared with the watcher's cursor files; we only touch our
	// own distinctly-prefixed temp files.
	sweepOrphanContentTemps(cfg.stateDir)
	u := &contentUploader{
		sender:    cfg.sender,
		sessions:  cfg.sessions,
		stateDir:  cfg.stateDir,
		maxBytes:  maxBytes,
		debounce:  debounce,
		read:      read,
		now:       now,
		log:       cfg.log,
		consent:   cfg.consent,
		tokenFile: cfg.tokenFile,
		interval:  interval,
		files:     map[transcriptIdentity]*contentState{},

		guardRefusals: map[contentguard.Reason]int{},
	}
	// Content an earlier run queued under consent that no longer applies — withdrawn or re-registered
	// while the daemon was stopped — is discarded before anything can key it.
	n, err := sweepContentPending(u.stateDir, u.pendingConsented)
	if n > 0 {
		u.logf("content upload: discarded the queued content of %d transcripts: the consent it was queued under no longer applies", n)
	}
	if err != nil {
		u.logf("content upload: discard content queued under withdrawn consent: %v", err)
	}
	u.logTokenFile()
	return u, nil
}

// contentUploader is the watcher's ContentObserver.
var _ codex.ContentObserver = (*contentUploader)(nil)

// ObserveContent records one tracked transcript's current identity/path/stat. It is called from the
// watcher's poll goroutine and MUST stay cheap: it only updates in-memory debounce state (no I/O),
// so a slow content upload can never stall the metadata poll. Any size/mtime change restarts the
// stability clock; an unchanged observation lets stability accumulate toward the debounce window.
func (u *contentUploader) ObserveContent(_ context.Context, o codex.ContentObservation) {
	u.observe(consentOrigin{}, o)
}

// observe records one observation captured under origin. Under a live consent policy an
// observation the policy no longer covers is not queued, and drops whatever was queued for it.
func (u *contentUploader) observe(origin consentOrigin, o codex.ContentObservation) {
	id := transcriptIdentity{device: o.Device, inode: o.Inode}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.allowedLocked(origin) {
		delete(u.files, id)
		return
	}
	st := u.files[id]
	if st == nil {
		st = &contentState{}
		u.files[id] = st
	}
	st.origin = origin
	st.root, st.locator, st.path = o.Root, o.Locator, o.Path
	if st.gcSessionID != o.GCSessionID {
		// Metadata can land after the transcript bytes. Re-arm this exact snapshot so it is sent
		// once with the newly authoritative binding even when its size and hash are unchanged.
		st.gcSessionID = o.GCSessionID
		st.evalSet = false
	}
	if !st.observed || st.size != o.Size || st.modNanos != o.ModNanos {
		st.size = o.Size
		st.modNanos = o.ModNanos
		st.stableSince = u.now()
		st.observed = true
	}
}

// tick evaluates every tracked transcript once and uploads those that are stable and changed. It is
// the deterministic unit the content loop drives and tests call directly. Reads and POSTs happen
// with u.mu released so ObserveContent never blocks on content I/O.
func (u *contentUploader) tick(ctx context.Context) {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	u.refreshConsent()
	now := u.now()
	jobs, saves := u.plan(now)
	// What is owed is recorded before anything can hold the upload, so content first queued during a
	// refusal or a shed survives a restart all the same.
	u.savePending(saves)
	if u.postingHeld(now) {
		return
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		// Consent is re-checked before every upload: a narrowing written since this tick began drops
		// the jobs it no longer covers before any of their bytes are read.
		u.refreshConsent()
		// A shed (429) or a refusal (401/403/404/501) recorded while processing an earlier job in this
		// same tick must stop the rest — re-check before each POST, not only at tick entry.
		if u.postingHeld(u.now()) {
			return
		}
		u.mu.Lock()
		skip := !u.allowedLocked(j.origin) || u.files[j.id] == nil
		u.mu.Unlock()
		if skip {
			continue
		}
		u.processOne(ctx, j.id, j.origin, j.root, j.locator, j.path, j.native, j.provider, j.gcSessionID)
		// An upload can take minutes: content first owed while it was in flight is recorded now, not
		// at the next tick.
		u.recordOwedIfStale()
	}
}

// recordOwed writes the pending records of every transcript whose content is owed and not yet
// recorded: plan's durable half, without its uploads. The tick runs it between uploads and the daemon
// runs it once more as it stops, so content first owed since the last plan still survives a restart.
// It does not take tickMu: it runs inside a tick, and at shutdown possibly beside one.
func (u *contentUploader) recordOwed() {
	_, saves := u.plan(u.now())
	u.savePending(saves)
}

// recordOwedIfStale runs recordOwed unless a plan ran within the last content interval (the content
// loop's configured cadence), so a long upload burst spends one plan per interval on its bookkeeping
// rather than one per upload.
func (u *contentUploader) recordOwedIfStale() {
	u.mu.Lock()
	stale := u.now().Sub(u.lastPlanned) >= u.interval
	u.mu.Unlock()
	if stale {
		u.recordOwed()
	}
}

// contentJob is one stable, changed transcript a tick reads and, if its content changed, uploads.
type contentJob struct {
	id                            transcriptIdentity
	origin                        consentOrigin
	root, locator, path           string
	native, provider, gcSessionID string
	size                          int64
	// fails is how many consecutive POSTs of this snapshot have failed.
	fails int
}

// plan evaluates every tracked transcript once, without reading any: it returns the stable, changed
// transcripts to upload, and the pending records the transcripts whose content is owed need. It runs
// whether or not posting is held. A snapshot that just failed goes behind every one that has not, so
// an outage spreads its failures over the queue instead of exhausting one transcript's attempts
// (maxContentPostAttempts) after another; otherwise jobs come smallest first. While a refusal holds,
// they come smallest first regardless: the next request only probes the collector, so it should be
// the cheapest one.
func (u *contentUploader) plan(now time.Time) ([]contentJob, []pendingSave) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastPlanned = now
	var jobs []contentJob
	var saves []pendingSave
	for id, st := range u.files {
		if !u.allowedLocked(st.origin) {
			delete(u.files, id) // queued under consent that no longer applies: never sent
			continue
		}
		u.ensureMarkerLoadedLocked(id, st)
		if !st.observed || st.handled() {
			continue // unchanged since the last snapshot we handled
		}
		u.ensurePendingLoadedLocked(id, st)
		// Resolve the native session id BEFORE any whole-file read/hash. Prefer the live sink; fall
		// back to the pending record's or the marker's persisted id so a transcript queued or uploaded
		// before a restart still keys after it. Unknown → skip cheaply (no read, no hash); a later tick
		// retries once the session is threaded or the marker lands. This is the guard that stops an
		// unknown-session transcript from being fully re-read and re-hashed on every tick.
		native, provider, ok := u.resolveSessionLocked(id, st)
		if !ok {
			continue
		}
		// Enforce the server's header contract client-side. A structurally invalid value can never be
		// accepted, so record the current stat as evaluated (skip future re-reads) and log once instead
		// of POSTing bytes the server would reject with 422.
		if !validContentHeaders(native, provider, st.path) {
			if !st.invalidLogged {
				u.logf("content upload: skipping %s: invalid provenance (session=%q provider=%q path-bytes=%d)", st.locator, native, provider, len(st.path))
				st.invalidLogged = true
			}
			st.markEvaluated(st.size, st.modNanos, st.gcSessionID)
			continue
		}
		// Always-on content-lane filename guards: the secrets/config denylist and the strict
		// per-provider transcript-shape allowlist (contentguard). A credential, config, or off-shape
		// file authored under an approved root is refused HERE — before any whole-file read or upload
		// request is constructed. Advance eval so a refused file is not re-read every tick; the refusal
		// is logged + counted once, never silent.
		if reason, refused := contentguard.ScreenName(provider, st.path); refused {
			u.recordGuardRefusalLocked(st, st.locator, reason)
			st.markEvaluated(st.size, st.modNanos, st.gcSessionID)
			continue
		}
		// The content is owed from here on, settled or not: one the daemon stops before it settles
		// is owed after the restart too.
		if rec, owed := st.pendingRecord(id, native, provider); owed {
			saves = append(saves, pendingSave{id: id, st: st, rec: rec})
		}
		if now.Sub(st.stableSince) < u.debounce {
			continue // still growing or not stable long enough
		}
		jobs = append(jobs, contentJob{id: id, origin: st.origin, root: st.root, locator: st.locator, path: st.path, native: native, provider: provider, gcSessionID: st.gcSessionID, size: st.size, fails: st.failures()})
	}
	probing := u.refusal != nil
	slices.SortFunc(jobs, func(a, b contentJob) int {
		fails := 0
		if !probing {
			fails = cmp.Compare(a.fails, b.fails)
		}
		return cmp.Or(fails, cmp.Compare(a.size, b.size), cmp.Compare(a.id.device, b.id.device), cmp.Compare(a.id.inode, b.id.inode))
	})
	return jobs, saves
}

// handled reports whether the transcript's current snapshot — its stat and gc session id — is the one
// last evaluated to an outcome that needs no upload.
func (st *contentState) handled() bool {
	return st.evalSet && st.size == st.evalSize && st.modNanos == st.evalMod && st.gcSessionID == st.evalGCSessionID
}

// failures returns how many consecutive POSTs of the transcript's current snapshot have failed.
func (st *contentState) failures() int {
	if st.postFailSize != st.size || st.postFailMod != st.modNanos {
		return 0
	}
	return st.postFailCount
}

// queuedLocked counts the tracked transcripts whose current content is owed and can be keyed: what a
// refusal holds back. Called under u.mu.
func (u *contentUploader) queuedLocked() int {
	n := 0
	for id, st := range u.files {
		if !st.observed || st.handled() {
			continue
		}
		if _, _, ok := u.resolveSessionLocked(id, st); ok {
			n++
		}
	}
	return n
}

// refreshConsent re-checks the live consent policy; a change runs onConsentChange.
func (u *contentUploader) refreshConsent() {
	if u.consent != nil {
		u.consent.Current()
	}
}

// allowedLocked reports whether the live consent policy still covers content captured under origin.
// Without a live policy everything the watcher observes is covered. Called under u.mu.
func (u *contentUploader) allowedLocked(origin consentOrigin) bool {
	if u.consent == nil {
		return true
	}
	return contentAllowedBy(u.consent.Latest(), origin)
}

// contentAllowedBy reports whether p consents to uploading content captured under origin.
func contentAllowedBy(p consent.Policy, origin consentOrigin) bool {
	return p.ContentUpload && origin.allowedBy(p)
}

// onConsentChange applies a consent change to content not yet sent: queued transcripts the policy no
// longer covers are dropped — their pending records with them, so a restart cannot resurrect them —
// and an upload in flight that it no longer covers is cancelled. It is the consent Source's
// subscriber, so it runs on whichever daemon loop observed the change.
func (u *contentUploader) onConsentChange() {
	p := u.consent.Latest()
	u.mu.Lock()
	dropped := 0
	for id, st := range u.files {
		if !contentAllowedBy(p, st.origin) {
			delete(u.files, id)
			dropped++
		}
	}
	if f := u.inflight; f != nil && !f.withdrawn && !contentAllowedBy(p, f.origin) {
		f.withdrawn = true
		f.cancel() // postSnapshot logs the withdrawal when the request returns
	}
	u.mu.Unlock()
	if dropped > 0 {
		u.logf("content upload: consent narrowed; dropped %d queued transcripts without sending them", dropped)
	}
	u.sweepPending()
}

// dropAll forgets every queued transcript. The daemon calls it when it rebuilds the watcher for a
// changed consent policy; the new watcher re-observes what it still tails.
func (u *contentUploader) dropAll() {
	u.mu.Lock()
	defer u.mu.Unlock()
	clear(u.files)
}

// resolveSessionLocked resolves the native session id + provider for a transcript, preferring the
// live sink threading and falling back to the identities persisted across a restart: the pending
// record of content queued and not yet accepted, then the last-uploaded marker. Called under u.mu.
func (u *contentUploader) resolveSessionLocked(id transcriptIdentity, st *contentState) (native, provider string, ok bool) {
	if n, p, ok := u.sessions.SessionFor(id.device, id.inode); ok {
		return n, p, true
	}
	if p := st.pending; p != nil {
		return p.NativeSessionID, p.Provider, true
	}
	if st.markerNative != "" {
		return st.markerNative, st.markerProvider, true
	}
	return "", "", false
}

// processOne reads, hashes, and (if changed) uploads one transcript's whole content, then records
// the outcome. The native session id + provider are already resolved and validated by the caller, so
// no whole-file read happens for a transcript whose session id is unknown or structurally invalid.
// All slow work (file read, network POST) runs without u.mu held.
func (u *contentUploader) processOne(ctx context.Context, id transcriptIdentity, origin consentOrigin, root, locator, path, native, provider, gcSessionID string) {
	content, rsize, rmod, err := u.read(root, locator, id.device, id.inode, u.maxBytes)
	if errors.Is(err, codex.ErrTranscriptTooLarge) {
		u.mu.Lock()
		if st := u.files[id]; st != nil {
			if !st.oversizeLogged {
				u.logf("content upload: skipping oversize transcript (%d bytes): %s", rsize, locator)
				st.oversizeLogged = true
			}
			st.markEvaluated(rsize, rmod, gcSessionID)
			st.pending = nil
		}
		u.mu.Unlock()
		u.dropPending(id) // a transcript only grows: it is not owed
		return
	}
	if err != nil {
		// Vanished / rotated / transient read error: best-effort, retry on a later tick. Do not
		// advance eval so the next stable observation re-reads. Log at most once per error streak so a
		// transcript deleted between the poll that observed it and the reconcile that GCs it does not
		// spam a log line every tick in that window.
		u.mu.Lock()
		logIt := true
		if st := u.files[id]; st != nil {
			logIt = !st.readErrLogged
			st.readErrLogged = true
		}
		u.mu.Unlock()
		if logIt {
			u.logf("content upload: read %s: %v", locator, err)
		}
		return
	}

	// Always-on PEM content sniff (applied LAST in the guard chain): a PEM/PKCS key block that
	// reached here under a transcript-shaped name is refused before it is hashed or POSTed, so no
	// upload request is ever constructed for it. Advance eval so it is not re-read; log + count once.
	if reason, refused := contentguard.ScreenContent(content); refused {
		u.mu.Lock()
		if st := u.files[id]; st != nil {
			u.recordGuardRefusalLocked(st, locator, reason)
			st.markEvaluated(rsize, rmod, gcSessionID)
			st.pending = nil
		}
		u.mu.Unlock()
		u.dropPending(id) // refused content is not owed
		return
	}

	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	u.mu.Lock()
	st := u.files[id]
	if st == nil {
		u.mu.Unlock()
		return
	}
	st.readErrLogged = false
	if st.markerHash != "" && hash == st.markerHash && gcSessionID == st.markerGCSessionID {
		// Content identical to the last handled snapshot (e.g. only the mtime moved): idempotent no-op.
		// Advance eval so future ticks skip the re-read and do not re-POST. Only refresh + persist the
		// durable marker when the hash came from a REAL acceptance; a hash recorded from a permanent-4xx
		// rejection stays in-memory-only so a restart still re-probes it (the 400/413/422 intent).
		// Either way the content is not owed: accepted, or rejected for good. A pending record written
		// for it since — after only its mtime moved, or by a run that stopped between persisting the
		// marker and deleting the record — goes.
		st.markEvaluated(rsize, rmod, gcSessionID)
		pending := st.pending != nil
		st.pending = nil
		if st.uploaded {
			st.markerSize, st.markerMod = rsize, rmod
			st.markerNative, st.markerProvider, st.markerGCSessionID = native, provider, gcSessionID
			marker := st.markerRecord(id, u.now())
			u.mu.Unlock()
			u.persistMarker(id, marker)
		} else {
			u.mu.Unlock()
		}
		if pending {
			u.dropPending(id)
		}
		return
	}
	// A GC binding already refused for this transcript is never re-offered: the content store binds a
	// transcript's GC session once, so a second, different value can only conflict again.
	sendGC := gcSessionID
	if st.gcBindingRefused {
		sendGC = ""
	}
	u.mu.Unlock()

	u.postSnapshot(ctx, id, origin, locator, path, content, hash, rsize, rmod, native, provider, gcSessionID, sendGC)
}

// postSnapshot POSTs one already-read, already-hashed snapshot and records the outcome. observedGC is
// the binding the watcher read from the transcript's sidecar and is what all dedup bookkeeping is
// keyed by; sendGC is what actually goes on the wire, which is "" once the collector has refused the
// binding. Called with u.mu released.
func (u *contentUploader) postSnapshot(ctx context.Context, id transcriptIdentity, origin consentOrigin, locator, path string, content []byte, hash string, rsize, rmod int64, native, provider, observedGC, sendGC string) {
	// Consent is checked right before the request (the file read that precedes it can be long), and
	// the upload is registered under the same lock a consent narrowing takes: either the narrowing
	// is already visible here and nothing is sent, or it cancels this request.
	u.refreshConsent()
	postCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The token file as it is before the request: a refusal is recorded against the oldest credential
	// the request could carry, so a renewal racing the request is still seen as one and retried.
	token := statTokenFile(u.tokenFile)
	u.mu.Lock()
	if !u.allowedLocked(origin) {
		delete(u.files, id)
		u.mu.Unlock()
		return
	}
	flight := &contentFlight{origin: origin, cancel: cancel}
	u.inflight = flight
	u.mu.Unlock()

	res, err := u.sender.PostContent(postCtx, upload.ContentRequest{
		NativeSessionID: native,
		GCSessionID:     sendGC,
		Provider:        provider,
		SourcePath:      path,
		Body:            content,
	})

	gcSessionID := observedGC
	now := u.now()
	u.mu.Lock()
	u.inflight = nil
	if flight.withdrawn && err != nil {
		// Consent was narrowed while this upload was in flight and the request was cancelled. That is
		// not a collector failure: no hold, no retry; the transcript's queued state is already gone.
		// (A request that completed before the cancellation landed is recorded as what it was.)
		delete(u.files, id)
		u.mu.Unlock()
		u.logf("content upload: withdrew the in-flight upload of %s (consent narrowed)", locator)
		return
	}
	st := u.files[id]
	if err != nil {
		u.holdUntil = now.Add(contentTransientHold)
		gaveUp := false
		if st != nil {
			gaveUp = st.recordPostFailureLocked(rsize, rmod, gcSessionID)
		}
		u.mu.Unlock()
		u.logf("content upload: POST %s: %v", locator, err)
		if gaveUp {
			u.logf("content upload: giving up on %s after %d failed attempts on this snapshot; will retry when it changes", locator, maxContentPostAttempts)
		}
		return
	}
	switch {
	case res.StatusCode == 200 || res.StatusCode == 201:
		resumed := u.acceptedLocked()
		marker, ok := u.acceptedSnapshotLocked(st, id, hash, rsize, rmod, native, provider, gcSessionID, now)
		u.mu.Unlock()
		u.recordAccepted(id, marker, ok, resumed, res.StatusCode)
		u.logf("content upload: sent %s for session %s (%d bytes, gc_session_id=%s)", locator, native, len(content), res.GCSessionID)
	case res.StatusCode == 409 && res.Code == wire.ObserverErrorBodyCodeSOURCEBINDINGCONFLICT && sendGC != "":
		// The content store already binds this transcript's source path to a DIFFERENT GC session id,
		// and that binding is write-once upstream — re-offering ours can only conflict again. The bytes
		// still belong to the bound transcript, so adopt the store's binding: drop the GC session id and
		// re-send the same snapshot under the provider-native identity alone, which is the store's
		// primary key for the path. Latched (and persisted) so it is offered exactly once per transcript.
		if st != nil {
			st.gcBindingRefused = true
		}
		logIt := st == nil || !st.gcRefusedLogged
		if st != nil {
			st.gcRefusedLogged = true
		}
		// The collector judged the binding, so it accepted the credential: a refusal is over.
		resumed := u.acceptedLocked()
		u.mu.Unlock()
		if resumed {
			u.logResumed(res.StatusCode)
		}
		if logIt {
			u.logf("content upload: collector refused the gc session binding for %s (session %s)%s; re-sending without it", locator, native, serverMessage(res))
		}
		u.postSnapshot(ctx, id, origin, locator, path, content, hash, rsize, rmod, native, provider, gcSessionID, "")
	case res.StatusCode == 409:
		// Idempotency content mismatch: the server already holds different bytes for this
		// (session, hash) pair. Advance the marker to this hash so we do not hot-loop; log and move on.
		resumed := u.acceptedLocked()
		marker, ok := u.acceptedSnapshotLocked(st, id, hash, rsize, rmod, native, provider, gcSessionID, now)
		u.mu.Unlock()
		u.recordAccepted(id, marker, ok, resumed, res.StatusCode)
		u.logf("content upload: 409 content mismatch for session %s%s; advancing", native, serverMessage(res))
	case res.StatusCode == 429:
		// Shed: honor Retry-After, but cap it so an absurd value cannot disable upload for the run.
		hold := res.RetryAfter
		if hold <= 0 {
			hold = contentTransientHold
		}
		if hold > maxContentHold {
			hold = maxContentHold
		}
		u.holdUntil = now.Add(hold)
		u.mu.Unlock()
		u.logf("content upload: 429 shed; backing off %s", hold)
	case isContentRefusal(res.StatusCode):
		// The collector refuses content upload itself — the credential (401/403), or content upload
		// not provisioned or disabled for this source (404/501) — not these bytes. An operator fixes
		// either without restarting the daemon, so back off and keep every queued transcript, its
		// snapshot unmarked, rather than latch off (see contentRefusal).
		wait, transition := u.recordRefusalLocked(res.StatusCode, now, token)
		queued := u.queuedLocked()
		u.mu.Unlock()
		if transition {
			u.logRefusal(res.StatusCode, serverMessage(res), queued, wait)
		}
	case res.StatusCode == 400 || res.StatusCode == 413 || res.StatusCode == 422:
		// Permanent for THESE bytes (malformed / too large / contract violation the client guard
		// missed): record the hash in memory so identical bytes are not re-POSTed, advance eval so the
		// file is not re-read, but do NOT persist (a restart re-probes) and do NOT arm the global hold
		// (other transcripts may upload fine). A genuine content change produces a new hash and is
		// retried once. The collector judged the bytes, so it accepted the credential: a refusal is
		// over. And the rejected content is not owed: its pending record goes.
		if st != nil {
			st.markerHash = hash
			st.uploaded = false // in-memory dedup only; a restart re-probes (do not persist)
			st.markerNative, st.markerProvider, st.markerGCSessionID = native, provider, gcSessionID
			st.markEvaluated(rsize, rmod, gcSessionID)
			st.pending = nil
			if !st.permanentLogged {
				u.logf("content upload: permanent status %d for session %s%s; not retrying identical bytes", res.StatusCode, native, serverMessage(res))
				st.permanentLogged = true
			}
		}
		resumed := u.acceptedLocked()
		u.mu.Unlock()
		u.dropPending(id)
		if resumed {
			u.logResumed(res.StatusCode)
		}
	default:
		u.holdUntil = now.Add(contentTransientHold)
		gaveUp := false
		if st != nil {
			gaveUp = st.recordPostFailureLocked(rsize, rmod, gcSessionID)
		}
		u.mu.Unlock()
		u.logf("content upload: unexpected status %d for session %s%s", res.StatusCode, native, serverMessage(res))
		if gaveUp {
			u.logf("content upload: giving up on %s after %d failed attempts on this snapshot; will retry when it changes", locator, maxContentPostAttempts)
		}
	}
}

// markEvaluated records the snapshot last evaluated to a non-upload-needed outcome. Every
// eval-advance site goes through here because tick's skip predicate compares the gc session id
// alongside the stat: a site that advanced only (size,mod) would leave a transcript that carries a
// gc session id re-armed on every tick, re-reading, re-hashing and re-POSTing it forever.
func (st *contentState) markEvaluated(size, mod int64, gcSessionID string) {
	st.evalSize, st.evalMod, st.evalGCSessionID, st.evalSet = size, mod, gcSessionID, true
}

// recordPostFailureLocked bumps the consecutive-failure counter for the current (size,mod) snapshot
// and reports whether the uploader should give up on it. Once a single snapshot has failed
// maxContentPostAttempts times it advances eval so the file is not re-read/re-hashed/re-POSTed until
// its content changes (a new stat resets the counter and re-arms retries). Called under u.mu.
func (st *contentState) recordPostFailureLocked(rsize, rmod int64, gcSessionID string) (gaveUp bool) {
	if st.postFailSize != rsize || st.postFailMod != rmod {
		st.postFailSize, st.postFailMod, st.postFailCount, st.giveUpLogged = rsize, rmod, 0, false
	}
	st.postFailCount++
	if st.postFailCount >= maxContentPostAttempts && !st.giveUpLogged {
		st.markEvaluated(rsize, rmod, gcSessionID)
		st.giveUpLogged = true
		return true
	}
	return false
}

// setUploaded records a successful (or advanced) upload of the given snapshot, so future ticks
// dedup against it in memory and a restart can re-key the transcript from the persisted identity.
func (st *contentState) setUploaded(hash string, size, mod int64, native, provider, gcSessionID string) {
	st.markerHash = hash
	st.markerSize = size
	st.markerMod = mod
	st.markerNative = native
	st.markerProvider = provider
	st.markerGCSessionID = gcSessionID
	st.markerLoaded = true
	st.uploaded = true
	st.markEvaluated(size, mod, gcSessionID)
	st.postFailCount, st.giveUpLogged = 0, false
}

// acceptedSnapshotLocked records that the collector accepted (or already holds) a snapshot: the
// in-memory marker advances to it, and the content is no longer owed. It returns the marker to
// persist, or ok=false when the transcript is no longer tracked. Called under u.mu.
func (u *contentUploader) acceptedSnapshotLocked(st *contentState, id transcriptIdentity, hash string, size, mod int64, native, provider, gcSessionID string, now time.Time) (marker contentMarker, ok bool) {
	if st == nil {
		return contentMarker{}, false
	}
	st.setUploaded(hash, size, mod, native, provider, gcSessionID)
	st.pending = nil
	return st.markerRecord(id, now), true
}

// recordAccepted makes an acceptance durable: a still-tracked transcript's marker is persisted, and
// its pending record is deleted either way — accepted content is no longer owed. The end of a refusal
// is logged once. Called with u.mu released.
func (u *contentUploader) recordAccepted(id transcriptIdentity, marker contentMarker, tracked, resumed bool, status int) {
	if tracked {
		u.persistMarker(id, marker)
	}
	u.dropPending(id)
	if resumed {
		u.logResumed(status)
	}
}

// ensureMarkerLoadedLocked loads the persisted last-uploaded marker the first time a transcript is
// evaluated, seeding the in-memory dedup and the eval stat so an unchanged file is neither re-read
// nor re-shipped after a restart. Called under u.mu.
func (u *contentUploader) ensureMarkerLoadedLocked(id transcriptIdentity, st *contentState) {
	if st.markerLoaded {
		return
	}
	st.markerLoaded = true
	m, ok := u.loadMarker(id)
	if !ok {
		return
	}
	st.markerHash = m.ContentSHA256
	st.markerSize = m.Size
	st.markerMod = m.ModNanos
	st.markerNative = m.NativeSessionID
	st.markerProvider = m.Provider
	st.markerGCSessionID = m.GCSessionID
	st.gcBindingRefused = m.GCBindingRefused
	// A persisted marker is only ever written for a real acceptance (2xx / 409); permanent-4xx
	// rejections are never persisted, so a loaded marker is always a real upload.
	st.uploaded = true
	st.markEvaluated(m.Size, m.ModNanos, m.GCSessionID)
}

// contentMarker is the atomic on-disk record of the last content snapshot uploaded for a transcript
// identity. It survives a restart so the daemon does not re-ship every transcript on boot.
type contentMarker struct {
	Version         int    `json:"version"`
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	ContentSHA256   string `json:"content_sha256"`
	Size            int64  `json:"size"`
	ModNanos        int64  `json:"observed_mtime_nanos"`
	NativeSessionID string `json:"native_session_id,omitempty"`
	Provider        string `json:"provider,omitempty"`
	GCSessionID     string `json:"gc_session_id,omitempty"`
	// GCBindingRefused records that the collector refused this transcript's GC session binding as
	// conflicting with the one the content store already holds. It survives a restart so the daemon
	// does not re-offer a binding that can only conflict again.
	GCBindingRefused bool   `json:"gc_binding_refused,omitempty"`
	UploadedAt       string `json:"uploaded_at"`
}

// markerRecord projects the in-memory upload state into a persistable marker.
func (st *contentState) markerRecord(id transcriptIdentity, now time.Time) contentMarker {
	return contentMarker{
		Version:          contentMarkerVersion,
		Device:           id.device,
		Inode:            id.inode,
		ContentSHA256:    st.markerHash,
		Size:             st.markerSize,
		ModNanos:         st.markerMod,
		NativeSessionID:  st.markerNative,
		Provider:         st.markerProvider,
		GCSessionID:      st.markerGCSessionID,
		GCBindingRefused: st.gcBindingRefused,
		UploadedAt:       now.UTC().Format(time.RFC3339Nano),
	}
}

// contentMarkerPath is the deterministic marker path for one identity. It shares the watcher's state
// dir (outside the approved roots, so it is never itself tailed) but uses a distinct filename prefix
// from the cursor state files.
func contentMarkerPath(stateDir string, dev, ino uint64) string {
	return filepath.Join(stateDir, fmt.Sprintf("content-marker-%d-%d.json", dev, ino))
}

// loadMarker reads and validates the persisted marker for id, returning ok=false when it is absent,
// unreadable, malformed, or for a different identity/version (start fresh rather than trust it).
func (u *contentUploader) loadMarker(id transcriptIdentity) (contentMarker, bool) {
	data, err := os.ReadFile(contentMarkerPath(u.stateDir, id.device, id.inode))
	if err != nil {
		return contentMarker{}, false
	}
	var m contentMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return contentMarker{}, false
	}
	if (m.Version != contentMarkerVersion && m.Version != legacyContentMarkerVersion) || m.Device != id.device || m.Inode != id.inode || m.ContentSHA256 == "" {
		return contentMarker{}, false
	}
	return m, true
}

// persistMarker atomically writes the last-uploaded marker (temp file → rename, owner-only). It is
// best-effort: a failed write only costs one redundant (idempotent) re-upload after a restart, so an
// error is logged, not propagated into the content path.
func (u *contentUploader) persistMarker(id transcriptIdentity, m contentMarker) {
	data, err := json.Marshal(m)
	if err != nil {
		u.logf("content upload: marshal marker: %v", err)
		return
	}
	if err := writeStateFile(u.stateDir, filepath.Base(contentMarkerPath(u.stateDir, id.device, id.inode)), contentMarkerTempPrefix, data); err != nil {
		u.logf("content upload: write marker: %v", err)
	}
}

// ForgetContent releases all state for a transcript identity the watcher has dropped (fully rotated
// away / deleted): the in-memory bookkeeping, the durable marker and pending record, and the sink's
// threaded session id. Mirroring the cursor GC, this bounds memory + on-disk state for a long-lived
// daemon and stops a vanished transcript from being re-read every tick, and it ensures a later file
// that reuses the same (device,inode) starts fresh rather than resurrecting a stale marker or session.
func (u *contentUploader) ForgetContent(device, inode uint64) {
	id := transcriptIdentity{device: device, inode: inode}
	u.mu.Lock()
	delete(u.files, id)
	u.mu.Unlock()
	_ = os.Remove(contentMarkerPath(u.stateDir, device, inode))
	u.dropPending(id)
	if u.sessions != nil {
		u.sessions.Forget(device, inode)
	}
}

// sweepOrphanContentTemps removes marker and pending-record temp files left by a crash between
// CreateTemp and rename, so they cannot accumulate across restarts. It only removes our own
// distinctly-prefixed temp files and silently tolerates an absent state dir (nothing has been written
// yet).
func sweepOrphanContentTemps(stateDir string) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), contentMarkerTempPrefix) || strings.HasPrefix(e.Name(), contentPendingTempPrefix) {
			_ = os.Remove(filepath.Join(stateDir, e.Name()))
		}
	}
}

// recordGuardRefusalLocked logs (once per transcript) and counts a content-guard refusal so a
// dropped credential/config/key file is visible and never silent — the daemon analogue of the
// recall forwarder's surfaced drop count. Called under u.mu.
func (u *contentUploader) recordGuardRefusalLocked(st *contentState, locator string, reason contentguard.Reason) {
	if st == nil || st.guardLogged {
		return
	}
	st.guardLogged = true
	if u.guardRefusals == nil {
		u.guardRefusals = map[contentguard.Reason]int{}
	}
	u.guardRefusals[reason]++
	u.logf("content upload: refusing %s: %s guard", locator, reason)
}

// serverMessage renders the collector's typed error message as a log suffix, or "" when the
// response carried no decodable message. PostContent already decodes it into ContentResult.Message;
// without this the operator sees only a bare status code and has to replay the request by hand to
// learn which contract the upload violated.
func serverMessage(res *upload.ContentResult) string {
	if res == nil || res.Message == "" {
		return ""
	}
	return " (server: " + res.Message + ")"
}

func (u *contentUploader) logf(format string, args ...any) {
	if u.log == nil {
		return
	}
	u.log(fmt.Sprintf(format, args...))
}
