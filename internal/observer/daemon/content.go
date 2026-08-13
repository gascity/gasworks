//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/contentguard"
	"github.com/gascity/gasworks/internal/observer/upload"
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

	mu    sync.Mutex
	files map[transcriptIdentity]*contentState
	// guardRefusals counts transcripts dropped by an always-on content guard (denylist / allowlist /
	// PEM sniff), keyed by reason, so a refused credential/config/key file is visible and testable —
	// counted + logged, never silent. Guarded by u.mu.
	guardRefusals map[contentguard.Reason]int
	// disabled is latched when the server reports the tenant is not provisioned (501): content upload
	// stops for the process lifetime (a restart re-probes). It never affects the metadata pipeline.
	disabled bool
	// holdUntil shed-backs off ALL content uploads until this time, set on a 429 Retry-After or a
	// transient/5xx failure. It is a coarse global gate because the shed is a server-wide signal.
	holdUntil time.Time
}

// contentState is the per-transcript upload bookkeeping, keyed by filesystem identity.
type contentState struct {
	root, locator, path string
	size, modNanos      int64
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

	// eval* is the (size,modNanos) of the snapshot last EVALUATED to a non-upload-needed outcome
	// (uploaded, unchanged, oversize, invalid, or permanently-rejected). A file whose current stat
	// equals eval* is skipped without a re-read. It is seeded from the marker on load so an unchanged
	// file is not re-read after restart.
	evalSize        int64
	evalMod         int64
	evalSet         bool
	evalGCSessionID string

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
	// Sweep any orphaned marker temp files left by a crash mid-persist, so they cannot accumulate
	// across restarts. The state dir is shared with the watcher's cursor files; we only touch our
	// own distinctly-prefixed temp files.
	sweepOrphanContentTemps(cfg.stateDir)
	return &contentUploader{
		sender:   cfg.sender,
		sessions: cfg.sessions,
		stateDir: cfg.stateDir,
		maxBytes: maxBytes,
		debounce: debounce,
		read:     read,
		now:      now,
		log:      cfg.log,
		files:    map[transcriptIdentity]*contentState{},

		guardRefusals: map[contentguard.Reason]int{},
	}, nil
}

// contentUploader is the watcher's ContentObserver.
var _ codex.ContentObserver = (*contentUploader)(nil)

// ObserveContent records one tracked transcript's current identity/path/stat. It is called from the
// watcher's poll goroutine and MUST stay cheap: it only updates in-memory debounce state (no I/O),
// so a slow content upload can never stall the metadata poll. Any size/mtime change restarts the
// stability clock; an unchanged observation lets stability accumulate toward the debounce window.
func (u *contentUploader) ObserveContent(_ context.Context, o codex.ContentObservation) {
	id := transcriptIdentity{device: o.Device, inode: o.Inode}
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.files[id]
	if st == nil {
		st = &contentState{}
		u.files[id] = st
	}
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
	now := u.now()
	u.mu.Lock()
	if u.disabled || (!u.holdUntil.IsZero() && now.Before(u.holdUntil)) {
		u.mu.Unlock()
		return
	}
	type job struct {
		id                            transcriptIdentity
		root, locator, path           string
		native, provider, gcSessionID string
	}
	var jobs []job
	for id, st := range u.files {
		u.ensureMarkerLoadedLocked(id, st)
		if !st.observed || now.Sub(st.stableSince) < u.debounce {
			continue // still growing or not stable long enough
		}
		if st.evalSet && st.size == st.evalSize && st.modNanos == st.evalMod && st.gcSessionID == st.evalGCSessionID {
			continue // unchanged since the last snapshot we handled
		}
		// Resolve the native session id BEFORE any whole-file read/hash. Prefer the live sink; fall
		// back to the marker's persisted id so a transcript uploaded at least once still keys after a
		// restart. Unknown → skip cheaply (no read, no hash); a later tick retries once the session is
		// threaded or the marker lands. This is the guard that stops an unknown-session transcript from
		// being fully re-read and re-hashed on every tick.
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
			st.evalSize, st.evalMod, st.evalSet = st.size, st.modNanos, true
			continue
		}
		// Always-on content-lane filename guards: the secrets/config denylist and the strict
		// per-provider transcript-shape allowlist (contentguard). A credential, config, or off-shape
		// file authored under an approved root is refused HERE — before any whole-file read or upload
		// request is constructed. Advance eval so a refused file is not re-read every tick; the refusal
		// is logged + counted once, never silent.
		if reason, refused := contentguard.ScreenName(provider, st.path); refused {
			u.recordGuardRefusalLocked(st, st.locator, reason)
			st.evalSize, st.evalMod, st.evalSet = st.size, st.modNanos, true
			continue
		}
		jobs = append(jobs, job{id: id, root: st.root, locator: st.locator, path: st.path, native: native, provider: provider, gcSessionID: st.gcSessionID})
	}
	u.mu.Unlock()

	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		// A shed (429) or provision/auth latch (401/403/404/501) recorded while processing an earlier
		// job in this same tick must stop the rest — re-check before each POST, not only at tick entry.
		u.mu.Lock()
		stop := u.disabled || (!u.holdUntil.IsZero() && u.now().Before(u.holdUntil))
		u.mu.Unlock()
		if stop {
			return
		}
		u.processOne(ctx, j.id, j.root, j.locator, j.path, j.native, j.provider, j.gcSessionID)
	}
}

// resolveSessionLocked resolves the native session id + provider for a transcript, preferring the
// live sink threading and falling back to the last-uploaded marker's persisted identity (which
// survives a restart). Called under u.mu.
func (u *contentUploader) resolveSessionLocked(id transcriptIdentity, st *contentState) (native, provider string, ok bool) {
	if n, p, ok := u.sessions.SessionFor(id.device, id.inode); ok {
		return n, p, true
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
func (u *contentUploader) processOne(ctx context.Context, id transcriptIdentity, root, locator, path, native, provider, gcSessionID string) {
	content, rsize, rmod, err := u.read(root, locator, id.device, id.inode, u.maxBytes)
	if errors.Is(err, codex.ErrTranscriptTooLarge) {
		u.mu.Lock()
		if st := u.files[id]; st != nil {
			if !st.oversizeLogged {
				u.logf("content upload: skipping oversize transcript (%d bytes): %s", rsize, locator)
				st.oversizeLogged = true
			}
			st.evalSize, st.evalMod, st.evalSet = rsize, rmod, true
		}
		u.mu.Unlock()
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
			st.evalSize, st.evalMod, st.evalSet = rsize, rmod, true
		}
		u.mu.Unlock()
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
		st.evalSize, st.evalMod, st.evalSet, st.evalGCSessionID = rsize, rmod, true, gcSessionID
		if st.uploaded {
			st.markerSize, st.markerMod = rsize, rmod
			st.markerNative, st.markerProvider, st.markerGCSessionID = native, provider, gcSessionID
			marker := st.markerRecord(id, u.now())
			u.mu.Unlock()
			u.persistMarker(id, marker)
			return
		}
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()

	res, err := u.sender.PostContent(ctx, upload.ContentRequest{
		NativeSessionID: native,
		GCSessionID:     gcSessionID,
		Provider:        provider,
		SourcePath:      path,
		Body:            content,
	})

	now := u.now()
	u.mu.Lock()
	st = u.files[id]
	if err != nil {
		u.holdUntil = now.Add(contentTransientHold)
		gaveUp := false
		if st != nil {
			gaveUp = st.recordPostFailureLocked(rsize, rmod)
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
		var marker contentMarker
		if st != nil {
			st.setUploaded(hash, rsize, rmod, native, provider, gcSessionID)
			marker = st.markerRecord(id, now)
		}
		u.mu.Unlock()
		if st != nil {
			u.persistMarker(id, marker)
		}
		u.logf("content upload: sent %s for session %s (%d bytes, gc_session_id=%s)", locator, native, len(content), res.GCSessionID)
	case res.StatusCode == 409:
		// Idempotency content mismatch: the server already holds different bytes for this
		// (session, hash) pair. Advance the marker to this hash so we do not hot-loop; log and move on.
		var marker contentMarker
		if st != nil {
			st.setUploaded(hash, rsize, rmod, native, provider, gcSessionID)
			marker = st.markerRecord(id, now)
		}
		u.mu.Unlock()
		if st != nil {
			u.persistMarker(id, marker)
		}
		u.logf("content upload: 409 content mismatch for session %s; advancing", native)
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
	case res.StatusCode == 401 || res.StatusCode == 403 || res.StatusCode == 404 || res.StatusCode == 501:
		// Provisioning / authorization / route failure: content upload cannot work for this run at
		// all (the credential, tenant provisioning, or route will not change), so latch off rather
		// than retry every transcript forever. A restart re-probes.
		u.disabled = true
		u.mu.Unlock()
		u.logf("content upload: status %d; disabling content upload for this run", res.StatusCode)
	case res.StatusCode == 400 || res.StatusCode == 413 || res.StatusCode == 422:
		// Permanent for THESE bytes (malformed / too large / contract violation the client guard
		// missed): record the hash in memory so identical bytes are not re-POSTed, advance eval so the
		// file is not re-read, but do NOT persist (a restart re-probes) and do NOT arm the global hold
		// (other transcripts may upload fine). A genuine content change produces a new hash and is
		// retried once.
		if st != nil {
			st.markerHash = hash
			st.uploaded = false // in-memory dedup only; a restart re-probes (do not persist)
			st.markerNative, st.markerProvider, st.markerGCSessionID = native, provider, gcSessionID
			st.evalSize, st.evalMod, st.evalSet, st.evalGCSessionID = rsize, rmod, true, gcSessionID
			if !st.permanentLogged {
				u.logf("content upload: permanent status %d for session %s; not retrying identical bytes", res.StatusCode, native)
				st.permanentLogged = true
			}
		}
		u.mu.Unlock()
	default:
		u.holdUntil = now.Add(contentTransientHold)
		gaveUp := false
		if st != nil {
			gaveUp = st.recordPostFailureLocked(rsize, rmod)
		}
		u.mu.Unlock()
		u.logf("content upload: unexpected status %d for session %s", res.StatusCode, native)
		if gaveUp {
			u.logf("content upload: giving up on %s after %d failed attempts on this snapshot; will retry when it changes", locator, maxContentPostAttempts)
		}
	}
}

// recordPostFailureLocked bumps the consecutive-failure counter for the current (size,mod) snapshot
// and reports whether the uploader should give up on it. Once a single snapshot has failed
// maxContentPostAttempts times it advances eval so the file is not re-read/re-hashed/re-POSTed until
// its content changes (a new stat resets the counter and re-arms retries). Called under u.mu.
func (st *contentState) recordPostFailureLocked(rsize, rmod int64) (gaveUp bool) {
	if st.postFailSize != rsize || st.postFailMod != rmod {
		st.postFailSize, st.postFailMod, st.postFailCount, st.giveUpLogged = rsize, rmod, 0, false
	}
	st.postFailCount++
	if st.postFailCount >= maxContentPostAttempts && !st.giveUpLogged {
		st.evalSize, st.evalMod, st.evalSet = rsize, rmod, true
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
	st.evalSize = size
	st.evalMod = mod
	st.evalSet = true
	st.evalGCSessionID = gcSessionID
	st.postFailCount, st.giveUpLogged = 0, false
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
	// A persisted marker is only ever written for a real acceptance (2xx / 409); permanent-4xx
	// rejections are never persisted, so a loaded marker is always a real upload.
	st.uploaded = true
	st.evalSize = m.Size
	st.evalMod = m.ModNanos
	st.evalSet = true
	st.evalGCSessionID = m.GCSessionID
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
	UploadedAt      string `json:"uploaded_at"`
}

// markerRecord projects the in-memory upload state into a persistable marker.
func (st *contentState) markerRecord(id transcriptIdentity, now time.Time) contentMarker {
	return contentMarker{
		Version:         contentMarkerVersion,
		Device:          id.device,
		Inode:           id.inode,
		ContentSHA256:   st.markerHash,
		Size:            st.markerSize,
		ModNanos:        st.markerMod,
		NativeSessionID: st.markerNative,
		Provider:        st.markerProvider,
		GCSessionID:     st.markerGCSessionID,
		UploadedAt:      now.UTC().Format(time.RFC3339Nano),
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
	path := contentMarkerPath(u.stateDir, id.device, id.inode)
	if err := os.MkdirAll(u.stateDir, 0o700); err != nil {
		u.logf("content upload: create marker dir: %v", err)
		return
	}
	tmp, err := os.CreateTemp(u.stateDir, ".tmp-content-marker-*")
	if err != nil {
		u.logf("content upload: create marker temp: %v", err)
		return
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		u.logf("content upload: chmod marker temp: %v", err)
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		u.logf("content upload: write marker temp: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		u.logf("content upload: close marker temp: %v", err)
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		u.logf("content upload: rename marker: %v", err)
	}
}

// ForgetContent releases all state for a transcript identity the watcher has dropped (fully rotated
// away / deleted): the in-memory bookkeeping, the durable marker file, and the sink's threaded
// session id. Mirroring the cursor GC, this bounds memory + on-disk markers for a long-lived daemon
// and stops a vanished transcript from being re-read every tick, and it ensures a later file that
// reuses the same (device,inode) starts fresh rather than resurrecting a stale marker or session id.
func (u *contentUploader) ForgetContent(device, inode uint64) {
	id := transcriptIdentity{device: device, inode: inode}
	u.mu.Lock()
	delete(u.files, id)
	u.mu.Unlock()
	_ = os.Remove(contentMarkerPath(u.stateDir, device, inode))
	if u.sessions != nil {
		u.sessions.Forget(device, inode)
	}
}

// sweepOrphanContentTemps removes marker temp files left by a crash between CreateTemp and rename, so
// they cannot accumulate across restarts. It only removes our own distinctly-prefixed temp files and
// silently tolerates an absent state dir (nothing has been written yet).
func sweepOrphanContentTemps(stateDir string) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".tmp-content-marker-") {
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

func (u *contentUploader) logf(format string, args ...any) {
	if u.log == nil {
		return
	}
	u.log(fmt.Sprintf(format, args...))
}
