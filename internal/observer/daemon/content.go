//go:build linux

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
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
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
	// contentMarkerVersion is the on-disk last-uploaded marker schema version.
	contentMarkerVersion = 1
)

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
	// has been uploaded for this identity yet.
	markerLoaded bool
	markerHash   string
	markerSize   int64
	markerMod    int64

	// eval* is the (size,modNanos) of the snapshot last EVALUATED to a non-upload-needed outcome
	// (uploaded, unchanged, or oversize). A file whose current stat equals eval* is skipped without a
	// re-read. It is seeded from the marker on load so an unchanged file is not re-read after restart.
	evalSize int64
	evalMod  int64
	evalSet  bool

	oversizeLogged bool
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
		id                  transcriptIdentity
		root, locator, path string
	}
	var jobs []job
	for id, st := range u.files {
		u.ensureMarkerLoadedLocked(id, st)
		if !st.observed || now.Sub(st.stableSince) < u.debounce {
			continue // still growing or not stable long enough
		}
		if st.evalSet && st.size == st.evalSize && st.modNanos == st.evalMod {
			continue // unchanged since the last snapshot we handled
		}
		jobs = append(jobs, job{id: id, root: st.root, locator: st.locator, path: st.path})
	}
	u.mu.Unlock()

	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		u.processOne(ctx, j.id, j.root, j.locator, j.path)
	}
}

// processOne reads, hashes, and (if changed) uploads one transcript's whole content, then records
// the outcome. All slow work (file read, network POST) runs without u.mu held.
func (u *contentUploader) processOne(ctx context.Context, id transcriptIdentity, root, locator, path string) {
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
		// advance eval so the next stable observation re-reads.
		u.logf("content upload: read %s: %v", locator, err)
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
	if st.markerHash != "" && hash == st.markerHash {
		// Content identical to the last upload (e.g. only the mtime moved): idempotent no-op. Advance
		// the marker's stat so future ticks skip the re-read; do not re-POST.
		st.markerSize, st.markerMod = rsize, rmod
		st.evalSize, st.evalMod, st.evalSet = rsize, rmod, true
		marker := st.markerRecord(id, u.now())
		u.mu.Unlock()
		u.persistMarker(id, marker)
		return
	}
	u.mu.Unlock()

	native, provider, ok := u.sessions.SessionFor(id.device, id.inode)
	if !ok {
		// The transcript's session record has not been parsed yet, so we cannot key the snapshot.
		// Skip without advancing; a later tick retries once the session id is known.
		return
	}

	res, err := u.sender.PostContent(ctx, upload.ContentRequest{
		NativeSessionID: native,
		Provider:        provider,
		SourcePath:      path,
		Body:            content,
	})

	now := u.now()
	u.mu.Lock()
	st = u.files[id]
	if err != nil {
		u.holdUntil = now.Add(contentTransientHold)
		u.mu.Unlock()
		u.logf("content upload: POST %s: %v", locator, err)
		return
	}
	switch {
	case res.StatusCode == 200 || res.StatusCode == 201:
		var marker contentMarker
		if st != nil {
			st.setUploaded(hash, rsize, rmod)
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
			st.setUploaded(hash, rsize, rmod)
			marker = st.markerRecord(id, now)
		}
		u.mu.Unlock()
		if st != nil {
			u.persistMarker(id, marker)
		}
		u.logf("content upload: 409 content mismatch for session %s; advancing", native)
	case res.StatusCode == 429:
		hold := res.RetryAfter
		if hold <= 0 {
			hold = contentTransientHold
		}
		u.holdUntil = now.Add(hold)
		u.mu.Unlock()
		u.logf("content upload: 429 shed; backing off %s", hold)
	case res.StatusCode == 501:
		u.disabled = true
		u.mu.Unlock()
		u.logf("content upload: 501 not provisioned; disabling content upload for this run")
	default:
		u.holdUntil = now.Add(contentTransientHold)
		u.mu.Unlock()
		u.logf("content upload: unexpected status %d for session %s", res.StatusCode, native)
	}
}

// setUploaded records a successful (or advanced) upload of the given snapshot, so future ticks
// dedup against it in memory.
func (st *contentState) setUploaded(hash string, size, mod int64) {
	st.markerHash = hash
	st.markerSize = size
	st.markerMod = mod
	st.markerLoaded = true
	st.evalSize = size
	st.evalMod = mod
	st.evalSet = true
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
	st.evalSize = m.Size
	st.evalMod = m.ModNanos
	st.evalSet = true
}

// contentMarker is the atomic on-disk record of the last content snapshot uploaded for a transcript
// identity. It survives a restart so the daemon does not re-ship every transcript on boot.
type contentMarker struct {
	Version       int    `json:"version"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	ContentSHA256 string `json:"content_sha256"`
	Size          int64  `json:"size"`
	ModNanos      int64  `json:"observed_mtime_nanos"`
	UploadedAt    string `json:"uploaded_at"`
}

// markerRecord projects the in-memory upload state into a persistable marker.
func (st *contentState) markerRecord(id transcriptIdentity, now time.Time) contentMarker {
	return contentMarker{
		Version:       contentMarkerVersion,
		Device:        id.device,
		Inode:         id.inode,
		ContentSHA256: st.markerHash,
		Size:          st.markerSize,
		ModNanos:      st.markerMod,
		UploadedAt:    now.UTC().Format(time.RFC3339Nano),
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
	if m.Version != contentMarkerVersion || m.Device != id.device || m.Inode != id.inode || m.ContentSHA256 == "" {
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

func (u *contentUploader) logf(format string, args ...any) {
	if u.log == nil {
		return
	}
	u.log(fmt.Sprintf(format, args...))
}
