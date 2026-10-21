//go:build linux || darwin

package daemon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/contentguard"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Content re-upload.
//
// The daemon uploads a transcript's content once and then trusts its last-uploaded marker: it never
// re-sends unchanged bytes. Content accepted by a destination that no longer serves it — the
// transcripts uploaded before the 2026-08-02 content-store cell cutover went to the pre-cutover cell —
// is therefore never sent again. RunContentReupload is the one-shot, paced operator tool that re-sends
// it: it selects markers by their upload time (before a cutoff) and/or by native session id, finds
// each marker's transcript under the given roots by its (device, inode), and POSTs the transcript's
// current whole content through the same collector client the daemon uses, under the marker's native
// session id. An accepted upload advances the marker exactly as the daemon would.
//
// It is resumable: every transcript it settles (accepted, or permanently rejected) is appended to a
// progress journal, and a rerun skips what the journal holds. An accepted upload also advances its
// marker past the cutoff, so a cutoff rerun would skip it even without the journal. A collector
// refusal (401/403/404/501), the context, or a run of consecutive failures stops the run; nothing it
// did not settle is journaled, so the rerun resumes there. The content store's ingest is idempotent
// per observation id, so a snapshot it already holds comes back as a duplicate receipt, not a second
// copy.

// Re-upload defaults.
const (
	// DefaultReuploadInterval paces the POSTs: one per second.
	DefaultReuploadInterval = time.Second
	// DefaultReuploadMaxConsecutiveFailures stops a run once this many transcripts in a row could not
	// be sent (transport errors and 5xx after their retries), so a collector outage does not walk the
	// whole selection.
	DefaultReuploadMaxConsecutiveFailures = 10
	// reuploadAttempts bounds the POSTs of one transcript on transport/5xx/429 before it counts as
	// failed (and stays unjournaled, so a rerun retries it).
	reuploadAttempts = 4
	// reuploadBackoff is the first retry delay; it doubles per attempt, capped at maxContentHold.
	reuploadBackoff = 5 * time.Second
)

// ContentReuploadCutover is the default -before cutoff: the content-store cell cutover. Content a
// marker records as uploaded before it went to the pre-cutover destination.
var ContentReuploadCutover = time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

// ErrReuploadRefused reports that the collector refused content upload itself (401/403/404/501).
var ErrReuploadRefused = errors.New("collector refused content upload")

// ErrReuploadTooManyFailures reports that the run stopped after too many consecutive failures.
var ErrReuploadTooManyFailures = errors.New("too many consecutive failed uploads")

// ReuploadConfig configures one RunContentReupload run.
type ReuploadConfig struct {
	// Sender POSTs the content (the daemon's collector client). It may be nil in a dry run.
	Sender ContentSender
	// StateDir is the producer's marker directory (its -cursor-dir).
	StateDir string
	// Roots are the transcript roots the producer watches; markers are matched to files by identity.
	Roots []string
	// Before selects markers whose uploaded_at is before it. Zero selects none by time.
	Before time.Time
	// IDs selects markers by native session id. Empty selects none by id. A marker matching Before
	// OR IDs is selected.
	IDs map[string]bool
	// Provider, when set, restricts the selection to one provider ("claude" or "codex").
	Provider string
	// ProgressFile is the append-only journal of settled transcripts; required unless DryRun.
	ProgressFile string
	// Interval paces POSTs (DefaultReuploadInterval when 0).
	Interval time.Duration
	// MaxConsecutiveFailures stops the run (DefaultReuploadMaxConsecutiveFailures when 0).
	MaxConsecutiveFailures int
	// MaxBytes bounds one transcript (DefaultMaxContentBytes when 0).
	MaxBytes int64
	// Limit, when > 0, stops after that many POSTed transcripts (a canary slice).
	Limit int
	// DryRun selects and locates, and reports counts, without reading content or POSTing anything.
	DryRun bool

	// read, now and sleep are test seams.
	read  transcriptReader
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	// Log receives content-free progress lines (counts and ids only). nil discards them.
	Log func(string)
}

// ReuploadReport is what one run found and did. Every field is a count; nothing names content.
type ReuploadReport struct {
	Markers  int // valid markers in the state dir
	Selected int // markers the cutoff / id list / provider selected
	// SelectedByProvider counts the selection per provider.
	SelectedByProvider map[string]int
	AlreadyDone        int // selected, and settled by an earlier run (progress journal)
	Located            int // selected, not done, and their transcript was found under a root
	Missing            int // selected, not done, and no transcript under the roots has the identity
	IdentityMismatch   int // located, but the file's name names a different provider/rollout (a reused inode)
	NativeDiffersName  int // located Claude transcripts whose marker id is not their file's uuid (resumed/forked)
	Unkeyed            int // located, but neither marker nor name yields a valid native session id
	Guarded            int // refused by the always-on content guards
	Oversize           int
	ReadErrors         int
	Sent               int // transcripts POSTed (counted once, however many attempts)
	Accepted           int // 2xx
	Duplicate          int // 2xx whose receipt says the store already held the snapshot
	Rejected           int // 400/413/422: permanent for those bytes
	Conflict           int // 409: the store binds the path to another identity or other bytes
	Failed             int // transport/5xx/429 after every retry (not journaled: a rerun retries)
}

// reuploadItem is one selected marker and, once located, its transcript.
type reuploadItem struct {
	marker              contentMarker
	root, locator, path string
}

// reuploadProgress is one journal line.
type reuploadProgress struct {
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Native  string `json:"native_session_id"`
	Outcome string `json:"outcome"`
	At      string `json:"at"`
}

// RunContentReupload runs one re-upload pass and returns its report. A returned error stops the run
// early (refusal, failures, context, or setup); the report counts what it did until then.
func RunContentReupload(ctx context.Context, cfg ReuploadConfig) (ReuploadReport, error) {
	rep := ReuploadReport{SelectedByProvider: map[string]int{}}
	if cfg.StateDir == "" {
		return rep, errors.New("content re-upload: a state dir is required")
	}
	if !cfg.DryRun && (cfg.Sender == nil || cfg.ProgressFile == "") {
		return rep, errors.New("content re-upload: a sender and a progress file are required unless dry-running")
	}
	if cfg.Before.IsZero() && len(cfg.IDs) == 0 {
		return rep, errors.New("content re-upload: select by a cutoff, an id list, or both")
	}
	read := cfg.read
	if read == nil {
		read = codex.ReadValidatedTranscript
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	sleep := cfg.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	interval := durationOr(cfg.Interval, DefaultReuploadInterval)
	maxFails := cfg.MaxConsecutiveFailures
	if maxFails <= 0 {
		maxFails = DefaultReuploadMaxConsecutiveFailures
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxContentBytes
	}
	logf := func(format string, args ...any) {
		if cfg.Log != nil {
			cfg.Log(fmt.Sprintf(format, args...))
		}
	}

	markers, err := loadAllMarkers(cfg.StateDir)
	if err != nil {
		return rep, err
	}
	rep.Markers = len(markers)
	done, err := loadReuploadProgress(cfg.ProgressFile)
	if err != nil {
		return rep, err
	}
	var selected []contentMarker
	for _, m := range markers {
		if !reuploadSelects(cfg, m) {
			continue
		}
		rep.Selected++
		rep.SelectedByProvider[m.Provider]++
		if done[transcriptIdentity{device: m.Device, inode: m.Inode}] {
			rep.AlreadyDone++
			continue
		}
		selected = append(selected, m)
	}
	files, err := indexTranscripts(cfg.Roots)
	if err != nil {
		return rep, err
	}
	var items []reuploadItem
	for _, m := range selected {
		f, ok := files[transcriptIdentity{device: m.Device, inode: m.Inode}]
		if !ok {
			rep.Missing++
			continue
		}
		rep.Located++
		it := reuploadItem{marker: m, root: f.root, locator: f.locator, path: f.path}
		nameNative, nameProvider, named := deriveSessionFromName(f.path)
		switch {
		case named && m.Provider != "" && nameProvider != m.Provider,
			named && nameProvider == "codex" && isLowerUUID(m.NativeSessionID) && nameNative != m.NativeSessionID:
			// The identity now belongs to another transcript than the one the marker recorded.
			rep.IdentityMismatch++
			continue
		case named && nameProvider == "claude" && m.NativeSessionID != "" && nameNative != m.NativeSessionID:
			rep.NativeDiffersName++
		}
		if it.marker.NativeSessionID == "" && named {
			it.marker.NativeSessionID, it.marker.Provider = nameNative, nameProvider
		}
		if !validContentHeaders(it.marker.NativeSessionID, it.marker.Provider, it.path) {
			rep.Unkeyed++
			continue
		}
		if _, refused := contentguard.ScreenName(it.marker.Provider, it.path); refused {
			rep.Guarded++
			continue
		}
		items = append(items, it)
	}
	logf("content re-upload: %d markers, %d selected (%d already done), %d located, %d missing, %d to send", rep.Markers, rep.Selected, rep.AlreadyDone, rep.Located, rep.Missing, len(items))
	if cfg.DryRun {
		return rep, nil
	}

	journal, err := os.OpenFile(cfg.ProgressFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return rep, fmt.Errorf("content re-upload: open progress file: %w", err)
	}
	defer journal.Close()
	settle := func(m contentMarker, outcome string) error {
		line, _ := json.Marshal(reuploadProgress{Device: m.Device, Inode: m.Inode, Native: m.NativeSessionID, Outcome: outcome, At: now().UTC().Format(time.RFC3339Nano)})
		if _, err := journal.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("content re-upload: write progress: %w", err)
		}
		return nil
	}

	fails := 0
	for i, it := range items {
		if cfg.Limit > 0 && rep.Sent >= cfg.Limit {
			logf("content re-upload: stopped at the limit of %d transcripts", cfg.Limit)
			break
		}
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		id := transcriptIdentity{device: it.marker.Device, inode: it.marker.Inode}
		content, size, mod, err := read(it.root, it.locator, id.device, id.inode, maxBytes)
		if errors.Is(err, codex.ErrTranscriptTooLarge) {
			rep.Oversize++
			if err := settle(it.marker, "oversize"); err != nil {
				return rep, err
			}
			continue
		}
		if err != nil {
			rep.ReadErrors++
			continue
		}
		if _, refused := contentguard.ScreenContent(content); refused {
			rep.Guarded++
			continue
		}
		sum := sha256.Sum256(content)
		hash := hex.EncodeToString(sum[:])

		outcome, res, err := postReupload(ctx, cfg.Sender, it, content, sleep)
		rep.Sent++
		if err != nil {
			return rep, err
		}
		switch outcome {
		case "accepted", "gc-refused":
			rep.Accepted++
			if res.StatusCode == 200 {
				rep.Duplicate++ // the store already held this snapshot: 200 duplicate, 201 new
			}
			m := it.marker
			m.Version = contentMarkerVersion
			m.GCBindingRefused = m.GCBindingRefused || outcome == "gc-refused"
			m.ContentSHA256, m.Size, m.ModNanos = hash, size, mod
			m.UploadedAt = now().UTC().Format(time.RFC3339Nano)
			data, _ := json.Marshal(m)
			if err := writeStateFile(cfg.StateDir, filepath.Base(contentMarkerPath(cfg.StateDir, id.device, id.inode)), contentMarkerTempPrefix, data); err != nil {
				return rep, fmt.Errorf("content re-upload: write marker: %w", err)
			}
			outcome = "accepted"
			fails = 0
		case "rejected":
			rep.Rejected++
			fails = 0
		case "conflict":
			rep.Conflict++
			fails = 0
		case "failed":
			rep.Failed++
			fails++
			if fails >= maxFails {
				return rep, fmt.Errorf("content re-upload: %w (%d in a row)", ErrReuploadTooManyFailures, fails)
			}
			continue // not settled: a rerun retries it
		}
		if err := settle(it.marker, outcome); err != nil {
			return rep, err
		}
		if (i+1)%100 == 0 {
			logf("content re-upload: %d/%d sent (%d accepted, %d duplicate, %d rejected, %d conflict, %d failed)", rep.Sent, len(items), rep.Accepted, rep.Duplicate, rep.Rejected, rep.Conflict, rep.Failed)
		}
		if i+1 < len(items) {
			if err := sleep(ctx, interval); err != nil {
				return rep, err
			}
		}
	}
	return rep, nil
}

// postReupload POSTs one transcript, retrying transport errors, 5xx and 429 with a capped backoff
// (honoring Retry-After), and classifies the final answer. A refusal returns ErrReuploadRefused.
func postReupload(ctx context.Context, sender ContentSender, it reuploadItem, content []byte, sleep func(context.Context, time.Duration) error) (string, *upload.ContentResult, error) {
	gc := it.marker.GCSessionID
	if it.marker.GCBindingRefused {
		gc = ""
	}
	gcDropped := false
	backoff := reuploadBackoff
	for attempt := 1; ; attempt++ {
		res, err := sender.PostContent(ctx, upload.ContentRequest{
			NativeSessionID: it.marker.NativeSessionID,
			GCSessionID:     gc,
			Provider:        it.marker.Provider,
			SourcePath:      it.path,
			Body:            content,
		})
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		wait := time.Duration(0)
		switch {
		case err != nil:
			wait = backoff
		case res.StatusCode == 200 || res.StatusCode == 201:
			if gcDropped {
				return "gc-refused", res, nil
			}
			return "accepted", res, nil
		case res.StatusCode == 409 && res.Code == wire.ObserverErrorBodyCodeSOURCEBINDINGCONFLICT && gc != "":
			gc, gcDropped = "", true
			continue // re-send once without the refused binding, as the daemon does
		case res.StatusCode == 409:
			return "conflict", res, nil
		case res.StatusCode == 400 || res.StatusCode == 413 || res.StatusCode == 422:
			return "rejected", res, nil
		case isContentRefusal(res.StatusCode):
			return "", res, fmt.Errorf("content re-upload: %w (status %d)", ErrReuploadRefused, res.StatusCode)
		case res.StatusCode == 429 && res.RetryAfter > 0:
			wait = res.RetryAfter
		default:
			wait = backoff
		}
		if attempt >= reuploadAttempts {
			return "failed", res, nil
		}
		if wait > maxContentHold {
			wait = maxContentHold
		}
		if err := sleep(ctx, wait); err != nil {
			return "", nil, err
		}
		backoff = min(backoff*2, maxContentHold)
	}
}

// reuploadSelects reports whether cfg selects marker m.
func reuploadSelects(cfg ReuploadConfig, m contentMarker) bool {
	if cfg.Provider != "" && m.Provider != cfg.Provider {
		return false
	}
	if cfg.IDs[m.NativeSessionID] && m.NativeSessionID != "" {
		return true
	}
	if cfg.Before.IsZero() {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, m.UploadedAt)
	return err == nil && at.Before(cfg.Before)
}

// loadAllMarkers reads every valid content marker in dir, in (device, inode) order.
func loadAllMarkers(dir string) ([]contentMarker, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "content-marker-*.json"))
	if err != nil {
		return nil, err
	}
	var out []contentMarker
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var m contentMarker
		if json.Unmarshal(data, &m) != nil || m.ContentSHA256 == "" ||
			(m.Version != contentMarkerVersion && m.Version != legacyContentMarkerVersion) ||
			filepath.Base(p) != filepath.Base(contentMarkerPath(dir, m.Device, m.Inode)) {
			continue
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b contentMarker) int {
		if a.Device != b.Device {
			return compareUint(a.Device, b.Device)
		}
		return compareUint(a.Inode, b.Inode)
	})
	return out, nil
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// loadReuploadProgress reads the progress journal's settled identities. A missing journal is empty;
// a torn last line (a crash mid-append) is ignored.
func loadReuploadProgress(path string) (map[transcriptIdentity]bool, error) {
	done := map[transcriptIdentity]bool{}
	if path == "" {
		return done, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return done, nil
	}
	if err != nil {
		return nil, fmt.Errorf("content re-upload: open progress file: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var p reuploadProgress
		if json.Unmarshal(sc.Bytes(), &p) == nil && p.Outcome != "" {
			done[transcriptIdentity{device: p.Device, inode: p.Inode}] = true
		}
	}
	return done, sc.Err()
}

// indexedTranscript is one .jsonl file found under a root.
type indexedTranscript struct{ root, locator, path string }

// indexTranscripts maps the (device, inode) of every regular .jsonl file under roots to its location.
// It never follows a symlink (WalkDir does not, and a symlink's own Lstat is not a regular file).
func indexTranscripts(roots []string) (map[transcriptIdentity]indexedTranscript, error) {
	out := map[transcriptIdentity]indexedTranscript{}
	for _, root := range roots {
		root = filepath.Clean(root)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root {
					return err
				}
				return nil // an unreadable subtree is skipped, not fatal
			}
			if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".jsonl") {
				return nil
			}
			info, err := os.Lstat(p)
			if err != nil {
				return nil
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			out[transcriptIdentity{device: uint64(st.Dev), inode: uint64(st.Ino)}] = indexedTranscript{root: root, locator: rel, path: p}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("content re-upload: walk %s: %w", root, err)
		}
	}
	return out, nil
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
