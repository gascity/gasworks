//go:build linux || darwin

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/consent"
)

// Pending content.
//
// A transcript's content is owed to the collector from the moment the uploader has a session to key
// it by until the collector accepts it. All of that is in memory except one fact a restart cannot
// recover: the session. The watcher's cursor resumes where the previous run stopped parsing, so a
// transcript that run consumed to its end is never parsed again, and only a transcript uploaded at
// least once has a marker naming its session. Without more, content owed but never accepted —
// refused by the collector, shed, or still settling when the daemon stopped — would be lost to a
// restart.
//
// A pending record keeps it: one small owner-only file per such transcript, written by the content
// loop the first time its content is owed under a session no marker records — at each plan, after
// each upload, and once more as the daemon stops — naming that session and the consent the content
// was queued under. After a restart the record keys the transcript's content once the watcher
// observes it again, under that same consent and name. The record is deleted when the collector
// accepts the content or rejects it for good, and when the watcher drops the transcript; and —
// consent wins over retry — as soon as the live consent policy no longer covers the content, at the
// start of a run whose policy no longer does, and at the start of a run with -content-upload off
// (DiscardQueuedContent). There is at most one record per transcript with content owed; like a
// marker or a cursor, a record whose transcript is deleted while the daemon is stopped stays until
// its identity is reused or the state dir is cleaned. A record holds metadata only (a session id, a
// provider, a consent root and generation, a name, a size and a time), never transcript content.

// contentPendingVersion is the pending record's on-disk schema version.
const contentPendingVersion = 1

// Pending record file names: the record of one identity, and the temporary file a write renames over
// it (swept at startup, like the marker's).
const (
	contentPendingPrefix     = "content-pending-"
	contentPendingTempPrefix = ".tmp-content-pending-"
)

// contentPending is the durable pending record of one transcript.
type contentPending struct {
	Version         int    `json:"version"`
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	NativeSessionID string `json:"native_session_id"`
	Provider        string `json:"provider"`
	// ConsentRoot / ConsentGeneration are the consent the content was queued under; both are empty
	// under the static configuration (no live consent policy).
	ConsentRoot       string `json:"consent_root,omitempty"`
	ConsentGeneration uint64 `json:"consent_generation,omitempty"`
	// Locator is the transcript's path below its root. Providers name a transcript after its
	// session, so a file that reused the identity after the transcript was deleted while the daemon
	// was stopped has another name, and the record never keys it.
	Locator string `json:"locator"`
	// Size / ModNanos are the transcript's stat when the record was written. A transcript only grows,
	// so a file smaller or older than that is not the one the record names either.
	Size     int64  `json:"observed_size"`
	ModNanos int64  `json:"observed_mtime_nanos"`
	QueuedAt string `json:"queued_at"`
}

// origin is the consent the content was queued under.
func (p contentPending) origin() consentOrigin {
	return consentOrigin{root: p.ConsentRoot, generation: p.ConsentGeneration}
}

// contentPendingName is the pending record's file name for one identity, beside the identity's marker
// in the content state dir.
func contentPendingName(dev, ino uint64) string {
	return fmt.Sprintf("%s%d-%d.json", contentPendingPrefix, dev, ino)
}

// readContentPending reads and validates one pending record, reporting ok=false for an absent,
// unreadable, malformed, or foreign-version record.
func readContentPending(path string) (contentPending, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contentPending{}, false
	}
	var p contentPending
	if err := json.Unmarshal(data, &p); err != nil {
		return contentPending{}, false
	}
	if p.Version != contentPendingVersion || p.NativeSessionID == "" || p.Provider == "" {
		return contentPending{}, false
	}
	return p, true
}

// ensurePendingLoadedLocked looks for the transcript's pending record the first time its content is
// owed. The record keys the transcript only when it was written for this same file — same name, and
// no larger or newer than the file is now — under the consent the transcript is observed under now;
// any other record is left to be replaced, swept, or deleted with the transcript. Called under u.mu.
func (u *contentUploader) ensurePendingLoadedLocked(id transcriptIdentity, st *contentState) {
	if st.pendingLoaded {
		return
	}
	st.pendingLoaded = true
	p, ok := readContentPending(filepath.Join(u.stateDir, contentPendingName(id.device, id.inode)))
	if !ok || p.Device != id.device || p.Inode != id.inode || !p.names(st) || st.size < p.Size || st.modNanos < p.ModNanos {
		return
	}
	st.pending = &p
}

// names reports whether the record was written for the transcript as st observes it now: under the
// same consent, at the same name.
func (p contentPending) names(st *contentState) bool {
	return p.origin() == st.origin && p.Locator == st.locator
}

// pendingRecord returns the record a transcript whose content is now owed under native/provider
// needs, or ok=false when a restart could already key it: by its marker (an accepted upload of the
// same session) or by the record it has. Called under u.mu.
func (st *contentState) pendingRecord(id transcriptIdentity, native, provider string, now time.Time) (rec contentPending, ok bool) {
	if st.uploaded && st.markerNative == native && st.markerProvider == provider {
		return contentPending{}, false
	}
	if p := st.pending; p != nil && p.NativeSessionID == native && p.Provider == provider && p.names(st) {
		return contentPending{}, false
	}
	return contentPending{
		Version:           contentPendingVersion,
		Device:            id.device,
		Inode:             id.inode,
		NativeSessionID:   native,
		Provider:          provider,
		ConsentRoot:       st.origin.root,
		ConsentGeneration: st.origin.generation,
		Locator:           st.locator,
		Size:              st.size,
		ModNanos:          st.modNanos,
		QueuedAt:          now.UTC().Format(time.RFC3339Nano),
	}, true
}

// pendingSave is one pending record a tick found owed.
type pendingSave struct {
	id      transcriptIdentity
	st      *contentState
	locator string
	rec     contentPending
}

// savePending writes the pending records a plan found owed. It runs outside u.mu, so the watcher's
// observations never wait on the disk.
func (u *contentUploader) savePending(saves []pendingSave) {
	for _, s := range saves {
		u.savePendingRecord(s)
	}
}

// savePendingRecord writes one pending record under pendingMu, which a consent narrowing's sweep also
// takes, and only while its transcript is still tracked and its content still consented: no record
// outlives a narrowing that already dropped its content. A failed write is retried by the next plan.
func (u *contentUploader) savePendingRecord(s pendingSave) {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	u.mu.Lock()
	current := u.files[s.id] == s.st && u.allowedLocked(s.st.origin)
	u.mu.Unlock()
	if !current {
		return
	}
	data, err := json.Marshal(s.rec)
	if err == nil {
		err = writeStateFile(u.stateDir, contentPendingName(s.id.device, s.id.inode), contentPendingTempPrefix, data)
	}
	u.mu.Lock()
	tracked := u.files[s.id] == s.st
	logIt := err != nil && tracked && !s.st.pendingWriteLogged
	if tracked {
		// Each transcript's failure streak is reported once, whatever other records do meanwhile.
		s.st.pendingWriteLogged = err != nil
		if err == nil {
			rec := s.rec
			s.st.pending = &rec
		}
	}
	u.mu.Unlock()
	if logIt {
		u.logf("content upload: record the queued content of %s: %v (retried every tick; not logged again until it succeeds)", s.locator, err)
	}
}

// dropPending deletes a transcript's pending record: its content was accepted or rejected for good,
// or the watcher dropped the transcript.
func (u *contentUploader) dropPending(id transcriptIdentity) {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	err := os.Remove(filepath.Join(u.stateDir, contentPendingName(id.device, id.inode)))
	switch {
	case err == nil:
		u.pendingDeleteFailing = false
	case errors.Is(err, os.ErrNotExist):
		// There was none: that says nothing about the disk.
	case !u.pendingDeleteFailing:
		u.pendingDeleteFailing = true
		u.logf("content upload: delete a pending record: %v (not logged again until a delete succeeds)", err)
	}
}

// pendingConsented reports whether content queued under origin may still be sent by this uploader:
// under a live consent policy, while the policy still consents to it; under the static configuration,
// when it was queued under the static configuration too.
func (u *contentUploader) pendingConsented(origin consentOrigin) bool {
	return pendingConsentedBy(u.consent, origin)
}

// pendingConsentedBy reports whether content queued under origin is still consented: under the live
// consent policy src, while src still consents to it; under the static configuration (src nil), when
// it was queued under the static configuration too.
func pendingConsentedBy(src *consent.Source, origin consentOrigin) bool {
	if src == nil {
		return origin == (consentOrigin{})
	}
	return origin != (consentOrigin{}) && contentAllowedBy(src.Latest(), origin)
}

// followQueuedContentConsent applies the live consent policy src to the content an earlier run queued
// in stateDir, for a run without a content channel: nothing here uploads content, yet what the policy
// no longer consents to — at start, or at any change during the run — is discarded, so a later run
// with a collector cannot send it.
func followQueuedContentConsent(src *consent.Source, stateDir string, log func(string)) {
	sweep := func() {
		if _, err := sweepContentPending(stateDir, func(o consentOrigin) bool { return pendingConsentedBy(src, o) }); err != nil && log != nil {
			log(fmt.Sprintf("content upload: discard content queued under withdrawn consent: %v", err))
		}
	}
	sweep()
	src.Subscribe(sweep)
}

// sweepPending deletes every pending record whose content the consent policy no longer covers. It
// takes pendingMu, so a record being written as the policy narrows is either on disk before the sweep
// reads the directory or refused by its own consent check.
func (u *contentUploader) sweepPending() {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	if _, err := sweepContentPending(u.stateDir, u.pendingConsented); err != nil {
		u.logf("content upload: discard content queued under withdrawn consent: %v", err)
	}
}

// sweepContentPending deletes the pending records in stateDir that keep rejects, and any it cannot
// read, returning how many it deleted. An absent state dir holds none.
func sweepContentPending(stateDir string, keep func(consentOrigin) bool) (int, error) {
	entries, err := os.ReadDir(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", stateDir, err)
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, contentPendingPrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(stateDir, name)
		if p, ok := readContentPending(path); ok && keep(p.origin()) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("delete %s: %w", name, err)
		}
		removed++
	}
	return removed, nil
}

// DiscardQueuedContent deletes the content an earlier run queued for upload and never had accepted,
// in the content state dir stateDir (the watcher's cursor dir unless ContentUploadLoopConfig.StateDir
// says otherwise), and returns how many transcripts' queued content it discarded. A daemon started
// with -content-upload off calls it: switching content upload off withdraws consent for that queue,
// so a later run that uploads content again must not send it.
func DiscardQueuedContent(stateDir string) (int, error) {
	return sweepContentPending(stateDir, func(consentOrigin) bool { return false })
}

// writeStateFile atomically replaces dir/name with data, owner-only: a temporary file named with
// tmpPrefix (which startup sweeps) is written, closed, then renamed over the target. Like the rest of
// the content channel's bookkeeping it is not fsynced: a crash at worst loses one record.
func writeStateFile(dir, name, tmpPrefix string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(step string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%s: %w", step, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail("chmod temp", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write temp", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
