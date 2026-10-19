//go:build linux || darwin

package daemon

import (
	"net/http"
	"os"
	"syscall"
	"time"
)

// contentRefusalBackoff is how long content upload waits after the collector first refuses it. Each
// further refusal doubles the wait, up to maxContentHold.
const contentRefusalBackoff = 15 * time.Second

// contentRefusal is the back-off content upload is in while the collector refuses it: 401/403 (the
// credential) or 404/501 (content upload not provisioned, or disabled, for this source). None of
// these is permanent — an operator renews the credential, the collector is provisioned — so the
// uploader keeps every queued transcript and retries: once the back-off has passed, or at once when
// the token file the collector client reads its credential from is renewed (holds a usable credential
// other than the one refused). A refusal says nothing about the snapshot it was sent with, so it never
// counts against that snapshot. The first upload the collector accepts, or judges on its bytes, ends
// it.
type contentRefusal struct {
	// status is the HTTP status of the latest refusal.
	status int
	// backoff is the wait the latest refusal armed, and retryAt when it ends.
	backoff time.Duration
	retryAt time.Time
	// token is the token file as it was when the latest refused request was sent. A different usable
	// version is a renewed (or rotated) credential, which is retried without waiting.
	token tokenFileVersion
}

// isContentRefusal reports whether a content-upload status refuses content upload itself rather than
// the snapshot sent: the credential (401/403), or a collector without content upload for this source
// (404/501).
func isContentRefusal(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

// holds reports whether the refusal still holds content upload at now, given the token file's current
// version: its back-off has not passed, and the token file holds no renewed credential — it is the
// one that was refused, or it is not usable at all (missing, empty, or unreadable, as it can be in the
// middle of a rotation), which is no renewal.
func (r *contentRefusal) holds(now time.Time, token tokenFileVersion) bool {
	return now.Before(r.retryAt) && (!token.usable() || token.equal(r.token))
}

// tokenFileVersion identifies one version of the token file: its identity (device and inode), size,
// and modification time. Comparing versions is how the content channel notices a renewed credential
// without ever reading the secret. The zero value stands for no usable token file.
type tokenFileVersion struct {
	info os.FileInfo
}

// statTokenFile returns the token file's current version, or the zero version when it holds no
// usable credential: no token file configured, or one that is missing, not a regular file, empty, or
// unreadable. It opens the file without reading it — non-blocking, so a FIFO in its place cannot hang
// the content loop — and follows a symlink, as reading the token does: a credential mounted behind a
// link is renewed by swapping the link's target.
func statTokenFile(path string) tokenFileVersion {
	if path == "" {
		return tokenFileVersion{}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return tokenFileVersion{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return tokenFileVersion{}
	}
	return tokenFileVersion{info: info}
}

// usable reports whether the version is of a token file that holds a credential to send.
func (v tokenFileVersion) usable() bool { return v.info != nil }

// equal reports whether two versions are the same file with the same size and modification time. Two
// zero versions are equal: a token file that was missing and still is has not been renewed.
func (v tokenFileVersion) equal(o tokenFileVersion) bool {
	if v.info == nil || o.info == nil {
		return v.info == nil && o.info == nil
	}
	return os.SameFile(v.info, o.info) && v.info.Size() == o.info.Size() && v.info.ModTime().Equal(o.info.ModTime())
}

// postingHeld reports whether content upload is held at now: by a shed or a transient failure
// (holdUntil), or by a collector refusal that still holds. Planning a tick is never held — only the
// reads and POSTs are — so content first queued during a hold is still recorded as pending.
func (u *contentUploader) postingHeld(now time.Time) bool {
	token := statTokenFile(u.tokenFile)
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.holdUntil.IsZero() && now.Before(u.holdUntil) {
		return true
	}
	return u.refusal != nil && u.refusal.holds(now, token)
}

// recordRefusalLocked arms the refusal back-off after the collector refused an upload sent with the
// token file at version token: contentRefusalBackoff for the first refusal, doubled by each refusal
// after it up to maxContentHold. It returns the wait, and whether this refusal is a transition worth
// one log line: the first refusal, a different refusing status, or a renewed credential refused as
// well. Called under u.mu.
func (u *contentUploader) recordRefusalLocked(status int, now time.Time, token tokenFileVersion) (wait time.Duration, transition bool) {
	r := u.refusal
	if r == nil {
		r = &contentRefusal{backoff: contentRefusalBackoff}
		u.refusal = r
		transition = true
	} else {
		transition = r.status != status || !r.token.equal(token)
		r.backoff = min(2*r.backoff, maxContentHold)
	}
	r.status, r.token, r.retryAt = status, token, now.Add(r.backoff)
	return r.backoff, transition
}

// acceptedLocked ends a refusal once the collector accepts an upload again, reporting whether one was
// in force, so the resumption is logged once. Called under u.mu.
func (u *contentUploader) acceptedLocked() (resumed bool) {
	resumed = u.refusal != nil
	u.refusal = nil
	return resumed
}

// logRefusal logs one refusal transition.
func (u *contentUploader) logRefusal(status int, server string, queued int, wait time.Duration) {
	retry := "retrying in " + wait.String()
	if u.tokenFile != "" {
		retry += ", or as soon as the token file is renewed"
	}
	u.logf("content upload: status %d%s: the collector refused content upload; keeping %d queued transcripts and %s", status, server, queued, retry)
}

// logResumed logs the end of a refusal.
func (u *contentUploader) logResumed(status int) {
	u.logf("content upload: the collector accepted content upload again (status %d); resuming", status)
}

// logTokenFile logs, once at start, which token file a refused credential is retried on, so an
// operator knows that renewing that file is enough to resume content upload.
func (u *contentUploader) logTokenFile() {
	if u.tokenFile != "" {
		u.logf("content upload: a refused credential is retried as soon as the token file %s is renewed", u.tokenFile)
	}
}
