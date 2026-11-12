// Package operatorfile loads the bd-login operator file and hot-reloads it (S10 M3; gasworks-platform
// attribution.md r2 §2.1).
//
// bd writes, per org, which principal it is logged in as: a small non-secret JSON file
// (schema bd.operator/v1: org_id, principal_id, principal_class, principal_since, written_at, and
// logged_out_at after a logout). The Companion reads the file for its org and stamps the principal on
// the sessions it reports, so the observer can name each run's human. The file is never uploaded.
//
// Reload is poll-based and lazy, like the bead prefix map: Current re-stats the file at most once per
// check interval and re-reads it only when it was replaced or rewritten. Unlike the prefix map, the
// operator is a claim about now, so it never outlives its file: a removed, unreadable or malformed
// file reads as no report (the run's human is then simply not reported), never as the last good
// principal. A malformed file is logged content-free (its path and the failing check, never a value
// from it) once per distinct file state.
package operatorfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Schema is the file's schema tag.
const Schema = "bd.operator/v1"

// MaxFileBytes bounds the file read; a larger file is malformed.
const MaxFileBytes = 4 << 10

// maxPrincipalBytes is the observer contract's principal_id maxLength.
const maxPrincipalBytes = 64

// Principal classes the file carries.
const (
	ClassUser    = "USER"
	ClassService = "SERVICE"
)

var principalPattern = regexp.MustCompile(`^(usr|sp)_[A-Za-z0-9_-]+$`)

// Snapshot is one valid reading of the file. PrincipalID is "" after a logout.
type Snapshot struct {
	PrincipalID    string
	PrincipalClass string
	// PrincipalSince is when bd first recorded this principal; zero when the file names none.
	PrincipalSince time.Time
}

// LoggedOut reports whether the file records a logout (no principal).
func (s Snapshot) LoggedOut() bool { return s.PrincipalID == "" }

// Config configures a File.
type Config struct {
	// Path is the operator file (required, absolute).
	Path string
	// CheckInterval is the minimum spacing between file stats; <=0 stats on every Current call.
	CheckInterval time.Duration
	// Log receives content-free load status lines (nil discards them).
	Log func(string)
	// Now is the clock (nil uses time.Now).
	Now func() time.Time
}

// File is a hot-reloading operator file. It is safe for concurrent use.
type File struct {
	cfg Config

	mu        sync.Mutex
	current   *Snapshot
	state     fs.FileInfo // the file state current (or the last failure) was read from; nil when absent
	failedMsg string
	lastCheck time.Time
}

// Open arms the operator file and performs the initial load. It fails only on a configuration error
// (an empty or relative path): the file's absence or content never fails startup, because a daemon
// that refuses to start stops all transcript capture.
func Open(cfg Config) (*File, error) {
	if cfg.Path == "" || !filepath.IsAbs(cfg.Path) {
		return nil, errors.New("operator file path must be absolute")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	f := &File{cfg: cfg}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastCheck = cfg.Now()
	f.refreshLocked()
	return f, nil
}

// Current returns the file's current reading, first re-reading it when the check interval has
// elapsed and the file changed. ok is false when there is no valid file.
func (f *File) Current() (Snapshot, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.cfg.Now()
	if f.cfg.CheckInterval <= 0 || f.lastCheck.IsZero() || now.Sub(f.lastCheck) >= f.cfg.CheckInterval {
		f.lastCheck = now
		f.refreshLocked()
	}
	if f.current == nil {
		return Snapshot{}, false
	}
	return *f.current, true
}

func (f *File) refreshLocked() {
	info, err := os.Stat(f.cfg.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if f.current != nil {
			f.cfg.Log(fmt.Sprintf("operator file %s removed; sessions report no operator until bd writes it", f.cfg.Path))
		}
		f.current, f.state, f.failedMsg = nil, nil, ""
		return
	case err != nil:
		f.failLocked(nil, "stat failed")
		return
	case !info.Mode().IsRegular():
		f.failLocked(info, "not a regular file")
		return
	}
	if f.state != nil && sameState(f.state, info) {
		return
	}
	snap, why := load(f.cfg.Path)
	if why != "" {
		f.failLocked(info, why)
		return
	}
	f.current, f.state, f.failedMsg = &snap, info, ""
	who := "a principal"
	if snap.LoggedOut() {
		who = "a logout"
	}
	f.cfg.Log(fmt.Sprintf("operator file %s loaded: %s", f.cfg.Path, who))
}

// failLocked drops the current reading and logs the failure once per distinct (state, reason).
func (f *File) failLocked(info fs.FileInfo, why string) {
	f.current = nil
	if f.failedMsg == why && ((info == nil && f.state == nil) || (info != nil && f.state != nil && sameState(f.state, info))) {
		return
	}
	f.state, f.failedMsg = info, why
	f.cfg.Log(fmt.Sprintf("operator file %s not loaded: %s; sessions report no operator until it is valid", f.cfg.Path, why))
}

func sameState(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// fileBody is the file's JSON shape. Unknown members are ignored: bd may add some.
type fileBody struct {
	Schema         string `json:"schema"`
	OrgID          string `json:"org_id"`
	PrincipalID    string `json:"principal_id"`
	PrincipalClass string `json:"principal_class"`
	PrincipalSince string `json:"principal_since"`
	LoggedOutAt    string `json:"logged_out_at"`
}

// load reads and validates the file, returning the reading or a content-free reason it is invalid.
func load(path string) (Snapshot, string) {
	fh, err := os.Open(path)
	if err != nil {
		return Snapshot{}, "open failed"
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return Snapshot{}, "read failed"
	}
	if len(data) > MaxFileBytes {
		return Snapshot{}, "file too large"
	}
	var b fileBody
	if err := json.Unmarshal(data, &b); err != nil {
		return Snapshot{}, "not a JSON object"
	}
	return parse(b)
}

// parse validates a decoded file body: the schema, the principal's shape and class, and the
// principal_since time.
func parse(b fileBody) (Snapshot, string) {
	if b.Schema != Schema {
		return Snapshot{}, "unknown schema"
	}
	if b.PrincipalID == "" {
		if b.PrincipalClass != "" {
			return Snapshot{}, "principal_class without a principal"
		}
		return Snapshot{}, ""
	}
	if len(b.PrincipalID) > maxPrincipalBytes || !principalPattern.MatchString(b.PrincipalID) {
		return Snapshot{}, "principal_id is not an Accounts principal id"
	}
	want := ClassUser
	if strings.HasPrefix(b.PrincipalID, "sp_") {
		want = ClassService
	}
	if b.PrincipalClass != want {
		return Snapshot{}, "principal_class does not match the principal"
	}
	since, err := time.Parse(time.RFC3339, b.PrincipalSince)
	if err != nil {
		return Snapshot{}, "principal_since is not an RFC 3339 time"
	}
	return Snapshot{PrincipalID: b.PrincipalID, PrincipalClass: b.PrincipalClass, PrincipalSince: since.UTC()}, ""
}
