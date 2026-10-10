// Package prefixmap loads the companion's multi-project bead-prefix map file and hot-reloads it.
//
// The file is a JSON array of {"prefix": "<issue_prefix>-", "project_id": "<team-server project>"}
// written by bd from the team server's project list (each project's issue prefix is sealed and
// immutable). The companion uses it to capture bead ids of every listed project and to resolve each
// captured id to its project by longest-prefix match, so a session touching beads of several
// projects yields references to all of them.
//
// Reload is poll-based and lazy: Current re-stats the file at most once per check interval (the
// transcript watcher's poll cadence) and re-reads it only when the file was replaced (a different
// inode, as an atomic rename produces) or its modification time or size changed. The map is
// best-effort enrichment, so its file never stops the daemon: a missing, unreadable or invalid file
// at startup leaves bead capture idle until a valid map is written, and one that becomes unreadable,
// invalid or removed later keeps serving the last good snapshot. Each failure is logged once per
// distinct file state. Individual declarations the map cannot apply (a malformed prefix, a prefix
// declared for two projects) are skipped or left unresolved by evidence.NewBeadPrefixMap without
// rejecting the rest of the file, and are reported in the load log line.
package prefixmap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
)

// MaxFileBytes bounds the map file read; a larger file is rejected as malformed.
const MaxFileBytes = 1 << 20

// Config configures a File.
type Config struct {
	// Path is the prefix map file (required).
	Path string
	// CheckInterval is the minimum spacing between file stats; <=0 stats on every Current call.
	CheckInterval time.Duration
	// Log receives content-free load status lines (nil discards them).
	Log func(string)
	// Now is the clock (nil uses time.Now).
	Now func() time.Time
}

// File is a hot-reloading prefix map file. It is safe for concurrent use and satisfies
// codex.BeadPrefixMapSource.
type File struct {
	cfg Config

	mu        sync.Mutex
	current   *evidence.BeadPrefixMap
	loaded    fileState // the state the current snapshot was read from (absent before any load)
	failed    fileState // the last state that failed (log de-duplication)
	failedMsg string    // the last failure message (log de-duplication); "" when the last check succeeded
	lastCheck time.Time
}

// fileState identifies one observed version of the file. info is nil when the file is absent.
type fileState struct {
	info fs.FileInfo
}

func (s fileState) present() bool { return s.info != nil }

// equal reports whether two observations are the same version of the file: the same file object
// (device and inode, so an atomic replace is always a change even within one timestamp tick) with
// the same size and modification time (an in-place rewrite).
func (s fileState) equal(o fileState) bool {
	if s.info == nil || o.info == nil {
		return s.info == nil && o.info == nil
	}
	return os.SameFile(s.info, o.info) && s.info.Size() == o.info.Size() && s.info.ModTime().Equal(o.info.ModTime())
}

// Open arms the map file and performs the initial load. It fails only on a configuration error (an
// empty or relative path — a service manager's working directory is not the caller's): the file's
// absence or content never fails startup, because the map is enrichment and a daemon that refuses
// to start stops all transcript capture (under launchd/systemd it would crash-loop on a bad file bd
// wrote). A missing file is expected (bd may write it after the daemon starts); an unreadable or
// invalid one is logged and retried on every check until it is fixed.
func Open(cfg Config) (*File, error) {
	if cfg.Path == "" || !filepath.IsAbs(cfg.Path) {
		return nil, errors.New("bead prefix map path must be absolute")
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
	if f.current == nil && f.failedMsg == "" {
		cfg.Log(fmt.Sprintf("bead prefix map %s not present yet; bead capture idle until it appears", cfg.Path))
	}
	return f, nil
}

// Current returns the latest good snapshot (nil before any valid map was read), first re-reading
// the file when the check interval has elapsed and the file changed. It never returns an error: on
// failure the previous snapshot stays.
func (f *File) Current() *evidence.BeadPrefixMap {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.cfg.Now()
	if f.cfg.CheckInterval > 0 && !f.lastCheck.IsZero() && now.Sub(f.lastCheck) < f.cfg.CheckInterval {
		return f.current
	}
	f.lastCheck = now
	f.refreshLocked()
	return f.current
}

func (f *File) refreshLocked() {
	st, err := stat(f.cfg.Path)
	if err != nil {
		f.failLocked(fileState{}, err)
		return
	}
	if st.equal(f.loaded) {
		// Unchanged since the last good load (or still absent before any load). A failure seen in
		// between (e.g. a transient stat error) is over.
		f.failed, f.failedMsg = fileState{}, ""
		return
	}
	if !st.present() {
		// A removed file keeps the last good map: deletion is not a declaration that every
		// project went away, and the daemon's lifecycle (revoke/stop) is owned elsewhere.
		f.failLocked(st, errors.New("file removed"))
		return
	}
	m, err := Load(f.cfg.Path)
	if err != nil {
		f.failLocked(st, err)
		return
	}
	recovered := f.failedMsg != ""
	changed := !m.Equal(f.current) || f.current == nil
	f.loaded, f.failed, f.failedMsg = st, fileState{}, ""
	if !changed && !recovered {
		// A rewrite with identical content (bd's periodic refresh) keeps the current snapshot, so
		// the extractor's compiled pattern stays valid and the log stays quiet.
		return
	}
	if changed {
		f.current = m
	}
	msg := fmt.Sprintf("bead prefix map %s loaded: %d prefixes", f.cfg.Path, m.Len())
	if p := m.Problems(); p != "" {
		msg += "; " + p
	}
	f.cfg.Log(msg)
}

// failLocked logs a load failure once per distinct (file state, error). The loaded state is
// deliberately not advanced, so a file that failed is re-read on the next check and picked up as
// soon as it is valid.
func (f *File) failLocked(st fileState, err error) {
	msg := err.Error()
	if st.equal(f.failed) && msg == f.failedMsg {
		return
	}
	f.failed, f.failedMsg = st, msg
	keep := "bead capture idle until a valid map is written"
	if f.current != nil {
		keep = fmt.Sprintf("keeping the last loaded map (%d prefixes)", f.current.Len())
	}
	f.cfg.Log(fmt.Sprintf("bead prefix map %s not loaded: %v; %s", f.cfg.Path, err, keep))
}

func stat(path string) (fileState, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, fmt.Errorf("stat bead prefix map: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fileState{}, errors.New("not a regular file")
	}
	return fileState{info: info}, nil
}

// Load reads and parses a prefix map file.
func Load(path string) (*evidence.BeadPrefixMap, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bead prefix map: %w", err)
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bead prefix map: %w", err)
	}
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("bead prefix map exceeds %d bytes", MaxFileBytes)
	}
	return Parse(data)
}

// Parse decodes a prefix map document: a JSON array of {prefix, project_id}. The document itself
// must be well formed — exactly one JSON array of objects, nothing after it — or it is rejected
// whole (a truncated or corrupt write never applies). Within a well-formed array each declaration
// stands alone (see evidence.NewBeadPrefixMap): a malformed one is skipped and reported by
// Problems, never failing the rest. Unknown member names are ignored (forward-compatible
// additive fields).
func Parse(data []byte) (*evidence.BeadPrefixMap, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("bead prefix map is empty (want a JSON array)")
	}
	var mappings []evidence.BeadPrefixMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return nil, fmt.Errorf("decode bead prefix map: %w", err)
	}
	if mappings == nil {
		return nil, errors.New("bead prefix map must be a JSON array, not null")
	}
	return evidence.NewBeadPrefixMap(mappings)
}
