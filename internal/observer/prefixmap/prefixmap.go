// Package prefixmap loads the companion's multi-project bead-prefix map file and hot-reloads it.
//
// The file is a JSON array of {"prefix": "<issue_prefix>-", "project_id": "<team-server project>"}
// written by bd from the team server's project list (each project's issue prefix is sealed and
// immutable). The companion uses it to capture bead ids of every listed project and to resolve each
// captured id to its project by longest-prefix match, so a session touching beads of several
// projects yields references to all of them.
//
// Reload is poll-based and lazy: Current re-stats the file at most once per check interval (the
// transcript watcher's poll cadence) and re-reads it only when its modification time or size
// changed. A file that fails to read or validate never replaces the last good map — the previous
// snapshot keeps serving and the failure is logged once per distinct file state.
package prefixmap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
	// Log receives content-free reload status lines (nil discards them).
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
	loaded    fileState // the state the current snapshot was read from
	failed    fileState // the last state that failed (log de-duplication)
	failedMsg string    // the last failure message (log de-duplication)
	lastCheck time.Time
}

// fileState identifies one observed version of the file.
type fileState struct {
	present bool
	modTime time.Time
	size    int64
}

func (s fileState) equal(o fileState) bool {
	return s.present == o.present && s.size == o.size && s.modTime.Equal(o.modTime)
}

// Open performs the initial load. A missing file is not an error (bd may write it after the daemon
// starts; capture stays off until it appears), but a present file that is unreadable or invalid is,
// so a misconfigured map fails loud at startup instead of silently capturing nothing.
func Open(cfg Config) (*File, error) {
	if cfg.Path == "" {
		return nil, errors.New("prefixmap: path is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	f := &File{cfg: cfg}
	st, err := stat(cfg.Path)
	if err != nil {
		return nil, err
	}
	f.lastCheck = cfg.Now()
	if !st.present {
		f.loaded = st
		cfg.Log(fmt.Sprintf("bead prefix map %s not present yet; bead capture idle until it appears", cfg.Path))
		return f, nil
	}
	m, err := Load(cfg.Path)
	if err != nil {
		return nil, err
	}
	f.current, f.loaded = m, st
	return f, nil
}

// Current returns the latest good snapshot, first re-reading the file when the check interval has
// elapsed and the file changed. It never returns an error: on failure the previous snapshot stays.
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
		return
	}
	if !st.present {
		// A removed file keeps the last good map: deletion is not a declaration that every
		// project went away, and the daemon's lifecycle (revoke/stop) is owned elsewhere.
		f.failLocked(st, errors.New("file removed; keeping the last loaded map"))
		return
	}
	m, err := Load(f.cfg.Path)
	if err != nil {
		f.failLocked(st, err)
		return
	}
	f.current, f.loaded, f.failed, f.failedMsg = m, st, fileState{}, ""
	f.cfg.Log(fmt.Sprintf("bead prefix map reloaded: %d prefixes", m.Len()))
}

// failLocked logs a reload failure once per distinct (file state, error). The loaded state is deliberately
// not advanced, so a half-written file is retried on the next check and picked up once complete.
func (f *File) failLocked(st fileState, err error) {
	msg := err.Error()
	if st.equal(f.failed) && msg == f.failedMsg {
		return
	}
	f.failed, f.failedMsg = st, msg
	f.cfg.Log(fmt.Sprintf("bead prefix map %s not reloaded: %v", f.cfg.Path, err))
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
		return fileState{}, fmt.Errorf("bead prefix map %s is not a regular file", path)
	}
	return fileState{present: true, modTime: info.ModTime(), size: info.Size()}, nil
}

// Load reads and validates a prefix map file.
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

// Parse decodes and validates a prefix map document: a JSON array of {prefix, project_id}. Unknown
// member names are ignored (forward-compatible additive fields); trailing data is rejected.
func Parse(data []byte) (*evidence.BeadPrefixMap, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("bead prefix map is empty (want a JSON array)")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var mappings []evidence.BeadPrefixMapping
	if err := dec.Decode(&mappings); err != nil {
		return nil, fmt.Errorf("decode bead prefix map: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode bead prefix map: trailing data after the array")
	}
	if mappings == nil {
		return nil, errors.New("bead prefix map must be a JSON array, not null")
	}
	m, err := evidence.NewBeadPrefixMap(mappings)
	if err != nil {
		return nil, err
	}
	return m, nil
}
