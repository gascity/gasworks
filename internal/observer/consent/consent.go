// Package consent applies the companion's owner-supplied consent policy while the daemon runs.
//
// The policy is the root policy document (package rootpolicy): which transcript roots the owner
// consented to, at which generation, and — from schema v3 on — whether whole-transcript content may
// be uploaded. A Source re-reads that file whenever a caller asks for the current policy and the
// file changed since it was last read: one lstat per call, and a re-read only when the file's
// identity, size, or modification time moved. The daemon asks before every content upload, before
// every observation batch, and before every transcript poll, so a consent change written while the
// daemon runs takes effect at its next check instead of at its next restart.
//
// The Source fails closed. A policy file that cannot be read or does not validate withdraws content
// upload at once and keeps it withdrawn until a valid document is written; transcript metadata
// capture continues under the last valid document, which the owner did consent to — narrowed by the
// invalid document when it can still be decoded: a root it no longer lists as active at the same
// generation is withdrawn, while nothing it adds is granted. Each change — including each
// fail-closed transition and each recovery — is logged as one line.
//
// Writers must replace the file atomically (write a temporary file in the same directory, then
// rename it over the policy) so the daemon never reads a half-written document; a torn document
// fails validation and is treated as unreadable.
package consent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gascity/gasworks/internal/observer/rootpolicy"
)

// Config configures a Source.
type Config struct {
	// Path is the absolute root policy file (required).
	Path string
	// ContentDefault is the content-upload consent of a document that states none (schema v1 or
	// v2): the daemon's -content-upload flag, whose default is OBSERVER_CONTENT_UPLOAD. A v3
	// document's content_upload always decides instead.
	ContentDefault bool
	// Capturable selects the records the daemon can act on; nil admits every record. A record it
	// rejects never reaches the watcher and is absent from every Policy's Roots.
	Capturable func(rootpolicy.Record) bool
	// Log receives one line per applied change and per fail-closed transition; nil discards them.
	Log func(string)
}

// Policy is one effective consent decision.
type Policy struct {
	// Version increases every time the effective policy changes, including a fail-closed transition
	// and a recovery, so a caller that remembers the version it acted on can tell it is stale.
	Version uint64
	// ContentUpload is the effective whole-transcript content-upload consent. It is false whenever
	// the policy file is unusable.
	ContentUpload bool
	// Roots are the capturable consent records of the last valid document, tombstones included, in
	// document order.
	Roots []rootpolicy.Record
	// Problem is empty while the policy file is valid. Otherwise it says why the file cannot be
	// applied: content upload is then withdrawn and Roots still describe the last valid document.
	Problem string
}

// Valid reports whether the policy file was readable and valid at the last check.
func (p Policy) Valid() bool { return p.Problem == "" }

// Allows reports whether root is an active consent root at exactly generation. A generation is one
// consent interval: re-registering a root mints a new one, so evidence captured under an earlier
// generation is not covered by the current consent even though the path is active again.
func (p Policy) Allows(root string, generation uint64) bool {
	for _, r := range p.Roots {
		if r.Path == root {
			return r.Active && r.Generation == generation
		}
	}
	return false
}

// Source is the live consent policy. It is safe for concurrent use.
type Source struct {
	cfg Config

	// mu serializes checks (the stat, any re-read, and publication) and guards loaded and subs.
	mu     sync.Mutex
	loaded fileState // the file the current valid policy was read from
	subs   []func()
	// cur is the published policy. Latest reads it without taking mu, so the per-append hot path
	// never waits behind a check that is reading the file.
	cur atomic.Pointer[Policy]
}

// Open reads the policy file and returns a Source serving it. It fails on an unusable file: a
// daemon must not start capturing under a consent policy it cannot read. Once open, a later
// unusable file never fails anything — it withdraws content upload instead (see Current).
func Open(cfg Config) (*Source, error) {
	if cfg.Path == "" || !filepath.IsAbs(cfg.Path) {
		return nil, errors.New("consent policy path must be absolute")
	}
	if cfg.Capturable == nil {
		cfg.Capturable = func(rootpolicy.Record) bool { return true }
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	// Stat before reading: a replacement racing the read is then seen as a change on the next check
	// and re-read, never mistaken for the document already loaded.
	st, err := statFile(cfg.Path)
	if err != nil {
		return nil, err
	}
	doc, err := rootpolicy.LoadPolicy(cfg.Path)
	if err != nil {
		return nil, err
	}
	s := &Source{cfg: cfg, loaded: st}
	first := s.derive(doc)
	first.Version = 1
	s.cur.Store(&first)
	cfg.Log(fmt.Sprintf("consent policy %s loaded: content upload %s; %s", cfg.Path, s.contentState(first, doc), describeRoots(first.Roots)))
	return s, nil
}

// Current returns the effective policy after checking the file: one lstat, and a re-read when the
// file changed or the last read failed. A file that cannot be read or does not validate yields a
// fail-closed policy (no content upload; the last valid roots, narrowed by the document when it can
// still be decoded) and is logged once per distinct problem. Subscribers run after a change is
// published, outside the Source's lock, on the calling goroutine.
func (s *Source) Current() Policy {
	s.mu.Lock()
	prev := *s.cur.Load()
	st, statErr := statFile(s.cfg.Path)
	if statErr == nil && prev.Valid() && st.equal(s.loaded) {
		s.mu.Unlock()
		return prev
	}
	var next Policy
	var doc rootpolicy.Policy
	if statErr != nil {
		next = s.failClosed(prev, statErr)
	} else if d, err := rootpolicy.LoadPolicy(s.cfg.Path); err != nil {
		next = s.failClosed(prev, err)
	} else {
		doc = d
		next = s.derive(d)
		s.loaded = st
	}
	if samePolicy(prev, next) {
		s.mu.Unlock()
		return prev
	}
	next.Version = prev.Version + 1
	s.cur.Store(&next)
	// Logged under the lock so concurrent checks report changes in the order they were published.
	s.cfg.Log(s.describeChange(prev, next, doc))
	subs := append([]func(){}, s.subs...)
	s.mu.Unlock()

	for _, fn := range subs {
		fn()
	}
	return next
}

// Latest returns the policy as of the last check without touching the file. It is for hot paths
// that run between checks (each durable append), which must still honor a change some other caller
// has already observed.
func (s *Source) Latest() Policy {
	return *s.cur.Load()
}

// Subscribe registers fn to run after every published change. It runs on the goroutine whose check
// observed the change, after the Source's lock is released; it reads the change through Latest
// (two checks racing can deliver their notifications out of order, but Latest is always the newest
// policy) and must not block.
func (s *Source) Subscribe(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs = append(s.subs, fn)
}

// derive turns a valid document into the effective policy.
func (s *Source) derive(doc rootpolicy.Policy) Policy {
	content := s.cfg.ContentDefault
	switch doc.Content {
	case rootpolicy.ContentGranted:
		content = true
	case rootpolicy.ContentDenied:
		content = false
	}
	roots := make([]rootpolicy.Record, 0, len(doc.Roots))
	for _, r := range doc.Roots {
		if s.cfg.Capturable(r) {
			roots = append(roots, r)
		}
	}
	return Policy{ContentUpload: content, Roots: roots}
}

// failClosed is the policy an unusable file yields: content withdrawn, and metadata capture kept
// under the last valid roots — minus any root the document, if it can still be decoded, no longer
// lists as active at the same generation. An unusable document can withdraw consent; it never
// grants any.
func (s *Source) failClosed(prev Policy, err error) Policy {
	roots := prev.Roots
	if records, derr := rootpolicy.DecodeFileRecords(s.cfg.Path); derr == nil {
		roots = narrowRoots(prev.Roots, records)
	}
	return Policy{ContentUpload: false, Roots: roots, Problem: err.Error()}
}

// narrowRoots keeps every tombstone in prev and every active record the document still lists as
// active at the same generation; every other active record is withdrawn.
func narrowRoots(prev, doc []rootpolicy.Record) []rootpolicy.Record {
	still := make(map[string]uint64, len(doc))
	for _, r := range doc {
		if r.Active {
			still[r.Path] = r.Generation
		}
	}
	out := make([]rootpolicy.Record, 0, len(prev))
	for _, r := range prev {
		if r.Active {
			if gen, ok := still[r.Path]; !ok || gen != r.Generation {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// contentState names the effective content consent and where it came from.
func (s *Source) contentState(p Policy, doc rootpolicy.Policy) string {
	state := onOff(p.ContentUpload)
	if doc.Content == rootpolicy.ContentUnstated {
		return state + " (-content-upload; the policy does not state content consent)"
	}
	return state + " (stated by the policy)"
}

// describeChange renders one applied change as a single log line.
func (s *Source) describeChange(prev, next Policy, doc rootpolicy.Policy) string {
	if !next.Valid() {
		line := fmt.Sprintf("consent policy %s cannot be applied: %s; content upload is withdrawn (fail closed) until a valid policy is written, and transcript capture continues under the last valid policy (%s)",
			s.cfg.Path, next.Problem, describeRoots(next.Roots))
		if changes := describeRootChanges(prev.Roots, next.Roots); len(changes) > 0 {
			line += "; the unusable document still " + strings.Join(changes, "; ")
		}
		return line
	}
	parts := []string{"content upload " + s.contentState(next, doc)}
	if !prev.Valid() {
		parts = append(parts, "the policy file is valid again")
	}
	parts = append(parts, describeRootChanges(prev.Roots, next.Roots)...)
	parts = append(parts, describeRoots(next.Roots))
	return fmt.Sprintf("consent policy %s applied (version %d): %s", s.cfg.Path, next.Version, strings.Join(parts, "; "))
}

// describeRoots summarizes a record set.
func describeRoots(records []rootpolicy.Record) string {
	active := 0
	for _, r := range records {
		if r.Active {
			active++
		}
	}
	return fmt.Sprintf("%d consented roots, %d withdrawn", active, len(records)-active)
}

// describeRootChanges lists every root whose consent changed between two record sets.
func describeRootChanges(prev, next []rootpolicy.Record) []string {
	before := activeByPath(prev)
	after := activeByPath(next)
	var out []string
	for _, path := range sortedKeys(before) {
		was := before[path]
		now, ok := after[path]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("withdrew %s (generation %d)", path, was.Generation))
		case now.Generation != was.Generation:
			out = append(out, fmt.Sprintf("re-registered %s (generation %d -> %d, %s)", path, was.Generation, now.Generation, now.Mode))
		}
	}
	for _, path := range sortedKeys(after) {
		if _, ok := before[path]; !ok {
			now := after[path]
			out = append(out, fmt.Sprintf("consented %s (generation %d, %s)", path, now.Generation, now.Mode))
		}
	}
	return out
}

func activeByPath(records []rootpolicy.Record) map[string]rootpolicy.Record {
	out := make(map[string]rootpolicy.Record, len(records))
	for _, r := range records {
		if r.Active {
			out[r.Path] = r
		}
	}
	return out
}

func sortedKeys(m map[string]rootpolicy.Record) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// samePolicy reports whether two policies are the same effective decision. Record order is not part
// of the decision.
func samePolicy(a, b Policy) bool {
	if a.ContentUpload != b.ContentUpload || a.Problem != b.Problem || len(a.Roots) != len(b.Roots) {
		return false
	}
	byPath := make(map[string]rootpolicy.Record, len(a.Roots))
	for _, r := range a.Roots {
		byPath[r.Path] = r
	}
	for _, r := range b.Roots {
		if prev, ok := byPath[r.Path]; !ok || prev != r {
			return false
		}
	}
	return true
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// fileState identifies one observed version of the policy file.
type fileState struct {
	info  fs.FileInfo
	stamp changeStamp
}

// equal reports whether two observations are the same version of the file: the same file object
// (an atomic replace is always a change) with the same size and modification time (an in-place
// rewrite), the same mode (a chmod can make the file no longer owner-only, which the policy loader
// refuses), and — where the platform reports them — the same change time and owner (an in-place
// copy that preserved the modification time, or a chown).
func (s fileState) equal(o fileState) bool {
	if s.info == nil || o.info == nil {
		return false
	}
	return os.SameFile(s.info, o.info) && s.info.Size() == o.info.Size() &&
		s.info.ModTime().Equal(o.info.ModTime()) && s.info.Mode() == o.info.Mode() && s.stamp == o.stamp
}

func statFile(path string) (fileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileState{}, fmt.Errorf("stat consent policy: %w", err)
	}
	return fileState{info: info, stamp: changeStampOf(info)}, nil
}
