//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/consent"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/upload"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// The consent fence keeps every observation the transcript watcher captures inside the consent it
// was captured under, all the way to the collector.
//
// Capture: the watcher's sink refuses a candidate whose consent root is no longer consented at the
// generation the watcher was built for, so nothing new is appended once a withdrawal is observed.
//
// Upload: a withdrawal also reaches observations already appended to the durable spool but not yet
// uploaded. The batch lane is contiguous by sequence (the collector accepts one gap-free range and
// binds each sequence to its payload forever), so a withdrawn observation cannot simply be skipped:
// it is uploaded as a content-free CAPTURE_DIAGNOSTIC placeholder at the same sequence — "withheld"
// — and none of its own fields leave the machine. Whether a sequence is withheld is decided once and
// never revisited: a sequence already sent with its original payload is never withheld afterwards
// (that would conflict at the collector), and a withheld sequence stays withheld across restarts
// (the decision is recorded in the consent ledger before the batch carrying it is sent).
//
// Origins: the fence learns which consent each watcher append was captured under from the append
// itself (the sink records the sequence). That knowledge is in memory; a graceful shutdown records
// what is still undecided in the ledger (before its final upload drain, and kept exact by every send
// of that drain), and the next run applies it until its first send, so a withdrawal written while
// the daemon is stopped still withholds what the previous run captured but had not sent. Two kinds
// of frame carry no origin and upload as captured: what a run that crashed had queued, and an
// append whose acknowledgement never reached the sink (it timed out) — the watcher re-delivers that
// candidate, and the re-delivery is attributed. Observations appended by other local producers (the
// run wrapper, the provider hook) are not tied to a watched root and are never withheld.

// errConsentWithdrawn refuses a watcher append whose consent root is no longer consented at the
// generation the watcher was built for. The watcher does not advance past the refused candidate,
// and the daemon's next watcher pass is rebuilt without the withdrawn root.
var errConsentWithdrawn = errors.New("observer daemon: consent for this transcript root was withdrawn")

// consentLedgerFilename is the durable consent ledger beside the WAL in the state directory.
const consentLedgerFilename = "consent-ledger.json"

// consentLedgerVersion is the ledger's on-disk schema version.
const consentLedgerVersion = 1

// withheldContext is the content-free context every withheld placeholder carries.
//
// The placeholder's bytes are a cross-version contract (see withheldPlaceholder): a placeholder sent
// but not yet acknowledged is re-sent by whichever build runs next, and the collector binds a
// sequence to the first payload it received. Never change this text or the placeholder's shape
// without a ledger version that records which format each withheld sequence was sent in.
const withheldContext = "observation withheld before upload: the owner withdrew consent for the transcript root it was captured under"

// ledgerCRC is the ledger's integrity checksum table (CRC-32C, as the spool's sidecars use).
var ledgerCRC = crc32.MakeTable(crc32.Castagnoli)

// consentOrigin is the consent one watcher observation was captured under: its consent root and that
// root's consent generation at capture time.
type consentOrigin struct {
	root       string
	generation uint64
}

// allowedBy reports whether the policy still consents to observations captured under o.
func (o consentOrigin) allowedBy(p consent.Policy) bool { return p.Allows(o.root, o.generation) }

// originRun is a contiguous run of WAL sequences captured under one consent origin.
type originRun struct {
	first, last int64
	origin      consentOrigin
}

// originIndex maps the sequences the watcher appended to the consent each was captured under, as
// ascending, disjoint runs: the watcher appends one transcript's candidates back to back, so a run
// per transcript per poll keeps the index small however large the backlog grows.
type originIndex struct {
	runs []originRun
}

// record notes that seq was captured under o.
func (x *originIndex) record(seq int64, o consentOrigin) {
	x.addRun(seq, seq, o)
}

// addRun notes that every sequence in [first, last] was captured under o. Runs arrive in ascending
// order from the single watcher goroutine and from the ledger; an out-of-order run is still placed
// correctly, and a sequence already recorded keeps its origin (a sequence is assigned exactly once).
func (x *originIndex) addRun(first, last int64, o consentOrigin) {
	if last < first {
		return
	}
	n := len(x.runs)
	if n == 0 || x.runs[n-1].last < first {
		if n > 0 && x.runs[n-1].last+1 == first && x.runs[n-1].origin == o {
			x.runs[n-1].last = last
			return
		}
		x.runs = append(x.runs, originRun{first: first, last: last, origin: o})
		return
	}
	i := sort.Search(n, func(i int) bool { return x.runs[i].last >= first })
	if i < n && x.runs[i].first <= last {
		return // overlaps what is already recorded
	}
	x.runs = append(x.runs, originRun{})
	copy(x.runs[i+1:], x.runs[i:])
	x.runs[i] = originRun{first: first, last: last, origin: o}
}

// lookup returns the origin seq was captured under, if the watcher appended it.
func (x *originIndex) lookup(seq int64) (consentOrigin, bool) {
	i := sort.Search(len(x.runs), func(i int) bool { return x.runs[i].last >= seq })
	if i < len(x.runs) && x.runs[i].first <= seq {
		return x.runs[i].origin, true
	}
	return consentOrigin{}, false
}

// prune forgets every sequence at or below through.
func (x *originIndex) prune(through int64) {
	i := sort.Search(len(x.runs), func(i int) bool { return x.runs[i].last > through })
	x.runs = x.runs[i:]
	if len(x.runs) > 0 && x.runs[0].first <= through {
		x.runs[0].first = through + 1
	}
}

// seqSet is a set of sequences held as ascending, disjoint, non-adjacent inclusive ranges.
type seqSet struct {
	ranges [][2]int64
}

// add inserts [first, last] and returns how many sequences were not already present.
func (s *seqSet) add(first, last int64) int64 {
	if last < first {
		return 0
	}
	added := last - first + 1
	out := make([][2]int64, 0, len(s.ranges)+1)
	merged := [2]int64{first, last}
	for _, r := range s.ranges {
		switch {
		case r[1]+1 < merged[0]:
			out = append(out, r)
		case merged[1]+1 < r[0]:
			out = append(out, merged)
			merged = r
		default:
			lo, hi := max(r[0], first), min(r[1], last)
			if lo <= hi {
				added -= hi - lo + 1
			}
			merged = [2]int64{min(merged[0], r[0]), max(merged[1], r[1])}
		}
	}
	s.ranges = append(out, merged)
	return added
}

// contains reports whether seq is in the set.
func (s *seqSet) contains(seq int64) bool {
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i][1] >= seq })
	return i < len(s.ranges) && s.ranges[i][0] <= seq
}

// prune forgets every sequence at or below through.
func (s *seqSet) prune(through int64) {
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i][1] > through })
	s.ranges = s.ranges[i:]
	if len(s.ranges) > 0 && s.ranges[0][0] <= through {
		s.ranges[0][0] = through + 1
	}
}

// consentFence is the daemon's observation-lane consent enforcement (see the comment at the top of
// this file). The sink calls admit/recordAppend; the upload loop calls refresh, ceiling, frameStore,
// beforeSend, and acknowledged; Shutdown calls recordShutdown.
//
// A daemon started without a live policy over a state directory that has a consent ledger runs a
// passive fence (src nil). It can confirm no consent at all, so it fails closed: every sequence the
// ledger withholds is still uploaded only as its placeholder, and everything a policy run recorded
// as captured but not sent is withheld as well — dropping -root-policy-file can neither upload
// evidence whose consent it cannot check nor send a sequence twice with different payloads.
type consentFence struct {
	dir string
	src *consent.Source // nil for a passive fence
	log func(string)

	// gate orders watcher appends against the upload lane's view of the spool. An append holds it
	// shared from its consent check until its origin is recorded; the upload lane holds it exclusively
	// while it reads the durable ceiling, so every watcher frame at or below that ceiling already has
	// its origin recorded when the lane decides what to withhold.
	gate sync.RWMutex

	mu       sync.Mutex
	origins  originIndex
	withheld seqSet
	// attempted is the highest sequence whose upload payload is final: every sequence at or below it
	// has been sent at least once (or predates this run without a recorded origin), so it is uploaded
	// exactly as it was first decided and is never newly withheld.
	attempted int64
	// applied is the policy last applied to the whole backlog (see applyLocked); appliedSet is false
	// until the first application.
	applied    consent.Policy
	appliedSet bool
	// dirty marks withheld decisions not yet recorded in the ledger. A batch is never sent while
	// its decisions are dirty.
	dirty bool
	// pending is the shutdown record on disk, carried through every rewrite of the ledger. Until
	// recorded is set it is the previous run's, applied at load and retired by this run's first send
	// (a start that fails before sending anything leaves it for the next start). Once this run writes
	// its own (recorded), every later send rewrites it with the new attempted-through mark before
	// sending, so the record on disk is exact whenever the process stops.
	pending  *consentLedgerShutdown
	recorded bool
}

// consentLedger is the durable half of the fence: the withheld sequences, and — only from a
// graceful shutdown until the next run's first send — the origins of what that run captured but had
// not sent. Checksum is a CRC-32C over the document's JSON encoding with Checksum zero.
type consentLedger struct {
	Version  int                    `json:"version"`
	Withheld [][2]int64             `json:"withheld"`
	Shutdown *consentLedgerShutdown `json:"shutdown,omitempty"`
	Checksum uint32                 `json:"crc32c"`
}

// consentLedgerShutdown is what a graceful shutdown hands the next start: the run's highest durable
// sequence (to prove the WAL did not change while stopped), the sequence through which its uploads
// were final, and the origins of every later watcher frame.
type consentLedgerShutdown struct {
	HighestDurable   int64                 `json:"highest_durable"`
	AttemptedThrough int64                 `json:"attempted_through"`
	Origins          []consentLedgerOrigin `json:"origins"`
}

// consentLedgerOrigin is one originRun on disk.
type consentLedgerOrigin struct {
	First      int64  `json:"first"`
	Last       int64  `json:"last"`
	Root       string `json:"root"`
	Generation uint64 `json:"generation"`
}

// newConsentFence loads the consent ledger for a spool whose highest durable sequence is
// highestDurable. It fails on an unreadable ledger: the ledger records which queued observations
// were withheld after a withdrawal, and uploading without it could send one of them as captured.
//
// A graceful-shutdown record is applied here and kept until this run's first send (see pending), so
// it is only ever applied by runs that sent nothing since it was written — for which its
// attempted-through mark is still exact. Frames appended after it (by such a run that then
// crashed) carry no origin.
func newConsentFence(dir string, src *consent.Source, highestDurable int64, log func(string)) (*consentFence, error) {
	f := &consentFence{dir: dir, src: src, log: log, attempted: highestDurable}
	sweepLedgerTemps(dir)
	doc, err := readConsentLedger(dir)
	if err != nil {
		return nil, err
	}
	for _, r := range doc.Withheld {
		// A withheld range above the durable ceiling names frames that no longer exist (an operator
		// moved WAL segments aside); their sequences will be reassigned, so the decisions are dropped.
		if r[0] <= highestDurable {
			f.withheld.add(r[0], min(r[1], highestDurable))
		}
	}
	sh := doc.Shutdown
	if sh == nil {
		return f, nil
	}
	if sh.HighestDurable > highestDurable || sh.AttemptedThrough > sh.HighestDurable {
		// The spool lost frames since the record was written (an operator moved WAL segments aside),
		// so the sequences it names will be reassigned. Drop it before anything is appended.
		f.logf("consent ledger: dropping the shutdown record: it describes a spool durable through sequence %d, and this one is durable through %d", sh.HighestDurable, highestDurable)
		if err := f.persistLocked(); err != nil {
			return nil, fmt.Errorf("observer daemon: drop the consent ledger's shutdown record: %w", err)
		}
		return f, nil
	}
	f.attempted = sh.AttemptedThrough
	for _, o := range sh.Origins {
		f.origins.addRun(max(o.First, f.attempted+1), min(o.Last, sh.HighestDurable), consentOrigin{root: o.Root, generation: o.Generation})
	}
	f.pending = sh
	if src == nil {
		// Passive: no policy can confirm the consent those frames were captured under, so they are
		// withheld — recorded before anything is sent.
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := f.applyAndRecordLocked(f.latest()); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ledgerExists reports whether dir holds a consent ledger, so a daemon without a live policy knows
// to honor it.
func ledgerExists(dir string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, consentLedgerFilename))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("observer daemon: stat consent ledger: %w", err)
	}
	return true, nil
}

// latest is the newest published consent policy. A passive fence consents to nothing.
func (f *consentFence) latest() consent.Policy {
	if f.src == nil {
		return consent.Policy{}
	}
	return f.src.Latest()
}

// admit checks a watcher append against the live consent policy and, when it is still consented,
// holds the gate until release is called after the append's origin is recorded.
func (f *consentFence) admit(o consentOrigin) (release func(), err error) {
	f.gate.RLock()
	if !o.allowedBy(f.latest()) {
		f.gate.RUnlock()
		return nil, errConsentWithdrawn
	}
	return f.gate.RUnlock, nil
}

// recordAppend notes the consent the watcher frame at seq was captured under. A frame whose consent
// was withdrawn between its admission and now is withheld here, as refresh would have, so the
// decision is recorded without waiting for a batch to read it. The check is against the newest
// published policy — never the upload lane's last applied one, which can predate the policy that
// admitted the frame (a root consented a moment ago).
func (f *consentFence) recordAppend(seq int64, o consentOrigin) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.origins.record(seq, o)
	if seq <= f.attempted || o.allowedBy(f.latest()) {
		return
	}
	f.withheld.add(seq, seq)
	f.dirty = true
	if err := f.persistLocked(); err != nil {
		// Still dirty: beforeSend records it before any batch is sent.
		f.logf("consent ledger: record a withheld observation: %v", err)
	}
}

// refresh re-checks the consent policy file (the per-batch check) and applies the newest published
// policy to the whole backlog, recording the decisions before returning. It runs before every batch.
func (f *consentFence) refresh() error {
	if f.src != nil {
		f.src.Current()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applyAndRecordLocked(f.latest())
}

// applyLocked applies pol to the whole backlog unless it is the policy last applied: every watcher
// frame not yet sent whose consent pol no longer covers is withheld. It returns the sequences it
// newly withheld, counted by origin. In memory only: the caller records them. Called with f.mu held.
func (f *consentFence) applyLocked(pol consent.Policy) map[consentOrigin]int64 {
	if f.appliedSet && pol.Version == f.applied.Version {
		return nil
	}
	f.applied, f.appliedSet = pol, true
	var withdrawn map[consentOrigin]int64
	for _, run := range f.origins.runs {
		if run.last <= f.attempted || run.origin.allowedBy(pol) {
			continue
		}
		if n := f.withheld.add(max(run.first, f.attempted+1), run.last); n > 0 {
			if withdrawn == nil {
				withdrawn = map[consentOrigin]int64{}
			}
			withdrawn[run.origin] += n
		}
	}
	if withdrawn != nil {
		f.dirty = true
	}
	return withdrawn
}

// applyAndRecordLocked applies pol (applyLocked) and, when that withheld anything, logs and records
// the decisions. Called with f.mu held.
func (f *consentFence) applyAndRecordLocked(pol consent.Policy) error {
	withdrawn := f.applyLocked(pol)
	if withdrawn == nil {
		return nil
	}
	f.logWithheld(withdrawn)
	if err := f.persistLocked(); err != nil {
		// Still dirty: beforeSend records the decisions before any batch is sent, or sends nothing.
		return fmt.Errorf("observer daemon: record withheld observations: %w", err)
	}
	return nil
}

// logWithheld reports newly withheld sequences by origin.
func (f *consentFence) logWithheld(withdrawn map[consentOrigin]int64) {
	var total int64
	for _, n := range withdrawn {
		total += n
	}
	why := "the owner withdrew their consent"
	if f.src == nil {
		why = "no live consent policy can confirm their consent"
	}
	f.logf("consent narrowed: withholding %d queued observations not yet uploaded (%s), because %s; each uploads as a content-free placeholder", total, describeOrigins(withdrawn), why)
}

// ceiling reads the spool's highest durable sequence with the gate held exclusively, so no watcher
// append is between its WAL write and its origin record.
func (f *consentFence) ceiling(health func() (int64, error)) (int64, error) {
	f.gate.Lock()
	defer f.gate.Unlock()
	return health()
}

// frameStore wraps the spool's frame store so every frame the batch lane reads is decided: withheld
// frames come back as their placeholder, every other frame unchanged.
func (f *consentFence) frameStore(inner upload.FrameStore) upload.FrameStore {
	return fencedFrameStore{inner: inner, fence: f}
}

// decide applies the upload decision to frames read for a batch, under the newest published policy
// — not the one the lane applied at its last refresh: a withdrawal another loop published since then
// is applied here, to the whole backlog, before any frame of this batch is decided.
func (f *consentFence) decide(recs []upload.Record) ([]upload.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pol := f.latest()
	if withdrawn := f.applyLocked(pol); withdrawn != nil {
		f.logWithheld(withdrawn)
		if err := f.persistLocked(); err != nil {
			// Still dirty: beforeSend records the decisions before this batch is sent, or sends nothing.
			f.logf("consent ledger: record withheld observations: %v", err)
		}
	}
	out := make([]upload.Record, len(recs))
	for i, rec := range recs {
		out[i] = rec
		if !f.withheld.contains(rec.Sequence) {
			if rec.Sequence <= f.attempted {
				continue
			}
			o, ok := f.origins.lookup(rec.Sequence)
			if !ok || o.allowedBy(pol) {
				continue
			}
			f.withheld.add(rec.Sequence, rec.Sequence)
			f.dirty = true
		}
		payload, err := withheldPlaceholder(rec)
		if err != nil {
			return nil, err
		}
		out[i].Payload = payload
	}
	return out, nil
}

// beforeSend records any new withheld decisions and marks the range's payloads final. It runs after
// a batch is formed and before it is sent; a failure to record stops the send. A shutdown record on
// disk must stay exact across the send: the previous run's is retired (this run's attempts move the
// attempted-through mark past what it says), and this run's own is rewritten with the new mark.
func (f *consentFence) beforeSend(r wire.SequenceRange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prevAttempted, prevPending := f.attempted, f.pending
	f.attempted = max(f.attempted, r.LastSequence)
	switch {
	case f.recorded:
		f.pending = f.shutdownRecordLocked(f.pending.HighestDurable)
	case f.pending != nil:
		f.pending = nil
	case !f.dirty:
		return nil
	}
	if err := f.persistLocked(); err != nil {
		f.attempted, f.pending = prevAttempted, prevPending
		return fmt.Errorf("observer daemon: record withheld observations: %w", err)
	}
	return nil
}

// acknowledged forgets everything at or below the collector's acknowledgement: those sequences are
// never read again. The ledger drops them at its next write.
func (f *consentFence) acknowledged(through int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.origins.prune(through)
	f.withheld.prune(through)
}

// recordShutdown writes this run's shutdown record: the origins of every watcher frame it captured
// but has not sent, so the next start can still withhold them if consent was withdrawn in between.
// Shutdown writes it before the final upload drain, and every send after it keeps it exact (see
// beforeSend), so a drain that hangs until the process is killed cannot lose it.
func (f *consentFence) recordShutdown(highestDurable int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	prevPending, prevRecorded := f.pending, f.recorded
	f.pending, f.recorded = f.shutdownRecordLocked(highestDurable), true
	if err := f.persistLocked(); err != nil {
		f.pending, f.recorded = prevPending, prevRecorded
		return err
	}
	return nil
}

// shutdownRecordLocked describes this run to the next start: the sequence through which its uploads
// are final and the origins of every watcher frame above it. Its durable ceiling covers both, so a
// record taken while frames are still being appended or sent is never mistaken for one describing
// frames the spool lost. Called with f.mu held.
func (f *consentFence) shutdownRecordLocked(highestDurable int64) *consentLedgerShutdown {
	sh := &consentLedgerShutdown{HighestDurable: max(highestDurable, f.attempted), AttemptedThrough: f.attempted, Origins: []consentLedgerOrigin{}}
	for _, run := range f.origins.runs {
		if run.last <= f.attempted {
			continue
		}
		sh.Origins = append(sh.Origins, consentLedgerOrigin{
			First: max(run.first, f.attempted+1), Last: run.last, Root: run.origin.root, Generation: run.origin.generation,
		})
		sh.HighestDurable = max(sh.HighestDurable, run.last)
	}
	return sh
}

// persistLocked atomically rewrites the ledger with the current withheld set and the pending
// shutdown record, if any. Called with f.mu held.
func (f *consentFence) persistLocked() error {
	doc := consentLedger{Version: consentLedgerVersion, Withheld: f.withheld.ranges, Shutdown: f.pending}
	if doc.Withheld == nil {
		doc.Withheld = [][2]int64{}
	}
	data, err := encodeConsentLedger(doc)
	if err != nil {
		return err
	}
	if err := spool.WriteFileAtomic(filepath.Join(f.dir, consentLedgerFilename), data); err != nil {
		return fmt.Errorf("write consent ledger: %w", err)
	}
	f.dirty = false
	return nil
}

// encodeConsentLedger renders the ledger with its checksum.
func encodeConsentLedger(doc consentLedger) ([]byte, error) {
	doc.Checksum = 0
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode consent ledger: %w", err)
	}
	doc.Checksum = crc32.Checksum(body, ledgerCRC)
	return json.Marshal(doc)
}

func (f *consentFence) logf(format string, args ...any) {
	if f.log != nil {
		f.log(fmt.Sprintf(format, args...))
	}
}

// describeOrigins renders withdrawn origins and their counts for a log line.
func describeOrigins(counts map[consentOrigin]int64) string {
	parts := make([]string, 0, len(counts))
	for o, n := range counts {
		parts = append(parts, fmt.Sprintf("%d from %s generation %d", n, o.root, o.generation))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// readConsentLedger reads the ledger strictly. An absent ledger is an empty one.
func readConsentLedger(dir string) (consentLedger, error) {
	path := filepath.Join(dir, consentLedgerFilename)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return consentLedger{Version: consentLedgerVersion}, nil
	}
	if err != nil {
		return consentLedger{}, fmt.Errorf("observer daemon: read consent ledger %s: %w", path, err)
	}
	var doc consentLedger
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s is unreadable: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s carries trailing data", path)
	}
	if doc.Version != consentLedgerVersion {
		return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s has unsupported version %d", path, doc.Version)
	}
	sum := doc.Checksum
	doc.Checksum = 0
	body, err := json.Marshal(doc)
	if err != nil {
		return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s: %w", path, err)
	}
	if crc32.Checksum(body, ledgerCRC) != sum {
		return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s fails its checksum", path)
	}
	if sh := doc.Shutdown; sh != nil {
		if sh.HighestDurable < 0 || sh.AttemptedThrough < 0 {
			return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s has a malformed shutdown record", path)
		}
		prevOrigin := int64(0)
		for _, o := range sh.Origins {
			if o.First < 1 || o.Last < o.First || o.First <= prevOrigin || o.Root == "" || o.Generation == 0 {
				return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s has a malformed shutdown origin %+v", path, o)
			}
			prevOrigin = o.Last
		}
	}
	prev := int64(0)
	for _, r := range doc.Withheld {
		if r[0] < 1 || r[1] < r[0] || r[0] <= prev {
			return consentLedger{}, fmt.Errorf("observer daemon: consent ledger %s has a malformed withheld range %v", path, r)
		}
		prev = r[1]
	}
	return doc, nil
}

// sweepLedgerTemps removes temporary ledger files a crash left between create and rename. Only this
// single-writer daemon creates them, under the state directory's exclusive lock.
func sweepLedgerTemps(dir string) {
	prefix := spool.AtomicTempPrefix(filepath.Join(dir, consentLedgerFilename))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// fencedFrameStore is the batch lane's frame store under the consent fence.
type fencedFrameStore struct {
	inner upload.FrameStore
	fence *consentFence
}

// ReadRange reads the durable frames and applies the fence's upload decision to each.
func (s fencedFrameStore) ReadRange(first, last int64) ([]upload.Record, error) {
	recs, err := s.inner.ReadRange(first, last)
	if err != nil {
		return nil, err
	}
	return s.fence.decide(recs)
}

// withheldPlaceholder builds the content-free CAPTURE_DIAGNOSTIC uploaded in place of a withheld
// frame. It keeps the frame's sequence and observation id (the batch lane is contiguous and the id
// was never sent with any other payload), its capture time, and its capturing adapter's identity,
// and nothing else: no session, provider, locator, run, or payload of the original leaves the
// machine. It is a pure function of the durable frame, so every replay sends identical bytes.
func withheldPlaceholder(rec upload.Record) ([]byte, error) {
	var env struct {
		ObservationID string    `json:"observation_id"`
		CapturedAt    time.Time `json:"captured_at"`
		Provenance    struct {
			Adapter        string                       `json:"adapter"`
			AdapterVersion string                       `json:"adapter_version"`
			ContentPolicy  wire.ProvenanceContentPolicy `json:"content_policy"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(rec.Payload, &env); err != nil {
		return nil, fmt.Errorf("observer daemon: decode withheld frame %d: %w", rec.Sequence, err)
	}
	pending, err := evidence.NewCaptureDiagnostic(evidence.Common{
		OccurredAt: env.CapturedAt,
		CapturedAt: env.CapturedAt,
		Provenance: wire.Provenance{
			Adapter:        env.Provenance.Adapter,
			AdapterVersion: env.Provenance.AdapterVersion,
			ContentPolicy:  env.Provenance.ContentPolicy,
		},
	}, evidence.CaptureDiagnosticInput{
		Code:               wire.CaptureDiagnosticPayloadCodeCAPTURELOSS,
		Severity:           wire.CaptureDiagnosticPayloadSeverityINFO,
		CompletenessEffect: wire.CaptureDiagnosticPayloadCompletenessEffectLOST,
		Context:            withheldContext,
	})
	if err != nil {
		return nil, fmt.Errorf("observer daemon: build withheld placeholder %d: %w", rec.Sequence, err)
	}
	obs, err := pending.Seal(rec.Sequence, env.ObservationID)
	if err != nil {
		return nil, fmt.Errorf("observer daemon: seal withheld placeholder %d: %w", rec.Sequence, err)
	}
	return wire.CanonicalBytes(obs)
}

// consentSink is the watcher's candidate sink under a live consent policy. Each watcher build gets
// its own, carrying the consent generation of every root it was built for: a candidate whose root is
// no longer consented at that generation is refused, and every durable append's origin is recorded
// for the upload lane. A watcher-scoped diagnostic (no consent root) carries no transcript evidence
// and passes through unfenced.
type consentSink struct {
	inner       *CandidateSinkAdapter
	fence       *consentFence
	generations map[string]uint64
}

var _ codex.PartialCandidateSink = (*consentSink)(nil)

// DeliverCandidates delivers the whole batch, discarding the delivered count.
func (s *consentSink) DeliverCandidates(ctx context.Context, ref codex.TranscriptRef, cands []*codex.Candidate) error {
	_, err := s.DeliverCandidatesPartial(ctx, ref, cands)
	return err
}

// DeliverCandidatesPartial delivers cands in transcript order, one at a time, stopping at the first
// failure or refusal, and reports how many leading candidates were durably delivered.
func (s *consentSink) DeliverCandidatesPartial(ctx context.Context, ref codex.TranscriptRef, cands []*codex.Candidate) (int, error) {
	for i, cand := range cands {
		if err := s.deliverOne(ctx, ref, cand); err != nil {
			return i, err
		}
	}
	return len(cands), nil
}

func (s *consentSink) deliverOne(ctx context.Context, ref codex.TranscriptRef, cand *codex.Candidate) error {
	if ref.ConsentRoot == "" {
		_, err := s.inner.deliverOne(ctx, ref, cand)
		return err
	}
	gen, ok := s.generations[ref.ConsentRoot]
	if !ok {
		return errConsentWithdrawn
	}
	origin := consentOrigin{root: ref.ConsentRoot, generation: gen}
	release, err := s.fence.admit(origin)
	if err != nil {
		return err
	}
	defer release()
	seq, err := s.inner.deliverOne(ctx, ref, cand)
	if err != nil {
		return err
	}
	if seq > 0 {
		s.fence.recordAppend(seq, origin)
	}
	return nil
}
