// Package rootpolicy parses the owner-supplied companion transcript consent
// policy. It deliberately has no discovery behavior: every root is supplied by
// the policy document and normalized to its canonical filesystem identity.
package rootpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Schema is the v1 document: roots[] alone, and every root path IS a transcript directory.
	Schema = "gasworks.companion.root-policy/v1"
	// SchemaV2 adds a per-root kind and the recorded provider transcript stores. Each version is
	// decoded against its own strict shape, so a v1 document still refuses v2's fields outright.
	SchemaV2 = "gasworks.companion.root-policy/v2"
	// SchemaV3 is v2 plus the owner's whole-transcript content-upload consent (content_upload), so
	// every consent the companion acts on lives in one document the daemon re-reads while it runs.
	// content_upload is required in v3: the decision is always stated, never defaulted.
	SchemaV3 = "gasworks.companion.root-policy/v3"
)

// ContentConsent is a policy document's decision about whole-transcript content upload.
type ContentConsent uint8

const (
	// ContentUnstated is a v1 or v2 document, which carries no content decision; the daemon then
	// keeps the content-upload setting it was started with.
	ContentUnstated ContentConsent = iota
	// ContentDenied is a v3 document with content_upload=false.
	ContentDenied
	// ContentGranted is a v3 document with content_upload=true.
	ContentGranted
)

// Mode is a root's capture mode. It also fixes the cross-generation re-delivery idempotency
// contract the endpoint dedups against, because both modes re-present the same transcript bytes on a
// re-read and the two must agree on what makes a re-delivery identical.
//
// Re-delivery is ordinary at-least-once bookkeeping. The watcher tails each transcript behind a
// durable per-generation scoped cursor; on a delivery failure the cursor is not advanced, and on a
// restart that lost the durable cursor, or a re-registration that mints a new generation (and so a
// fresh scoped cursor), the file is re-read from its floor and its records are delivered again. The
// same bytes therefore reach the endpoint more than once, and the endpoint deduplicates them by
// observation identity.
//
// CROSS-GENERATION DEDUP KEY (the contract a server implementer relies on). A re-delivered record is
// the SAME observation as its first delivery when, and only when, these generation-stable,
// content-derived fields match — the watcher re-presents every one of them byte-identically across a
// generation bump or a restart:
//   - provenance.source_locator (the transcript path relative to its consent root),
//   - occurred_at (the provider event time parsed from the record),
//   - the observation kind, and
//   - that kind's typed payload metadata (for MESSAGE, role and byte_count; for USAGE, the token
//     counts and message id; for TOOL_CALL/TOOL_RESULT, the category/status and byte counts),
//   - together with provenance.native_session_id and provenance.provider, which the watcher threads
//     from the transcript's own session record and so are likewise stable.
//
// The endpoint MUST dedup on that set. It MUST NOT dedup on any value minted per delivery downstream
// of the watcher: the single-writer daemon assigns a FRESH sequence and observation id to every WAL
// append, and stamps a delivery-time captured_at, so the platform's logical dedup key
// (source_id, sequence, observation_id) is not stable across a re-append and captured_at differs on
// every re-read. Keying on any of those would let a backfill re-delivery ingest the same transcript
// bytes twice. This is a documentation contract only: closing it fully needs a content-derived
// idempotency token on the wire, which is a cross-repo server change and out of scope here.
type Mode string

const (
	// ForwardOnly seals a root's existing content at a per-file line-aligned EOF floor at registration
	// and delivers only bytes appended after it. A re-registration mints a new generation whose fresh
	// scoped cursor reseals at the current floor, so a Backfill->ForwardOnly flip never republishes the
	// content beneath the new floor: the new generation's floor governs.
	ForwardOnly Mode = "forward-only"
	// Backfill delivers the whole file, floor at zero, because the owner consented to full history. A
	// re-read (restart with a lost cursor, or a new generation) re-delivers that history; it is
	// idempotent because every re-delivery re-presents byte-identical content under the
	// generation-stable dedup key documented on Mode. The whole-file content side channel is likewise
	// idempotent: it re-presents the same identity (locator, device, inode) and size, which the content
	// endpoint dedups by hash plus identity, superseding with a later, larger snapshot.
	Backfill Mode = "backfill"
)

// Kind says what a root's path names. The empty kind is v1's implicit Transcripts: v1 documents
// carry no kind field and must keep parsing exactly as they did.
type Kind string

const (
	// Transcripts means the path is itself a directory of transcripts to tail (v1 semantics).
	Transcripts Kind = "transcripts"
	// Project means the path is the owner's project folder. Its sessions live in the recorded
	// stores and are selected by membership, so the path is never tailed directly.
	Project Kind = "project"
)

// Record is one root's complete consent transition. An inactive record is a
// tombstone and therefore must not carry a capture mode.
type Record struct {
	Path       string
	Generation uint64
	Active     bool
	Mode       Mode
	// Kind is empty for v1 documents and for v2 records that name a transcript directory.
	Kind Kind
}

// IsProject reports whether the record's path names a project folder rather than a directory of
// transcripts. It is the single place the empty v1 kind is read as Transcripts.
func (r Record) IsProject() bool { return r.Kind == Project }

// Policy is one parsed policy document: the consent records plus, from v2 on, the recorded
// provider transcript stores that project roots draw their sessions from, and from v3 on the
// content-upload consent.
type Policy struct {
	Roots []Record
	// Stores are the absolute, canonical provider store directories (the Claude projects dir, the
	// Codex sessions dir). They are recorded state: only a registration verb changes them.
	Stores []string
	// Content is the document's whole-transcript content-upload consent: ContentUnstated for v1 and
	// v2 documents, ContentGranted or ContentDenied for v3.
	Content ContentConsent
}

type rawRecord struct {
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Active     bool   `json:"active"`
	Mode       Mode   `json:"mode"`
}

type documentV1 struct {
	Schema string      `json:"schema_version"`
	Roots  []rawRecord `json:"roots"`
}

type rawRecordV2 struct {
	rawRecord
	Kind Kind `json:"kind"`
}

type documentV2 struct {
	Schema string        `json:"schema_version"`
	Roots  []rawRecordV2 `json:"roots"`
	Stores []string      `json:"stores"`
}

// documentV3 is v2's shape plus the required content-upload consent. The pointer is how a decode
// tells an absent (or null) content_upload from an explicit false; v3 refuses both.
type documentV3 struct {
	Schema        string        `json:"schema_version"`
	ContentUpload *bool         `json:"content_upload"`
	Roots         []rawRecordV2 `json:"roots"`
	Stores        []string      `json:"stores"`
}

// Load reads one strict, owner-only policy file and returns its consent records. It is the v1-era
// entry point and stays byte-for-byte compatible; callers that need the recorded stores use
// LoadPolicy.
func Load(path string) ([]Record, error) {
	policy, err := LoadPolicy(path)
	if err != nil {
		return nil, err
	}
	return policy.Roots, nil
}

// LoadPolicy reads one strict, owner-only policy file of any supported schema version. Symlinked
// policy files, roots, and stores are resolved before use so the daemon's state is keyed by the
// stable canonical path, never a caller-controlled spelling.
func LoadPolicy(path string) (Policy, error) {
	data, err := readDocument(path)
	if err != nil {
		return Policy{}, err
	}
	schema, err := documentSchema(data)
	if err != nil {
		return Policy{}, err
	}
	var d documentV2
	content := ContentUnstated
	switch schema {
	case Schema:
		var v1 documentV1
		if err := decodeStrict(data, &v1); err != nil {
			return Policy{}, err
		}
		d.Roots = make([]rawRecordV2, 0, len(v1.Roots))
		for _, r := range v1.Roots {
			d.Roots = append(d.Roots, rawRecordV2{rawRecord: r})
		}
	case SchemaV2:
		if err := decodeStrict(data, &d); err != nil {
			return Policy{}, err
		}
	case SchemaV3:
		var v3 documentV3
		if err := decodeStrict(data, &v3); err != nil {
			return Policy{}, err
		}
		if v3.ContentUpload == nil {
			return Policy{}, fmt.Errorf("root policy %s must state content_upload as true or false", SchemaV3)
		}
		content = ContentDenied
		if *v3.ContentUpload {
			content = ContentGranted
		}
		d = documentV2{Schema: v3.Schema, Roots: v3.Roots, Stores: v3.Stores}
	default:
		return Policy{}, fmt.Errorf("root policy schema %q is not supported", schema)
	}
	seen := make(map[string]struct{}, len(d.Roots))
	out := make([]Record, 0, len(d.Roots))
	for i, r := range d.Roots {
		if r.Path == "" || !filepath.IsAbs(r.Path) {
			return Policy{}, fmt.Errorf("root policy record %d path must be absolute", i)
		}
		if r.Generation == 0 {
			return Policy{}, fmt.Errorf("root policy record %d generation must be greater than zero", i)
		}
		if r.Kind != "" && r.Kind != Transcripts && r.Kind != Project {
			return Policy{}, fmt.Errorf("root policy record %d kind must be transcripts or project", i)
		}
		canonical := filepath.Clean(r.Path)
		resolved, err := filepath.EvalSymlinks(canonical)
		if r.Active {
			if canonical != r.Path {
				return Policy{}, fmt.Errorf("root policy record %d active path must be canonical", i)
			}
			info, err := os.Lstat(canonical)
			if err != nil {
				return Policy{}, fmt.Errorf("stat root policy record %d path: %w", i, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return Policy{}, fmt.Errorf("root policy record %d active path must name a canonical directory", i)
			}
			if resolved != canonical {
				return Policy{}, fmt.Errorf("root policy record %d active path must not cross a symlink", i)
			}
		}
		if err == nil {
			canonical = resolved
			info, statErr := os.Stat(canonical)
			if statErr != nil || !info.IsDir() {
				return Policy{}, fmt.Errorf("root policy record %d path must name a directory", i)
			}
		} else if r.Active || !os.IsNotExist(err) {
			return Policy{}, fmt.Errorf("resolve root policy record %d path: %w", i, err)
		}
		// An inactive record is a tombstone. Its directory may have been removed after consent
		// was revoked, so preserve the clean explicit absolute spelling as its stable identity.
		if _, ok := seen[canonical]; ok {
			return Policy{}, fmt.Errorf("root policy contains duplicate canonical root %q", canonical)
		}
		seen[canonical] = struct{}{}
		if r.Active {
			if r.Mode != ForwardOnly && r.Mode != Backfill {
				return Policy{}, fmt.Errorf("root policy record %d active mode must be forward-only or backfill", i)
			}
		} else if r.Mode != "" {
			return Policy{}, fmt.Errorf("root policy record %d inactive tombstone must not carry a mode", i)
		}
		out = append(out, Record{Path: canonical, Generation: r.Generation, Active: r.Active, Mode: r.Mode, Kind: r.Kind})
	}
	if err := checkRootOverlap(out); err != nil {
		return Policy{}, err
	}
	stores, err := loadStores(d.Stores, out)
	if err != nil {
		return Policy{}, err
	}
	return Policy{Roots: out, Stores: stores, Content: content}, nil
}

// MaxDocumentBytes bounds a policy document; a larger file is refused.
const MaxDocumentBytes = 1 << 20

// readDocument reads a policy file under the rules every policy read applies: an absolute path, an
// owner-only regular file owned by this user, at most MaxDocumentBytes. The checks run on the opened
// file itself (the open refuses to follow a symlink and never blocks on a FIFO), so the path cannot
// be swapped between the check and the read.
func readDocument(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("root policy path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollowNonBlock, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat root policy: %w", err)
		}
		if isSymlinkRefusal(err) {
			return nil, fmt.Errorf("root policy must be an owner-only regular file")
		}
		return nil, fmt.Errorf("open root policy: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat root policy: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownerSupplied(info) {
		return nil, fmt.Errorf("root policy must be an owner-only regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read root policy: %w", err)
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("root policy exceeds %d bytes", MaxDocumentBytes)
	}
	return data, nil
}

// DecodeFileRecords reads a policy file under the same file rules as LoadPolicy and decodes its
// records with DecodeRecords: for narrowing only.
func DecodeFileRecords(path string) ([]Record, error) {
	data, err := readDocument(path)
	if err != nil {
		return nil, err
	}
	return DecodeRecords(data)
}

// DecodeRecords decodes the consent records of a policy document of any supported schema version
// with the same strict shape checks LoadPolicy applies, but without checking the records against the
// filesystem (existence, canonical spelling, overlap) or resolving symlinks: paths are only cleaned.
// It exists so a document that fails validation can still NARROW consent — a root it no longer
// lists as active at the same generation is withdrawn. Never grant consent from its result.
func DecodeRecords(data []byte) ([]Record, error) {
	schema, err := documentSchema(data)
	if err != nil {
		return nil, err
	}
	var roots []rawRecordV2
	switch schema {
	case Schema:
		var v1 documentV1
		if err := decodeStrict(data, &v1); err != nil {
			return nil, err
		}
		for _, r := range v1.Roots {
			roots = append(roots, rawRecordV2{rawRecord: r})
		}
	case SchemaV2:
		var v2 documentV2
		if err := decodeStrict(data, &v2); err != nil {
			return nil, err
		}
		roots = v2.Roots
	case SchemaV3:
		var v3 documentV3
		if err := decodeStrict(data, &v3); err != nil {
			return nil, err
		}
		roots = v3.Roots
	default:
		return nil, fmt.Errorf("root policy schema %q is not supported", schema)
	}
	out := make([]Record, 0, len(roots))
	for i, r := range roots {
		if r.Path == "" || !filepath.IsAbs(r.Path) || r.Generation == 0 {
			return nil, fmt.Errorf("root policy record %d is malformed", i)
		}
		out = append(out, Record{Path: filepath.Clean(r.Path), Generation: r.Generation, Active: r.Active, Mode: r.Mode, Kind: r.Kind})
	}
	return out, nil
}

// documentSchema reads schema_version alone so the document can then be decoded against the strict
// shape of exactly that version. It tolerates the fields it does not name; the versioned decode is
// what refuses unknown ones.
func documentSchema(data []byte) (string, error) {
	var probe struct {
		Schema string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("decode root policy: %w", err)
	}
	return probe.Schema, nil
}

// decodeStrict decodes exactly one JSON value into v, refusing unknown fields and trailing values.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode root policy: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode root policy: trailing JSON value")
	}
	return nil
}

// checkRootOverlap enforces A19: an active project root must be the unique match for a session's
// cwd, so it may neither contain nor sit beneath any other active root, of either kind. Transcript
// roots keep v1's laxer rule between themselves (nesting allowed; exact duplicates are already
// refused above). Tombstones are excluded: a revoked root captures nothing, and constraining a
// document by its own dead records would permanently poison paths that consent later reuses.
func checkRootOverlap(records []Record) error {
	for i, a := range records {
		if !a.Active {
			continue
		}
		for _, b := range records[i+1:] {
			if !b.Active || (!a.IsProject() && !b.IsProject()) {
				continue
			}
			if pathOverlaps(a.Path, b.Path) {
				return fmt.Errorf("root policy active roots %q and %q overlap; a project root must be disjoint from every other root", a.Path, b.Path)
			}
		}
	}
	return nil
}

// loadStores validates the recorded provider stores under the same canonicalization stance as the
// roots: absolute, lexically canonical, and — once they exist — real directories no symlink crosses.
// Stores are required only once a project root is active, because only membership reads them; until
// then they are inert recorded state whose directories may legitimately have been removed.
func loadStores(stores []string, records []Record) ([]string, error) {
	activeProject := false
	for _, r := range records {
		if r.Active && r.IsProject() {
			activeProject = true
			break
		}
	}
	if len(stores) == 0 {
		if activeProject {
			return nil, fmt.Errorf("root policy with an active project root must record at least one store")
		}
		return nil, nil
	}
	out := make([]string, 0, len(stores))
	for i, store := range stores {
		if store == "" || !filepath.IsAbs(store) || filepath.Clean(store) != store {
			return nil, fmt.Errorf("root policy store %d path must be absolute and canonical", i)
		}
		info, err := os.Lstat(store)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, fmt.Errorf("root policy store %d path must name a canonical directory", i)
			}
			resolved, err := filepath.EvalSymlinks(store)
			if err != nil {
				return nil, fmt.Errorf("resolve root policy store %d path: %w", i, err)
			}
			if resolved != store {
				return nil, fmt.Errorf("root policy store %d path must not cross a symlink", i)
			}
		case os.IsNotExist(err) && !activeProject:
		default:
			return nil, fmt.Errorf("stat root policy store %d: %w", i, err)
		}
		for _, other := range out {
			if pathOverlaps(store, other) {
				return nil, fmt.Errorf("root policy stores %q and %q overlap", store, other)
			}
		}
		// A store that contains (or sits inside) an active root would let membership and that root
		// tail the same transcript twice, so the two capture spaces must stay disjoint.
		for _, r := range records {
			if r.Active && pathOverlaps(store, r.Path) {
				return nil, fmt.Errorf("root policy store %q overlaps root %q", store, r.Path)
			}
		}
		out = append(out, store)
	}
	return out, nil
}

// pathOverlaps reports whether two cleaned absolute directories are the same or one lies beneath
// the other, comparing whole path components so /p/proj never matches /p/project.
func pathOverlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, withSeparator(b)) || strings.HasPrefix(b, withSeparator(a))
}

func withSeparator(dir string) string {
	if strings.HasSuffix(dir, string(filepath.Separator)) {
		return dir
	}
	return dir + string(filepath.Separator)
}
