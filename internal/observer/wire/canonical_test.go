package wire

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the canonical byte-golden corpus under testdata/canonical/")

const (
	canonicalGoldenRoot = "testdata/canonical"
	// canonicalHashLockPath is the byte-exact vendored copy of the platform's
	// apigen/testdata/canonical_golden.json. It pins the version-1 canonical SHA-256 of
	// every valid fixture as authored by the SERVER. It is the cross-repo contract:
	// -update may regenerate the endpoint's byte goldens, but the per-fixture hash must
	// still equal this platform-pinned value, so the endpoint can never silently
	// redefine the canonical form the server hashes over.
	canonicalHashLockPath = "testdata/canonical_golden.json"
)

type canonicalHashLock struct {
	CanonicalEncodingVersion int               `json:"canonical_encoding_version"`
	Note                     string            `json:"note"`
	Hashes                   map[string]string `json:"hashes"`
}

func loadCanonicalHashLock(t *testing.T) canonicalHashLock {
	t.Helper()
	b, err := os.ReadFile(canonicalHashLockPath)
	if err != nil {
		t.Fatalf("read vendored canonical hash lock: %v", err)
	}
	var g canonicalHashLock
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("parse canonical hash lock: %v", err)
	}
	if g.CanonicalEncodingVersion != CanonicalEncodingVersion {
		t.Fatalf("vendored canonical hash lock version %d != wire encoder version %d",
			g.CanonicalEncodingVersion, CanonicalEncodingVersion)
	}
	if len(g.Hashes) == 0 {
		t.Fatal("canonical hash lock has no hashes")
	}
	return g
}

// TestCanonicalTypedGoldenCorpus is the reconciliation proof: for every valid fixture,
// the endpoint's typed canonical encoder produces bytes whose SHA-256 equals the
// platform-pinned hash (cross-repo lock), the bytes match the committed byte golden,
// and the encoding is a deterministic fixed point. Because the encode routes through
// the generated types (strict decode -> typed marshal -> canonicalize), timestamps and
// optional fields are normalized the same way the server normalizes them — closing the
// ".000Z" vs "Z" divergence a raw byte-preserving canonicalizer had.
func TestCanonicalTypedGoldenCorpus(t *testing.T) {
	m := loadManifest(t)
	lock := loadCanonicalHashLock(t)
	got := map[string]string{}

	for _, fx := range m.Fixtures {
		if fx.Expect != "valid" {
			continue
		}
		fx := fx
		t.Run(fx.Path, func(t *testing.T) {
			data := readFixture(t, fx)

			v, err := decodeSchemaValue(fx.Schema, data)
			if err != nil {
				t.Fatalf("strict-decode %s into %s: %v", fx.Path, fx.Schema, err)
			}
			canon, err := CanonicalBytes(v)
			if err != nil {
				t.Fatalf("canonical encode: %v", err)
			}
			if !json.Valid(canon) {
				t.Fatalf("canonical bytes are not valid JSON: %s", canon)
			}
			assertCompactSorted(t, canon)

			// Idempotence: decode the canonical bytes back into the same type and
			// re-encode; the wire form the hash covers must be a fixed point.
			v2, err := decodeSchemaValue(fx.Schema, canon)
			if err != nil {
				t.Fatalf("re-decode canonical bytes: %v", err)
			}
			canon2, err := CanonicalBytes(v2)
			if err != nil {
				t.Fatalf("re-encode canonical bytes: %v", err)
			}
			if !bytes.Equal(canon, canon2) {
				t.Fatalf("canonical encoding is not idempotent:\n first: %s\nsecond: %s", canon, canon2)
			}

			h, err := CanonicalHash(v)
			if err != nil {
				t.Fatalf("canonical hash: %v", err)
			}
			if want := sha256Hex(canon); h != want {
				t.Fatalf("CanonicalHash %s != sha256(CanonicalBytes) %s", h, want)
			}

			// Cross-repo lock: the endpoint hash MUST equal the platform-pinned hash.
			want, ok := lock.Hashes[fx.Path]
			if !ok {
				t.Fatalf("%s: no platform-pinned canonical hash in the vendored lock", fx.Path)
			}
			if h != want {
				t.Fatalf("%s: canonical hash diverges from platform: platform %s, endpoint %s", fx.Path, want, h)
			}
			got[fx.Path] = h

			// Byte golden: human-diffable canonical bytes, regenerable with -update, but
			// always re-checked against the platform hash above so -update cannot redefine
			// the cross-repo contract.
			goldenPath := filepath.Join(canonicalGoldenRoot, filepath.FromSlash(fx.Path))
			if *update {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatalf("mkdir golden: %v", err)
				}
				if err := os.WriteFile(goldenPath, canon, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			} else {
				wantBytes, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("read byte golden %s: %v (regenerate with -update)", goldenPath, err)
				}
				if !bytes.Equal(canon, wantBytes) {
					t.Fatalf("canonical bytes for %s differ from byte golden %s\n got: %s\nwant: %s",
						fx.Path, goldenPath, canon, wantBytes)
				}
				if s := sha256Hex(wantBytes); s != want {
					t.Fatalf("byte golden %s sha256 %s != platform-pinned %s", goldenPath, s, want)
				}
			}
		})
	}

	// Completeness: every platform-pinned hash has a live valid fixture and vice versa.
	if len(lock.Hashes) != len(got) {
		t.Errorf("platform lock has %d hashes, endpoint computed %d valid fixtures", len(lock.Hashes), len(got))
	}
	for p := range lock.Hashes {
		if _, ok := got[p]; !ok {
			t.Errorf("%s: platform-pinned hash has no live valid fixture", p)
		}
	}
}

// assertCompactSorted verifies the canonical bytes carry no insignificant whitespace
// and that every object's member names are already in ascending order — proven jointly
// by re-canonicalizing the bytes and requiring a no-op (canonical form is a fixed point
// of canonicalizeJSON). It also checks compactness independently.
func assertCompactSorted(t *testing.T, canon []byte) {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, canon); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if !bytes.Equal(canon, compact.Bytes()) {
		t.Fatalf("canonical bytes carry insignificant whitespace")
	}
	again, err := canonicalizeJSON(canon)
	if err != nil {
		t.Fatalf("re-canonicalize: %v", err)
	}
	if !bytes.Equal(canon, again) {
		t.Fatalf("canonical bytes are not a fixed point of canonicalization (unsorted keys?):\n in: %s\nout: %s", canon, again)
	}
}

// TestCanonicalizePreservesLargeIntegers proves the canonicalizer does not round-trip
// 64-bit sequences/IDs through float64 (which would corrupt them) and sorts keys.
func TestCanonicalizePreservesLargeIntegers(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`{"b":9223372036854775807,"a":1}`))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if want := `{"a":1,"b":9223372036854775807}`; string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

// TestCanonicalizeStringsSkipHTMLEscape proves hostile angle brackets/ampersands stay
// literal (stable, minimal bytes) rather than HTML-escaped.
func TestCanonicalizeStringsSkipHTMLEscape(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`{"x":"<a>&</a>"}`))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if want := `{"x":"<a>&</a>"}`; string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}
