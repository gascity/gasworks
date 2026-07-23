package evidence

import (
	"encoding/json"
	"path"
	"testing"

	observerv1 "github.com/gascity/gasworks/contracts/observer/v1"
)

// Shared read-only helpers over the vendored contract corpus (contracts/observer/v1,
// embedded via observerv1.Corpus). The evidence package validators are proven against
// the exact same manifest-pinned fixtures the wire package and the platform validators
// use, so the three stay in lockstep. Nothing here mutates the corpus.

type fixtureEntry struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	Schema            string `json:"schema"`
	Expect            string `json:"expect"`
	Category          string `json:"category"`
	SemanticViolation string `json:"semantic_violation"`
	Note              string `json:"note"`
}

type fixtureManifest struct {
	Spec       string         `json:"spec"`
	SpecSHA256 string         `json:"spec_sha256"`
	Fixtures   []fixtureEntry `json:"fixtures"`
}

func loadManifest(t *testing.T) fixtureManifest {
	t.Helper()
	b, err := observerv1.Corpus.ReadFile(observerv1.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m fixtureManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(m.Fixtures) == 0 {
		t.Fatal("manifest lists no fixtures")
	}
	return m
}

func readFixture(t *testing.T, fx fixtureEntry) []byte {
	t.Helper()
	b, err := observerv1.Corpus.ReadFile(path.Join("testdata", fx.Path))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fx.Path, err)
	}
	return b
}

func readCorpusFile(t *testing.T, relPath string) []byte {
	t.Helper()
	b, err := observerv1.Corpus.ReadFile(path.Join("testdata", relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return b
}
