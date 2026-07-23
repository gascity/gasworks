package wire

import (
	"encoding/json"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"

	observerv1 "github.com/gascity/gasworks/contracts/observer/v1"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// These tests are the endpoint drift gate over the vendored Observer contract. They
// mirror the platform gate (internal/observercontract/openapi_spec_test.go): recompute
// the artifact SHA-256 against the committed checksum and the manifest SHA-256 against
// the manifest-hash lock, then validate every vendored fixture against the vendored
// schema exactly as the server does — valid fixtures conform, invalid fixtures are
// rejected, and every per-fixture sha256 matches. The schema validator
// (santhosh-tekuri/jsonschema) is a test-only dependency; it never enters the
// gasworks-observer binary closure.

// TestVendoredArtifactChecksumMatches fails if the vendored openapi.json is edited
// without regenerating openapi.json.sha256 — any change to the vendored source that
// skipped the sync rule fails CI.
func TestVendoredArtifactChecksumMatches(t *testing.T) {
	got := sha256Hex(observerv1.OpenAPISpec)
	if want := observerv1.ExpectedSHA256(); got != want {
		t.Fatalf("openapi.json sha256 = %s, but openapi.json.sha256 records %s; "+
			"re-run `sha256sum openapi.json > openapi.json.sha256` after any spec edit", got, want)
	}
	if want := loadManifest(t).SpecSHA256; got != want {
		t.Fatalf("openapi.json sha256 = %s, but the vendored manifest spec_sha256 is %s; "+
			"re-vendor the artifact and corpus together", got, want)
	}
}

// TestVendoredManifestHashLock fails if testdata/manifest.json is edited without
// regenerating testdata/manifest.json.sha256. This locks the whole corpus manifest:
// a coordinated fixture+manifest fork must also touch the lock file, so a fork cannot
// silently redefine which fixtures the contract covers.
func TestVendoredManifestHashLock(t *testing.T) {
	b, err := observerv1.Corpus.ReadFile(observerv1.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	got := sha256Hex(b)
	if want := observerv1.ExpectedManifestSHA256(); got != want {
		t.Fatalf("manifest.json sha256 = %s, but manifest.json.sha256 records %s; "+
			"re-run `sha256sum manifest.json > manifest.json.sha256` after any corpus edit", got, want)
	}
}

// convertNullable rewrites OpenAPI 3.0 `nullable: true` into a JSON Schema type union
// so santhosh-tekuri (which does not understand `nullable`) accepts the `null` a
// handler may emit. Mirrors the platform gate.
func convertNullable(v any) {
	switch x := v.(type) {
	case map[string]any:
		if x["nullable"] == true {
			if tp, ok := x["type"].(string); ok {
				x["type"] = []any{tp, "null"}
			}
			delete(x, "nullable")
		}
		for _, val := range x {
			convertNullable(val)
		}
	case []any:
		for _, val := range x {
			convertNullable(val)
		}
	}
}

func compileSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(observerv1.OpenAPISpec, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	convertNullable(doc)
	comps, ok := doc["components"].(map[string]any)
	if !ok {
		t.Fatalf("spec has no components object")
	}
	defs, ok := comps["schemas"].(map[string]any)
	if !ok {
		t.Fatalf("spec has no components.schemas object")
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("observer.json", doc); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	out := map[string]*jsonschema.Schema{}
	for name := range defs {
		sch, err := c.Compile("observer.json#/components/schemas/" + name)
		if err != nil {
			t.Fatalf("compile schema %s: %v", name, err)
		}
		out[name] = sch
	}
	return out
}

// TestVendoredFixturesConformToSchema validates every vendored fixture against the
// vendored artifact: valid fixtures conform, invalid fixtures are rejected, and every
// sha256 matches — the heart of the drift gate.
func TestVendoredFixturesConformToSchema(t *testing.T) {
	schemas := compileSchemas(t)
	m := loadManifest(t)
	for _, fx := range m.Fixtures {
		fx := fx
		t.Run(fx.Path, func(t *testing.T) {
			b, err := observerv1.Corpus.ReadFile(path.Join("testdata", fx.Path))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if got := sha256Hex(b); got != fx.SHA256 {
				t.Fatalf("sha256 drift: manifest %s, file %s (re-vendor the corpus)", fx.SHA256, got)
			}
			sch, ok := schemas[fx.Schema]
			if !ok {
				t.Fatalf("fixture names unknown schema %q (not in components.schemas)", fx.Schema)
			}
			var inst any
			if err := json.Unmarshal(b, &inst); err != nil {
				t.Fatalf("fixture is not JSON: %v", err)
			}
			err = sch.Validate(inst)
			switch fx.Expect {
			case "valid":
				if err != nil {
					t.Fatalf("expected conformance to %s but got:\n%v", fx.Schema, err)
				}
			case "invalid":
				if err == nil {
					t.Fatalf("expected %s to reject this fixture, but it conformed", fx.Schema)
				}
			default:
				t.Fatalf("fixture has unknown expect %q (want valid|invalid)", fx.Expect)
			}
		})
	}
}

// TestVendoredFixtureManifestIsComplete fails on any fixture file not listed in the
// manifest and any manifest entry without a file (corpus completeness).
func TestVendoredFixtureManifestIsComplete(t *testing.T) {
	m := loadManifest(t)
	listed := map[string]bool{}
	for _, fx := range m.Fixtures {
		listed[fx.Path] = true
	}
	onDisk := map[string]bool{}
	err := fs.WalkDir(observerv1.Corpus, observerv1.FixturesRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		onDisk[strings.TrimPrefix(p, "testdata/")] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	var missing, orphan []string
	for p := range listed {
		if !onDisk[p] {
			missing = append(missing, p)
		}
	}
	for p := range onDisk {
		if !listed[p] {
			orphan = append(orphan, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphan)
	if len(missing) > 0 {
		t.Errorf("manifest lists fixtures with no file: %v", missing)
	}
	if len(orphan) > 0 {
		t.Errorf("fixture files absent from the manifest (add them with a sha256): %v", orphan)
	}
}
