package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"testing"

	observerv1 "github.com/gascity/gasworks/contracts/observer/v1"
)

// These helpers are shared by the wire package's internal tests. They read the
// vendored corpus (contracts/observer/v1, embedded via observerv1.Corpus) read-only,
// through the generated types and the canonical/decoder layers, and never mutate it.

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

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

// decodeSchemaValue strictly decodes fixture bytes into the concrete generated type
// named by the fixture's component schema and returns a pointer to it. It uses
// DisallowUnknownFields so the golden pipeline exercises the same closed-world
// semantics CanonicalBytes documents as its precondition — an unknown member in a
// fixture is a hard error, not a silent drop into a truncated canonical golden. This
// mirrors the platform's apigen decodeSchemaValue exactly.
func decodeSchemaValue(schema string, data []byte) (any, error) {
	var v any
	switch schema {
	case "ObservationBatch":
		v = new(ObservationBatch)
	case "ObserverError":
		v = new(ObserverError)
	case "IngestAck":
		v = new(IngestAck)
	case "CapabilitiesResponse":
		v = new(CapabilitiesResponse)
	case "RunDetail":
		v = new(RunDetail)
	case "RunEvidencePage":
		v = new(RunEvidencePage)
	case "RunListResponse":
		v = new(RunListResponse)
	case "WorkRunDetail":
		v = new(WorkRunDetail)
	case "SourceDescriptor":
		v = new(SourceDescriptor)
	case "SourceDecommissionRequest":
		v = new(SourceDecommissionRequest)
	case "SourceEnrollRequest":
		v = new(SourceEnrollRequest)
	case "SourceRotationRequest":
		v = new(SourceRotationRequest)
	case "SourceRotationResult":
		v = new(SourceRotationResult)
	default:
		return nil, errUnknownSchema(schema)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errTrailingFixture
	}
	return v, nil
}

var errTrailingFixture = errors.New("unexpected trailing data in fixture")

type errUnknownSchema string

func (e errUnknownSchema) Error() string {
	return "no generated type registered for schema " + string(e)
}
