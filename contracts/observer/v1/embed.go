// Package observerv1 exposes the vendored Observer wire contract (OpenAPI 3.0.3
// artifact plus the canonical fixture corpus) as embedded bytes.
//
// The artifact and corpus in this directory are a byte-exact vendored copy of
// gasworks-platform's Observer contract (see README.md for the pinned commit and
// sync rule). The endpoint never imports platform code; it embeds this local copy
// so the contract travels with the binary and the drift test in
// internal/observer/wire can validate it offline.
//
// Nothing here decodes or interprets the contract — that is the generated wire
// package's job. This package is a byte accessor only.
package observerv1

import (
	"embed"
	"strings"
)

// OpenAPISpec is the vendored Observer OpenAPI 3.0.3 artifact, byte-for-byte
// identical to the upstream source of truth recorded in README.md.
//
//go:embed openapi.json
var OpenAPISpec []byte

//go:embed openapi.json.sha256
var checksumFile string

// Corpus holds the vendored canonical fixture corpus: testdata/manifest.json and
// the testdata/fixtures/ tree, byte-for-byte identical to upstream.
//
//go:embed testdata
var Corpus embed.FS

// ManifestPath is the path of the fixture manifest within Corpus.
const ManifestPath = "testdata/manifest.json"

// ManifestChecksumPath is the path of the manifest-hash lock within Corpus.
const ManifestChecksumPath = "testdata/manifest.json.sha256"

// FixturesRoot is the root of the fixture tree within Corpus.
const FixturesRoot = "testdata/fixtures"

// ExpectedSHA256 returns the hex SHA-256 recorded in openapi.json.sha256 (the
// leading field of the sha256sum-format checksum file). The drift test recomputes
// sha256(OpenAPISpec) and fails if it no longer matches this value.
func ExpectedSHA256() string {
	return firstField(checksumFile)
}

// ExpectedManifestSHA256 returns the hex SHA-256 recorded in the manifest-hash lock
// (testdata/manifest.json.sha256). The drift test recomputes sha256(manifest bytes)
// and fails if it no longer matches — so a coordinated fixture+manifest fork must
// also touch the lock file.
func ExpectedManifestSHA256() string {
	b, err := Corpus.ReadFile(ManifestChecksumPath)
	if err != nil {
		return ""
	}
	return firstField(string(b))
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
