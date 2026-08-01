# Beads API v1 contract (vendored)

This directory is a byte-exact copy of the frozen Beads Team Server `/api/v1`
contract used to generate Gasworks' Observer artifact client. Gasworks does not
import the server module or its server-only generated bindings.

## Provenance

| Item | Value |
| --- | --- |
| Source repository | `gascity/beads-team-server` |
| Source commit | `8c91782e023f8e5c6ab02af2eb6338eaf37219eb` |
| Source path | `api/v1/` |
| Bundle SHA-256 | `e08b2b5b244a57bb3a5f4e742cb0f4d07887a579038e46099a34be05cf61cc46` |
| Digest-file SHA-256 | `919879c70605dc79ff12e82146cfc0fa67f6a4aae50e7f7cda8956396adf7f0d` |
| Policy-matrix SHA-256 | `da05687a27e25e1e1fb9857729fca97940b5258a59bca55564c7bc1dd18da283` |
| Published contract digest | `sha256:a9728ca23ec0f0b471d58ded2f52787819d0e54c7bd71c48b2242c1cbab36366` |

`openapi.bundled.json`, `CONTRACT_DIGESTS.json`, and `policy_matrix.json` are
vendored source artifacts. Do not hand-edit them. The generated client is
committed at `internal/observer/artifactapi/client.gen.go` so builds do not need
the generator or the source repository.

The published document is OpenAPI 3.1.1. The pinned oapi-codegen v2.6.0 parser
accepts OpenAPI 3.0, so generation first applies a mechanical, fail-closed 3.0.3
view. That lowered view is temporary and is not a published contract artifact.

## Refresh and regenerate

1. Copy all three source files byte-for-byte from one reviewed upstream commit.
2. Update the provenance and SHA-256 locks above and in
   `internal/observer/artifactapi/client_contract_test.go`.
3. Run `go generate ./internal/observer/artifactapi` twice.
4. Confirm the second run leaves `client.gen.go` byte-identical.
5. Run `go test ./internal/observer/artifactapi/...` and the Observer suites.

The contract test requires typed `WithResponse` coverage for exactly the 39
policy-matrix operations (oapi-codegen also emits `WithBodyWithResponse`
convenience variants) and pins the eight artifact operations, including
multipart `part_number`, binary upload, ranged 200/206 reads, and default RFC
9457 Problem responses.
