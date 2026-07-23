// Package wire holds the Go DTOs generated from the vendored Observer OpenAPI
// contract, plus the canonical JSON encoder used at the WAL/wire edge.
//
// Direction is spec-first: the source of truth is the vendored artifact
// contracts/observer/v1/openapi.json (see contracts/observer/v1/README.md for the
// pinned upstream commit and sync rule). The DTOs in observer.gen.go are derived
// from it and committed so the compiler flags drift. Do NOT hand-edit
// observer.gen.go — change the vendored artifact (following the sync rule) and
// regenerate.
//
// Regeneration is deterministic. The generator is pinned to oapi-codegen v2.6.0
// and invoked with @-version form so it never enters this vendored module's
// dependency graph — the only generator artifact that reaches the binary is the
// tiny github.com/oapi-codegen/runtime helper the generated union methods import.
// The config (oapi-codegen.yaml) mirrors platform P0.4, including
// always-prefix-enum-values for stable enum constant names.
//
// Alongside the DTOs this package provides:
//   - CanonicalBytes/CanonicalHash (canonical.go): the version-1 typed-normalized
//     canonical JSON encoder, byte-identical to the platform's, whose output the WAL
//     frame payload hash and the vendored canonical golden hashes are computed over.
//   - DecodeObservationBatch and the wire-shape strict decoders (strictdecode.go,
//     enumcheck.go, errors.go): closed-world ingest decoding — unknown field/kind,
//     absent/null payload member, out-of-range sequence, and out-of-enum rejection —
//     mirrored from platform P0.4 with stdlib only, so no new dependency enters the
//     binary closure.
//
// Scope boundary: this package stops at wire-shape strictness. The demoted semantic
// couplings the OpenAPI 3.0 schema cannot carry — batch contiguity, RUN_ENDED
// drain-pair travel-together, ESTIMATED usage requiring price_table_version, and the
// reference/batch cardinality caps — are enforced by the server validators (platform
// apigen.ValidateBatch, the S2.4 track) and by endpoint-side evidence/policy checks in
// E1.1, per the refuted-finding scope ruling. Their semantic_violation-tagged fixtures
// live in the vendored corpus and are the negative inputs for those validators.
//
//go:generate go run -mod=mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0 -config oapi-codegen.yaml ../../../contracts/observer/v1/openapi.json
package wire
