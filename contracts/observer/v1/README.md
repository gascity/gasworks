# Observer wire contract, v1 (vendored)

This directory is a **byte-exact vendored copy** of the Observer OpenAPI
contract and its canonical fixture corpus. The endpoint (`gasworks`) does not
import platform code; it regenerates its DTOs from this local copy so the
contract travels with the binary and drift is caught by CI.

## Source of truth

| Item | Value |
| --- | --- |
| Upstream repo | `gasworks-platform` |
| Upstream commit | `6b24350bace8abb5a5a10ddc01296842d8b195b4` (P0.4) |
| Upstream artifact | `docs/reference/schema/observer.openapi.json` |
| Upstream corpus | `internal/observercontract/testdata/` (`fixtures/` + `manifest.json`) |
| Upstream canonical hashes | `internal/observercontract/apigen/testdata/canonical_golden.json` |
| Artifact SHA-256 | `1befe74b3ddfa3fd6768547a3a0502569298d66c55c209ddc4987ff69831919e` |
| Manifest SHA-256 | `3ca8c9c0c65550b1a3cbe52c9cf75cc168e528c097bb525c534a44d95df550fc` |

The upstream artifact is the hand-authored source of truth. It is **OpenAPI
3.0.3 with zero 2020-12-only keywords** (the Checkpoint-0 dialect ruling):
conditional couplings that 3.0 cannot express (drain-pair travel-together,
`ESTIMATED` → `price_table_version`) are server-validator rules pinned by
`semantic_violation`-tagged fixtures, not schema keywords.

## Contents

- `openapi.json` — the vendored contract, byte-for-byte identical to upstream.
- `openapi.json.sha256` — `sha256sum(openapi.json)` in `sha256sum -c` format.
- `testdata/manifest.json` — the canonical fixture manifest (byte-exact, 54 fixtures).
- `testdata/manifest.json.sha256` — the manifest-hash lock (`sha256sum -c` format);
  a coordinated fixture+manifest fork must also touch this file.
- `testdata/fixtures/` — the 54-fixture corpus (byte-exact).

The endpoint's per-fixture **canonical hash lock** — the byte-exact copy of the
platform's `canonical_golden.json` — lives with the wire tests at
`internal/observer/wire/testdata/canonical_golden.json` (the cross-repo contract:
the endpoint's typed canonical bytes must hash to the platform-pinned value for
every valid fixture).

## Sync rule

`openapi.json` and everything under `testdata/` are **vendored, not authored
here**. Never hand-edit them. To pick up a contract change:

1. Re-copy `openapi.json`, `testdata/manifest.json`, and `testdata/fixtures/`
   byte-for-byte from the new upstream commit, plus the platform
   `apigen/testdata/canonical_golden.json` to
   `internal/observer/wire/testdata/canonical_golden.json`.
2. Recompute the checksums:
   `sha256sum openapi.json > openapi.json.sha256` and, from `testdata/`,
   `sha256sum manifest.json > manifest.json.sha256`.
3. Regenerate the endpoint DTOs: `go generate ./internal/observer/wire/...`.
4. Regenerate the canonical byte goldens:
   `go test ./internal/observer/wire/... -run TestCanonicalTypedGoldenCorpus -update`,
   then re-run the full suite.
5. Update the upstream commit/hashes in this README.

CI fails closed if any of these steps is skipped: the drift test recomputes the
artifact SHA-256 against `openapi.json.sha256` and the manifest SHA-256 against
`manifest.json.sha256`; the canonical test re-checks every valid fixture's typed
canonical hash against the platform-pinned `canonical_golden.json`; and the
generated DTOs are committed so the compiler flags any spec change that was not
regenerated.
