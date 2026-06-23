# Migrating from the Python CLI (pipx)

The `gasworks` CLI is now a single statically-linked **Go** binary. It replaces the old Python package that shipped via `pipx install git+https://github.com/gascity/gasworks`.

**The commands, flags, and behavior are identical.** `login`, `getToken`, `whoami`, `logout`, and `version` work exactly as before — only the install path changes. Nothing in your scripts needs to change beyond how the binary gets onto the box.

## For users

Replace your pipx install with Homebrew:

```sh
# Remove the old Python CLI
pipx uninstall gasworks

# Install the Go CLI
brew install gascity/tap/gasworks
```

`gascity/tap` is the [`gascity/homebrew-tap`](https://github.com/gascity/homebrew-tap) repo. Or download a signed binary directly from the [GitHub Releases](https://github.com/gascity/gasworks/releases).

Your existing credentials carry over: the config dir is unchanged (`~/.config/gasworks`, `%APPDATA%\gasworks` on Windows, or `GASWORKS_CONFIG_DIR`), so a prior `gasworks login` session keeps working after the swap. If anything looks off, just `gasworks login` again.

### Verify the signed binary

If you download from Releases (rather than Homebrew), verify the artifact before running it, pinning the repo identity and the GitHub Actions OIDC issuer, and fail closed:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gascity/gasworks' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature   <artifact>.sig \
  --certificate <artifact>.pem \
  <artifact>
```

> The `gasworks-forwarder` daemon is **not** distributed via Homebrew — it is installed through the [gasworks pack](https://github.com/gascity/gasworks-pack), whose install stub runs the verification above before placing the binary. Its integrity check must never be bypassed by a tap fast-path.

## For maintainers — the staged cutover

The cutover follows the **add-Go-then-retire** rule: never leave `main` in a state that breaks existing `pipx` users mid-flight. Go is added *alongside* the Python tree first, a signed release is cut and **proven**, and only then is the Python tree removed. Two PRs, in order, with a gate between them.

### PR-1 — add the Go tree alongside Python

Add the full Go monorepo (`cmd/`, `internal/`, `go.mod`/`go.sum`, `.goreleaser.yaml`, `.github/workflows/go-ci.yml`, `.github/workflows/release.yml`) **without removing anything**:

- Python `src/`, `tests/`, `pyproject.toml`, and `.github/workflows/ci.yml` stay in place and keep working.
- Both CIs run side by side: `ci.yml` exercises pytest, `go-ci.yml` exercises the Go toolchain (`gofmt`, build, vet, race tests, and a GoReleaser snapshot cross-build).
- `pipx install git+...` still works off `main` throughout. Nothing user-visible changes yet.

### Out-of-band prerequisites (gate the first release)

These cannot be done from inside this repo and **must** exist before a real `v*` tag is cut:

1. **Create the empty `gascity/homebrew-tap` repo.** GoReleaser pushes the formula into it but will **not** create the repository.
2. **Create the `GASWORKS_RELEASE_TOKEN` org secret** with `contents:write` on `gascity/gasworks` **and** push access to `gascity/homebrew-tap`. The workflow's `GITHUB_TOKEN` is scoped to this repo only and cannot push the tap cross-repo.

### Gate — cut and PROVE a signed release

Push a `v*` tag (`git tag v1.0.0 && git push --tags`) to fire `release.yml`, then prove the release end-to-end before deleting anything:

- Signed artifacts exist on the Release (each archive + `checksums.txt`, each with a `.sig` and `.pem`), plus SBOM and provenance.
- `brew install gascity/tap/gasworks` works and the formula landed in the tap.
- `cosign verify-blob` passes against a downloaded artifact with the **pinned identity** (`--certificate-identity-regexp '^https://github.com/gascity/gasworks'`) and **pinned issuer** (`--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`), failing closed on a mismatch.

Do not proceed to PR-2 until all three hold. Until the release is proven, `pipx` remains the live install path and must keep working.

### PR-2 — retire the Python tree

Only after a release is proven, remove Python and flip the docs fully to Go:

- Delete `src/`, `tests/`, `pyproject.toml`, and the Python `.github/workflows/ci.yml`.
- The `README.md` is already the Go-world doc; remove any remaining pipx/venv/pytest references.

After PR-2, `main` ships Go only, and the signed Homebrew/Releases path is the sole supported install.
