# gasworks

`gasworks login` (SSO) → `gasworks getToken <product>` → a short-lived **EIA** credential your tools can use. A single statically-linked Go binary, no runtime dependencies.

This repo also ships **`gasworks-forwarder`**, an unattended daemon that ships coding-agent transcripts (recall) — and, in a future release, gasworks events — to their hosted ingest endpoints.

> **Migration in progress.** This Go rewrite lands _alongside_ the existing Python CLI. Until the first signed `v*` release is tagged, the supported install remains `pipx install git+https://github.com/gascity/gasworks` (the Python CLI, still on `main`); the Homebrew + signed-binary paths below activate with that release. Commands and behavior are identical — see **[MIGRATION.md](./MIGRATION.md)**.

## Install

### CLI — Homebrew (recommended)

```sh
brew install gascity/tap/gasworks
```

`gascity/tap` is the [`gascity/homebrew-tap`](https://github.com/gascity/homebrew-tap) repo; Homebrew expands the short name automatically.

### CLI — signed binary from Releases

Download the archive for your OS/arch from the [GitHub Releases](https://github.com/gascity/gasworks/releases), **verify the signature** (see [Verifying a release](#verifying-a-release)), unpack it, and put `gasworks` on your `PATH`.

### Forwarder daemon — via the pack (not Homebrew)

`gasworks-forwarder` is **not** installed with `brew`. It runs unattended holding ingest credentials, so its integrity check must never be bypassed by a tap fast-path. Install it through the [gasworks pack](https://github.com/gascity/gasworks-pack), whose install stub performs the cosign verification before placing the binary.

## Usage

```sh
gasworks login                 # SSO sign-in (browser on a laptop, device-code when headless)
gasworks login --device        # force the device-code flow (SSH / sandboxes / CI)
gasworks login --browser       # force the loopback browser flow
gasworks login --org acme      # remember a default org for getToken

gasworks getToken manifold     # mint an EIA for manifold (raw token on stdout — pipeable)
gasworks getToken crucible --org acme        # pick an org by slug or id
gasworks getToken manifold --json            # {access_token, token_type, expires_in, scope}
gasworks getToken manifold --refresh         # bypass the local EIA cache
MANIFOLD_TOKEN=$(gasworks getToken manifold) # capture for a tool

gasworks whoami                # who you are + the orgs you can mint for
gasworks logout                # revoke the refresh token + wipe local credentials
gasworks version               # print the build version
```

| Command | Description |
|---|---|
| `gasworks login [--device\|--browser] [--org <id\|slug>]` | SSO sign-in (browser loopback on a laptop, device-code when headless); `--org` remembers a default org. |
| `gasworks getToken <product> [--org <id\|slug>] [--scope "<space-sep>"] [--json] [--refresh]` | Mint a short-lived EIA for a product; `--json` emits an envelope, `--refresh` bypasses the cache. |
| `gasworks whoami` | Print your subject/email and the orgs (with roles + products) you can mint for. |
| `gasworks logout` | Revoke the refresh token at the IdP and wipe local credentials. |
| `gasworks version` | Print the build version (`--version` also works). |

You don't pass scopes or an org id by hand: `getToken` **discovers** which orgs you belong to and the exact mintable scopes per product (including the org-derived `manifold:pool:<name>` you couldn't guess). Pass `--org` only if you belong to more than one. Override the discovered scopes with `--scope "<space separated>"` only if you really need to.

## How it works

Three short-lived layers, each cached and auto-renewed:

1. **SSO** — Keycloak (device-code or browser, both PKCE) → an `id_token` + a refresh token.
2. **Session** — the `id_token` + a DPoP proof → a DPoP-bound STS session per org (≤8h).
3. **EIA** — the session → a ≤90s product token (RFC 8693 token-exchange), re-minted automatically.

All narrowing happens **server-side**: the client only ever learns what it may mint and asks for it; the STS fails closed if you ask for more. Products verify the EIA offline — there is nothing to call back.

## Storage & security

Credentials live under the platform config dir (`~/.config/gasworks` on Linux, `%APPDATA%\gasworks` on Windows; override with `GASWORKS_CONFIG_DIR`), written mode `0600` (POSIX) / a user-only ACL (Windows, via `icacls`), atomic + lock-guarded. The file holds the refresh token, the per-org session, and the session's DPoP key. A **stolen credentials file is co-located-key vulnerable** (DPoP binds the key, not the file) — keep it as private as an SSH key. `logout` revokes the refresh token at the IdP before clearing.

### Security limitations

These are acknowledged, documented limitations of the current design — not bugs. They are listed so operators can reason about the trust model:

- **Co-located-key / stolen credentials file.** The credentials file holds the DPoP private key next to the session it's bound to. DPoP binds the key to the request, *not* the file to a machine, so anyone who can read the file can mint EIAs until the session/refresh token expires. Protect it like an SSH private key (it's `0600` / user-only-ACL, but that's only as strong as the host). OS-keyring storage is a documented follow-up.
- **Recall forwarder default filter is a blocklist (not an allowlist).** See the forwarder section above: secret-bearing JSON under a provider root with an unanticipated name is forwarded unless `RECALL_FORWARDER_STRICT_ALLOWLIST=1` is set.
- **Hardlinks inside a transcript dir.** A hardlink in a scanned directory pointing at a sensitive inode is read and forwarded if its content isn't PEM-shaped (the PEM sniff still catches key files). Exploiting this requires a same-uid local writer who can already read the target. A possible future guard is to drop in-scope files with `st_nlink > 1`; it is not implemented today.
- **Env-token `/proc` exposure.** `RECALL_FORWARDER_TOKEN` (the dev-only env path) is visible in `/proc/<pid>/environ` to the same user. It is popped from the environment at start and flagged with a warning; the production path (`RECALL_FORWARDER_TOKEN_FILE`, mode `0600`, re-read each cycle) avoids this.
- **EIA / session claims are not validated locally.** The CLI never verifies JWT signatures itself. The local id_token checks at login (issuer/audience/azp/expiry) are *advisory sanity checks over an unverified token*, not a trust boundary — the STS is the authoritative verifier of the subject token, and products verify the EIA offline.
- **Custom `RECALL_FORWARDER_ROOTS` bypass the narrow-scoping guarantee.** Overriding the roots can point the scanner outside the narrow per-provider subdirs. A root that isn't under a known provider home (`.claude`/`.codex`/`.gemini`) is inert (nothing gets a provider and so nothing is forwarded) and the forwarder prints a startup warning, but if you point a root *into* a provider home other than the default narrow subdir you weaken the scoping the defaults provide.

## Configuration

CLI endpoint + client overrides (`GASWORKS_*`). Defaults target production; override only for dev/testing.

| Env | Default |
|---|---|
| `GASWORKS_STS_URL` | `https://works.gascity.com` |
| `GASWORKS_OIDC_ISSUER` | `https://auth.gascity.com/realms/gascity` |
| `GASWORKS_CLIENT_ID` | `gasworks-cli` |
| `GASWORKS_LOOPBACK_PORT` | `9822` (browser-flow loopback callback; non-numeric falls back to the default) |
| `GASWORKS_CONFIG_DIR` | the platform config dir |

### Forwarder (`gasworks-forwarder`)

```sh
gasworks-forwarder recall [--once]   # run the recall transcript forwarder (--once = single pass)
gasworks-forwarder events            # not yet available — pending pkg/eventexport release
gasworks-forwarder all [--once]      # run every available axis (currently recall; events pending)
```

The **events axis is a stub**: `gasworks-forwarder events` exits non-zero with "events axis not yet available (pending pkg/eventexport release)", and `all` runs recall then reports the events gap (it will not silently give you a partial fan-out). Each axis has its own config and its own bearer credential — a recall token is never shared with events (axis isolation).

The recall axis is **idle by default** and never dials until a URL, a source id, and a token source are all set. It is configured via `RECALL_FORWARDER_*`:

| Env | Default | Meaning |
|---|---|---|
| `RECALL_FORWARDER_URL` | (unset → idle) | Ingest base URL. Must be `https://` (loopback `http` only with `RECALL_FORWARDER_ALLOW_HTTP=1`). |
| `RECALL_FORWARDER_SOURCE_ID` | (unset → idle) | `X-Cass-Source-Id` for this source. |
| `RECALL_FORWARDER_TOKEN_FILE` | (unset) | Path to a bearer-token file (mode `0600`, re-read each cycle — the production path). |
| `RECALL_FORWARDER_TOKEN` | (unset) | Bearer token from the environment. **Dev-only** (visible in `/proc/<pid>/environ`); popped from the env at start. `_TOKEN_FILE` wins if both are set. |
| `RECALL_FORWARDER_ROOTS` | `~/.claude/projects`, `~/.codex/sessions`, `~/.gemini/tmp` | `PATH`-separated transcript roots to scan (the narrow per-provider subdirs, never the agent home). |
| `RECALL_FORWARDER_STATE` | `$XDG_STATE_HOME/recall-forwarder/state.json` | Dedup state file. |
| `RECALL_FORWARDER_INTERVAL` | `60` | Daemon scan interval, seconds (floored at 5). |
| `RECALL_FORWARDER_MAX_BYTES` | `104857600` (100 MiB) | Per-file byte cap. |
| `RECALL_FORWARDER_ALLOW_HTTP` | off | `1` permits a `http://localhost` URL (dev only). |
| `RECALL_FORWARDER_STRICT_ALLOWLIST` | off | See below. |

**`RECALL_FORWARDER_STRICT_ALLOWLIST` is OFF by default.** With it off, the forwarder forwards every transcript `.jsonl`/`.json` under a provider root that passes the denylist (plus the suffix check, symlink/containment guards, and a PEM content-sniff that drops key/secret files). Setting `RECALL_FORWARDER_STRICT_ALLOWLIST=1` **opts in** to a per-provider transcript-*shape* allowlist (claude `<uuid>.jsonl`, codex `rollout-*.jsonl`, gemini `*.json` under `tmp/<id>/`). Strict mode can silently drop new transcript shapes (e.g. subagent files), which is why it is opt-in rather than the default.

> **⚠️ The default filter is a BLOCKLIST, not an allowlist.** With strict mode off, the forwarder ships *every* `.jsonl`/`.json` under a provider root that isn't caught by the denylist/PEM-sniff. That denylist enumerates the *known* secret-bearing files (`credentials.json`, `*mcp*.json`, `*token*.json`, …); a secret-bearing JSON written **under a provider root with a name the denylist doesn't anticipate** (non-standard tooling dropping tokens into `~/.claude/projects`, custom plugins, future config files) **will be forwarded**. If you run non-standard tooling that writes secrets into those directories, set `RECALL_FORWARDER_STRICT_ALLOWLIST=1` so only recognized transcript *shapes* are shipped (a positive allowlist), accepting that strict mode may also drop transcript shapes it doesn't yet recognize.

> **Raw-transcript egress — no content redaction by design.** Recall ships the full transcript bytes, which may contain anything pasted into a session (secrets, code, PII). This is an operator-acknowledged channel: the axis is disabled unless explicitly configured, scoped to the narrow per-provider subdirs, https-only, symlink-contained, and never follows redirects or leaks the bearer across a non-TLS hop.

## Verifying a release

Every released artifact is keyless-signed with [cosign](https://github.com/sigstore/cosign) (Fulcio cert + Rekor transparency log). Before trusting a binary — and the pack's forwarder install stub does exactly this (M19) — verify it and **fail closed**, pinning both the signing identity (this repo) and the OIDC issuer (GitHub Actions):

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gascity/gasworks' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature   <artifact>.sig \
  --certificate <artifact>.pem \
  <artifact>
```

Each archive ships its own `.sig` + `.pem`, and `checksums.txt` is signed the same way (verify it, then check each artifact's `sha256` against it). A bare checksum match is **not** sufficient on its own. The release also carries an SBOM and SLSA provenance for the full supply-chain bundle.

## Develop

```sh
go build ./...
go vet ./...
go test ./... -race
```

The Go CI (`go-ci.yml`) runs `gofmt -l`, `go build`, `go vet`, `go test -race`, and a GoReleaser snapshot cross-build on every PR. Releases are cut by pushing a `v*` tag, which fires the signed `release.yml` pipeline (merging to `main` does **not** release).
