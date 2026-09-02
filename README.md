# gasworks

`gasworks login` (SSO) → `gasworks getToken <product>` → a short-lived **EIA** credential your tools can use. A single statically-linked Go binary, no runtime dependencies.

This repo also ships **`gasworks-forwarder`**, an unattended daemon that ships coding-agent transcripts (recall) — and, in a future release, gasworks events — to their hosted ingest endpoints.

> Coming from the old `pipx install gasworks` (the Python CLI, now retired)? The Go commands and behavior are identical — see **[MIGRATION.md](./MIGRATION.md)** for the one-step switch to Homebrew.

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
gasworks getToken manifold --json            # Bearer + truthful remaining/absolute expiry
gasworks getToken manifold --refresh         # bypass the local EIA cache
MANIFOLD_TOKEN=$(gasworks getToken manifold) # capture for a tool

gasworks credential-provider < request.json  # versioned noninteractive JSON protocol

gasworks inspect               # what the SDK is holding: sessions, keys, EIA claims
gasworks inspect --json        # the same, machine-readable
gasworks rotate-key            # new DPoP key + a new session pinned to it
gasworks rotate-key --org acme # rotate one org's session key

gasworks whoami                # who you are + the orgs you can mint for
gasworks logout                # revoke the refresh token + wipe local credentials
gasworks version               # print the build version
```

| Command | Description |
|---|---|
| `gasworks login [--device\|--browser] [--org <id\|slug>]` | SSO sign-in (browser loopback on a laptop, device-code when headless); `--org` remembers a default org. |
| `gasworks getToken <product> [--org <id\|slug>] [--scope "<space-sep>"] [--json] [--refresh] [--allow-file-keystore]` | Mint a short-lived EIA for a product; `--json` emits an envelope, `--refresh` bypasses the cache. |
| `gasworks credential-provider` | Read a v1 credential request from stdin and emit one typed JSON response for automation. |
| `gasworks inspect [--json]` | Decode what is cached locally — login, sessions and where their DPoP keys live, and each cached EIA's Auth Access v1 claims (`authn_class`, `auth_time`, `acr`, `amr`, `session_id`, delegation). Offline; prints claims, never credentials. |
| `gasworks rotate-key [--org <id\|slug>] [--allow-file-keystore]` | Generate a fresh DPoP key and establish a new session pinned to it. Drops the cached EIAs minted from the superseded session, which itself stays valid at the STS until it expires. |
| `gasworks whoami` | Print your subject/email and the orgs (with roles + products) you can mint for. |
| `gasworks logout` | Revoke the refresh token at the IdP and wipe local credentials. |
| `gasworks version` | Print the build version (`--version` also works). |

You don't pass scopes or an org id by hand: `getToken` **discovers** which orgs you belong to and the exact mintable scopes per product (including the org-derived `manifold:pool:<name>` you couldn't guess). Pass `--org` only if you belong to more than one. Override the discovered scopes with `--scope "<space separated>"` only if you really need to.

### Credential-provider protocol

`credential-provider` is the stable, noninteractive interface for tools such as `gc`. It reads
exactly one bounded JSON object from stdin, never starts a login flow, and writes exactly one JSON
object to stdout. Run `gasworks login` separately to establish the durable human session.

Request:

```json
{
  "version": "gascity.dev/credential-provider/v1",
  "audience": "manifold",
  "required_scopes": ["manifold:proxy"],
  "org": "",
  "force_refresh": false,
  "interactive": false
}
```

Success:

```json
{
  "version": "gascity.dev/credential-provider/v1",
  "kind": "Credential",
  "access_token": "<opaque>",
  "authorization_scheme": "Bearer",
  "expires_at": "2026-07-16T01:02:03Z",
  "audience": "manifold",
  "scopes": ["manifold:proxy"]
}
```

Failures are typed JSON with `kind: "Error"` and a stable code such as
`interaction_required`; they exit nonzero and never echo credentials or upstream response bodies.

For a managed service principal, keep the same v1 JSON protocol and configure the invocation
with the complete flag set below. The key file is reread for each invocation; this mode does not
read or modify the human login store.

```sh
gasworks credential-provider \
  --service-principal-credential-file /absolute/path/to/api-key \
  --service-principal-audience manifold \
  --service-principal-org org_123 \
  --service-principal-scope manifold:proxy \
  --service-principal-scope manifold:pool:acme \
  < request.json
```

The request audience must match exactly, `org` may be omitted or must match exactly, and its
nonempty scopes must be a subset of the configured scopes. Any incomplete service-principal flag
set is rejected.

## How it works

Three short-lived layers, each cached and auto-renewed:

1. **SSO** — Keycloak (device-code or browser, both PKCE) → an `id_token` + a refresh token.
2. **Session** — the `id_token` + a DPoP proof → a DPoP-bound STS session per org (≤8h).
3. **EIA** — the session → a ≤90s product token (RFC 8693 token-exchange), re-minted automatically.

All narrowing happens **server-side**: the client only ever learns what it may mint and asks for it; the STS fails closed if you ask for more. Products verify the EIA offline — there is nothing to call back.

The Go STS client exposes optional fixed-label origin-selection events (`operation`, `origin`,
`outcome`, `reason`) through `Config.STSTelemetry`. A non-provisioning (read-only)
`/sts/v0/context` request may fall back from the canonical origin to the legacy origin on any
retryable failure. Provisioning context (`?provision=true`) and session establishment
(`/sts/v0/login`, `/sts/v0/machine`) fall back only when the canonical host's name does not
resolve — resolution precedes the dial, so no request reached the server and no identity, org, or
session state can have been created there. Every other failure makes one attempt at the selected
origin and never cross-origin retries after an uncertain response; so does the token exchange
(`/sts/v0/token`), which is only valid at the origin that issued the session. A canonical origin
that is unreachable for a reason other than name resolution — an HTTP proxy answering `CONNECT`
with an error, say — is not a resolution failure and does not fall back: set
`GASWORKS_STS_URL=https://works.gascity.com` explicitly in that environment.
The CLI does not enable an exporter or persist these events, so this hook is an integration seam
rather than a production counter. Events never include URLs, tokens, subjects, or DPoP proofs.

## Storage & security

Credentials live under the platform config dir (`~/.config/gasworks` on Linux, `%APPDATA%\gasworks` on Windows; override with `GASWORKS_CONFIG_DIR`), written mode `0600` (POSIX) / a user-only ACL (Windows, via `icacls`), atomic + lock-guarded. `credentials.json` holds the refresh token, the per-org sessions, and the EIA cache. It does **not** hold the DPoP private key of any session this CLI writes: those live in a separate credential store and the session keeps only a reference to one, so a stolen credentials file carries no signing key of ours. (Entries written by another tool that shares the file are carried through as found — see the limitations below.) `logout` revokes the refresh token at the IdP, purges every enrolled key, and then clears the file.

### Credential custody: where the DPoP key lives

The key that proves a session is held in an approved credential store, chosen from a closed per-platform registry (`gasworks.dev/keystore-registry/v1`). `gasworks inspect` prints the registry for the host you are on, with each store's exportability, backup, access-control and deletion semantics.

| Store | Platform | Default |
|---|---|---|
| `keychain` — macOS login keychain (generic password, per-profile service `com.gascity.gasworks.dpop.<digest>`) | macOS | selected automatically |
| `file` — one PKCS#8 PEM per session in the key dir (`0600` in a `0700` dir; user-only ACL on Windows) | all | selected where there is no platform store; **opt-in** on macOS |

The registry is ordered by preference and `Select` takes the first eligible store, so a platform keystore always wins over a plain file. Linux (Secret Service, TPM2/PKCS#11) and Windows (CNG, Credential Manager) are registry slots this build does not fill yet — **on those hosts the key is a plain file**, and the enrolment says so:

```
gasworks: no OS keystore backend for linux in this build — the session's DPoP private key is kept as plaintext PKCS#8 PEM files in /home/you/.local/state/gasworks/dpop-keys
```

That is the honest state of custody on Linux today: the key is split out of `credentials.json` and out of the config dir, but it is still exportable by anyone running as you. Fail-closed enrolment (below) is what happens once a platform has a real store to fail closed *to*; that is where Linux goes when a Secret Service / TPM2 backend lands, and it is already how macOS behaves when `/usr/bin/security` is missing:

```
gasworks: keystore: no approved credential store is available (registry gasworks.dev/keystore-registry/v1: keychain unavailable on this host; file registered but requires an explicit opt-in).
The DPoP private key is never written to a plain file unless you ask for it: re-run with --allow-file-keystore, or set GASWORKS_ALLOW_FILE_KEYSTORE=1, to keep it in a 0600 file under /Users/you/.local/state/gasworks/dpop-keys.
```

Opt in with `--allow-file-keystore` on `getToken` / `rotate-key`, or `GASWORKS_ALLOW_FILE_KEYSTORE=1` for every command (including `credential-provider`, which takes no such flag; its error names the variable). Reading back a key you already enrolled never needs the opt-in — the gate is on choosing where a *new* key goes.

The key dir is deliberately not the config dir, so a "back up my dotfiles" job does not carry both halves: `$GASWORKS_KEY_DIR` if set, else `~/.local/state/gasworks/dpop-keys` (`%LOCALAPPDATA%\gasworks\dpop-keys` on Windows). A profile pinned with `GASWORKS_CONFIG_DIR` is self-contained — its keys stay inside it, and `logout` in that profile purges only that profile's keys.

`gasworks rotate-key` generates a fresh key and establishes a new session pinned to it, dropping the cached EIAs minted from the superseded one. It is **not** a remedy for a suspected key compromise: the superseded session stays mintable at the STS until it expires (≤8h) because no route revokes the old session family yet. `rotate-key` says so every time.

Headless automation does not persist a key at all: `credential-provider --service-principal-credential-file …` mints with an **ephemeral** DPoP key held only in memory, so the managed secret and a signing key are never on disk together.

### Who refreshes

The SDK does, at every layer, before expiry — a caller holds a credential and never writes a refresh loop. `gasworks inspect` prints the thresholds in force (`id_token` at 60s remaining, the STS session at 30s, the EIA at 15s). `--refresh` / `force_refresh` exist to *discard* a cached credential, not to drive renewal.

### Security limitations

These are acknowledged, documented limitations of the current design — not bugs. They are listed so operators can reason about the trust model:

- **Co-located key theft on the host.** DPoP protects against token-only exfiltration, not against an attacker who is already running as you. Splitting the key out of `credentials.json`, and out of the config dir, means one stolen file (or one dotfile backup) is not enough — but a same-uid attacker can still read both halves. Exclude the key dir from backups, and prefer a platform keystore where one exists.
- **No store registered today is non-exportable.** The macOS keychain releases the key to this process once unlocked, and the `file` store is a plain PEM. Hardware-held keys that sign in-place (Secure Enclave, TPM) are a registry slot, not a shipped backend.
- **Linux and Windows have no platform keystore in this build.** The key is a plain file there. That is a smaller change than it sounds — it is where the key already was, minus co-location with the session — but it is not the custody the design asks for, and it is why the fail-closed default is not on for those platforms yet.
- **Rotation does not revoke the old session.** `rotate-key` establishes a new session with a new key, but the superseded session remains usable at the STS until its own expiry (≤8h); there is no re-enrollment route that revokes the old session family yet. Treat `rotate-key` as scheduled hygiene, not incident response.
- **`credentials.json` is a shared document.** `bd` (bd-enterprise) vendors this store and writes its own sessions — with its key inline — into the same file. The CLI replaces only the entry it is writing and carries every other entry through untouched, so the two binaries do not sign each other out; the reverse is not true until bd adopts split storage, and a `bd` write drops the `key` reference from a gasworks session (which then re-establishes itself).
- **Recall forwarder default filter is a blocklist (not an allowlist).** See the forwarder section above: secret-bearing JSON under a provider root with an unanticipated name is forwarded unless `RECALL_FORWARDER_STRICT_ALLOWLIST=1` is set.
- **Hardlinks inside a transcript dir.** A hardlink in a scanned directory pointing at a sensitive inode is read and forwarded if its content isn't PEM-shaped (the PEM sniff still catches key files). Exploiting this requires a same-uid local writer who can already read the target. A possible future guard is to drop in-scope files with `st_nlink > 1`; it is not implemented today.
- **Env-token `/proc` exposure.** `RECALL_FORWARDER_TOKEN` (the dev-only env path) is visible in `/proc/<pid>/environ` to the same user. It is popped from the environment at start and flagged with a warning; the production path (`RECALL_FORWARDER_TOKEN_FILE`, mode `0600`, re-read each cycle) avoids this.
- **EIA / session claims are not validated locally.** The CLI never verifies JWT signatures itself. The local id_token checks at login (issuer/audience/azp/expiry) are *advisory sanity checks over an unverified token*, not a trust boundary — the STS is the authoritative verifier of the subject token, and products verify the EIA offline.
- **Custom `RECALL_FORWARDER_ROOTS` bypass the narrow-scoping guarantee.** Overriding the roots can point the scanner outside the narrow per-provider subdirs. A root that isn't under a known provider home (`.claude`/`.codex`/`.gemini`) is inert (nothing gets a provider and so nothing is forwarded) and the forwarder prints a startup warning, but if you point a root *into* a provider home other than the default narrow subdir you weaken the scoping the defaults provide.

## Configuration

CLI endpoint + client overrides (`GASWORKS_*`). Defaults target production; override only for dev/testing.

| Env | Default |
|---|---|
| `GASWORKS_STS_CANONICAL_URL` | `https://api.gascity.com` (preferred STS origin; non-provisioning context falls back to the legacy origin for network/404/5xx failures, provisioning context and session establishment only when this host does not resolve) |
| `GASWORKS_STS_URL` | `https://works.gascity.com` (legacy/compatibility origin; setting this explicitly disables the implicit canonical probe) |
| `GASWORKS_OIDC_ISSUER` | `https://auth.gascity.com/realms/gasworks-customers` |
| `GASWORKS_CLIENT_ID` | `gasworks-cli` |
| `GASWORKS_LOOPBACK_PORT` | OS-assigned ephemeral port on `127.0.0.1` (set a numeric fixed-port override for tests/dev) |
| `GASWORKS_CONFIG_DIR` | the platform config dir |
| `GASWORKS_ALLOW_FILE_KEYSTORE` | unset. Set to `1` to permit storing the DPoP private key as a `0600` PEM where a platform keystore would otherwise be required (macOS), and to silence the "no OS keystore backend" notice where the file store is the only one (Linux, Windows). |
| `GASWORKS_KEY_DIR` | `~/.local/state/gasworks/dpop-keys` (`%LOCALAPPDATA%\gasworks\dpop-keys` on Windows; `<config dir>/dpop-keys` when `GASWORKS_CONFIG_DIR` pins a profile) |

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
