# gasworks CLI

`gasworks login` (SSO) → `gasworks getToken <product>` → a short-lived **EIA** credential your tools can use. Cross-platform Python; the only dependency is `cryptography` (for DPoP).

```
pipx install git+https://github.com/gascity/gasworks
```

## Usage

```sh
gasworks login                 # SSO sign-in (browser on a laptop, device-code when headless)
gasworks login --device        # force the device-code flow (SSH / sandboxes / CI)
gasworks whoami                # who you are + the orgs you can mint for

gasworks getToken manifold     # mint an EIA for manifold (raw token on stdout — pipeable)
gasworks getToken crucible --org acme        # pick an org by slug or id
gasworks getToken manifold --json            # {access_token, expires_in, scope}
MANIFOLD_TOKEN=$(gasworks getToken manifold) # capture for a tool

gasworks logout                # revoke the refresh token + wipe local credentials
```

You don't pass scopes or an org id by hand: `getToken` **discovers** which orgs you belong to and the exact mintable scopes per product (including the org-derived `manifold:pool:<name>` you couldn't guess). Pass `--org` only if you belong to more than one. Override the discovered scopes with `--scope "<space separated>"` if you really need to.

## How it works

Three short-lived layers, each cached and auto-renewed:

1. **SSO** — Keycloak (device-code or browser, both PKCE) → an `id_token` + a refresh token.
2. **Session** — the `id_token` + a DPoP proof → a DPoP-bound STS session per org (≤8h).
3. **EIA** — the session → a ≤90s product token (RFC 8693 token-exchange), re-minted automatically.

All narrowing happens **server-side**: the client only ever learns what it may mint and asks for it; the STS fails closed if you ask for more. Products verify the EIA offline — there is nothing to call back.

## Storage & security

Credentials live in `~/.config/gasworks/credentials.json` (mode `0600`, atomic + lock-guarded; `%APPDATA%\gasworks` on Windows). It holds the refresh token, the per-org session, and the session's DPoP key. A **stolen credentials file is co-located-key vulnerable** (DPoP binds the key, not the file) — keep it as private as an SSH key; OS-keyring storage is planned. `logout` revokes the refresh token at the IdP.

## Config (overrides, for dev)

| env | default |
|---|---|
| `GASWORKS_STS_URL` | `https://works.gascity.com` |
| `GASWORKS_OIDC_ISSUER` | `https://auth.gascity.com/realms/gascity` |
| `GASWORKS_CLIENT_ID` | `gasworks-cli` |
| `GASWORKS_CONFIG_DIR` | the platform config dir |

## Develop

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```
