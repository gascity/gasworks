"""gasworks CLI: login, getToken, whoami, logout.

The token lifecycle has three layers, each cached with its own TTL:
  Keycloak refresh_token -> id_token (refreshed when <60s left; rotation persisted)
  id_token -> STS session per org (8h; DPoP-bound)
  session -> EIA per (org, product, scope) (90s; re-minted when <15s left)
Discovery (`/sts/v0/context`) supplies the concrete org + the exact mintable scopes so the
strict /login + /token gates can be satisfied without the user guessing.
"""

import argparse
import json
import os
import sys
import time

from . import config, oidc, store, sts
from .dpop import DPoPKey
from .httpc import HTTPError
from .jwtutil import decode_payload


def _now() -> int:
    return int(time.time())


def _eprint(*a) -> None:
    print(*a, file=sys.stderr)


def _die(msg: str, code: int = 1):
    _eprint(f"gasworks: {msg}")
    sys.exit(code)


def _token_exp(tok: str) -> int:
    try:
        return int(decode_payload(tok).get("exp", 0))
    except Exception:
        return 0


def _has_display() -> bool:
    if sys.platform in ("darwin", "win32"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _org_list(orgs) -> str:
    return ", ".join(f"{o.get('slug')}({o['org_id']})" for o in orgs) or "(none)"


# --- login ---

def cmd_login(cfg, args):
    use_device = args.device or (not args.browser and not _has_display())
    flow = oidc.device_login if use_device else oidc.browser_login
    try:
        tok = flow(cfg)
    except (RuntimeError, HTTPError) as e:
        _die(str(e))
    idt = tok.get("id_token")
    if not idt:
        _die("login returned no id_token (is the 'openid' scope enabled on the client?)")
    # Assert the token is OUR client's id_token before trusting it (catches a realm-default change
    # as a clear client error rather than an opaque STS 401 later).
    claims = decode_payload(idt)
    aud = claims.get("aud")
    aud = aud if isinstance(aud, list) else [aud]
    if cfg.client_id not in aud or claims.get("azp") not in (cfg.client_id, None):
        _die(f"the id_token is not for {cfg.client_id} (aud/azp mismatch)")
    with store.update() as data:
        data["id_token"] = idt
        if tok.get("refresh_token"):
            data["refresh_token"] = tok["refresh_token"]
        if args.org:
            data["default_org"] = args.org
        # a fresh login invalidates any prior STS sessions / cached EIAs
        data.pop("sessions", None)
        data.pop("eia_cache", None)
    who = claims.get("email") or claims.get("preferred_username") or claims.get("sub")
    print(f"Logged in as {who}.")


# --- token lifecycle helpers ---

def _ensure_id_token(cfg):
    """Return a valid id_token, refreshing (and persisting the rotated refresh token) if needed.
    Runs in its own locked write so the rotation survives even if a later mint step fails."""
    with store.update() as data:
        idt = data.get("id_token")
        if idt and _token_exp(idt) - _now() > 60:
            return idt
        rt = data.get("refresh_token")
        if not rt:
            _die("not logged in — run `gasworks login`")
        try:
            tok = oidc.refresh(cfg, rt)
        except HTTPError as e:
            _die(f"session expired ({e.oauth_error or e.status}) — run `gasworks login` again")
        data["refresh_token"] = tok.get("refresh_token", rt)  # Keycloak rotates — persist it
        if tok.get("id_token"):
            data["id_token"] = tok["id_token"]
        return data["id_token"]


def _pick_org(ctx, requested, data):
    orgs = ctx.get("orgs", [])
    ids = [o["org_id"] for o in orgs]
    if requested:
        for o in orgs:
            if requested in (o["org_id"], o.get("slug")):
                return o["org_id"]
        _die(f"you are not a member of org '{requested}'. Your orgs: {_org_list(orgs)}")
    if data.get("default_org") in ids:
        return data["default_org"]
    if ctx.get("default_org_id") in ids:
        return ctx["default_org_id"]
    if len(orgs) == 1:
        return orgs[0]["org_id"]
    if not orgs:
        _die("no orgs for this account — run `gasworks whoami` to check your account, "
             "or ask an admin to add you to an org")
    _die(f"you belong to multiple orgs — pass --org. Your orgs: {_org_list(orgs)}")


def _new_session(cfg, data, org, id_token):
    dpop = DPoPKey.generate()
    try:
        res = sts.login(cfg, id_token, org, dpop)
    except HTTPError as e:
        if e.status == 403:
            _die(f"not a member of org {org} ({e.oauth_error})")
        _die(f"login to org {org} failed: {e}")
    data.setdefault("sessions", {})[org] = {
        "session_token": res["session_token"],
        "dpop_pem": dpop.to_pem(),
        "expires_at": _now() + int(res.get("expires_in", 28800)),
    }
    return res["session_token"], dpop


def _ensure_session(cfg, data, org, id_token):
    sess = data.get("sessions", {}).get(org)
    if sess and sess.get("expires_at", 0) - _now() > 30:
        return sess["session_token"], DPoPKey.from_pem(sess["dpop_pem"])
    return _new_session(cfg, data, org, id_token)


def _emit(eia, scope, as_json):
    if as_json:
        print(json.dumps({"access_token": eia, "token_type": "DPoP", "expires_in": 90, "scope": scope}))
    else:
        print(eia)  # raw EIA, pipeable


# --- getToken ---

def cmd_get_token(cfg, args):
    product = args.product
    id_token = _ensure_id_token(cfg)
    try:
        ctx = sts.context(cfg, id_token, provision=True)
    except HTTPError as e:
        _die(f"discovery failed: {e}")

    with store.update() as data:
        org = _pick_org(ctx, args.org, data)
        org_ctx = next((o for o in ctx["orgs"] if o["org_id"] == org), None)
        if org_ctx is None:
            _die(f"you are not a member of org {org}")

        if args.scope:
            scope = args.scope
        else:
            prod = org_ctx.get("products", {}).get(product)
            if not prod or not prod.get("scopes"):
                avail = ", ".join(sorted(org_ctx.get("products", {}).keys())) or "(none)"
                _die(f"no mintable '{product}' scope for org {org_ctx.get('slug')} "
                     f"(entitled products: {avail})")
            scope = " ".join(prod["scopes"])

        cache_key = f"{org}|{product}|{scope}"
        cached = data.get("eia_cache", {}).get(cache_key)
        if not args.refresh and cached and cached.get("expires_at", 0) - _now() > 15:
            _emit(cached["eia"], scope, args.json)
            return

        session_token, dpop = _ensure_session(cfg, data, org, id_token)
        try:
            res = sts.exchange(cfg, session_token, product, scope, dpop)
        except HTTPError as e:
            if e.status == 401:  # session not resolvable -> re-establish once and retry
                session_token, dpop = _new_session(cfg, data, org, id_token)
                try:
                    res = sts.exchange(cfg, session_token, product, scope, dpop)
                except HTTPError as e2:
                    _die(f"getToken failed: {e2}")
            elif e.status == 403:
                _die(f"getToken denied: {e.oauth_error} ({e})")
            else:
                _die(f"getToken failed: {e}")

        eia = res["access_token"]
        data.setdefault("eia_cache", {})[cache_key] = {
            "eia": eia, "expires_at": _now() + int(res.get("expires_in", 90))
        }
        _emit(eia, res.get("scope", scope), args.json)


# --- whoami / logout ---

def cmd_whoami(cfg, args):
    data = store.load()
    if not data.get("id_token"):
        _die("not logged in — run `gasworks login`")
    id_token = _ensure_id_token(cfg)
    claims = decode_payload(id_token)
    print(f"subject:  {claims.get('sub')}")
    print(f"email:    {claims.get('email')}")
    if claims.get("preferred_username"):
        print(f"username: {claims.get('preferred_username')}")
    try:
        ctx = sts.context(cfg, id_token, provision=False)
    except HTTPError as e:
        if e.status == 404:
            print("orgs:     (no account yet — run `gasworks getToken <product>` to provision one)")
            return
        _eprint(f"  (could not list orgs: {e})")
        return
    print(f"default org: {ctx.get('default_org_id')}")
    for o in ctx.get("orgs", []):
        prods = ", ".join(sorted(o.get("products", {}).keys())) or "(none)"
        star = " *" if o.get("is_default") else ""
        print(f"  - {o.get('slug')} ({o.get('org_id')}) role={o.get('role')} products=[{prods}]{star}")


def cmd_logout(cfg, args):
    data = store.load()
    rt = data.get("refresh_token")
    if rt:
        oidc.revoke(cfg, rt)  # best-effort server-side revocation
    store.clear()
    print("Logged out.")


def main(argv=None) -> int:
    cfg = config.load()
    p = argparse.ArgumentParser(prog="gasworks", description="SSO login + getToken (EIA) for Gas City.")
    sub = p.add_subparsers(dest="cmd")

    lp = sub.add_parser("login", help="authenticate via SSO")
    lp.add_argument("--device", action="store_true", help="force the device-code flow (headless)")
    lp.add_argument("--browser", action="store_true", help="force the browser loopback flow")
    lp.add_argument("--org", help="remember a default org for getToken")

    gp = sub.add_parser("getToken", aliases=["get-token"], help="mint a short-lived EIA for a product")
    gp.add_argument("product", help="e.g. manifold, crucible")
    gp.add_argument("--org", help="org id or slug (defaults to your default/sole org)")
    gp.add_argument("--scope", help="override the discovered scopes (space-separated)")
    gp.add_argument("--json", action="store_true", help="emit a JSON envelope instead of the raw EIA")
    gp.add_argument("--refresh", action="store_true", help="bypass the local EIA cache")

    sub.add_parser("whoami", help="show the logged-in identity + orgs")
    sub.add_parser("logout", help="revoke the refresh token + clear stored credentials")

    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 2
    handler = {
        "login": cmd_login, "getToken": cmd_get_token, "get-token": cmd_get_token,
        "whoami": cmd_whoami, "logout": cmd_logout,
    }[args.cmd]
    handler(cfg, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
