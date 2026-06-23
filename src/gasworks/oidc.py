"""Keycloak OIDC: device-code and browser auth-code (both PKCE), refresh, and revoke.

Every grant requests scope='openid ...' — `openid` is NOT a default client scope, and without
it Keycloak returns only an access_token and no id_token (the STS subject_token). `offline_access`
asks for a durable refresh token. Keycloak rotates refresh tokens on use, so the caller MUST
persist the newly-returned one.
"""

import base64
import hashlib
import http.server
import os
import secrets
import time
import urllib.parse
import webbrowser
from typing import Callable, Dict

from . import httpc
from .config import Config
from .jwtutil import decode_payload

OIDC_SCOPE = "openid profile email offline_access"


def _pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def device_login(cfg: Config, print_fn: Callable[[str], None] = print) -> Dict:
    """Device-authorization grant (headless). Returns the token response (id_token, refresh_token...)."""
    verifier, challenge = _pkce()
    _, body = httpc.post_form(cfg.device_auth_url, {
        "client_id": cfg.client_id,
        "scope": OIDC_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    device_code = body["device_code"]
    interval = int(body.get("interval", 5))
    deadline = time.time() + int(body.get("expires_in", 600))
    uri = body.get("verification_uri_complete") or body.get("verification_uri")
    print_fn(f"\nTo sign in, open:\n\n    {uri}\n")
    if body.get("user_code") and not body.get("verification_uri_complete"):
        print_fn(f"and enter the code:  {body['user_code']}\n")
    print_fn("Waiting for you to authorize...")
    while time.time() < deadline:
        time.sleep(max(interval, 1))
        try:
            _, tok = httpc.post_form(cfg.oidc_token_url, {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": cfg.client_id,
                "code_verifier": verifier,
            })
            return tok
        except httpc.HTTPError as e:
            err = e.oauth_error
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err in ("expired_token", "access_denied"):
                raise RuntimeError(f"device login failed: {err}") from None
            raise
    raise RuntimeError("device login timed out")


def browser_login(cfg: Config, print_fn: Callable[[str], None] = print) -> Dict:
    """Authorization-code + PKCE on a 127.0.0.1 loopback. The fixed port must be a registered
    redirect URI on the gasworks-cli client (Keycloak's `*` does not span the port)."""
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    redirect_uri = f"http://127.0.0.1:{cfg.loopback_port}/callback"
    auth_url = cfg.authorize_url + "?" + urllib.parse.urlencode({
        "client_id": cfg.client_id, "response_type": "code", "redirect_uri": redirect_uri,
        "scope": OIDC_SCOPE, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })

    box: Dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            q = urllib.parse.parse_qs(parsed.query)
            box["code"] = (q.get("code") or [""])[0]
            box["state"] = (q.get("state") or [""])[0]
            box["error"] = (q.get("error") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h3>gasworks: signed in. You can close this tab.</h3></body></html>")

    try:
        # bind 127.0.0.1 ONLY (never 0.0.0.0)
        httpd = http.server.HTTPServer(("127.0.0.1", cfg.loopback_port), Handler)
    except OSError as e:
        raise RuntimeError(
            f"loopback port {cfg.loopback_port} is busy ({e}); free it or use --device"
        ) from None
    httpd.timeout = 300
    print_fn(f"\nOpening your browser to sign in...\nIf it doesn't open, visit:\n\n    {auth_url}\n")
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass
    try:
        httpd.handle_request()  # serve exactly one callback, or time out
    finally:
        httpd.server_close()

    if box.get("error"):
        raise RuntimeError(f"login failed: {box['error']}")
    if not box.get("code"):
        raise RuntimeError("login timed out waiting for the browser callback")
    if box.get("state") != state:
        raise RuntimeError("state mismatch (possible CSRF) — aborting")
    _, tok = httpc.post_form(cfg.oidc_token_url, {
        "grant_type": "authorization_code", "code": box["code"], "redirect_uri": redirect_uri,
        "client_id": cfg.client_id, "code_verifier": verifier,
    })
    if tok.get("id_token") and decode_payload(tok["id_token"]).get("nonce") != nonce:
        raise RuntimeError("id_token nonce mismatch — aborting")
    return tok


def refresh(cfg: Config, refresh_token: str) -> Dict:
    """Refresh grant. Keycloak rotates the refresh token — persist the returned one."""
    _, tok = httpc.post_form(cfg.oidc_token_url, {
        "grant_type": "refresh_token", "refresh_token": refresh_token,
        "client_id": cfg.client_id, "scope": OIDC_SCOPE,
    })
    return tok


def revoke(cfg: Config, refresh_token: str) -> None:
    """Best-effort refresh-token revocation at Keycloak (called on logout)."""
    try:
        httpc.post_form(cfg.revoke_url, {
            "token": refresh_token, "token_type_hint": "refresh_token", "client_id": cfg.client_id,
        })
    except httpc.HTTPError:
        pass
