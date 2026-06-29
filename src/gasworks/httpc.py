"""Thin urllib wrapper: a custom User-Agent on every request (Keycloak/Cloudflare returns
1010 to the default Python UA), TLS verification always on, form/GET helpers, and a typed
HTTPError carrying the parsed body for OAuth/STS error mapping.

Named `httpc` (not `http`) so it never shadows the stdlib `http` package.
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .config import USER_AGENT

_TLS = ssl.create_default_context()  # verifies certs — never disabled


class HTTPError(Exception):
    def __init__(self, status: int, body: Any, url: str):
        self.status = status
        self.body = body  # parsed dict when JSON, else str
        self.url = url
        err = body.get("error") if isinstance(body, dict) else None
        desc = body.get("error_description") if isinstance(body, dict) else None
        detail = desc or (body if isinstance(body, str) else "")
        super().__init__(f"{status} {err or ''} {detail}".strip())

    @property
    def oauth_error(self) -> Optional[str]:
        return self.body.get("error") if isinstance(self.body, dict) else None


def _parse(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _request(method: str, url: str, *, data: Optional[bytes] = None,
             headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, Any]:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_TLS) as resp:
            return resp.status, _parse(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HTTPError(e.code, _parse(e.read().decode("utf-8", "replace")), url) from None


def post_form(url: str, form: Dict[str, str], headers: Optional[Dict[str, str]] = None,
              timeout: int = 30) -> Tuple[int, Any]:
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    return _request("POST", url, data=urllib.parse.urlencode(form).encode("utf-8"),
                    headers=h, timeout=timeout)


def get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, Any]:
    return _request("GET", url, headers=headers, timeout=timeout)
