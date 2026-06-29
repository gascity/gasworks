import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from gasworks.config import Config


class _Stub(BaseHTTPRequestHandler):
    """A dumb recorder: logs (path, headers, form) and responds by path. Assertions live in
    the tests (raising in a handler thread would not surface as a clean failure)."""

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode() if n else ""
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        self.server.state["requests"].append(
            {"path": self.path, "headers": dict(self.headers), "form": form}
        )
        return form

    def do_POST(self):
        form = self._record()
        st = self.server.state
        if self.path.endswith("/auth/device"):
            self._send(200, {"device_code": "dev1", "user_code": "ABCD-EFGH",
                             "verification_uri": "http://kc/device",
                             "verification_uri_complete": "http://kc/device?user_code=ABCD-EFGH",
                             "interval": 0, "expires_in": 60})
        elif self.path.endswith("/openid-connect/token"):
            if form.get("grant_type", "").endswith("device_code"):
                st["device_polls"] += 1
                if st["device_polls"] < 2:
                    self._send(400, {"error": "authorization_pending"})
                else:
                    self._send(200, {"id_token": "ID.TOK.EN", "refresh_token": "RT", "access_token": "AT"})
            else:
                self._send(200, {"id_token": "ID2", "refresh_token": "RT2"})
        elif self.path.endswith("/sts/v0/login"):
            self._send(201, {"session_token": "SESS", "session_id": "ses_1",
                             "org_id": form.get("org"), "token_type": "DPoP", "expires_in": 28800})
        elif self.path.endswith("/sts/v0/token"):
            self._send(200, {"access_token": "EIA.JWT", "token_type": "DPoP",
                             "expires_in": 90, "scope": form.get("scope", "")})
        else:
            self._send(404, {"error": "nope"})

    def do_GET(self):
        self._record()
        if "/sts/v0/context" in self.path:
            self._send(200, {"user_id": "usr_1", "default_org_id": "org_a", "orgs": [
                {"org_id": "org_a", "slug": "acme", "role": "owner", "is_default": True, "products": {
                    "manifold": {"audience": "manifold", "scopes": ["manifold:proxy", "manifold:pool:acme"]}}}]})
        else:
            self._send(404, {"error": "nope"})


@pytest.fixture
def stub():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    srv.state = {"requests": [], "device_polls": 0}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    cfg = Config(sts_base=base, oidc_issuer=base + "/realms/g", client_id="gasworks-cli", loopback_port=9999)
    try:
        yield cfg, srv
    finally:
        srv.shutdown()


def reqs(srv, suffix):
    return [r for r in srv.state["requests"] if r["path"].endswith(suffix)]
