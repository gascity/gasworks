from gasworks import oidc, sts
from gasworks.dpop import DPoPKey


def _reqs(srv, suffix):
    return [r for r in srv.state["requests"] if r["path"].endswith(suffix)]


def test_device_login_polls_through_pending_with_pkce(stub):
    cfg, srv = stub
    tok = oidc.device_login(cfg, print_fn=lambda *_: None)
    assert tok["id_token"] == "ID.TOK.EN" and tok["refresh_token"] == "RT"
    assert srv.state["device_polls"] >= 2  # authorization_pending then success
    dev = _reqs(srv, "/auth/device")[0]["form"]
    assert dev["code_challenge_method"] == "S256" and dev["code_challenge"]
    assert "openid" in dev["scope"]  # without openid Keycloak returns no id_token
    poll = _reqs(srv, "/openid-connect/token")[-1]["form"]
    assert poll["code_verifier"]  # PKCE verifier on the poll


def test_login_and_exchange_omit_subject_token_type(stub):
    cfg, srv = stub
    dpop = DPoPKey.generate()
    sess = sts.login(cfg, "ID.TOK.EN", "org_a", dpop)
    assert sess["session_token"] == "SESS"
    eia = sts.exchange(cfg, sess["session_token"], "manifold", "manifold:proxy manifold:pool:acme", dpop)
    assert eia["access_token"] == "EIA.JWT" and eia["expires_in"] == 90

    # HTTP headers are case-insensitive; urllib sends "Dpop", Go's r.Header.Get("DPoP") canonicalizes the same.
    def has_dpop(req):
        return any(k.lower() == "dpop" for k in req["headers"])

    login_req = _reqs(srv, "/sts/v0/login")[0]
    assert has_dpop(login_req) and login_req["form"]["subject_token"] == "ID.TOK.EN"
    tok_req = _reqs(srv, "/sts/v0/token")[0]
    assert has_dpop(tok_req)
    assert tok_req["form"]["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert "subject_token_type" not in tok_req["form"]  # MUST be omitted (server 400s otherwise)
    assert tok_req["form"]["subject_token"] == "SESS"  # the session token, not the id_token


def test_context_sends_bearer_and_provision(stub):
    cfg, srv = stub
    ctx = sts.context(cfg, "ID.TOK.EN", provision=True)
    assert ctx["default_org_id"] == "org_a"
    assert ctx["orgs"][0]["products"]["manifold"]["scopes"] == ["manifold:proxy", "manifold:pool:acme"]
    req = _reqs(srv, "provision=true")[0]
    assert req["headers"].get("Authorization") == "Bearer ID.TOK.EN"


def test_custom_user_agent_on_every_call(stub):
    cfg, srv = stub
    sts.context(cfg, "ID.TOK.EN", provision=False)
    ua = srv.state["requests"][-1]["headers"].get("User-Agent", "")
    assert ua.startswith("gasworks-cli/")  # never the default Python UA (Cloudflare 1010)


def test_refresh_returns_rotated_token(stub):
    cfg, _ = stub
    tok = oidc.refresh(cfg, "RT")
    assert tok["refresh_token"] == "RT2"  # rotated; the caller must persist it
