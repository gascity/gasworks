import base64
import json
import time

import pytest

from gasworks import cli, store


def _fake_jwt(claims):
    def b(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b({'alg': 'none', 'typ': 'JWT'})}.{b(claims)}.sig"


def _seed(stub_cfg, tmp_path, monkeypatch, *, creds):
    monkeypatch.setenv("GASWORKS_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("GASWORKS_STS_URL", stub_cfg.sts_base)
    monkeypatch.setenv("GASWORKS_OIDC_ISSUER", stub_cfg.oidc_issuer)
    monkeypatch.setenv("GASWORKS_CLIENT_ID", "gasworks-cli")
    store.save(creds)


def _valid_id_token():
    return _fake_jwt({"sub": "kc-1", "email": "u@gascity.com", "exp": int(time.time()) + 3600,
                      "aud": ["gasworks-cli"], "azp": "gasworks-cli"})


def test_get_token_end_to_end(stub, tmp_path, monkeypatch, capsys):
    cfg, srv = stub
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    rc = cli.main(["getToken", "manifold"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "EIA.JWT"  # raw EIA to stdout (pipeable)
    # discovery sent provision=true; the exchange used the discovered manifold scopes
    tok_form = [r for r in srv.state["requests"] if r["path"].endswith("/sts/v0/token")][0]["form"]
    assert tok_form["scope"] == "manifold:proxy manifold:pool:acme"
    assert "subject_token_type" not in tok_form


def test_get_token_json_envelope(stub, tmp_path, monkeypatch, capsys):
    cfg, _ = stub
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    cli.main(["getToken", "manifold", "--json"])
    env = json.loads(capsys.readouterr().out.strip())
    assert env["access_token"] == "EIA.JWT" and env["expires_in"] == 90


def test_get_token_caches_second_call(stub, tmp_path, monkeypatch, capsys):
    cfg, srv = stub
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    cli.main(["getToken", "manifold"])
    capsys.readouterr()
    cli.main(["getToken", "manifold"])  # within 90s -> cache hit, no second mint
    assert capsys.readouterr().out.strip() == "EIA.JWT"
    assert len([r for r in srv.state["requests"] if r["path"].endswith("/sts/v0/token")]) == 1


def test_get_token_unentitled_product_is_clear_error(stub, tmp_path, monkeypatch, capsys):
    cfg, _ = stub  # the stub org_a has only manifold
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    with pytest.raises(SystemExit):
        cli.main(["getToken", "crucible"])
    assert "no mintable 'crucible' scope" in capsys.readouterr().err


def test_get_token_requires_login(stub, tmp_path, monkeypatch, capsys):
    cfg, _ = stub
    _seed(cfg, tmp_path, monkeypatch, creds={})  # no refresh token / id token
    with pytest.raises(SystemExit):
        cli.main(["getToken", "manifold"])
    assert "not logged in" in capsys.readouterr().err


def test_whoami(stub, tmp_path, monkeypatch, capsys):
    cfg, _ = stub
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    cli.main(["whoami"])
    out = capsys.readouterr().out
    assert "u@gascity.com" in out and "acme" in out and "manifold" in out


def test_logout_clears(stub, tmp_path, monkeypatch, capsys):
    cfg, _ = stub
    _seed(cfg, tmp_path, monkeypatch, creds={"refresh_token": "RT", "id_token": _valid_id_token()})
    cli.main(["logout"])
    assert store.load() == {}
