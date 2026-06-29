"""STS client: discovery (context), session establishment (login), and the EIA exchange (token).

Each minting call carries a DPoP proof bound to the exact endpoint URL, signed by ONE key per
session (reused across login + token so the STS's session jkt match holds). Discovery carries no
DPoP — it mints nothing.
"""

from typing import Dict

from . import httpc
from .config import Config
from .dpop import DPoPKey

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def context(cfg: Config, id_token: str, provision: bool) -> Dict:
    """GET /sts/v0/context — the caller's orgs + per-org mintable scopes (incl. manifold:pool:<name>)."""
    url = cfg.context_url + ("?provision=true" if provision else "")
    _, body = httpc.get(url, headers={"Authorization": f"Bearer {id_token}"})
    return body


def login(cfg: Config, id_token: str, org: str, dpop: DPoPKey) -> Dict:
    """POST /sts/v0/login — establish a DPoP-bound session. Returns {session_token, expires_in, ...}."""
    _, body = httpc.post_form(
        cfg.login_url,
        {"subject_token": id_token, "org": org},
        headers={"DPoP": dpop.proof("POST", cfg.login_url)},
    )
    return body


def exchange(cfg: Config, session_token: str, audience: str, scope: str, dpop: DPoPKey) -> Dict:
    """POST /sts/v0/token — the RFC 8693 exchange. Returns {access_token: <EIA>, expires_in, scope}.

    subject_token_type is intentionally OMITTED: the STS accepts only empty or the gascity session
    URN, so the RFC-canonical access_token default would 400.
    """
    _, body = httpc.post_form(
        cfg.token_url,
        {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": session_token,
            "audience": audience,
            "scope": scope,
        },
        headers={"DPoP": dpop.proof("POST", cfg.token_url)},
    )
    return body
