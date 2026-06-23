"""Minimal JWT helpers: base64url + UNVERIFIED payload/header decode.

The CLI never verifies a JWT signature itself — the STS verifies the subject_token and
products verify the EIA offline. These helpers are only for reading claims (whoami, the
id_token aud/azp assertion, expiry checks) and for building DPoP proofs.
"""

import base64
import json
from typing import Any, Dict


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _segment(token: str, idx: int) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    return json.loads(b64url_decode(parts[idx]))


def decode_header(token: str) -> Dict[str, Any]:
    """Decode a JWT header WITHOUT verifying the signature."""
    return _segment(token, 0)


def decode_payload(token: str) -> Dict[str, Any]:
    """Decode a JWT payload WITHOUT verifying the signature."""
    return _segment(token, 1)
