"""RFC 9449 DPoP proofs over an EC P-256 (ES256) key, plus the RFC 7638 thumbprint.

Two server invariants are enforced here:
  * golang-jwt ES256 requires the JWS signature to be exactly 64 raw bytes (r||s, 32 each),
    NOT the DER `cryptography` emits — so we convert.
  * the STS re-derives the jkt over fixed 32-byte big-endian coordinates and pins it across
    /login and /token — so we emit fixed-width 32-byte coords and reuse ONE key per session.
Every proof gets a fresh jti + iat; proofs are never reused.
"""

import hashlib
import json
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .jwtutil import b64url_encode


def _coord(n: int) -> str:
    """A P-256 coordinate as 32-byte big-endian, base64url no padding (the jkt input)."""
    return b64url_encode(n.to_bytes(32, "big"))


class DPoPKey:
    """A session DPoP key. Generate once per STS session; reuse across login + token."""

    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> "DPoPKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: str) -> "DPoPKey":
        return cls(serialization.load_pem_private_key(pem.encode("ascii"), password=None))

    def to_pem(self) -> str:
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def public_jwk(self) -> dict:
        """The PUBLIC EC JWK embedded in the proof header (never the private `d`)."""
        nums = self._key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": _coord(nums.x), "y": _coord(nums.y)}

    def thumbprint(self) -> str:
        """RFC 7638 jkt: base64url(SHA-256(canonical JWK)). For display/debug; the STS
        re-derives its own from the proof's jwk and matches the session against itself."""
        jwk = self.public_jwk()  # exactly the 4 required EC members
        canon = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        return b64url_encode(hashlib.sha256(canon.encode("ascii")).digest())

    def _es256(self, signing_input: bytes) -> bytes:
        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # raw 64-byte JWS ES256

    def proof(self, htm: str, htu: str) -> str:
        """A fresh DPoP proof JWT for one request. `htu` must be the exact STS URL."""
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk()}
        payload = {
            "htm": htm.upper(),
            "htu": htu,
            "iat": int(time.time()),
            "jti": uuid.uuid4().hex,
        }
        h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = b64url_encode(self._es256(f"{h}.{p}".encode("ascii")))
        return f"{h}.{p}.{sig}"
