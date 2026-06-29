import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from gasworks.dpop import DPoPKey
from gasworks.jwtutil import b64url_decode


def _parts(proof):
    h, p, s = proof.split(".")
    return json.loads(b64url_decode(h)), json.loads(b64url_decode(p)), b64url_decode(s)


def test_proof_structure():
    hdr, pl, _ = _parts(DPoPKey.generate().proof("POST", "https://works.gascity.com/sts/v0/token"))
    assert hdr["typ"] == "dpop+jwt"
    assert hdr["alg"] == "ES256"
    jwk = hdr["jwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert "d" not in jwk  # PUBLIC key only — never leak the private scalar
    assert len(b64url_decode(jwk["x"])) == 32 and len(b64url_decode(jwk["y"])) == 32
    assert pl["htm"] == "POST"
    assert pl["htu"] == "https://works.gascity.com/sts/v0/token"
    assert isinstance(pl["iat"], int) and pl["jti"]


def test_signature_is_64_bytes_and_verifies_across_many_keys():
    # golang-jwt ES256 demands exactly 64 raw bytes (r||s); a DER or variable-length sig is rejected.
    # The 50-key sweep makes a zero-high-byte coordinate (the off-by-one bug) overwhelmingly likely.
    htu = "https://works.gascity.com/sts/v0/login"
    for _ in range(50):
        h, p, s = DPoPKey.generate().proof("POST", htu).split(".")
        sig = b64url_decode(s)
        assert len(sig) == 64, f"sig is {len(sig)} bytes, must be exactly 64"
        jwk = json.loads(b64url_decode(h))["jwk"]
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        r = int.from_bytes(sig[:32], "big")
        ss = int.from_bytes(sig[32:], "big")
        pub.verify(encode_dss_signature(r, ss), f"{h}.{p}".encode("ascii"), ec.ECDSA(hashes.SHA256()))


def test_fresh_jti_per_proof():
    k = DPoPKey.generate()
    a = _parts(k.proof("POST", "https://x/y"))[1]
    b = _parts(k.proof("POST", "https://x/y"))[1]
    assert a["jti"] != b["jti"]  # proofs are single-use; never cached/reused


def test_thumbprint_stable_and_b64url_nopad():
    k = DPoPKey.generate()
    t = k.thumbprint()
    assert t == k.thumbprint()
    assert "=" not in t and "+" not in t and "/" not in t
    assert len(b64url_decode(t)) == 32  # SHA-256


def test_pem_roundtrip_preserves_key():
    k = DPoPKey.generate()
    k2 = DPoPKey.from_pem(k.to_pem())
    # same x/y on reload -> same jwk in the proof header -> the STS's session jkt still matches
    assert k.public_jwk() == k2.public_jwk()
    assert k.thumbprint() == k2.thumbprint()
