package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// A fixed PKCS8 PEM and its pinned thumbprint. Cross-verified byte-for-byte against the
// Python reference implementation (gasworks.dpop.DPoPKey). If a future serialization change
// alters the canonical JWK or the jkt derivation, this test fails in CI.
const goldenPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/Xq/SC0cJj5fZ2WB
s/IK+xHX7Z8aZ7MbcLMDcUatZjShRANCAAS7WrffOuDLBB+C6cdHOT4Bj9C+QwFA
gnNmwBEuv3X3SEPGWCfRmFzKz1oZwpuR/eKrtbDXJZ9JTV1ABGAXAIMX
-----END PRIVATE KEY-----
`

const goldenJKT = "SU8dkHFkTiS6UTAlSmA5V26RglMHsdZdzPRY_bjth4w"

func parts(t *testing.T, proof string) (header, payload map[string]any, sig []byte) {
	t.Helper()
	p := strings.Split(proof, ".")
	if len(p) != 3 {
		t.Fatalf("proof has %d segments, want 3", len(p))
	}
	hb, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	sb, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return header, payload, sb
}

func TestProofStructure(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	hdr, pl, _ := parts(t, mustProof(t, k, "POST", "https://works.gascity.com/sts/v0/token"))

	if hdr["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want dpop+jwt", hdr["typ"])
	}
	if hdr["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", hdr["alg"])
	}
	jwk, ok := hdr["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("jwk missing or wrong type: %T", hdr["jwk"])
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		t.Errorf("jwk kty/crv = %v/%v", jwk["kty"], jwk["crv"])
	}
	if _, leaked := jwk["d"]; leaked {
		t.Error("jwk leaked the private scalar d")
	}
	for _, c := range []string{"x", "y"} {
		raw, err := base64.RawURLEncoding.DecodeString(jwk[c].(string))
		if err != nil {
			t.Fatalf("decode %s: %v", c, err)
		}
		if len(raw) != 32 {
			t.Errorf("%s decodes to %d bytes, want 32", c, len(raw))
		}
	}
	if pl["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", pl["htm"])
	}
	if pl["htu"] != "https://works.gascity.com/sts/v0/token" {
		t.Errorf("htu = %v", pl["htu"])
	}
	// iat must be a JSON integer. encoding/json decodes numbers into float64 by default;
	// assert it has no fractional part (a true integer on the wire).
	iat, ok := pl["iat"].(float64)
	if !ok {
		t.Fatalf("iat is %T, want a JSON number", pl["iat"])
	}
	if iat != float64(int64(iat)) {
		t.Errorf("iat = %v, want an integer", iat)
	}
	// Confirm it serialized WITHOUT a decimal point on the wire.
	if jti, _ := pl["jti"].(string); jti == "" {
		t.Error("jti is empty")
	}
}

func TestIatSerializesAsInteger(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	proof := mustProof(t, k, "POST", "https://x/y")
	pb, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pb), `"iat":`) == false {
		t.Fatalf("payload missing iat: %s", pb)
	}
	// The raw payload must not contain a decimal point in the iat value.
	if strings.Contains(string(pb), ".") {
		t.Errorf("payload contains a decimal point (iat not an integer?): %s", pb)
	}
}

func TestSignatureIs64BytesAndVerifiesAcrossManyKeys(t *testing.T) {
	const htu = "https://works.gascity.com/sts/v0/login"
	for i := 0; i < 50; i++ {
		k, err := NewKey()
		if err != nil {
			t.Fatal(err)
		}
		proof := mustProof(t, k, "POST", htu)
		seg := strings.Split(proof, ".")
		sig, err := base64.RawURLEncoding.DecodeString(seg[2])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("sig is %d bytes, must be exactly 64", len(sig))
		}
		hdr, _, _ := parts(t, proof)
		jwk := hdr["jwk"].(map[string]any)
		xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
		yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		digest := sha256.Sum256([]byte(seg[0] + "." + seg[1]))
		if !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatalf("signature failed to verify on iteration %d", i)
		}
	}
}

func TestFreshJTIPerProof(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	_, a, _ := parts(t, mustProof(t, k, "POST", "https://x/y"))
	_, b, _ := parts(t, mustProof(t, k, "POST", "https://x/y"))
	if a["jti"] == b["jti"] {
		t.Errorf("jti reused across proofs: %v", a["jti"])
	}
}

func TestThumbprintStableAndB64URLNoPad(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tp := k.Thumbprint()
	if tp != k.Thumbprint() {
		t.Error("thumbprint not stable across calls")
	}
	if strings.ContainsAny(tp, "=+/") {
		t.Errorf("thumbprint not base64url-no-pad: %q", tp)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tp)
	if err != nil {
		t.Fatalf("thumbprint decode: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("thumbprint decodes to %d bytes, want 32 (SHA-256)", len(raw))
	}
}

func TestPEMRoundtripPreservesKey(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pemStr, err := k.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := FromPEM(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if !jwkEqual(k.PublicJWK(), k2.PublicJWK()) {
		t.Error("public JWK changed across PEM roundtrip")
	}
	if k.Thumbprint() != k2.Thumbprint() {
		t.Errorf("thumbprint changed across PEM roundtrip: %s vs %s", k.Thumbprint(), k2.Thumbprint())
	}
}

func TestGoldenThumbprint(t *testing.T) {
	k, err := FromPEM(goldenPEM)
	if err != nil {
		t.Fatalf("load golden PEM: %v", err)
	}
	if got := k.Thumbprint(); got != goldenJKT {
		t.Fatalf("golden thumbprint drift: got %q, want %q", got, goldenJKT)
	}
}

func TestPublicJWKHasNoPrivateScalar(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk := k.PublicJWK()
	if _, ok := jwk["d"]; ok {
		t.Error("PublicJWK leaked d")
	}
	for _, c := range []string{"x", "y"} {
		raw, err := base64.RawURLEncoding.DecodeString(jwk[c])
		if err != nil {
			t.Fatalf("decode %s: %v", c, err)
		}
		if len(raw) != 32 {
			t.Errorf("%s = %d bytes, want 32", c, len(raw))
		}
	}
}

func mustProof(t *testing.T, k *Key, htm, htu string) string {
	t.Helper()
	p, err := k.Proof(htm, htu)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	return p
}

func jwkEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
