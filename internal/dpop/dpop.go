// Package dpop builds RFC 9449 DPoP proofs over an EC P-256 (ES256) key, plus the
// RFC 7638 thumbprint (jkt).
//
// Two server invariants are enforced here:
//   - the JWS signature must be exactly 64 raw bytes (r||s, 32 each), NOT ASN.1/DER —
//     a compliant ES256 verifier rejects a DER or variable-length signature, so we emit raw r||s.
//   - the STS re-derives the jkt over fixed 32-byte big-endian coordinates and pins it
//     across /login and /token — so we emit fixed-width 32-byte coords and reuse ONE key
//     per session, and we build the canonical JWK as a hand-written fixed-order string
//     (never json.Marshal a map — Go map iteration is randomized and would yield an
//     unstable jkt that breaks the server's jkt-pin).
//
// Every proof gets a fresh jti + iat; proofs are never reused.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// b64url is base64url without padding (RFC 7515 §2).
var b64url = base64.RawURLEncoding

// coord renders a P-256 coordinate as 32-byte big-endian, base64url no padding (the jkt
// input). FillBytes left-pads with zeroes so a coordinate with a zero high byte still
// serializes to exactly 32 bytes.
func coord(n *big.Int) string {
	return b64url.EncodeToString(n.FillBytes(make([]byte, 32)))
}

// Key is a session DPoP key. Generate once per STS session; reuse across login + token.
type Key struct {
	priv *ecdsa.PrivateKey
}

// NewKey generates a fresh P-256 (secp256r1) private key.
func NewKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

// FromPEM loads a key from an unencrypted PKCS8 PEM (the session-persistence format).
func FromPEM(pemStr string) (*Key, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("dpop: no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dpop: PEM is not an EC private key (got %T)", parsed)
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("dpop: key is not on the P-256 curve")
	}
	return &Key{priv: priv}, nil
}

// ToPEM serializes the key as an unencrypted PKCS8 PEM.
func (k *Key) ToPEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// PublicJWK returns the PUBLIC EC JWK embedded in the proof header (never the private d).
func (k *Key) PublicJWK() map[string]string {
	pub := k.priv.PublicKey
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   coord(pub.X),
		"y":   coord(pub.Y),
	}
}

// canonicalJWK is the RFC 7638 canonical JWK for an EC key: the required members in
// lexicographic order, no whitespace. Hand-written on purpose — see the package doc.
func (k *Key) canonicalJWK() string {
	pub := k.priv.PublicKey
	return fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, coord(pub.X), coord(pub.Y))
}

// Thumbprint returns the RFC 7638 jkt: base64url(SHA-256(canonical JWK)), no padding.
func (k *Key) Thumbprint() string {
	sum := sha256.Sum256([]byte(k.canonicalJWK()))
	return b64url.EncodeToString(sum[:])
}

// es256 signs the signing input and returns the raw 64-byte JWS ES256 signature (r||s),
// each coordinate fixed-width 32 bytes big-endian.
func (k *Key) es256(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// jti returns a fresh 16-byte random token, hex-encoded.
func jti() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out), nil
}

// Proof builds a fresh DPoP proof JWT for one request. htu must be the exact STS URL.
// iat is an int64 so encoding/json emits a JSON integer; header/payload key order is
// irrelevant on the wire — the server verifies over the received bytes and never re-derives
// the jkt from the header (that uses canonicalJWK).
func (k *Key) Proof(htm, htu string) (string, error) {
	jwk := k.PublicJWK()

	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": jwk,
	}
	id, err := jti()
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"htm": strings.ToUpper(htm),
		"htu": htu,
		"iat": time.Now().Unix(), // int64 -> JSON integer
		"jti": id,
	}

	hJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	h := b64url.EncodeToString(hJSON)
	p := b64url.EncodeToString(pJSON)
	sig, err := k.es256([]byte(h + "." + p))
	if err != nil {
		return "", err
	}
	s := b64url.EncodeToString(sig)
	return h + "." + p + "." + s, nil
}
