package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

// makeJWT builds an unsigned token with the given payload (the signature segment is junk —
// these helpers never verify it).
func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pj, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(pj)
	return header + "." + body + ".sig"
}

func TestDecodeClaims(t *testing.T) {
	tok := makeJWT(t, map[string]any{"sub": "usr_1", "nonce": "abc", "exp": 1700000000})
	claims, err := DecodeClaims(tok)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if claims["sub"] != "usr_1" || claims["nonce"] != "abc" {
		t.Errorf("claims = %v", claims)
	}
}

func TestDecodeClaimsNoPadding(t *testing.T) {
	// A payload whose base64 length is not a multiple of 4 must still decode (nopad).
	tok := makeJWT(t, map[string]any{"a": "b"})
	if _, err := DecodeClaims(tok); err != nil {
		t.Fatalf("nopad decode: %v", err)
	}
}

func TestDecodeClaimsNotAJWT(t *testing.T) {
	if _, err := DecodeClaims("notajwt"); err == nil {
		t.Error("expected error for single-segment token")
	}
}

func TestAudiences(t *testing.T) {
	cases := []struct {
		name   string
		aud    any
		expect []string
	}{
		{"string", "manifold", []string{"manifold"}},
		{"list", []any{"a", "b"}, []string{"a", "b"}},
		{"empty-string", "", nil},
		{"missing", nil, nil},
		{"list-with-nonstring", []any{"a", 7, "b"}, []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := map[string]any{}
			if c.aud != nil {
				claims["aud"] = c.aud
			}
			got := Audiences(claims)
			if !reflect.DeepEqual(got, c.expect) {
				t.Errorf("Audiences(%v) = %v, want %v", c.aud, got, c.expect)
			}
		})
	}
}

func TestExp(t *testing.T) {
	// JSON numbers decode to float64.
	claims := map[string]any{"exp": float64(1700000000)}
	if got := Exp(claims); got != 1700000000 {
		t.Errorf("Exp = %d, want 1700000000", got)
	}
	if got := Exp(map[string]any{}); got != 0 {
		t.Errorf("Exp(missing) = %d, want 0", got)
	}
}

// TestExpFromRealDecode exercises the real DecodeClaims->Exp path so the float64 coercion is
// covered end to end.
func TestExpFromRealDecode(t *testing.T) {
	tok := makeJWT(t, map[string]any{"exp": 1734000000})
	claims, err := DecodeClaims(tok)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if got := Exp(claims); got != 1734000000 {
		t.Errorf("Exp = %d, want 1734000000", got)
	}
}
