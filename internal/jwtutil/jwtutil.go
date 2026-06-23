// Package jwtutil reads JWT claims WITHOUT verifying the signature.
//
// The CLI never verifies a JWT signature itself — the STS verifies the subject_token and
// products verify the EIA offline. These helpers are only for reading claims (whoami, the
// id_token nonce/aud assertions, expiry checks).
package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// b64url is base64url WITHOUT padding (RFC 7515 §2); matches Python's urlsafe_b64decode
// after the explicit pad strip.
var b64url = base64.RawURLEncoding

// DecodeClaims decodes a JWT payload (the middle segment) WITHOUT verifying the signature.
func DecodeClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("jwtutil: not a JWT")
	}
	raw, err := b64url.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Audiences normalizes the `aud` claim (a string OR a list of strings, per RFC 7519) into a
// slice. A missing or empty aud yields nil; non-string list members are skipped.
func Audiences(claims map[string]any) []string {
	switch v := claims["aud"].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Issuer returns the `iss` claim as a string, or "" if absent/non-string.
func Issuer(claims map[string]any) string {
	if s, ok := claims["iss"].(string); ok {
		return s
	}
	return ""
}

// Exp returns the `exp` claim as a Unix timestamp, or 0 if absent/non-numeric. JSON numbers
// decode to float64, so a fractional exp truncates toward zero.
func Exp(claims map[string]any) int64 {
	switch v := claims["exp"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	default:
		return 0
	}
}
