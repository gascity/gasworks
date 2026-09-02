package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// eiaWithAuthnContext builds a cached assertion carrying the Auth Access v1 authentication
// context claims `gasworks inspect` exists to surface.
func eiaWithAuthnContext(authTime, exp int64) string {
	return fakeJWT(map[string]any{
		"iss": "https://api.gascity.com/sts/v0", "sub": "kc-1", "aud": []string{"manifold"},
		"org_id": "org_a", "subject_type": "user", "session_id": "ses_1",
		"authn_class": "human", "auth_time": authTime, "acr": "silver", "amr": []string{"pwd", "otp"},
		"placement_class": "eu", "iat": exp - 90, "exp": exp,
	})
}

func TestInspectReportsTheAuthenticationContextOfACachedEIA(t *testing.T) {
	srv := newStub(t)
	authTime := time.Now().Unix() - 300
	exp := time.Now().Unix() + 80
	eia := eiaWithAuthnContext(authTime, exp)
	srv.eiaResponse = map[string]any{
		"access_token": eia, "token_type": "DPoP", "expires_in": 90,
		"scope": "manifold:proxy manifold:pool:acme",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	out, errOut, code := capture(t, func() int { return run([]string{"inspect"}) })
	if code != 0 {
		t.Fatalf("inspect exit=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{
		"authn_class", "human", "auth_time", "acr", "silver", "amr", "pwd otp",
		"session_id", "ses_1", "audience manifold", "manifold:pool:acme",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect output does not report %q:\n%s", want, out)
		}
	}
	// Inspection prints claims, never credentials.
	if strings.Contains(out, eia) {
		t.Fatal("inspect printed the cached EIA itself")
	}
	if strings.Contains(out, "RT") && strings.Contains(out, "refresh_token") {
		t.Fatal("inspect printed refresh-token material")
	}
}

func TestInspectReportsWhereTheSessionKeyLives(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	out, _, code := capture(t, func() int { return run([]string{"inspect"}) })
	if code != 0 {
		t.Fatalf("inspect exit=%d", code)
	}
	data := loadStore(t)
	var ref string
	for _, session := range data.Sessions {
		ref = session.Key.Backend + ":" + session.Key.Handle
	}
	if !strings.Contains(out, ref) {
		t.Errorf("inspect does not name the key location %q:\n%s", ref, out)
	}
	if !strings.Contains(out, "jkt") {
		t.Errorf("inspect does not report the session key thumbprint:\n%s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("inspect printed key material")
	}
}

func TestInspectJSONIsMachineReadable(t *testing.T) {
	srv := newStub(t)
	exp := time.Now().Unix() + 80
	srv.eiaResponse = map[string]any{
		"access_token": eiaWithAuthnContext(time.Now().Unix()-300, exp), "token_type": "DPoP",
		"expires_in": 90, "scope": "manifold:proxy manifold:pool:acme",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	out, errOut, code := capture(t, func() int { return run([]string{"inspect", "--json"}) })
	if code != 0 {
		t.Fatalf("inspect --json exit=%d stderr=%q", code, errOut)
	}
	var report inspection
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("inspect --json is not valid JSON: %v\n%s", err, out)
	}
	if !report.LoggedIn || report.Login == nil || report.Login.Subject != "kc-1" {
		t.Fatalf("login block = %+v, want the decoded id_token subject", report.Login)
	}
	if len(report.CachedEIAs) != 1 || report.CachedEIAs[0].Claims == nil {
		t.Fatalf("cached EIAs = %+v, want one with decoded claims", report.CachedEIAs)
	}
	claims := report.CachedEIAs[0].Claims
	if claims.AuthnClass != "human" || claims.ACR != "silver" || len(claims.AMR) != 2 || claims.AuthTime == "" {
		t.Fatalf("claims = %+v, want the full authentication context", claims)
	}
	if report.RefreshPolicy.Owner != "sdk" || report.RefreshPolicy.EIARemintAtSeconds != eiaSkewSecs {
		t.Fatalf("refresh policy = %+v, want the SDK-owned thresholds", report.RefreshPolicy)
	}
	if len(report.Keystores) == 0 {
		t.Fatal("inspect --json reports no credential stores")
	}
}

func TestInspectOnAnOpaqueCachedCredentialSaysSoInsteadOfFailing(t *testing.T) {
	srv := newStub(t) // the default stub mints the opaque "EIA.JWT"
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	out, _, code := capture(t, func() int { return run([]string{"inspect"}) })
	if code != 0 {
		t.Fatalf("inspect exit=%d", code)
	}
	if !strings.Contains(out, "not a decodable assertion") {
		t.Errorf("inspect does not flag the undecodable credential:\n%s", out)
	}
}

func TestInspectWhenLoggedOut(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, nil)

	out, errOut, code := capture(t, func() int { return run([]string{"inspect"}) })
	if code != 0 {
		t.Fatalf("inspect exit=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "not logged in") {
		t.Errorf("inspect output = %q, want the logged-out hint", out)
	}
	// The credential-store registry is still reported: it is what tells an operator whether
	// this host can enrol a key at all.
	if !strings.Contains(out, "dpop keys") {
		t.Errorf("inspect does not report the credential-store registry:\n%s", out)
	}
}
