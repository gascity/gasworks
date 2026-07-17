package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/store"
)

const credentialProviderVersion = "gascity.dev/credential-provider/v1"

const (
	testCredentialGenerationA = "g1:00000000000000000000000000000001"
	testCredentialGenerationB = "g1:00000000000000000000000000000002"
)

type credentialProviderTestResponse struct {
	Version             string   `json:"version"`
	Kind                string   `json:"kind"`
	AccessToken         string   `json:"access_token"`
	AuthorizationScheme string   `json:"authorization_scheme"`
	ExpiresAt           string   `json:"expires_at"`
	Audience            string   `json:"audience"`
	Scopes              []string `json:"scopes"`
	Code                string   `json:"code"`
	Message             string   `json:"message"`
}

func runCredentialProvider(t *testing.T, request string) (credentialProviderTestResponse, string, int) {
	return runCredentialProviderCommand(t, []string{"credential-provider"}, request)
}

func runCredentialProviderCommand(t *testing.T, argv []string, request string) (credentialProviderTestResponse, string, int) {
	t.Helper()
	out, errOut, code := runCredentialProviderCommandRaw(t, argv, request)
	response := decodeProcessResponse(t, out)
	return response, errOut, code
}

func runCredentialProviderCommandRaw(t *testing.T, argv []string, request string) (string, string, int) {
	t.Helper()

	originalStdin := stdin
	stdin = strings.NewReader(request)
	defer func() { stdin = originalStdin }()

	out, errOut, code := capture(t, func() int { return run(argv) })
	return out, errOut, code
}

func TestCredentialProviderRejectsCommandArguments(t *testing.T) {
	response, errOut, code := runCredentialProviderCommand(
		t,
		[]string{"credential-provider", "--org", "acme"},
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"]}`,
	)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != "invalid_request" {
		t.Fatalf("argument response = exit %d stderr %q %+v", code, errOut, response)
	}
}

func TestCredentialProviderMintsRequestedScopes(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	freezeNow(t, fixedNow)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	request := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"org":"",
		"force_refresh":false,
		"interactive":false
	}`
	response, errOut, code := runCredentialProvider(t, request)

	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d stderr=%q, want clean success", code, errOut)
	}
	if response.Version != credentialProviderVersion || response.Kind != "Credential" {
		t.Fatalf("response identity = version %q kind %q", response.Version, response.Kind)
	}
	if response.AccessToken != "EIA.JWT" || response.AuthorizationScheme != "Bearer" {
		t.Fatalf("credential = token %q scheme %q", response.AccessToken, response.AuthorizationScheme)
	}
	if response.Audience != "manifold" || !slices.Equal(response.Scopes, []string{"manifold:proxy"}) {
		t.Fatalf("authority = audience %q scopes %v", response.Audience, response.Scopes)
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at = %q: %v", response.ExpiresAt, err)
	}
	if !expiresAt.Equal(fixedNow.Add(90 * time.Second)) {
		t.Fatalf("expires_at = %s, want %s", expiresAt, fixedNow.Add(90*time.Second))
	}

	mints := srv.reqs("/sts/v0/token")
	if len(mints) != 1 || mints[0].form.Get("scope") != "manifold:proxy" {
		t.Fatalf("mint requests = %+v, want only required scope", mints)
	}
}

func TestCredentialProviderForceRefreshBypassesCache(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
				"eia": "CACHED.EIA", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
		},
	})

	response, _, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"force_refresh":true,
		"interactive":false
	}`)

	if code != 0 || response.AccessToken != "EIA.JWT" {
		t.Fatalf("force-refresh response = code %d %+v", code, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("force refresh made %d token requests", mints)
	}
}

func TestCredentialProviderFailedForceRefreshInvalidatesRejectedCache(t *testing.T) {
	srv := newStub(t)
	srv.eiaResponse = map[string]any{
		"access_token": "INVALID.EIA",
		"scope":        "manifold:proxy",
	}
	cacheKey := eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"})
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			cacheKey: map[string]any{
				"eia": "REJECTED.EIA", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
		},
	})
	request := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"force_refresh":true,
		"interactive":false
	}`

	if response, _, code := runCredentialProvider(t, request); code == 0 || response.Kind != "Error" {
		t.Fatalf("failed forced refresh = exit %d %+v", code, response)
	}
	srv.eiaResponse = nil
	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", "manifold:proxy"})
	})
	if code != 0 || errOut != "" || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("ordinary retry = exit %d stdout %q stderr %q", code, out, errOut)
	}
	if strings.Contains(out, "REJECTED.EIA") {
		t.Fatal("rejected cached credential was reused")
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 2 {
		t.Fatalf("mint requests = %d, want failed force plus ordinary retry", mints)
	}
}

func TestCredentialProviderRejectsMissingExpiry(t *testing.T) {
	srv := newStub(t)
	srv.eiaResponse = map[string]any{
		"access_token": "EIA.JWT",
		"scope":        "manifold:proxy",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)

	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != "temporarily_unavailable" {
		t.Fatalf("missing-expiry response = exit %d stderr %q %+v", code, errOut, response)
	}
	if strings.Contains(response.Message, "EIA.JWT") {
		t.Fatalf("error leaked token: %+v", response)
	}
}

func TestCredentialProviderRejectsMixedAllowedAndForbiddenScopes(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy","manifold:admin"],
		"interactive":false
	}`)

	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != "access_denied" {
		t.Fatalf("mixed-scope response = exit %d stderr %q %+v", code, errOut, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 0 {
		t.Fatalf("denied mixed scopes made %d token requests", mints)
	}
}

func TestCredentialProviderRejectsUnexpectedGrantedScope(t *testing.T) {
	srv := newStub(t)
	srv.eiaResponse = map[string]any{
		"access_token": "EIA.JWT",
		"expires_in":   90,
		"scope":        "manifold:proxy manifold:admin",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	request := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`
	response, errOut, code := runCredentialProvider(t, request)

	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != "access_denied" {
		t.Fatalf("widened-grant response = exit %d stderr %q %+v", code, errOut, response)
	}
	if response.AccessToken != "" || strings.Contains(response.Message, "EIA.JWT") {
		t.Fatalf("widened grant leaked a credential: %+v", response)
	}

	srv.eiaResponse = nil
	response, errOut, code = runCredentialProvider(t, request)
	if code != 0 || errOut != "" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("retry after widened grant = exit %d stderr %q %+v", code, errOut, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 2 {
		t.Fatalf("widened grant was cached: token requests = %d, want 2", mints)
	}
}

func TestCredentialProviderIgnoresMalformedCachedCredential(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
				"eia": "  ", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
		},
	})

	response, _, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)

	if code != 0 || response.AccessToken != "EIA.JWT" {
		t.Fatalf("malformed-cache response = exit %d %+v", code, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("malformed cache made %d token requests", mints)
	}
}

func TestCredentialProviderDoesNotReuseLegacyCacheAfterAudienceRemap(t *testing.T) {
	srv := newStub(t)
	srv.productAudience = "manifold-v2"
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
				"eia": "OLD-AUDIENCE.EIA", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
			"org_a|manifold|manifold:proxy": map[string]any{
				"eia": "LEGACY.EIA", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
		},
	})

	response, _, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold-v2",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)

	if code != 0 || response.AccessToken != "EIA.JWT" || response.Audience != "manifold-v2" {
		t.Fatalf("remapped response = exit %d %+v", code, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("audience remap made %d token requests", mints)
	}
	if audience := srv.reqs("/sts/v0/token")[0].form.Get("audience"); audience != "manifold-v2" {
		t.Fatalf("audience remap minted for %q, want manifold-v2", audience)
	}
}

func TestCredentialProviderClassifiesRefreshFailures(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		oauthError string
		wantCode   string
	}{
		{name: "terminal rejection", status: 400, oauthError: "invalid_grant", wantCode: "interaction_required"},
		{name: "transient service failure", status: 503, oauthError: "temporarily_unavailable", wantCode: "temporarily_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newStub(t)
			srv.refreshHandler = func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, tt.status, map[string]any{"error": tt.oauthError, "error_description": "UPSTREAM-SECRET"})
			}
			seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": expiredIDToken()})

			response, errOut, code := runCredentialProvider(t, `{
				"version":"gascity.dev/credential-provider/v1",
				"audience":"manifold",
				"required_scopes":["manifold:proxy"],
				"interactive":false
			}`)

			if code == 0 || errOut != "" || response.Code != tt.wantCode {
				t.Fatalf("refresh failure = exit %d stderr %q %+v", code, errOut, response)
			}
			encoded, _ := json.Marshal(response)
			if strings.Contains(string(encoded), "UPSTREAM-SECRET") {
				t.Fatalf("refresh failure leaked upstream body: %s", encoded)
			}
		})
	}
}

func TestCredentialProviderClassifiesSessionAndExchangeFailures(t *testing.T) {
	const request = `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`
	assertError := func(t *testing.T, srv *stubServer, wantCode, secret string, wantLogins, wantExchanges int) {
		t.Helper()
		out, errOut, code := runCredentialProviderCommandRaw(t, []string{"credential-provider"}, request)
		response := decodeProcessResponse(t, out)
		if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != wantCode {
			t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
		}
		if strings.Contains(out+errOut, secret) || response.AccessToken != "" {
			t.Fatalf("response leaked secret or credential: stdout=%q stderr=%q", out, errOut)
		}
		if logins := len(srv.reqs("/sts/v0/login")); logins != wantLogins {
			t.Fatalf("login requests = %d, want %d", logins, wantLogins)
		}
		if exchanges := len(srv.reqs("/sts/v0/token")); exchanges != wantExchanges {
			t.Fatalf("exchange requests = %d, want %d", exchanges, wantExchanges)
		}
		if entries := len(loadStore(t).EIACache); entries != 0 {
			t.Fatalf("failed request cached %d credentials", entries)
		}
	}

	for _, test := range []struct {
		name     string
		status   int
		wantCode string
	}{
		{name: "login forbidden", status: http.StatusForbidden, wantCode: credentialErrorDenied},
		{name: "login unavailable", status: http.StatusInternalServerError, wantCode: credentialErrorUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			const secret = "LOGIN-UPSTREAM-SECRET"
			srv := newStub(t)
			srv.loginHandler = func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, test.status, map[string]any{"error": "rejected", "error_description": secret})
			}
			seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
			assertError(t, srv, test.wantCode, secret, 1, 0)
		})
	}

	for _, test := range []struct {
		name          string
		status        int
		wantCode      string
		wantExchanges int
	}{
		{name: "exchange forbidden", status: http.StatusForbidden, wantCode: credentialErrorDenied, wantExchanges: 1},
		{name: "exchange unavailable", status: http.StatusInternalServerError, wantCode: credentialErrorUnavailable, wantExchanges: 1},
		{name: "exchange retry rejected", status: http.StatusUnauthorized, wantCode: credentialErrorUnavailable, wantExchanges: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			const secret = "EXCHANGE-UPSTREAM-SECRET"
			srv := newStub(t)
			srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, test.status, map[string]any{"error": "rejected", "error_description": secret})
			}
			seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
			wantLogins := 1
			if test.status == http.StatusUnauthorized {
				wantLogins = 2
			}
			assertError(t, srv, test.wantCode, secret, wantLogins, test.wantExchanges)
		})
	}

	t.Run("401 retry succeeds", func(t *testing.T) {
		srv := newStub(t)
		var exchanges atomic.Int32
		srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
			if exchanges.Add(1) == 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "expired", "error_description": "FIRST-SECRET"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "RETRIED.EIA", "expires_in": 90, "scope": form.Get("scope"),
			})
		}
		seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
		out, errOut, code := runCredentialProviderCommandRaw(t, []string{"credential-provider"}, request)
		response := decodeProcessResponse(t, out)
		if code != 0 || errOut != "" || response.Kind != "Credential" || response.AccessToken != "RETRIED.EIA" || strings.Contains(out, "FIRST-SECRET") {
			t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
		}
		if logins := len(srv.reqs("/sts/v0/login")); logins != 2 {
			t.Fatalf("login requests = %d, want 2", logins)
		}
		if got := exchanges.Load(); got != 2 {
			t.Fatalf("exchange requests = %d, want 2", got)
		}
		if entries := len(loadStore(t).EIACache); entries != 1 {
			t.Fatalf("successful retry cached %d credentials, want 1", entries)
		}
	})

	t.Run("401 retry forbidden", func(t *testing.T) {
		const secret = "RETRY-FORBIDDEN-SECRET"
		srv := newStub(t)
		var exchanges atomic.Int32
		srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
			status := http.StatusUnauthorized
			if exchanges.Add(1) == 2 {
				status = http.StatusForbidden
			}
			writeJSON(w, status, map[string]any{"error": "rejected", "error_description": secret})
		}
		seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
		assertError(t, srv, credentialErrorDenied, secret, 2, 2)
	})
}

func TestCredentialProviderRejectsRefreshWithoutIDToken(t *testing.T) {
	srv := newStub(t)
	srv.refreshTok = map[string]any{"refresh_token": "RT-ROTATED"}
	seed(t, srv, map[string]any{"refresh_token": "RT-OLD", "id_token": expiredIDToken()})

	out, errOut, code := runCredentialProviderCommandRaw(t, []string{"credential-provider"}, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	response := decodeProcessResponse(t, out)
	if code == 0 || errOut != "" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	if refreshes := len(srv.reqs("/protocol/openid-connect/token")); refreshes != 1 {
		t.Fatalf("refresh requests = %d, want 1", refreshes)
	}
	credentials := loadStore(t)
	if credentials.RefreshToken != "RT-OLD" || len(credentials.EIACache) != 0 {
		t.Fatalf("failed refresh changed durable credentials: %+v", credentials)
	}
}

func TestCredentialProviderRequiresOrgForAmbiguousAccount(t *testing.T) {
	srv := newStub(t)
	srv.contextResponse = map[string]any{
		"user_id": "usr_1",
		"orgs": []any{
			map[string]any{"org_id": "org_a", "slug": "a", "products": map[string]any{"manifold": map[string]any{"audience": "manifold", "scopes": []string{"manifold:proxy"}}}},
			map[string]any{"org_id": "org_b", "slug": "b", "products": map[string]any{"manifold": map[string]any{"audience": "manifold", "scopes": []string{"manifold:proxy"}}}},
		},
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if code == 0 || errOut != "" || response.Code != credentialErrorInvalid {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	if logins := len(srv.reqs("/sts/v0/login")); logins != 0 {
		t.Fatalf("ambiguous account made %d login requests", logins)
	}
	if exchanges := len(srv.reqs("/sts/v0/token")); exchanges != 0 {
		t.Fatalf("ambiguous account made %d exchange requests", exchanges)
	}
	if entries := len(loadStore(t).EIACache); entries != 0 {
		t.Fatalf("ambiguous account cached %d credentials", entries)
	}
}

func TestCredentialProviderExpiryUsesExchangeStartTime(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(fixedNow.Unix())
	originalNow := now
	now = clock.Load
	t.Cleanup(func() { now = originalNow })
	srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		clock.Add(30)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "EIA.JWT", "expires_in": 90, "scope": form.Get("scope"),
		})
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if code != 0 || errOut != "" || response.ExpiresAt != fixedNow.Add(90*time.Second).Format(time.RFC3339) {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
}

func TestCredentialProviderRejectsCredentialExpiredInTransit(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(fixedNow.Unix())
	originalNow := now
	now = clock.Load
	t.Cleanup(func() { now = originalNow })
	srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		clock.Add(90)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "EXPIRED.EIA", "expires_in": 60, "scope": form.Get("scope"),
		})
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if code == 0 || errOut != "" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	if entries := len(loadStore(t).EIACache); entries != 0 {
		t.Fatalf("expired response cached %d credentials", entries)
	}
}

func TestCredentialProviderRejectsOverflowingExpiry(t *testing.T) {
	srv := newStub(t)
	srv.eiaResponse = map[string]any{
		"access_token": "EIA.JWT",
		"expires_in":   int64(math.MaxInt64 - (1 << 20)),
		"scope":        "manifold:proxy",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if code == 0 || errOut != "" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	if entries := len(loadStore(t).EIACache); entries != 0 {
		t.Fatalf("overflowing response cached %d credentials", entries)
	}
}

func TestCredentialProviderReportsCachedAbsoluteExpiry(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	freezeNow(t, fixedNow)
	expiresAt := fixedNow.Add(45 * time.Second)
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
				"eia": "CACHED.EIA", "expires_at": expiresAt.Unix(),
			},
		},
	})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)

	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d stderr=%q, want clean cache hit", code, errOut)
	}
	if response.AccessToken != "CACHED.EIA" || response.ExpiresAt != expiresAt.Format(time.RFC3339) {
		t.Fatalf("cached response = token %q expires_at %q", response.AccessToken, response.ExpiresAt)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 0 {
		t.Fatalf("cache hit made %d token requests", mints)
	}
}

func TestCredentialProviderCacheFreshnessBoundary(t *testing.T) {
	fixedNow := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name          string
		remaining     time.Duration
		wantToken     string
		wantExpiresAt time.Time
		wantMints     int
	}{
		{
			name:          "at skew remints",
			remaining:     time.Duration(eiaSkewSecs) * time.Second,
			wantToken:     "EIA.JWT",
			wantExpiresAt: fixedNow.Add(90 * time.Second),
			wantMints:     1,
		},
		{
			name:          "one second above skew hits",
			remaining:     time.Duration(eiaSkewSecs+1) * time.Second,
			wantToken:     "CACHED.EIA",
			wantExpiresAt: fixedNow.Add(time.Duration(eiaSkewSecs+1) * time.Second),
			wantMints:     0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := newStub(t)
			freezeNow(t, fixedNow)
			seed(t, srv, map[string]any{
				"refresh_token": "RT",
				"id_token":      validIDToken(),
				"eia_cache": map[string]any{
					eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
						"eia": "CACHED.EIA", "expires_at": fixedNow.Add(test.remaining).Unix(),
					},
				},
			})

			response, errOut, code := runCredentialProvider(t, `{
				"version":"gascity.dev/credential-provider/v1",
				"audience":"manifold",
				"required_scopes":["manifold:proxy"],
				"interactive":false
			}`)
			if code != 0 || errOut != "" || response.AccessToken != test.wantToken ||
				response.ExpiresAt != test.wantExpiresAt.Format(time.RFC3339) {
				t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
			}
			if mints := len(srv.reqs("/sts/v0/token")); mints != test.wantMints {
				t.Fatalf("mint requests = %d, want %d", mints, test.wantMints)
			}
		})
	}
}

func TestCredentialProviderDoesNotReuseCacheAcrossSTSAuthorities(t *testing.T) {
	first := newStub(t)
	first.eiaResponse = map[string]any{
		"access_token": "FIRST.EIA", "expires_in": 90, "scope": "manifold:proxy",
	}
	seed(t, first, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	request := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`
	if response, errOut, code := runCredentialProvider(t, request); code != 0 || errOut != "" || response.AccessToken != "FIRST.EIA" {
		t.Fatalf("first authority = exit %d stderr %q %+v", code, errOut, response)
	}

	second := newStub(t)
	second.eiaResponse = map[string]any{
		"access_token": "SECOND.EIA", "expires_in": 90, "scope": "manifold:proxy",
	}
	t.Setenv("GASWORKS_STS_URL", second.srv.URL+"/")
	t.Setenv("GASWORKS_OIDC_ISSUER", second.srv.URL+"/realms/g")
	response, errOut, code := runCredentialProvider(t, request)
	if code != 0 || errOut != "" || response.AccessToken != "SECOND.EIA" {
		t.Fatalf("second authority = exit %d stderr %q %+v", code, errOut, response)
	}
	if mints := len(second.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("second authority made %d mint requests, want 1", mints)
	}
	if logins := len(second.reqs("/sts/v0/login")); logins != 1 {
		t.Fatalf("second authority made %d login requests, want an authority-local session", logins)
	}
}

func TestCredentialProviderPrunesObsoleteCacheEntriesOnMint(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	freezeNow(t, fixedNow)
	requestKey := eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"})
	expiredKey := eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:pool:acme"})
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			"org_a|manifold|manifold:proxy": map[string]any{
				"eia": "LEGACY.EIA", "expires_at": fixedNow.Add(time.Hour).Unix(),
			},
			requestKey: map[string]any{
				"eia": "EXPIRED.EIA", "expires_at": fixedNow.Unix(),
			},
			expiredKey: map[string]any{
				"eia": "OTHER-EXPIRED.EIA", "expires_at": fixedNow.Add(-time.Second).Unix(),
			},
		},
	})

	response, errOut, code := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if code != 0 || errOut != "" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	cache := loadStore(t).EIACache
	if len(cache) != 1 || cache[requestKey].EIA != "EIA.JWT" {
		t.Fatalf("pruned cache = %+v, want only fresh requested credential", cache)
	}
}

func TestCredentialProviderScopeOrderSharesCacheEntry(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	first := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy","manifold:pool:acme"],
		"interactive":false
	}`
	second := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:pool:acme","manifold:proxy"],
		"interactive":false
	}`
	if response, _, code := runCredentialProvider(t, first); code != 0 || response.AccessToken == "" {
		t.Fatalf("first request = exit %d %+v", code, response)
	}
	if response, _, code := runCredentialProvider(t, second); code != 0 || response.AccessToken == "" {
		t.Fatalf("second request = exit %d %+v", code, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("scope-order requests made %d mints", mints)
	}
}

func TestCredentialProviderSharesCacheWithGetToken(t *testing.T) {
	providerRequest := `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`
	tests := []struct {
		name  string
		first func(*testing.T)
		last  func(*testing.T)
	}{
		{
			name: "getToken then provider",
			first: func(t *testing.T) {
				if _, errOut, code := capture(t, func() int {
					return run([]string{"getToken", "manifold", "--scope", "manifold:proxy"})
				}); code != 0 || errOut != "" {
					t.Fatalf("getToken = exit %d stderr %q", code, errOut)
				}
			},
			last: func(t *testing.T) {
				if response, errOut, code := runCredentialProvider(t, providerRequest); code != 0 || errOut != "" || response.AccessToken != "EIA.JWT" {
					t.Fatalf("provider = exit %d stderr %q %+v", code, errOut, response)
				}
			},
		},
		{
			name: "provider then getToken",
			first: func(t *testing.T) {
				if response, errOut, code := runCredentialProvider(t, providerRequest); code != 0 || errOut != "" || response.AccessToken != "EIA.JWT" {
					t.Fatalf("provider = exit %d stderr %q %+v", code, errOut, response)
				}
			},
			last: func(t *testing.T) {
				if out, errOut, code := capture(t, func() int {
					return run([]string{"getToken", "manifold", "--scope", "manifold:proxy"})
				}); code != 0 || errOut != "" || strings.TrimSpace(out) != "EIA.JWT" {
					t.Fatalf("getToken = exit %d stdout %q stderr %q", code, out, errOut)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newStub(t)
			seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

			tt.first(t)
			tt.last(t)

			if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
				t.Fatalf("cross-entry-point requests made %d mints", mints)
			}
			if entries := len(loadStore(t).EIACache); entries != 1 {
				t.Fatalf("cache entries = %d, want 1", entries)
			}
		})
	}
}

func TestCredentialProviderErrorsAreTypedAndSecretSafe(t *testing.T) {
	tests := []struct {
		name    string
		creds   map[string]any
		request string
		code    string
	}{
		{
			name: "unsupported version",
			request: `{"version":"v0","audience":"manifold",` +
				`"required_scopes":["manifold:proxy"],"interactive":false}`,
			code: "invalid_request",
		},
		{
			name: "interactive invocation",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:proxy"],"interactive":true}`,
			code: "invalid_request",
		},
		{
			name: "unknown field",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:proxy"],"interactive":false,"token":"forged"}`,
			code: "invalid_request",
		},
		{
			name:    "trailing JSON",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"]}{}`,
			code:    "invalid_request",
		},
		{
			name:    "empty input",
			request: "",
			code:    "invalid_request",
		},
		{
			name:    "truncated JSON",
			request: `{"version":"gascity.dev/credential-provider/v1"`,
			code:    "invalid_request",
		},
		{
			name: "duplicate scope",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:proxy","manifold:proxy"],"interactive":false}`,
			code: "invalid_request",
		},
		{
			name: "duplicate field",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"audience":"crucible","required_scopes":["manifold:proxy"],"interactive":false}`,
			code: "invalid_request",
		},
		{
			name: "case variant field",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"Audience":"crucible","required_scopes":["manifold:proxy"],"interactive":false}`,
			code: "invalid_request",
		},
		{
			name: "oversized request",
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"` +
				strings.Repeat("a", credentialRequestMaxBytes) + `","required_scopes":["manifold:proxy"]}`,
			code: "invalid_request",
		},
		{
			name:  "login required",
			creds: map[string]any{},
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:proxy"],"interactive":false}`,
			code: "interaction_required",
		},
		{
			name:  "org access denied",
			creds: map[string]any{"refresh_token": "RT", "id_token": validIDToken()},
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:proxy"],"org":"other","interactive":false}`,
			code: "access_denied",
		},
		{
			name:  "scope access denied",
			creds: map[string]any{"refresh_token": "RT", "id_token": validIDToken()},
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold",` +
				`"required_scopes":["manifold:admin"],"interactive":false}`,
			code: "access_denied",
		},
		{
			name:  "audience access denied",
			creds: map[string]any{"refresh_token": "RT", "id_token": validIDToken()},
			request: `{"version":"gascity.dev/credential-provider/v1","audience":"crucible",` +
				`"required_scopes":["crucible:sandbox.read"],"interactive":false}`,
			code: "access_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newStub(t)
			seed(t, srv, tt.creds)

			response, errOut, code := runCredentialProvider(t, tt.request)

			if code == 0 {
				t.Fatal("exit=0, want failure")
			}
			if errOut != "" {
				t.Fatalf("stderr=%q, want structured stdout only", errOut)
			}
			if response.Version != credentialProviderVersion || response.Kind != "Error" || response.Code != tt.code {
				t.Fatalf("error response = %+v", response)
			}
			if response.Message == "" || strings.Contains(response.Message, "forged") || response.AccessToken != "" {
				t.Fatalf("error is not secret-safe: %+v", response)
			}
		})
	}
}

func TestCredentialProviderRequestSizeBoundary(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`
	atLimit := request + strings.Repeat(" ", credentialRequestMaxBytes-len(request))

	if response, errOut, code := runCredentialProvider(t, atLimit); code != 0 || errOut != "" || response.Kind != "Credential" {
		t.Fatalf("at-limit response = exit %d stderr %q %+v", code, errOut, response)
	}
	contextCalls := len(srv.reqs("/sts/v0/context"))
	loginCalls := len(srv.reqs("/sts/v0/login"))
	tokenCalls := len(srv.reqs("/sts/v0/token"))
	response, errOut, code := runCredentialProvider(t, atLimit+" ")
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != "invalid_request" {
		t.Fatalf("over-limit response = exit %d stderr %q %+v", code, errOut, response)
	}
	if len(srv.reqs("/sts/v0/context")) != contextCalls ||
		len(srv.reqs("/sts/v0/login")) != loginCalls ||
		len(srv.reqs("/sts/v0/token")) != tokenCalls {
		t.Fatal("over-limit request reached an upstream endpoint")
	}
}

func TestDecodeCredentialProviderRequestBoundaries(t *testing.T) {
	decode := func(t *testing.T, request string) (credentialProviderRequest, error) {
		t.Helper()
		originalStdin := stdin
		stdin = strings.NewReader(request)
		defer func() { stdin = originalStdin }()
		return decodeCredentialProviderRequest(nil)
	}
	encode := func(t *testing.T, request any) string {
		t.Helper()
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		return string(encoded)
	}

	maxScopes := make([]string, credentialScopeMaxCount)
	for index := range maxScopes {
		maxScopes[index] = "scope:" + strings.Repeat("x", index+1)
	}
	maxScopes[len(maxScopes)-1] = strings.Repeat("s", credentialValueMaxBytes)
	atLimits := credentialProviderRequest{
		Version:        credentialProviderVersion,
		Audience:       strings.Repeat("a", credentialValueMaxBytes),
		RequiredScopes: maxScopes,
		Org:            strings.Repeat("o", credentialValueMaxBytes),
	}
	decoded, err := decode(t, encode(t, atLimits))
	if err != nil {
		t.Fatalf("decode values at limits: %v", err)
	}
	if len(decoded.RequiredScopes) != credentialScopeMaxCount ||
		len(decoded.Audience) != credentialValueMaxBytes ||
		len(decoded.Org) != credentialValueMaxBytes {
		t.Fatalf("decoded limits = audience %d org %d scopes %d", len(decoded.Audience), len(decoded.Org), len(decoded.RequiredScopes))
	}

	valid := func() map[string]any {
		return map[string]any{
			"version":         credentialProviderVersion,
			"audience":        "manifold",
			"required_scopes": []string{"manifold:proxy"},
			"interactive":     false,
		}
	}
	tests := []struct {
		name    string
		request string
	}{
		{name: "65 scopes", request: func() string {
			request := valid()
			scopes := make([]string, credentialScopeMaxCount+1)
			for index := range scopes {
				scopes[index] = "scope:" + strings.Repeat("x", index+1)
			}
			request["required_scopes"] = scopes
			return encode(t, request)
		}()},
		{name: "513 byte audience", request: func() string {
			request := valid()
			request["audience"] = strings.Repeat("a", credentialValueMaxBytes+1)
			return encode(t, request)
		}()},
		{name: "513 byte org", request: func() string {
			request := valid()
			request["org"] = strings.Repeat("o", credentialValueMaxBytes+1)
			return encode(t, request)
		}()},
		{name: "513 byte scope", request: func() string {
			request := valid()
			request["required_scopes"] = []string{strings.Repeat("s", credentialValueMaxBytes+1)}
			return encode(t, request)
		}()},
		{name: "missing scopes", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold"}`},
		{name: "empty scopes", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":[]}`},
		{name: "empty scope", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":[""]}`},
		{name: "missing version", request: `{"audience":"manifold","required_scopes":["manifold:proxy"]}`},
		{name: "empty audience", request: `{"version":"gascity.dev/credential-provider/v1","audience":"","required_scopes":["manifold:proxy"]}`},
		{name: "whitespace audience", request: `{"version":"gascity.dev/credential-provider/v1","audience":"mani fold","required_scopes":["manifold:proxy"]}`},
		{name: "whitespace org", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"ac me"}`},
		{name: "whitespace scope", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold: proxy"]}`},
		{name: "number version", request: `{"version":1,"audience":"manifold","required_scopes":["manifold:proxy"]}`},
		{name: "number audience", request: `{"version":"gascity.dev/credential-provider/v1","audience":1,"required_scopes":["manifold:proxy"]}`},
		{name: "string scopes", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":"manifold:proxy"}`},
		{name: "number scope", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":[1]}`},
		{name: "number org", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":1}`},
		{name: "string force refresh", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"force_refresh":"false"}`},
		{name: "string interactive", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":"false"}`},
		{name: "array top level", request: `[]`},
		{name: "null top level", request: `null`},
		{name: "string top level", request: `"request"`},
		{name: "number top level", request: `1`},
		{name: "boolean top level", request: `true`},
		{name: "unicode whitespace", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["scope:a\u00a0scope:b"]}`},
		{name: "control character", request: `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["scope:a\u0000scope:b"]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decode(t, test.request); err == nil {
				t.Fatal("decode succeeded, want invalid request")
			}
		})
	}
}

func TestCredentialProviderRejectsScopeSeparatorsBeforeUpstreamCalls(t *testing.T) {
	for _, scope := range []string{"scope:a\u00a0scope:b", "scope:a\x00scope:b"} {
		t.Run(fmt.Sprintf("%q", scope), func(t *testing.T) {
			srv := newStub(t)
			seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
			request, err := json.Marshal(map[string]any{
				"version":         credentialProviderVersion,
				"audience":        "manifold",
				"required_scopes": []string{scope},
				"interactive":     false,
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			response, errOut, code := runCredentialProvider(t, string(request))
			if code == 0 || errOut != "" || response.Code != credentialErrorInvalid {
				t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
			}
			if got := len(srv.reqs("/sts/v0/context")) + len(srv.reqs("/sts/v0/login")) + len(srv.reqs("/sts/v0/token")); got != 0 {
				t.Fatalf("invalid scope reached %d upstream endpoints", got)
			}
		})
	}
}

func TestCredentialProviderRejectsSessionCompletedAfterLoginChanges(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{
		"credential_generation": testCredentialGenerationA,
		"refresh_token":         "RT-A",
		"id_token":              validIDToken(),
	})
	srv.loginHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		err := store.Update(func(data *store.Data) error {
			data.CredentialGeneration = testCredentialGenerationB
			data.RefreshToken = "RT-B"
			data.IDToken = validIDToken()
			data.Sessions = nil
			data.EIACache = nil
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "test_login_switch_failed"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"session_token": "SESS-A", "session_id": "ses_a",
			"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 28800,
		})
	}

	response, errOut, code := runCredentialProvider(t,
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v, want secret-safe temporary failure", code, errOut, response)
	}
	persisted := loadStore(t)
	if persisted.CredentialGeneration != testCredentialGenerationB || persisted.RefreshToken != "RT-B" {
		t.Fatalf("persisted identity = generation %q refresh %q, want login B", persisted.CredentialGeneration, persisted.RefreshToken)
	}
	if len(persisted.Sessions) != 0 || len(persisted.EIACache) != 0 {
		t.Fatalf("login A repopulated login B caches: sessions=%v eia_cache=%v", persisted.Sessions, persisted.EIACache)
	}
}

func TestCredentialProviderRejectsEIACompletedAfterLogout(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{
		"credential_generation": testCredentialGenerationA,
		"refresh_token":         "RT-A",
		"id_token":              validIDToken(),
	})
	srv.eiaHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		if err := store.Clear(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "test_logout_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "EIA-A", "token_type": "DPoP",
			"expires_in": 90, "scope": form.Get("scope"),
		})
	}

	response, errOut, code := runCredentialProvider(t,
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v, want secret-safe temporary failure", code, errOut, response)
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("load logged-out store: %v", err)
	}
	if _, err := os.Stat(store.CredsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credentials path after logout = %v, want missing", err)
	}
}

func TestCredentialCacheKeysIncludeLoginGeneration(t *testing.T) {
	sessionA := sessionCacheKey("https://works.gascity.com", "org-a", testCredentialGenerationA)
	sessionB := sessionCacheKey("https://works.gascity.com", "org-a", testCredentialGenerationB)
	if sessionA == sessionB {
		t.Fatalf("session keys collide across login generations: %q", sessionA)
	}

	eiaA := eiaCacheKey("https://works.gascity.com", "org-a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"})
	eiaB := eiaCacheKey("https://works.gascity.com", "org-a", "manifold", testCredentialGenerationB, []string{"manifold:proxy"})
	if eiaA == eiaB {
		t.Fatalf("EIA keys collide across login generations: %q", eiaA)
	}
}

func TestCredentialProviderForceRefreshEvictsBeforeIdentityRefresh(t *testing.T) {
	srv := newStub(t)
	srv.refreshHandler = func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "temporarily_unavailable"})
	}
	cacheKey := eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"})
	seed(t, srv, map[string]any{
		"credential_generation": testCredentialGenerationA,
		"refresh_token":         "RT-A",
		"id_token":              expiredIDToken(),
		"eia_cache": map[string]any{
			cacheKey: map[string]any{"eia": "REJECTED-EIA", "expires_at": time.Now().Add(time.Hour).Unix()},
		},
	})

	response, errOut, code := runCredentialProvider(t,
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"force_refresh":true,"interactive":false}`)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorUnavailable {
		t.Fatalf("response = exit %d stderr %q %+v, want early refresh failure", code, errOut, response)
	}
	if _, exists := loadStore(t).EIACache[cacheKey]; exists {
		t.Fatal("force refresh left the rejected EIA reusable after identity refresh failed")
	}
}

func TestCredentialProviderMigratesLegacyLoginGeneration(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, nil)
	writeCreds(t, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			"legacy": map[string]any{"eia": "LEGACY-EIA", "expires_at": time.Now().Add(time.Hour).Unix()},
		},
	})

	response, errOut, code := runCredentialProvider(t,
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`)
	if code != 0 || errOut != "" || response.Kind != "Credential" {
		t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
	}
	persisted := loadStore(t)
	if !validCredentialGeneration(persisted.CredentialGeneration) {
		t.Fatalf("migrated generation = %q, want a valid durable generation", persisted.CredentialGeneration)
	}
	if _, exists := persisted.EIACache["legacy"]; exists {
		t.Fatal("legacy cache survived generation migration")
	}
}
