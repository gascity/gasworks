package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/config"
)

// --- test harness ------------------------------------------------------------------------

// stubServer is a dumb request recorder mirroring tests/conftest.py: it logs every request and
// responds by path. Behaviour is tunable per test via the knobs below.
type stubServer struct {
	mu       sync.Mutex
	requests []recordedReq
	srv      *httptest.Server

	// contextStatus, when non-zero, overrides the /sts/v0/context response status (e.g. 404
	// for "no account", 500 to exercise the refresh-rotation-persists-then-fails path).
	contextStatus int
	// refreshTok is the token body returned by the Keycloak refresh grant.
	refreshTok map[string]any
	// refreshHandler overrides refresh-grant handling when non-nil.
	refreshHandler func(http.ResponseWriter, *http.Request, url.Values)
	// loginHandler overrides STS session establishment when non-nil.
	loginHandler func(http.ResponseWriter, *http.Request, url.Values)
	// eiaHandler overrides STS token exchange when non-nil.
	eiaHandler func(http.ResponseWriter, *http.Request, url.Values)
	// eiaResponse overrides the successful /sts/v0/token response when non-nil.
	eiaResponse map[string]any
	// productAudience overrides the context product audience when non-empty.
	productAudience string
	// contextErrorBody overrides a failing context response when non-nil.
	contextErrorBody map[string]any
	// contextResponse overrides the successful context response when non-nil.
	contextResponse map[string]any

	// mint is the climint mint plane, started on demand by startMint. It is its OWN https
	// origin, not a route on the stub above: climint is served at auth.gascity.com, and the
	// config layer refuses a plain-http one because the URL is signed into the DPoP proof.
	mint *httptest.Server
	// mintChallengeHandler overrides leg A (POST /v0/cli/mint/challenges) when non-nil.
	// attempt is 0-based across the run.
	mintChallengeHandler func(w http.ResponseWriter, r *http.Request, attempt int)
	// mintCompleteHandler overrides leg C (POST .../challenges/{id}/complete) when non-nil,
	// so a test can answer 425 twice and then 201, or fail terminally.
	mintCompleteHandler func(w http.ResponseWriter, r *http.Request, attempt int)
	// mintChallenge is the default leg A 201 body; mintCredential the default leg C one.
	mintChallenge  map[string]any
	mintCredential map[string]any
}

type recordedReq struct {
	path string
	form url.Values
	// body is the raw request body — the mint legs post JSON, which does not survive form
	// parsing. auth and dpop are the two headers the ceremony's invariants are about.
	body string
	auth string
	dpop string
}

func (s *stubServer) record(r *http.Request) url.Values {
	form := url.Values{}
	var raw []byte
	if r.Method == http.MethodPost {
		raw, _ = io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(raw))
	}
	s.mu.Lock()
	s.requests = append(s.requests, recordedReq{
		path: r.URL.RequestURI(),
		form: form,
		body: string(raw),
		auth: r.Header.Get("Authorization"),
		dpop: r.Header.Get("DPoP"),
	})
	s.mu.Unlock()
	return form
}

func (s *stubServer) reqs(suffix string) []recordedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []recordedReq
	for _, r := range s.requests {
		if strings.HasSuffix(strings.SplitN(r.path, "?", 2)[0], suffix) {
			out = append(out, r)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func newStub(t *testing.T) *stubServer {
	t.Helper()
	s := &stubServer{
		refreshTok: map[string]any{"id_token": "ID2", "refresh_token": "RT2"},
		// approve_url is filled in by startMint: the CLI checks it against the configured
		// mint origin, which is not known until that server has a port.
		mintChallenge: map[string]any{
			"challenge_id": "chal_1", "confirm_code": "WXYZ-4242", "expires_in": 180,
		},
		mintCredential: map[string]any{
			"key_id": "spk_1", "secret": "gck_sp_secret_value", "prefix": "gck_sp",
			"org_id": "org_a", "scopes": []string{"forge:city.create", "forge:city.delete"},
			"expires_at": "2026-09-10T00:00:00Z",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		form := s.record(r)
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/protocol/openid-connect/auth/device"):
			// Device-authorization grant: interval 0 so the poll loop fires immediately.
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code": "dev1", "user_code": "ABCD-EFGH",
				"verification_uri":          "http://kc/device",
				"verification_uri_complete": "http://kc/device?user_code=ABCD-EFGH",
				"interval":                  0, "expires_in": 60,
			})
		case strings.HasSuffix(path, "/protocol/openid-connect/token"):
			if form.Get("grant_type") == "refresh_token" && s.refreshHandler != nil {
				s.refreshHandler(w, r, form)
				return
			}
			// Both the refresh grant and the device-code grant land here; the CLI tests only
			// need the token body, which is the same shape for both.
			writeJSON(w, http.StatusOK, s.refreshTok)
		case strings.HasSuffix(path, "/protocol/openid-connect/revoke"):
			writeJSON(w, http.StatusOK, map[string]any{})
		case strings.HasSuffix(path, "/sts/v0/login"):
			if s.loginHandler != nil {
				s.loginHandler(w, r, form)
				return
			}
			// The prefix is what the real STS returns for a human login, and the mint legs
			// accept nothing else (see climint.UserSessionPrefix).
			writeJSON(w, http.StatusCreated, map[string]any{
				"session_token": "gcs_user_SESS", "session_id": "ses_1",
				"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 28800,
			})
		case strings.HasSuffix(path, "/sts/v0/token"):
			if s.eiaHandler != nil {
				s.eiaHandler(w, r, form)
				return
			}
			response := s.eiaResponse
			if response == nil {
				response = map[string]any{
					"access_token": "EIA.JWT", "token_type": "DPoP",
					"expires_in": 90, "scope": form.Get("scope"),
				}
			}
			writeJSON(w, http.StatusOK, response)
		case strings.HasSuffix(path, "/sts/v0/context"):
			if s.contextStatus != 0 {
				body := s.contextErrorBody
				if body == nil {
					body = map[string]any{"error": "boom"}
				}
				writeJSON(w, s.contextStatus, body)
				return
			}
			if s.contextResponse != nil {
				writeJSON(w, http.StatusOK, s.contextResponse)
				return
			}
			audience := s.productAudience
			if audience == "" {
				audience = "manifold"
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id": "usr_1", "default_org_id": "org_a", "orgs": []any{
					map[string]any{
						"org_id": "org_a", "slug": "acme", "role": "owner", "is_default": true,
						"products": map[string]any{
							"manifold": map[string]any{
								"audience": audience,
								"scopes":   []string{"manifold:proxy", "manifold:pool:acme"},
							},
						},
					},
				},
			})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "nope"})
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// startMint brings up the climint mint plane and points the CLI at it. It is separate from
// newStub because it is a separate ORIGIN in production too: https only (the config layer
// refuses anything else, since the URL is signed into the DPoP proof as htu), which means the
// ceremony's client has to be swapped for one that trusts this server's CA.
//
// Requests land in the same recorder as the STS stub's, so reqs() sees the whole run in order.
func (s *stubServer) startMint(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/cli/mint/challenges", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if s.mintChallengeHandler != nil {
			s.mintChallengeHandler(w, r, len(s.reqs("/v0/cli/mint/challenges"))-1)
			return
		}
		writeJSON(w, http.StatusCreated, s.mintChallenge)
	})
	mux.HandleFunc("/v0/cli/mint/challenges/", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		attempt := len(s.reqs("/complete")) - 1
		if s.mintCompleteHandler != nil {
			s.mintCompleteHandler(w, r, attempt)
			return
		}
		writeJSON(w, http.StatusCreated, s.mintCredential)
	})
	s.mint = httptest.NewTLSServer(mux)
	t.Cleanup(s.mint.Close)
	t.Setenv(config.ClimintBaseEnv, s.mint.URL)
	// The approval page is served by the mint plane itself, which is what the CLI checks the
	// URL against before it hands it to a browser.
	s.mintChallenge["approve_url"] = s.mint.URL + "/cli/approve?c=chal_1"

	transport := s.mint.Client().Transport.(*http.Transport).Clone()
	// As in production (httpc.NewNoKeepAliveClient): a single-use proof is never replayed on a
	// pooled connection, and the transport never decompresses — the bytes the ceremony saves
	// have to be the bytes on the wire.
	transport.DisableKeepAlives = true
	transport.DisableCompression = true
	previous := mintClient
	mintClient = &climint.Client{HTTP: &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	t.Cleanup(func() { mintClient = previous })
}

// mintPending is the climint 425: not RFC 8628, no OAuth error field — a status discriminator
// and the interval to wait.
func mintPending(w http.ResponseWriter, status string, interval int) {
	writeJSON(w, http.StatusTooEarly, map[string]any{"status": status, "interval": interval})
}

// seed points the CLI at the stub + a fresh temp config dir and writes initial credentials.
// It returns a func that captures stdout/stderr around a single run() call.
func seed(t *testing.T, srv *stubServer, creds map[string]any) {
	t.Helper()
	base := srv.srv.URL
	useFileKeystore(t)
	t.Setenv("GASWORKS_STS_URL", base)
	t.Setenv("GASWORKS_OIDC_ISSUER", base+"/realms/g")
	t.Setenv("GASWORKS_CLIENT_ID", "gasworks-cli")
	if creds != nil {
		if _, exists := creds["credential_generation"]; !exists &&
			(creds["id_token"] != nil || creds["refresh_token"] != nil) {
			creds["credential_generation"] = testCredentialGenerationA
		}
		writeCreds(t, creds)
	}
}

// writeCreds writes a credentials document directly via the store JSON shape.
func writeCreds(t *testing.T, creds map[string]any) {
	t.Helper()
	// Reuse the running process's store by invoking it through the public env-driven path:
	// marshal the map to the store.Data JSON shape and let store.Load read it back.
	b, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal creds: %v", err)
	}
	if err := writeStoreRaw(b); err != nil {
		t.Fatalf("write creds: %v", err)
	}
}

// capture runs fn with stdout/stderr swapped to buffers and returns what each captured.
func capture(t *testing.T, fn func() int) (out string, errOut string, code int) {
	t.Helper()
	var ob, eb bytes.Buffer
	origOut, origErr := stdout, stderr
	stdout, stderr = &ob, &eb
	defer func() { stdout, stderr = origOut, origErr }()
	code = fn()
	return ob.String(), eb.String(), code
}

func freezeNow(t *testing.T, instant time.Time) {
	t.Helper()
	originalNow := now
	now = func() int64 { return instant.Unix() }
	t.Cleanup(func() { now = originalNow })
}

// fakeJWT builds an unsigned JWT (alg=none) with the given claims, matching test_cli's helper.
func fakeJWT(claims map[string]any) string {
	b := func(o any) string {
		raw, _ := json.Marshal(o)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return b(map[string]any{"alg": "none", "typ": "JWT"}) + "." + b(claims) + ".sig"
}

func validIDToken() string {
	return fakeJWT(map[string]any{
		"sub": "kc-1", "email": "u@gascity.com", "exp": time.Now().Unix() + 3600,
		"aud": []string{"gasworks-cli"}, "azp": "gasworks-cli",
	})
}

// validIDTokenIss is validIDToken with an explicit issuer, for the login flow which (M3)
// asserts iss == the configured OIDC issuer. The seeded getToken/whoami tests don't run the
// login iss check, so the plain validIDToken (no iss) is fine there.
func validIDTokenIss(iss string) string {
	return fakeJWT(map[string]any{
		"sub": "kc-1", "email": "u@gascity.com", "exp": time.Now().Unix() + 3600,
		"aud": []string{"gasworks-cli"}, "azp": "gasworks-cli", "iss": iss,
	})
}

// expiredIDToken is past its skew window so getToken/whoami must refresh.
func expiredIDToken() string {
	return fakeJWT(map[string]any{
		"sub": "kc-1", "email": "u@gascity.com", "exp": time.Now().Unix() - 10,
		"aud": []string{"gasworks-cli"}, "azp": "gasworks-cli",
	})
}

// --- the nine end-to-end tests (ported from tests/test_cli.py) ---------------------------

func TestGetTokenEndToEnd(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q, want raw EIA 'EIA.JWT'", out)
	}
	tok := srv.reqs("/sts/v0/token")
	if len(tok) != 1 {
		t.Fatalf("want 1 token mint, got %d", len(tok))
	}
	if got := tok[0].form.Get("scope"); got != "manifold:proxy manifold:pool:acme" {
		t.Errorf("exchange scope = %q, want the discovered manifold scopes", got)
	}
	if _, present := tok[0].form["subject_token_type"]; present {
		t.Error("subject_token_type must be omitted")
	}
}

func TestGetTokenJSONEnvelope(t *testing.T) {
	srv := newStub(t)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	freezeNow(t, fixedNow)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--json"}) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	var env struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		ExpiresAt   string `json:"expires_at"`
		Audience    string `json:"audience"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &env); err != nil {
		t.Fatalf("not JSON: %v (out=%q)", err, out)
	}
	if env.AccessToken != "EIA.JWT" || env.ExpiresIn != 90 ||
		env.TokenType != "Bearer" || env.Audience != "manifold" {
		t.Fatalf("envelope = %+v", env)
	}
	if expiresAt, err := time.Parse(time.RFC3339, env.ExpiresAt); err != nil {
		t.Fatalf("expires_at = %q: %v", env.ExpiresAt, err)
	} else if !expiresAt.Equal(fixedNow.Add(90 * time.Second)) {
		t.Fatalf("expires_at = %s, want %s", expiresAt, fixedNow.Add(90*time.Second))
	}
}

func TestGetTokenJSONReportsCachedRemainingLifetime(t *testing.T) {
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

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", "manifold:proxy", "--json"})
	})
	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	var envelope struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("not JSON: %v (out=%q)", err, out)
	}
	if envelope.AccessToken != "CACHED.EIA" || envelope.ExpiresIn != 45 ||
		envelope.ExpiresAt != expiresAt.Format(time.RFC3339) {
		t.Fatalf("cached envelope = %+v", envelope)
	}
}

func TestGetTokenDoesNotReuseCacheAfterAudienceRemap(t *testing.T) {
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

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", "manifold:proxy", "--json"})
	})
	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	var envelope struct {
		AccessToken string `json:"access_token"`
		Audience    string `json:"audience"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("not JSON: %v (out=%q)", err, out)
	}
	if envelope.AccessToken != "EIA.JWT" || envelope.Audience != "manifold-v2" {
		t.Fatalf("remapped envelope = %+v", envelope)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("audience remap made %d token requests", mints)
	}
}

func TestGetTokenRejectsUnexpectedGrantedScopesBeforeCaching(t *testing.T) {
	srv := newStub(t)
	srv.eiaResponse = map[string]any{
		"access_token": "WIDENED.EIA",
		"expires_in":   90,
		"scope":        "manifold:proxy manifold:admin",
	}
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", "manifold:proxy"})
	})
	if code == 0 || !strings.Contains(errOut, "unexpected scopes") {
		t.Fatalf("widened grant = exit %d stderr %q", code, errOut)
	}

	srv.eiaResponse = nil
	response, providerErr, providerCode := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1",
		"audience":"manifold",
		"required_scopes":["manifold:proxy"],
		"interactive":false
	}`)
	if providerCode != 0 || providerErr != "" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("provider after rejected grant = exit %d stderr %q %+v", providerCode, providerErr, response)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 2 {
		t.Fatalf("token requests = %d, want rejected legacy mint plus fresh provider mint", mints)
	}
}

func TestGetTokenRejectsDuplicateScopes(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", "manifold:proxy manifold:proxy"})
	})
	if code == 0 || !strings.Contains(errOut, "duplicate") {
		t.Fatalf("duplicate scopes = exit %d stderr %q", code, errOut)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 0 {
		t.Fatalf("duplicate scopes made %d token requests", mints)
	}
}

func TestGetTokenCachesSecondCall(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, e, c := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); c != 0 {
		t.Fatalf("first call exit=%d stderr=%q", c, e)
	}
	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 0 {
		t.Fatalf("second call exit=%d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("second-call stdout = %q, want cached 'EIA.JWT'", out)
	}
	// Within 90s the second call is a cache hit: exactly ONE mint total across both calls.
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("want exactly 1 EIA mint across both calls (cache hit), got %d", mints)
	}
}

func TestGetTokenScopeOrderSharesCacheEntry(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	firstScope := "manifold:proxy manifold:pool:acme"
	secondScope := "manifold:pool:acme manifold:proxy"
	if _, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", firstScope})
	}); code != 0 || errOut != "" {
		t.Fatalf("first request = exit %d stderr %q", code, errOut)
	}
	if _, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--scope", secondScope})
	}); code != 0 || errOut != "" {
		t.Fatalf("second request = exit %d stderr %q", code, errOut)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 1 {
		t.Fatalf("scope-order requests made %d mints", mints)
	}
}

func TestGetTokenUnentitledProductIsClearError(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "crucible"}) })
	if code == 0 {
		t.Fatal("want non-zero exit for unentitled product")
	}
	if !strings.Contains(errOut, "no mintable 'crucible' scope") {
		t.Fatalf("stderr = %q, want a clear unentitled-product error", errOut)
	}
}

// G11: --scope must NOT bypass the friendly unentitled-product check into a raw STS
// 400 invalid_target. An explicit scope still requires the product to be mintable.
func TestGetTokenUnentitledProductWithScopeIsClearError(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "crucible", "--scope", "crucible:exec"})
	})
	if code == 0 {
		t.Fatal("want non-zero exit for an unentitled product even with --scope")
	}
	if !strings.Contains(errOut, "no mintable 'crucible' scope") {
		t.Fatalf("stderr = %q, want the clear unentitled-product error", errOut)
	}
	if got := srv.reqs("/sts/v0/token"); len(got) != 0 {
		t.Fatalf("must NOT reach the STS token endpoint for an unentitled product, got %d mints", len(got))
	}
}

func TestGetTokenRequiresLogin(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{}) // no refresh token / id token

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code == 0 {
		t.Fatal("want non-zero exit when not logged in")
	}
	if !strings.Contains(errOut, "not logged in") {
		t.Fatalf("stderr = %q, want 'not logged in'", errOut)
	}
}

func TestWhoami(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	out, errOut, code := capture(t, func() int { return run([]string{"whoami"}) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	for _, want := range []string{"u@gascity.com", "acme", "manifold"} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami output missing %q\n%s", want, out)
		}
	}
}

func TestLogoutClears(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	out, errOut, code := capture(t, func() int { return run([]string{"logout"}) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "Logged out.") {
		t.Errorf("stdout = %q, want 'Logged out.'", out)
	}
	// The store is cleared.
	if data := loadStore(t); data.IDToken != "" || data.RefreshToken != "" {
		t.Errorf("store not cleared: %+v", data)
	}
	// The refresh token was revoked before clearing.
	if len(srv.reqs("/protocol/openid-connect/revoke")) != 1 {
		t.Error("logout must best-effort revoke the refresh token before clearing")
	}
}

// TestLoginOrgSelection drives the login flow with a forced device flow and --org, asserting
// the id_token assertion passes, default_org is recorded, and prior STS state is wiped.
func TestLoginOrgSelection(t *testing.T) {
	srv := newStub(t)
	// The device flow returns ID2/RT2 from the refresh-grant handler? No — login uses the
	// device grant. Point the token handler's id_token at a valid, asserted token by setting
	// the refresh body (the stub returns the same body for any /token grant in login tests).
	srv.refreshTok = map[string]any{"id_token": validIDTokenIss(srv.srv.URL + "/realms/g"), "refresh_token": "RT-NEW"}
	// Seed a stale session + EIA cache that a fresh login must invalidate.
	seed(t, srv, map[string]any{
		"id_token":  "old",
		"sessions":  map[string]any{"org_a": map[string]any{"session_token": "OLD", "dpop_pem": "x", "expires_at": 1}},
		"eia_cache": map[string]any{"k": map[string]any{"eia": "OLD", "expires_at": 1}},
	})

	out, errOut, code := capture(t, func() int {
		return run([]string{"login", "--device", "--org", "acme"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "Logged in as u@gascity.com.") {
		t.Fatalf("stdout = %q, want logged-in greeting", out)
	}
	data := loadStore(t)
	if data.DefaultOrg != "acme" {
		t.Errorf("default_org = %q, want 'acme' (from --org)", data.DefaultOrg)
	}
	if data.RefreshToken != "RT-NEW" {
		t.Errorf("refresh_token = %q, want the grant's RT-NEW", data.RefreshToken)
	}
	if !validCredentialGeneration(data.CredentialGeneration) || data.CredentialGeneration == testCredentialGenerationA {
		t.Errorf("fresh login generation = %q, want a new valid generation", data.CredentialGeneration)
	}
	if len(data.Sessions) != 0 || len(data.EIACache) != 0 {
		t.Errorf("fresh login must clear prior sessions/eia_cache: sessions=%v eia=%v",
			data.Sessions, data.EIACache)
	}
}

func TestLoginStaffRejectsDeviceFlow(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "OLD", "id_token": "OLD"})
	_, errOut, code := capture(t, func() int { return run([]string{"login", "--staff", "--device"}) })
	if code == 0 || !strings.Contains(errOut, "--staff requires the browser flow") {
		t.Fatalf("login = exit %d stderr %q, want staff/device rejection", code, errOut)
	}
	if got := len(srv.reqs("/protocol/openid-connect/auth/device")); got != 0 {
		t.Fatalf("staff/device made %d device authorization requests, want none", got)
	}
}

func TestLoginWithoutRefreshTokenPreservesPriorLogin(t *testing.T) {
	srv := newStub(t)
	srv.refreshTok = map[string]any{"id_token": validIDTokenIss(srv.srv.URL + "/realms/g")}
	seed(t, srv, map[string]any{
		"credential_generation": testCredentialGenerationA,
		"id_token":              "OLD-ID",
		"refresh_token":         "OLD-REFRESH",
		"default_org":           "old-org",
		"sessions":              map[string]any{"old": map[string]any{"session_token": "OLD", "dpop_pem": "OLD", "expires_at": 1}},
		"eia_cache":             map[string]any{"old": map[string]any{"eia": "OLD", "expires_at": 1}},
	})

	_, errOut, code := capture(t, func() int { return run([]string{"login", "--device"}) })
	if code == 0 || !strings.Contains(errOut, "refresh_token") {
		t.Fatalf("login = exit %d stderr %q, want missing-refresh-token failure", code, errOut)
	}
	persisted := loadStore(t)
	if persisted.CredentialGeneration != testCredentialGenerationA ||
		persisted.IDToken != "OLD-ID" || persisted.RefreshToken != "OLD-REFRESH" ||
		persisted.DefaultOrg != "old-org" || len(persisted.Sessions) != 1 || len(persisted.EIACache) != 1 {
		t.Fatalf("failed login changed prior credentials: %+v", persisted)
	}
}

func TestLoginWithoutOrgClearsPriorLoginDefaultOrg(t *testing.T) {
	srv := newStub(t)
	srv.refreshTok = map[string]any{
		"id_token": validIDTokenIss(srv.srv.URL + "/realms/g"), "refresh_token": "RT-NEW",
	}
	seed(t, srv, map[string]any{
		"credential_generation": testCredentialGenerationA,
		"id_token":              "OLD-ID",
		"refresh_token":         "OLD-REFRESH",
		"default_org":           "prior-user-org",
	})

	_, errOut, code := capture(t, func() int { return run([]string{"login", "--device"}) })
	if code != 0 {
		t.Fatalf("login = exit %d stderr %q", code, errOut)
	}
	if persisted := loadStore(t); persisted.DefaultOrg != "" {
		t.Fatalf("default_org = %q, want cleared for the new login", persisted.DefaultOrg)
	}
}

// TestRefreshRotationPersistsBeforeMint is the (M10) property: an expired id_token forces a
// refresh that ROTATES the refresh token; a LATER step (discovery) then fails — yet the new
// refresh token must already be persisted to disk.
func TestRefreshRotationPersistsBeforeMint(t *testing.T) {
	srv := newStub(t)
	srv.refreshTok = map[string]any{"id_token": validIDToken(), "refresh_token": "RT-ROTATED"}
	srv.contextStatus = http.StatusInternalServerError // discovery fails AFTER the refresh
	seed(t, srv, map[string]any{"refresh_token": "RT-OLD", "id_token": expiredIDToken()})

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code == 0 {
		t.Fatal("want non-zero exit (discovery fails)")
	}
	if !strings.Contains(errOut, "discovery failed") {
		t.Fatalf("stderr = %q, want a discovery failure", errOut)
	}
	// Despite the later failure, the rotated refresh token is on disk (a crash here must not
	// strand the user with a spent RT-OLD).
	if data := loadStore(t); data.RefreshToken != "RT-ROTATED" {
		t.Fatalf("refresh_token = %q, want the rotated 'RT-ROTATED' persisted before the mint step",
			data.RefreshToken)
	}
}
