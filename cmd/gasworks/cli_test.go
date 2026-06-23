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
}

type recordedReq struct {
	path string
	form url.Values
}

func (s *stubServer) record(r *http.Request) url.Values {
	form := url.Values{}
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
	}
	s.mu.Lock()
	s.requests = append(s.requests, recordedReq{path: r.URL.RequestURI(), form: form})
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
			// Both the refresh grant and the device-code grant land here; the CLI tests only
			// need the token body, which is the same shape for both.
			writeJSON(w, http.StatusOK, s.refreshTok)
		case strings.HasSuffix(path, "/protocol/openid-connect/revoke"):
			writeJSON(w, http.StatusOK, map[string]any{})
		case strings.HasSuffix(path, "/sts/v0/login"):
			writeJSON(w, http.StatusCreated, map[string]any{
				"session_token": "SESS", "session_id": "ses_1",
				"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 28800,
			})
		case strings.HasSuffix(path, "/sts/v0/token"):
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "EIA.JWT", "token_type": "DPoP",
				"expires_in": 90, "scope": form.Get("scope"),
			})
		case strings.HasSuffix(path, "/sts/v0/context"):
			if s.contextStatus != 0 {
				writeJSON(w, s.contextStatus, map[string]any{"error": "boom"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id": "usr_1", "default_org_id": "org_a", "orgs": []any{
					map[string]any{
						"org_id": "org_a", "slug": "acme", "role": "owner", "is_default": true,
						"products": map[string]any{
							"manifold": map[string]any{
								"audience": "manifold",
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

// seed points the CLI at the stub + a fresh temp config dir and writes initial credentials.
// It returns a func that captures stdout/stderr around a single run() call.
func seed(t *testing.T, srv *stubServer, creds map[string]any) {
	t.Helper()
	base := srv.srv.URL
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	t.Setenv("GASWORKS_STS_URL", base)
	t.Setenv("GASWORKS_OIDC_ISSUER", base+"/realms/g")
	t.Setenv("GASWORKS_CLIENT_ID", "gasworks-cli")
	if creds != nil {
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
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--json"}) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	var env struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &env); err != nil {
		t.Fatalf("not JSON: %v (out=%q)", err, out)
	}
	if env.AccessToken != "EIA.JWT" || env.ExpiresIn != 90 || env.TokenType != "DPoP" {
		t.Fatalf("envelope = %+v", env)
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
	if len(data.Sessions) != 0 || len(data.EIACache) != 0 {
		t.Errorf("fresh login must clear prior sessions/eia_cache: sessions=%v eia=%v",
			data.Sessions, data.EIACache)
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
