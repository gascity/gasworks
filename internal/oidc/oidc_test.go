package oidc

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
)

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

type recordedReq struct {
	path    string
	headers http.Header
	form    url.Values
}

// stubServer mirrors tests/conftest.py: records requests, responds by path, and steps the
// device poll through one authorization_pending before success.
type stubServer struct {
	mu          sync.Mutex
	requests    []recordedReq
	devicePolls int
	srv         *httptest.Server
}

func (s *stubServer) record(r *http.Request) url.Values {
	form := url.Values{}
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
	}
	s.mu.Lock()
	s.requests = append(s.requests, recordedReq{path: r.URL.RequestURI(), headers: r.Header.Clone(), form: form})
	s.mu.Unlock()
	return form
}

func (s *stubServer) reqs(suffix string) []recordedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []recordedReq
	for _, r := range s.requests {
		if strings.HasSuffix(r.path, suffix) {
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

func newStub(t *testing.T) (config.Config, *stubServer) {
	t.Helper()
	s := &stubServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		form := s.record(r)
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/auth/device"):
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code": "dev1", "user_code": "ABCD-EFGH",
				"verification_uri":          "http://kc/device",
				"verification_uri_complete": "http://kc/device?user_code=ABCD-EFGH",
				"interval":                  0, "expires_in": 60,
			})
		case strings.HasSuffix(path, "/openid-connect/token"):
			if strings.HasSuffix(form.Get("grant_type"), "device_code") {
				s.mu.Lock()
				s.devicePolls++
				n := s.devicePolls
				s.mu.Unlock()
				if n < 2 {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
				} else {
					writeJSON(w, http.StatusOK, map[string]any{"id_token": "ID.TOK.EN", "refresh_token": "RT", "access_token": "AT"})
				}
			} else {
				// refresh + auth-code both land here; conftest returns the rotated RT2.
				writeJSON(w, http.StatusOK, map[string]any{"id_token": "ID2", "refresh_token": "RT2"})
			}
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "nope"})
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	base := s.srv.URL
	cfg := config.Config{STSBase: base, OIDCIssuer: base + "/realms/g", ClientID: "gasworks-cli", LoopbackPort: 9999}
	return cfg, s
}

func TestDeviceLoginPollsThroughPendingWithPKCE(t *testing.T) {
	cfg, srv := newStub(t)
	tok, err := DeviceLogin(cfg, func(string) {})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if tok.IDToken != "ID.TOK.EN" || tok.RefreshToken != "RT" {
		t.Fatalf("tokens = %+v", tok)
	}
	srv.mu.Lock()
	polls := srv.devicePolls
	srv.mu.Unlock()
	if polls < 2 {
		t.Errorf("device_polls = %d, want >= 2 (pending then success)", polls)
	}

	dev := srv.reqs("/auth/device")
	if len(dev) != 1 {
		t.Fatalf("want 1 device-auth req, got %d", len(dev))
	}
	if dev[0].form.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", dev[0].form.Get("code_challenge_method"))
	}
	if dev[0].form.Get("code_challenge") == "" {
		t.Error("missing code_challenge")
	}
	if !strings.Contains(dev[0].form.Get("scope"), "openid") {
		t.Errorf("scope = %q, must contain openid", dev[0].form.Get("scope"))
	}

	polls2 := srv.reqs("/openid-connect/token")
	if len(polls2) == 0 {
		t.Fatal("no token polls recorded")
	}
	last := polls2[len(polls2)-1]
	if last.form.Get("code_verifier") == "" {
		t.Error("PKCE code_verifier missing on the poll")
	}
}

// TestDeviceLoginHonorsServerExpiresIn proves the poll deadline follows the device-auth
// response's expires_in (here 2s) rather than the 600s cap: when the user never authorizes
// (the token endpoint always returns authorization_pending), DeviceLogin must give up
// promptly — well under the 600s cap — mirroring the Python honoring the server lifetime.
func TestDeviceLoginHonorsServerExpiresIn(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/auth/device"):
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code":      "dev1",
				"user_code":        "ABCD-EFGH",
				"verification_uri": "http://kc/device",
				"interval":         0,
				"expires_in":       2, // short server lifetime — the deadline must follow this
			})
		case strings.HasSuffix(path, "/openid-connect/token"):
			// User never authorizes: keep returning authorization_pending forever.
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "nope"})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base := srv.URL
	cfg := config.Config{STSBase: base, OIDCIssuer: base + "/realms/g", ClientID: "gasworks-cli", LoopbackPort: 9999}

	start := time.Now()
	_, err := DeviceLogin(cfg, func(string) {})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("DeviceLogin must time out when the user never authorizes")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout error, got %v", err)
	}
	// expires_in=2s + the 1s minimum poll sleep: comfortably under 10s, nowhere near 600s.
	if elapsed > 10*time.Second {
		t.Fatalf("DeviceLogin ignored expires_in: took %s (should stop near 2s, cap is 600s)", elapsed)
	}
}

func TestRefreshReturnsRotatedToken(t *testing.T) {
	cfg, _ := newStub(t)
	tok, err := Refresh(cfg, "RT")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.RefreshToken != "RT2" {
		t.Errorf("refresh_token = %q, want RT2 (rotated)", tok.RefreshToken)
	}
}

func TestRefreshSendsScopeAndGrant(t *testing.T) {
	cfg, srv := newStub(t)
	if _, err := Refresh(cfg, "RT"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	req := srv.reqs("/openid-connect/token")
	if len(req) != 1 {
		t.Fatalf("want 1 token req, got %d", len(req))
	}
	if req[0].form.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", req[0].form.Get("grant_type"))
	}
	if req[0].form.Get("scope") != OIDCScope {
		t.Errorf("refresh scope = %q, want %q", req[0].form.Get("scope"), OIDCScope)
	}
	if req[0].form.Get("refresh_token") != "RT" {
		t.Errorf("refresh_token sent = %q, want RT", req[0].form.Get("refresh_token"))
	}
}

func TestRevokeBestEffort(t *testing.T) {
	cfg, srv := newStub(t)
	// /revoke 404s in the stub; Revoke must swallow the error.
	Revoke(cfg, "RT")
	req := srv.reqs("/revoke")
	if len(req) != 1 {
		t.Fatalf("want 1 revoke req, got %d", len(req))
	}
	if req[0].form.Get("token") != "RT" || req[0].form.Get("token_type_hint") != "refresh_token" {
		t.Errorf("revoke form = %v", req[0].form)
	}
	if req[0].form.Get("client_id") != "gasworks-cli" {
		t.Errorf("revoke client_id = %q", req[0].form.Get("client_id"))
	}
}

func TestScopeByteIdenticalAcrossGrants(t *testing.T) {
	cfg, srv := newStub(t)
	if _, err := DeviceLogin(cfg, func(string) {}); err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if _, err := Refresh(cfg, "RT"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	deviceScope := srv.reqs("/auth/device")[0].form.Get("scope")
	// The first /openid-connect/token request is a device poll (no scope); the refresh carries it.
	var refreshScope string
	for _, r := range srv.reqs("/openid-connect/token") {
		if r.form.Get("grant_type") == "refresh_token" {
			refreshScope = r.form.Get("scope")
		}
	}
	if deviceScope != OIDCScope || refreshScope != OIDCScope {
		t.Errorf("scope drift: device=%q refresh=%q want=%q", deviceScope, refreshScope, OIDCScope)
	}
	if OIDCScope != "openid profile email offline_access" {
		t.Errorf("OIDCScope = %q, want exact 'openid profile email offline_access'", OIDCScope)
	}
}

func TestPKCEChallengeIsS256OfVerifier(t *testing.T) {
	v, c, err := pkce()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	// verifier is base64url-nopad of 32 bytes => 43 chars.
	if len(v) != 43 {
		t.Errorf("verifier len = %d, want 43", len(v))
	}
	// Recompute the challenge to confirm S256.
	want := s256(v)
	if c != want {
		t.Errorf("challenge = %q, want S256(verifier) = %q", c, want)
	}
}

// s256 mirrors the production challenge derivation for the test assertion.
func s256(verifier string) string {
	sum := sha256Sum([]byte(verifier))
	return b64url.EncodeToString(sum)
}
