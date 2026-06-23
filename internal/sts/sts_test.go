package sts

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
)

func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// recordedReq is one captured request: its path, headers, and parsed form.
type recordedReq struct {
	path    string
	headers http.Header
	form    url.Values
}

// stubServer is a dumb recorder mirroring tests/conftest.py: it logs every request and
// responds by path. Assertions live in the tests.
type stubServer struct {
	mu       sync.Mutex
	requests []recordedReq
	srv      *httptest.Server
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
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id": "usr_1", "default_org_id": "org_a", "orgs": []any{
					map[string]any{
						"org_id": "org_a", "slug": "acme", "role": "owner", "is_default": true,
						"products": map[string]any{
							"manifold": map[string]any{"audience": "manifold", "scopes": []string{"manifold:proxy", "manifold:pool:acme"}},
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
	base := s.srv.URL
	cfg := config.Config{STSBase: base, OIDCIssuer: base + "/realms/g", ClientID: "gasworks-cli", LoopbackPort: 9999}
	return cfg, s
}

func hasDPoP(h http.Header) bool {
	for k := range h {
		if strings.EqualFold(k, "dpop") {
			return true
		}
	}
	return false
}

func TestLoginAndExchangeOmitSubjectTokenType(t *testing.T) {
	cfg, srv := newStub(t)
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}

	sess, err := Login(cfg, "ID.TOK.EN", "org_a", key)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.SessionToken != "SESS" || sess.SessionID != "ses_1" || sess.ExpiresIn != 28800 {
		t.Fatalf("session = %+v", sess)
	}

	eia, err := Exchange(cfg, sess.SessionToken, "manifold", "manifold:proxy manifold:pool:acme", key)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if eia.AccessToken != "EIA.JWT" || eia.ExpiresIn != 90 {
		t.Fatalf("eia = %+v", eia)
	}

	loginReq := srv.reqs("/sts/v0/login")
	if len(loginReq) != 1 {
		t.Fatalf("want 1 login req, got %d", len(loginReq))
	}
	if !hasDPoP(loginReq[0].headers) {
		t.Error("login request missing DPoP header")
	}
	if got := loginReq[0].form.Get("subject_token"); got != "ID.TOK.EN" {
		t.Errorf("login subject_token = %q, want ID.TOK.EN", got)
	}

	tokReq := srv.reqs("/sts/v0/token")
	if len(tokReq) != 1 {
		t.Fatalf("want 1 token req, got %d", len(tokReq))
	}
	if !hasDPoP(tokReq[0].headers) {
		t.Error("token request missing DPoP header")
	}
	if got := tokReq[0].form.Get("grant_type"); got != grantTokenExchange {
		t.Errorf("grant_type = %q, want %q", got, grantTokenExchange)
	}
	if _, present := tokReq[0].form["subject_token_type"]; present {
		t.Error("subject_token_type MUST be omitted (server 400s otherwise)")
	}
	if got := tokReq[0].form.Get("subject_token"); got != "SESS" {
		t.Errorf("exchange subject_token = %q, want SESS (the session token, not the id_token)", got)
	}
}

func TestLoginAndExchangeReuseOneKey(t *testing.T) {
	// The same key must drive both proofs so the server's jkt-pin holds. We assert the public
	// JWK embedded in both DPoP proofs is identical.
	cfg, srv := newStub(t)
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if _, err := Login(cfg, "ID.TOK.EN", "org_a", key); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := Exchange(cfg, "SESS", "manifold", "manifold:proxy", key); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	loginProof := srv.reqs("/sts/v0/login")[0].headers.Get("DPoP")
	tokenProof := srv.reqs("/sts/v0/token")[0].headers.Get("DPoP")
	if jwkOf(t, loginProof) != jwkOf(t, tokenProof) {
		t.Error("login and token DPoP proofs use different keys — jkt-pin would break")
	}
}

func TestContextSendsBearerAndProvision(t *testing.T) {
	cfg, srv := newStub(t)
	ctx, err := Context(cfg, "ID.TOK.EN", true)
	if err != nil {
		t.Fatalf("Context: %v", err)
	}
	if ctx.DefaultOrgID != "org_a" || ctx.UserID != "usr_1" {
		t.Fatalf("ctx = %+v", ctx)
	}
	if len(ctx.Orgs) != 1 {
		t.Fatalf("want 1 org, got %d", len(ctx.Orgs))
	}
	prod, ok := ctx.Orgs[0].Products["manifold"]
	if !ok {
		t.Fatalf("no manifold product: %+v", ctx.Orgs[0])
	}
	if got := strings.Join(prod.Scopes, " "); got != "manifold:proxy manifold:pool:acme" {
		t.Errorf("manifold scopes = %q", got)
	}
	if prod.Audience != "manifold" {
		t.Errorf("audience = %q", prod.Audience)
	}

	got := srv.reqs("provision=true")
	if len(got) != 1 {
		t.Fatalf("want 1 provision=true req, got %d", len(got))
	}
	if hasDPoP(got[0].headers) {
		t.Error("context must NOT send a DPoP header")
	}
	if auth := got[0].headers.Get("Authorization"); auth != "Bearer ID.TOK.EN" {
		t.Errorf("Authorization = %q, want Bearer ID.TOK.EN", auth)
	}
}

func TestContextNoProvision(t *testing.T) {
	cfg, srv := newStub(t)
	if _, err := Context(cfg, "ID.TOK.EN", false); err != nil {
		t.Fatalf("Context: %v", err)
	}
	// No ?provision=true on the path when provision is false.
	for _, r := range srv.reqs("/sts/v0/context") {
		if strings.Contains(r.path, "provision") {
			t.Errorf("provision=false must not add the query param, got %q", r.path)
		}
	}
}

func TestEveryCallCarriesUserAgent(t *testing.T) {
	cfg, srv := newStub(t)
	if _, err := Context(cfg, "ID.TOK.EN", false); err != nil {
		t.Fatalf("Context: %v", err)
	}
	srv.mu.Lock()
	last := srv.requests[len(srv.requests)-1]
	srv.mu.Unlock()
	if ua := last.headers.Get("User-Agent"); !strings.HasPrefix(ua, "gasworks-cli/") {
		t.Errorf("User-Agent = %q, want gasworks-cli/ prefix", ua)
	}
}

// jwkOf extracts the header.jwk object (as canonical JSON) from a DPoP proof's first segment.
func jwkOf(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed DPoP proof: %q", proof)
	}
	raw, err := base64urlDecode(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		JWK map[string]string `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	out, _ := json.Marshal(hdr.JWK)
	return string(out)
}
