package sts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
		case strings.HasSuffix(path, "/sts/v0/machine"):
			writeJSON(w, http.StatusCreated, map[string]any{
				"session_token": "SESS", "session_id": "ses_1", "org_id": "org_a",
				"token_type": "DPoP", "expires_in": 28800,
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
	if got := athOf(t, loginReq[0].headers.Get("DPoP")); got != ath("ID.TOK.EN") {
		t.Errorf("login ath = %q, want hash of the exact id_token", got)
	} else if got == ath("SESS") {
		t.Error("login ath incorrectly binds the session token instead of the id_token")
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
	if got := athOf(t, tokReq[0].headers.Get("DPoP")); got != ath("SESS") {
		t.Errorf("exchange ath = %q, want hash of the exact session token", got)
	} else if got == ath("ID.TOK.EN") {
		t.Error("exchange ath incorrectly binds the id_token instead of the session token")
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

func TestMachineUsesClientCredentialsAndATH(t *testing.T) {
	cfg, srv := newStub(t)
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if _, err := Machine(cfg, "service-key", key); err != nil {
		t.Fatalf("Machine: %v", err)
	}
	requests := srv.reqs("/sts/v0/machine")
	if len(requests) != 1 {
		t.Fatalf("machine requests = %d, want 1", len(requests))
	}
	if got := requests[0].form; got.Get("grant_type") != grantClientCredentials || got.Get("client_secret") != "service-key" || len(got) != 2 {
		t.Fatalf("machine form = %v", got)
	}
	if got := athOf(t, requests[0].headers.Get("DPoP")); got != ath("service-key") {
		t.Fatalf("machine ath = %q, want exact client credential hash", got)
	}
}

func TestOperationsRejectMissingSTSEndpoint(t *testing.T) {
	cfg := config.Config{}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if _, err := Context(cfg, "id", false); !errors.Is(err, errNoSTSEndpoint) {
		t.Fatalf("Context error = %v, want %v", err, errNoSTSEndpoint)
	}
	if _, err := Login(cfg, "id", "org", key); !errors.Is(err, errNoSTSEndpoint) {
		t.Fatalf("Login error = %v, want %v", err, errNoSTSEndpoint)
	}
	if _, err := Machine(cfg, "secret", key); !errors.Is(err, errNoSTSEndpoint) {
		t.Fatalf("Machine error = %v, want %v", err, errNoSTSEndpoint)
	}
	if _, err := Exchange(cfg, "session", "manifold", "scope", key); !errors.Is(err, errNoSTSEndpoint) {
		t.Fatalf("Exchange error = %v, want %v", err, errNoSTSEndpoint)
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

func TestContextCanonical404FallsBack(t *testing.T) {
	var canonicalHits int
	canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canonicalHits++
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	}))
	t.Cleanup(canonical.Close)
	legacyCfg, legacy := newStub(t)
	cfg := legacyCfg
	cfg.STSCanonical = canonical.URL
	var events []Event
	cfg.STSTelemetry = func(op, origin, outcome, reason string) {
		events = append(events, Event{op, origin, outcome, reason})
	}

	ctx, err := Context(cfg, "ID.TOK.EN", false)
	if err != nil {
		t.Fatalf("Context: %v", err)
	}
	if ctx.Origin != legacyCfg.STSBase {
		t.Fatalf("context origin = %q, want %q", ctx.Origin, legacyCfg.STSBase)
	}
	if canonicalHits != 1 {
		t.Fatalf("canonical context request count = %d, want 1", canonicalHits)
	}
	if got := len(legacy.reqs("/sts/v0/context")); got != 1 {
		t.Fatalf("legacy context request count = %d, want 1", got)
	}
	if len(events) != 1 || events[0].Operation != "context" || events[0].Origin != "legacy" ||
		events[0].Outcome != "fallback" || events[0].Reason != "success" {
		t.Fatalf("telemetry = %+v", events)
	}
}

func TestProvisioningContextDoesNotCrossOrigin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		network bool
		reason  string
	}{
		{name: "404", status: http.StatusNotFound, reason: "404"},
		{name: "401", status: http.StatusUnauthorized, reason: "401"},
		{name: "403", status: http.StatusForbidden, reason: "403"},
		{name: "5xx", status: http.StatusServiceUnavailable, reason: "5xx"},
		{name: "network", network: true, reason: "network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var canonicalHits atomic.Int32
			canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				canonicalHits.Add(1)
				if r.URL.Path != "/sts/v0/context" || r.URL.Query().Get("provision") != "true" {
					t.Errorf("canonical request = %q, want provisioning context", r.URL.RequestURI())
				}
				if tc.network {
					// Model an origin that receives the provisioning request but drops the
					// connection before a response. The mutation may already have committed,
					// so the client must not replay it at the legacy origin.
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Errorf("canonical writer does not support hijacking")
						return
					}
					conn, _, err := hijacker.Hijack()
					if err != nil {
						t.Errorf("hijack canonical connection: %v", err)
						return
					}
					_ = conn.Close()
					return
				}
				writeJSON(w, tc.status, map[string]any{"error": "unavailable"})
			}))
			canonicalURL := canonical.URL
			t.Cleanup(canonical.Close)
			_, legacy := newStub(t)
			var events []Event
			cfg := config.Config{
				STSCanonical: canonicalURL,
				STSBase:      legacy.srv.URL,
				STSTelemetry: func(op, origin, outcome, reason string) {
					events = append(events, Event{op, origin, outcome, reason})
				},
			}
			if _, err := Context(cfg, "ID.TOK.EN", true); err == nil {
				t.Fatal("provisioning Context unexpectedly succeeded")
			}
			if canonicalHits.Load() != 1 {
				t.Fatalf("canonical provisioning request count = %d, want 1", canonicalHits.Load())
			}
			if got := len(legacy.reqs("/sts/v0/context")); got != 0 {
				t.Fatalf("legacy received %d provisioning context requests", got)
			}
			if len(events) != 1 || events[0].Operation != "context" || events[0].Origin != "canonical" ||
				events[0].Outcome != "failure" || events[0].Reason != tc.reason {
				t.Fatalf("telemetry = %+v", events)
			}
		})
	}
}

func TestProvisioningContextFallsBackOnDNSResolutionError(t *testing.T) {
	// A name-resolution failure is the one provisioning failure that is safe to re-issue
	// elsewhere: nothing left the client, so the canonical origin cannot have created or
	// linked identity/org state. httptest cannot produce one, so inject it at the seam.
	const canonical = "https://api.gascity.com"
	_, legacy := newStub(t)
	live := getJSON
	getJSON = func(u string, headers map[string]string) (int, any, error) {
		if strings.HasPrefix(u, canonical) {
			return 0, nil, &url.Error{Op: "Get", URL: u, Err: &net.DNSError{
				Err: "no such host", Name: "api.gascity.com", IsNotFound: true,
			}}
		}
		return live(u, headers)
	}
	t.Cleanup(func() { getJSON = live })

	var events []Event
	cfg := config.Config{
		STSCanonical: canonical,
		STSBase:      legacy.srv.URL,
		STSTelemetry: func(op, origin, outcome, reason string) {
			events = append(events, Event{op, origin, outcome, reason})
		},
	}
	ctx, err := Context(cfg, "ID.TOK.EN", true)
	if err != nil {
		t.Fatalf("Context: %v", err)
	}
	if ctx.Origin != legacy.srv.URL {
		t.Fatalf("context origin = %q, want %q", ctx.Origin, legacy.srv.URL)
	}
	got := legacy.reqs("/sts/v0/context?provision=true")
	if len(got) != 1 {
		t.Fatalf("legacy provisioning request count = %d, want 1", len(got))
	}
	if auth := got[0].headers.Get("Authorization"); auth != "Bearer ID.TOK.EN" {
		t.Errorf("Authorization = %q, want Bearer ID.TOK.EN", auth)
	}
	if len(events) != 1 || events[0].Operation != "context" || events[0].Origin != "legacy" ||
		events[0].Outcome != "fallback" || events[0].Reason != "success" {
		t.Fatalf("telemetry = %+v", events)
	}
}

// dnsFailingPostForm points the postForm seam at a name-resolution failure for one origin and
// at the real transport for everything else. httptest cannot produce a DNS error, and the test
// must not touch a resolver.
func dnsFailingPostForm(t *testing.T, origin string) {
	t.Helper()
	live := postForm
	postForm = func(u string, values url.Values, headers map[string]string) (int, any, error) {
		if strings.HasPrefix(u, origin) {
			return 0, nil, &url.Error{Op: "Post", URL: u, Err: &net.DNSError{
				Err: "no such host", Name: "api.gascity.com", IsNotFound: true,
			}}
		}
		return live(u, values, headers)
	}
	t.Cleanup(func() { postForm = live })
}

func TestSessionEstablishmentFallsBackOnDNSResolutionError(t *testing.T) {
	// Session establishment gets the same exception as provisioning discovery: resolution
	// precedes the dial, so the canonical origin cannot hold a half-created session. Without
	// it the service-principal credential provider is dead on a default build for as long as
	// api.gascity.com is NXDOMAIN.
	const canonical = "https://api.gascity.com"
	for _, tc := range []struct {
		name string
		path string
		call func(config.Config, *dpop.Key) (Session, error)
	}{
		{
			name: "login",
			path: "/sts/v0/login",
			call: func(cfg config.Config, key *dpop.Key) (Session, error) {
				return Login(cfg, "ID.TOK.EN", "org_a", key)
			},
		},
		{
			name: "machine",
			path: "/sts/v0/machine",
			call: func(cfg config.Config, key *dpop.Key) (Session, error) {
				return Machine(cfg, "service-key", key)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, legacy := newStub(t)
			dnsFailingPostForm(t, canonical)
			var events []Event
			cfg := config.Config{
				STSCanonical: canonical,
				STSBase:      legacy.srv.URL,
				STSTelemetry: func(op, origin, outcome, reason string) {
					events = append(events, Event{op, origin, outcome, reason})
				},
			}
			key, err := dpop.NewKey()
			if err != nil {
				t.Fatal(err)
			}
			sess, err := tc.call(cfg, key)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if sess.SessionToken != "SESS" || sess.Origin != legacy.srv.URL {
				t.Fatalf("session = %+v, want SESS at %q", sess, legacy.srv.URL)
			}
			got := legacy.reqs(tc.path)
			if len(got) != 1 {
				t.Fatalf("legacy %s request count = %d, want 1", tc.name, len(got))
			}
			// The proof must be re-signed for the fallback URL; a canonical htu would be
			// rejected by the server that actually received it.
			if htu := htuOf(t, got[0].headers.Get("DPoP")); htu != legacy.srv.URL+tc.path {
				t.Errorf("DPoP htu = %q, want %q", htu, legacy.srv.URL+tc.path)
			}
			if len(events) != 1 || events[0].Operation != tc.name || events[0].Origin != "legacy" ||
				events[0].Outcome != "fallback" || events[0].Reason != "success" {
				t.Fatalf("telemetry = %+v", events)
			}
		})
	}
}

func TestExchangeDoesNotCrossOriginOnDNSResolutionError(t *testing.T) {
	// Exchange is session-bound, not merely state-changing: the session token is only valid at
	// the origin that issued it, so an unresolvable origin is a hard failure with nothing to
	// retry elsewhere.
	const canonical = "https://api.gascity.com"
	_, legacy := newStub(t)
	dnsFailingPostForm(t, canonical)
	var events []Event
	cfg := config.Config{
		STSCanonical: canonical,
		STSBase:      legacy.srv.URL,
		STSTelemetry: func(op, origin, outcome, reason string) {
			events = append(events, Event{op, origin, outcome, reason})
		},
	}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Exchange(cfg, "SESS", "manifold", "manifold:proxy", key); err == nil {
		t.Fatal("Exchange unexpectedly succeeded")
	}
	if got := len(legacy.reqs("/sts/v0/token")); got != 0 {
		t.Fatalf("legacy token request count = %d, want 0", got)
	}
	if len(events) != 1 || events[0].Operation != "token" || events[0].Origin != "canonical" ||
		events[0].Outcome != "failure" || events[0].Reason != "network" {
		t.Fatalf("telemetry = %+v", events)
	}
}

func TestStateChangingCallsDoNotCrossOriginOnRetryableFailure(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			for _, tc := range []struct {
				name string
				op   string
				path string
				call func(config.Config, *dpop.Key) error
			}{
				{
					name: "login",
					op:   "login",
					path: "/sts/v0/login",
					call: func(cfg config.Config, key *dpop.Key) error {
						_, err := Login(cfg, "ID.TOK.EN", "org_a", key)
						return err
					},
				},
				{
					name: "machine",
					op:   "machine",
					path: "/sts/v0/machine",
					call: func(cfg config.Config, key *dpop.Key) error {
						_, err := Machine(cfg, "service-key", key)
						return err
					},
				},
				{
					name: "token",
					op:   "token",
					path: "/sts/v0/token",
					call: func(cfg config.Config, key *dpop.Key) error {
						_, err := Exchange(cfg, "session", "manifold", "manifold:proxy", key)
						return err
					},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var canonicalHits int
					canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						canonicalHits++
						if r.URL.Path != tc.path {
							t.Errorf("canonical path = %q, want %q", r.URL.Path, tc.path)
						}
						writeJSON(w, status, map[string]any{"error": "unavailable"})
					}))
					t.Cleanup(canonical.Close)
					_, legacy := newStub(t)
					var events []Event
					cfg := config.Config{
						STSCanonical: canonical.URL,
						STSBase:      legacy.srv.URL,
						STSTelemetry: func(op, origin, outcome, reason string) {
							events = append(events, Event{op, origin, outcome, reason})
						},
					}
					key, err := dpop.NewKey()
					if err != nil {
						t.Fatal(err)
					}
					if err := tc.call(cfg, key); err == nil {
						t.Fatalf("%s unexpectedly succeeded", tc.name)
					}
					if canonicalHits != 1 {
						t.Fatalf("canonical %s request count = %d, want 1", tc.name, canonicalHits)
					}
					if got := len(legacy.reqs(tc.path)); got != 0 {
						t.Fatalf("legacy %s request count = %d, want 0", tc.name, got)
					}
					if len(events) != 1 || events[0].Operation != tc.op || events[0].Origin != "canonical" ||
						events[0].Outcome != "failure" || events[0].Reason != reasonForStatus(status) {
						t.Fatalf("telemetry = %+v", events)
					}
				})
			}
		})
	}
}

func TestLoginConnectionResetDoesNotCrossOrigin(t *testing.T) {
	var canonicalHits atomic.Int32
	var processed atomic.Int32
	canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canonicalHits.Add(1)
		// Model a server that has accepted the state change before the response
		// connection is lost. The client must treat this as an uncertain result.
		processed.Add(1)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "hijack unavailable"})
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err == nil {
			_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
			_ = rw.Flush()
			_ = conn.Close()
		}
	}))
	t.Cleanup(canonical.Close)
	_, legacy := newStub(t)
	var events []Event
	cfg := config.Config{
		STSCanonical: canonical.URL,
		STSBase:      legacy.srv.URL,
		STSTelemetry: func(op, origin, outcome, reason string) {
			events = append(events, Event{op, origin, outcome, reason})
		},
	}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Login(cfg, "ID.TOK.EN", "org_a", key); err == nil {
		t.Fatal("Login unexpectedly succeeded")
	}
	if got := canonicalHits.Load(); got != 1 {
		t.Fatalf("canonical login request count = %d, want 1", got)
	}
	if got := processed.Load(); got != 1 {
		t.Fatalf("canonical processed count = %d, want 1", got)
	}
	if got := len(legacy.reqs("/sts/v0/login")); got != 0 {
		t.Fatalf("legacy login request count = %d, want 0", got)
	}
	if len(events) != 1 || events[0].Operation != "login" || events[0].Origin != "canonical" ||
		events[0].Outcome != "failure" || events[0].Reason != "network" {
		t.Fatalf("telemetry = %+v", events)
	}
}

func TestSelectedLegacyOriginIsPinnedForLogin(t *testing.T) {
	var canonicalHits int
	canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canonicalHits++
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "must not be contacted"})
	}))
	t.Cleanup(canonical.Close)
	legacyCfg, legacy := newStub(t)
	cfg := (config.Config{STSCanonical: canonical.URL, STSBase: legacyCfg.STSBase}).WithSTSBase(legacyCfg.STSBase)
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := Login(cfg, "ID.TOK.EN", "org_a", key)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.Origin != legacyCfg.STSBase {
		t.Fatalf("session origin = %q, want %q", sess.Origin, legacyCfg.STSBase)
	}
	if canonicalHits != 0 {
		t.Fatalf("canonical request count = %d, want 0", canonicalHits)
	}
	if got := len(legacy.reqs("/sts/v0/login")); got != 1 {
		t.Fatalf("legacy login request count = %d, want 1", got)
	}
}

func reasonForStatus(status int) string {
	if status == http.StatusNotFound {
		return "404"
	}
	return "5xx"
}

func TestAuthenticationFailureNeverFallsBack(t *testing.T) {
	canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
	}))
	t.Cleanup(canonical.Close)
	_, legacy := newStub(t)
	cfg := config.Config{STSCanonical: canonical.URL, STSBase: legacy.srv.URL}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Login(cfg, "ID.TOK.EN", "org_a", key); err == nil {
		t.Fatal("Login unexpectedly succeeded")
	}
	if got := len(legacy.reqs("/sts/v0/login")); got != 0 {
		t.Fatalf("legacy received %d requests after canonical 401", got)
	}
}

func TestForbiddenAndInvalidRequestNeverFallBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body map[string]any
	}{
		{name: "forbidden", code: http.StatusForbidden, body: map[string]any{"error": "access_denied"}},
		{name: "invalid request", code: http.StatusBadRequest, body: map[string]any{"error": "invalid_request"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.code, tc.body)
			}))
			t.Cleanup(canonical.Close)
			_, legacy := newStub(t)
			cfg := config.Config{STSCanonical: canonical.URL, STSBase: legacy.srv.URL}
			key, err := dpop.NewKey()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Login(cfg, "ID.TOK.EN", "org_a", key); err == nil {
				t.Fatal("Login unexpectedly succeeded")
			}
			if got := len(legacy.reqs("/sts/v0/login")); got != 0 {
				t.Fatalf("legacy received %d requests", got)
			}
		})
	}
}

func TestLegacyOnlyTelemetryIsNotMislabelledCanonical(t *testing.T) {
	cfg, _ := newStub(t)
	var events []Event
	cfg.STSTelemetry = func(op, origin, outcome, reason string) {
		events = append(events, Event{op, origin, outcome, reason})
	}
	if _, err := Context(cfg, "ID.TOK.EN", false); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Origin != "legacy" || events[0].Outcome != "success" {
		t.Fatalf("telemetry = %+v", events)
	}
}

func TestNarrowedConfigKeepsCanonicalTelemetryClassification(t *testing.T) {
	cfg := config.Config{
		STSCanonical: "https://api.gascity.com",
		STSBase:      "https://works.gascity.com",
	}
	if got := originClass(cfg.WithPreferredSTS(cfg.STSBase), cfg.STSBase); got != "legacy" {
		t.Fatalf("legacy preference classified as %q, want legacy", got)
	}
	if got := originClass(cfg.WithSTSBase(cfg.STSBase), cfg.STSBase); got != "legacy" {
		t.Fatalf("legacy narrowing classified as %q, want legacy", got)
	}
	if got := originClass(cfg.WithSTSBase(cfg.STSCanonical), cfg.STSCanonical); got != "canonical" {
		t.Fatalf("canonical narrowing classified as %q, want canonical", got)
	}
}

func TestMalformedCanonicalURLDoesNotFallBack(t *testing.T) {
	_, legacy := newStub(t)
	cfg := config.Config{STSCanonical: "://malformed", STSBase: legacy.srv.URL}
	if _, err := Context(cfg, "ID.TOK.EN", false); err == nil {
		t.Fatal("Context unexpectedly succeeded")
	}
	if got := len(legacy.reqs("/sts/v0/context")); got != 0 {
		t.Fatalf("legacy received %d requests after malformed canonical URL", got)
	}
}

func TestRetryableRejectsPlainNonNetworkError(t *testing.T) {
	if retryable(errors.New("configuration invalid")) {
		t.Fatal("plain non-network error classified retryable")
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

func athOf(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed DPoP proof: %q", proof)
	}
	raw, err := base64urlDecode(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		ATH string `json:"ath"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.ATH
}

func htuOf(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed DPoP proof: %q", proof)
	}
	raw, err := base64urlDecode(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		HTU string `json:"htu"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.HTU
}

func ath(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
