package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/edgedevice"
	"github.com/gascity/gasworks/internal/keystore"
	"github.com/gascity/gasworks/internal/store"
)

// testEdgeRoot is shaped like a real cli-edge root: gcs_cli_ and 32 base32 characters.
const (
	testEdgeRoot       = "gcs_cli_abcdefghijklmnopqrstuvwxyz234567"
	testEdgeDeviceCode = "gcd_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// edgeSessionContext is the STS's discovery answer for a DPoP-presented edge-device root:
// exactly the one org the root is pinned to.
func edgeSessionContext(orgID, slug string) map[string]any {
	return map[string]any{
		"user_id": "usr_1", "default_org_id": orgID, "orgs": []any{
			map[string]any{
				"org_id": orgID, "slug": slug, "role": "member", "is_default": true,
				"products": map[string]any{
					"manifold": map[string]any{
						"audience": "manifold",
						"scopes":   []string{"manifold:proxy", "manifold:pool:" + slug},
					},
				},
			},
		},
	}
}

// startEdge brings up the cli-edge device plane and points the CLI at it. Like the mint
// plane it is its own https origin — the config layer refuses a plain-http one, because the
// URL is signed into every poll's proof — so the flow's client is swapped for one that trusts
// this server's CA, and its sleep for one that records the pacing without waiting.
func (s *stubServer) startEdge(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/gc/v0/auth/device/code", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if s.edgeIssueHandler != nil {
			s.edgeIssueHandler(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"device_code": testEdgeDeviceCode, "user_code": "BDWK-JQPX",
			"verification_uri":          s.edge.URL + "/gc/v0/device",
			"verification_uri_complete": s.edge.URL + "/gc/v0/device?code=BDWK-JQPX",
			"expires_in":                600, "interval": 5,
		})
	})
	mux.HandleFunc("/gc/v0/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		attempt := len(s.reqs("/gc/v0/auth/device/token")) - 1
		s.mu.Lock()
		answers := s.edgePollAnswers
		s.mu.Unlock()
		if attempt < len(answers) {
			answers[attempt](w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": testEdgeRoot, "token_type": "DPoP"})
	})
	mux.HandleFunc("/gc/v0/session", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.WriteHeader(http.StatusNoContent)
	})
	s.edge = httptest.NewTLSServer(mux)
	t.Cleanup(s.edge.Close)
	t.Setenv(config.CLIEdgeBaseEnv, s.edge.URL)
	previous := edgeClient
	edgeClient = &edgedevice.Client{HTTP: s.edge.Client(), Sleep: func(d time.Duration) {
		s.mu.Lock()
		s.edgeSleeps = append(s.edgeSleeps, d)
		s.mu.Unlock()
	}}
	t.Cleanup(func() { edgeClient = previous })
}

func edgePollError(code string, interval int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		body := map[string]any{"error": code}
		if interval > 0 {
			body["interval"] = interval
		}
		writeJSON(w, http.StatusBadRequest, body)
	}
}

// seedEdgeSession writes an edge-device login directly: a key enrolled in the scratch store and
// an edge session under generation, which credentials.json is set to carry.
func seedEdgeSession(t *testing.T, srv *stubServer, generation string) *dpop.Key {
	t.Helper()
	return seedEdgeSessionWithRoot(t, srv, generation, testEdgeRoot)
}

func seedEdgeSessionWithRoot(t *testing.T, srv *stubServer, generation, root string) *dpop.Key {
	t.Helper()
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	backend, err := keystore.Select(keystoreRegistry(), true)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := enrollSessionKey(backend, sessionKeyHandle(edgeSessionKeyPrefix+generation), key)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://works.gascity.com"
	if srv.edge != nil {
		origin = srv.edge.URL
	}
	if err := store.Transact(func(tx *store.Tx) error {
		tx.Data.CredentialGeneration = generation
		tx.ReplaceEdge(store.EdgeSession{
			CredentialGeneration: generation, RootToken: root, TokenType: "DPoP", Key: ref,
			EdgeOrigin: origin, OrgID: "org_a", OrgSlug: "acme", UserID: "usr_1", IssuedAt: time.Now().Unix(),
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

// loadEdgeFile reads edge-session.json back from disk, or nil when there is none.
func loadEdgeFile(t *testing.T) *store.EdgeSession {
	t.Helper()
	raw, err := os.ReadFile(store.EdgeSessionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var edge store.EdgeSession
	if err := json.Unmarshal(raw, &edge); err != nil {
		t.Fatal(err)
	}
	return &edge
}

func keyFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(store.KeyDir(), "*.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func jwkJSON(t *testing.T, key *dpop.Key) string {
	t.Helper()
	encoded, err := json.Marshal(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func assertPriorKeycloakLoginIntact(t *testing.T, refresh string) {
	t.Helper()
	data := loadStore(t)
	if data.CredentialGeneration != testCredentialGenerationA || data.RefreshToken != refresh || data.IDToken == "" {
		t.Fatalf("the failed edge login changed the prior login: %+v", data)
	}
	if edge := loadEdgeFile(t); edge != nil {
		t.Fatalf("the failed edge login saved an edge session: %+v", edge)
	}
}

// The whole flow: issue, the prompt, polls carrying fresh proofs from ONE key (no ath), the
// STS accepting the root, and a commit that replaces the Keycloak login — tokens cleared and
// revoked, sessions and cached EIAs dropped, the root stored outside credentials.json.
func TestEdgeDeviceLoginReplacesTheKeycloakLogin(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{
		"refresh_token": "RT-OLD", "id_token": validIDToken(),
		"eia_cache": map[string]any{
			eiaCacheKey(srv.srv.URL, "org_a", "manifold", testCredentialGenerationA, []string{"manifold:proxy"}): map[string]any{
				"eia": "OLD.EIA", "expires_at": time.Now().Add(time.Hour).Unix(),
			},
		},
	})
	oldKey := enrollTestKey(t, "dpop-old-session")
	if err := store.Update(func(d *store.Data) error {
		d.Sessions = map[string]store.Session{
			sessionCacheKey(srv.srv.URL, "org_a", testCredentialGenerationA): {SessionToken: "gcs_user_OLD", Key: oldKey, ExpiresAt: time.Now().Add(time.Hour).Unix()},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.startEdge(t)
	srv.edgePollAnswers = []func(http.ResponseWriter){edgePollError("authorization_pending", 0), edgePollError("authorization_pending", 0)}

	out, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device"}) })
	if code != 0 {
		t.Fatalf("login --edge-device = exit %d stderr %q", code, errOut)
	}
	if !strings.Contains(out, "Logged in with an edge-device session for org acme (org_a).") {
		t.Fatalf("stdout = %q", out)
	}
	for _, want := range []string{srv.edge.URL + "/gc/v0/device?code=BDWK-JQPX", "BDWK-JQPX", "bd (bd-enterprise)"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr does not show %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(out+errOut, testEdgeRoot) {
		t.Fatal("the login printed the root")
	}

	// The issue carries a label and no proof; every poll a fresh proof from the same key.
	issue := srv.reqs("/gc/v0/auth/device/code")
	if len(issue) != 1 || issue[0].dpop != "" || !strings.Contains(issue[0].body, `"label"`) {
		t.Fatalf("issue = %+v", issue)
	}
	polls := srv.reqs("/gc/v0/auth/device/token")
	if len(polls) != 3 {
		t.Fatalf("polls = %d, want 3", len(polls))
	}
	jwk := proofJWK(t, polls[0].dpop)
	jtis := map[string]bool{}
	for i, poll := range polls {
		claims := proofPayload(t, poll.dpop)
		if claims["htm"] != "POST" || claims["htu"] != srv.edge.URL+"/gc/v0/auth/device/token" {
			t.Fatalf("poll %d htm/htu = %v %v", i, claims["htm"], claims["htu"])
		}
		if _, present := claims["ath"]; present {
			t.Fatalf("poll %d proof carries ath: %v", i, claims)
		}
		jti, _ := claims["jti"].(string)
		if iat, _ := claims["iat"].(float64); jti == "" || jtis[jti] || iat == 0 {
			t.Fatalf("poll %d jti/iat = %q/%v", i, jti, claims["iat"])
		}
		jtis[jti] = true
		if proofJWK(t, poll.dpop) != jwk {
			t.Fatalf("poll %d was signed by a different key", i)
		}
		if poll.body != `{"device_code":"`+testEdgeDeviceCode+`"}` {
			t.Fatalf("poll %d body = %q", i, poll.body)
		}
	}
	if len(srv.edgeSleeps) != 3 || srv.edgeSleeps[0] != 5*time.Second {
		t.Fatalf("poll pacing = %v", srv.edgeSleeps)
	}

	// The STS accepted the root before anything changed: one DPoP-presented discovery with the
	// same key, and no /sts/v0/login.
	discovery := srv.reqs("/sts/v0/context")
	if len(discovery) != 1 || discovery[0].auth != "DPoP "+testEdgeRoot {
		t.Fatalf("discovery = %+v", discovery)
	}
	claims := proofPayload(t, discovery[0].dpop)
	if claims["htm"] != "GET" || claims["htu"] != srv.srv.URL+"/sts/v0/context" || claims["ath"] != wantATH(testEdgeRoot) ||
		proofJWK(t, discovery[0].dpop) != jwk {
		t.Fatalf("discovery proof = %v", claims)
	}
	if logins := srv.reqs("/sts/v0/login"); len(logins) != 0 {
		t.Fatalf("an edge login established %d STS sessions", len(logins))
	}

	// The commit: credentials.json carries the new generation and nothing else of note.
	raw, err := os.ReadFile(store.CredsPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testEdgeRoot) {
		t.Fatalf("credentials.json carries the root:\n%s", raw)
	}
	data := loadStore(t)
	if data.IDToken != "" || data.RefreshToken != "" || len(data.Sessions) != 0 || len(data.EIACache) != 0 ||
		!validCredentialGeneration(data.CredentialGeneration) || data.CredentialGeneration == testCredentialGenerationA ||
		data.DefaultOrg != "" {
		t.Fatalf("credentials after the edge login = %+v", data)
	}
	edge := loadEdgeFile(t)
	if edge == nil || edge.RootToken != testEdgeRoot || edge.TokenType != "DPoP" || edge.CredentialGeneration != data.CredentialGeneration ||
		edge.EdgeOrigin != srv.edge.URL || edge.OrgID != "org_a" || edge.OrgSlug != "acme" || edge.UserID != "usr_1" ||
		edge.Version != store.EdgeSessionVersion || edge.IssuedAt == 0 {
		t.Fatalf("edge session = %+v", edge)
	}
	stored, err := loadSessionKey(edge.Key)
	if err != nil {
		t.Fatalf("the edge key is not in the credential store: %v", err)
	}
	if jwkJSON(t, stored) != jwk {
		t.Fatal("the stored key is not the key the polls proved")
	}
	if os.PathSeparator != '\\' {
		if info, err := os.Stat(store.EdgeSessionPath()); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("edge session mode = %v, %v", info, err)
		}
	}

	// What the login replaced is gone: the Keycloak refresh token revoked, the old session key
	// deleted.
	revokes := srv.reqs("/protocol/openid-connect/revoke")
	if len(revokes) != 1 || revokes[0].form.Get("token") != "RT-OLD" {
		t.Fatalf("Keycloak revocations = %+v", revokes)
	}
	if _, err := loadSessionKey(oldKey); err == nil {
		t.Fatal("the replaced session's key is still enrolled")
	}
	if len(srv.reqs("/gc/v0/session")) != 0 {
		t.Fatal("a successful login revoked its own root")
	}
}

// getToken with an edge-device login presents the root itself at discovery and the exchange,
// with the stored key; it never reaches /sts/v0/login or Keycloak, and caches under its own
// credential kind.
func TestEdgeDeviceGetTokenExchangesTheRootDirectly(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	key := seedEdgeSession(t, srv, testCredentialGenerationA)

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 0 || errOut != "" || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("getToken = exit %d stdout %q stderr %q", code, out, errOut)
	}
	tokens := srv.reqs("/sts/v0/token")
	if len(tokens) != 1 {
		t.Fatalf("token requests = %d", len(tokens))
	}
	form := tokens[0].form
	if form.Get("subject_token") != testEdgeRoot || form.Get("audience") != "manifold" ||
		form.Get("scope") != "manifold:proxy manifold:pool:acme" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("exchange form = %v", form)
	}
	if _, present := form["subject_token_type"]; present {
		t.Fatal("subject_token_type must be omitted, as for /sts/v0/login sessions")
	}
	claims := proofPayload(t, tokens[0].dpop)
	if claims["htm"] != "POST" || claims["htu"] != srv.srv.URL+"/sts/v0/token" || claims["ath"] != wantATH(testEdgeRoot) {
		t.Fatalf("exchange proof = %v", claims)
	}
	if proofJWK(t, tokens[0].dpop) != jwkJSON(t, key) {
		t.Fatal("the exchange was not signed by the root's key")
	}
	discovery := srv.reqs("/sts/v0/context")
	if len(discovery) != 1 || discovery[0].auth != "DPoP "+testEdgeRoot || strings.Contains(discovery[0].path, "provision") {
		t.Fatalf("discovery = %+v", discovery)
	}
	for _, path := range []string{"/sts/v0/login", "/protocol/openid-connect/token"} {
		if got := srv.reqs(path); len(got) != 0 {
			t.Fatalf("an edge-device mint reached %s", path)
		}
	}
	data := loadStore(t)
	if _, cached := data.EIACache[eiaCacheKeyFor(edgeCredentialKind, srv.srv.URL, "org_a", "manifold",
		testCredentialGenerationA, []string{"manifold:proxy", "manifold:pool:acme"})]; !cached || len(data.Sessions) != 0 {
		t.Fatalf("cache/sessions after the edge mint = %+v", data)
	}

	// Within the EIA's life the second call is a cache hit; so is the credential-provider.
	if out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("second getToken = exit %d %q %q", code, out, errOut)
	}
	if got := len(srv.reqs("/sts/v0/token")); got != 1 {
		t.Fatalf("token requests after a cache hit = %d", got)
	}
	response, providerErr, providerCode := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1","audience":"manifold",
		"required_scopes":["manifold:proxy"],"interactive":false}`)
	if providerCode != 0 || providerErr != "" || response.Kind != "Credential" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("credential-provider = exit %d %q %+v", providerCode, providerErr, response)
	}
}

// The root is pinned to the approver's org: an --org (or a stored default org) naming another
// org is refused with the re-login instructions, before anything is minted.
func TestEdgeDeviceGetTokenRefusesAnotherOrg(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	seedEdgeSession(t, srv, testCredentialGenerationA)

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--org", "other"}) })
	if code == 0 || !strings.Contains(errOut, "pinned to org acme (org_a)") ||
		!strings.Contains(errOut, "Switch to other in the browser") || !strings.Contains(errOut, "gasworks login --edge-device") {
		t.Fatalf("--org other = exit %d stderr %q", code, errOut)
	}
	response, _, providerCode := runCredentialProvider(t, `{
		"version":"gascity.dev/credential-provider/v1","audience":"manifold",
		"required_scopes":["manifold:proxy"],"org":"other","interactive":false}`)
	if providerCode == 0 || response.Code != credentialErrorInteraction || !strings.Contains(response.Message, "login --edge-device") {
		t.Fatalf("provider for another org = exit %d %+v", providerCode, response)
	}
	if got := len(srv.reqs("/sts/v0/token")); got != 0 {
		t.Fatalf("a refused org reached the exchange %d times", got)
	}

	for _, named := range []string{"acme", "org_a"} {
		if out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--org", named, "--refresh"}) }); code != 0 || strings.TrimSpace(out) != "EIA.JWT" {
			t.Fatalf("--org %s = exit %d %q %q", named, code, out, errOut)
		}
	}

	if err := store.Update(func(d *store.Data) error { d.DefaultOrg = "org_b"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--refresh"}) }); code == 0 ||
		!strings.Contains(errOut, "the stored default org") {
		t.Fatalf("stale default org = exit %d stderr %q", code, errOut)
	}
}

// An STS that does not accept the root says so in words that name the fix, on both legs and
// through the credential-provider's fixed vocabulary.
func TestEdgeDeviceGetTokenRefusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		discovery   func(http.ResponseWriter, *http.Request)
		exchange    func(http.ResponseWriter, *http.Request, url.Values)
		wantCLI     string
		wantMessage string
	}{
		{
			name: "STS without the session path",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			},
			wantCLI: "not enabled on this server yet — sign in with `gasworks login`", wantMessage: "Run `gasworks login`.",
		},
		{
			name: "exchange switched off",
			exchange: func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			},
			wantCLI: "not enabled on this server yet — sign in with `gasworks login`", wantMessage: "Run `gasworks login`.",
		},
		{
			name: "expired root at discovery",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_grant"})
			},
			wantCLI: "expired or was revoked — run `gasworks login --edge-device` again", wantMessage: "login --edge-device",
		},
		{
			name: "revoked root at the exchange",
			exchange: func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_grant"})
			},
			wantCLI: "expired or was revoked — run `gasworks login --edge-device` again", wantMessage: "login --edge-device",
		},
		{
			name: "proof rejected",
			exchange: func(w http.ResponseWriter, _ *http.Request, _ url.Values) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_dpop_proof"})
			},
			wantCLI: "invalid_dpop_proof", wantMessage: "Check the clock",
		},
		{
			name: "session described with two orgs",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				body := edgeSessionContext("org_a", "acme")
				body["orgs"] = append(body["orgs"].([]any), edgeSessionContext("org_b", "beta")["orgs"].([]any)...)
				writeJSON(w, http.StatusOK, body)
			},
			wantCLI: "pinned to exactly one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newStub(t)
			srv.sessionContextHandler = tc.discovery
			srv.eiaHandler = tc.exchange
			seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
			seedEdgeSession(t, srv, testCredentialGenerationA)

			_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
			if code == 0 || !strings.Contains(errOut, tc.wantCLI) {
				t.Fatalf("getToken = exit %d stderr %q, want %q", code, errOut, tc.wantCLI)
			}
			if tc.wantMessage == "" {
				return
			}
			response, _, providerCode := runCredentialProvider(t, `{
				"version":"gascity.dev/credential-provider/v1","audience":"manifold",
				"required_scopes":["manifold:proxy"],"interactive":false}`)
			if providerCode == 0 || response.Code != credentialErrorInteraction || !strings.Contains(response.Message, tc.wantMessage) {
				t.Fatalf("credential-provider = exit %d %+v", providerCode, response)
			}
			if strings.Contains(response.Message, testEdgeRoot) || strings.Contains(errOut, testEdgeRoot) {
				t.Fatal("a refusal printed the root")
			}
		})
	}
}

// Refusals during the device flow leave the prior login exactly as it was, and never store a
// root. An unbound (bearer) root is refused and revoked.
func TestEdgeDeviceLoginRefusalsKeepThePriorLogin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		issue   func(http.ResponseWriter, *http.Request)
		answers []func(http.ResponseWriter)
		want    string
		revoked bool
	}{
		{name: "dark device plane", issue: func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
			want: "not enabled on this server yet — sign in with `gasworks login`"},
		{name: "denied", answers: []func(http.ResponseWriter){edgePollError("access_denied", 0)}, want: "denied in the browser"},
		{name: "expired", answers: []func(http.ResponseWriter){edgePollError("expired_token", 0)}, want: "expired before it was approved"},
		{name: "invalid proof", answers: []func(http.ResponseWriter){edgePollError("invalid_dpop_proof", 0)},
			want: "invalid_dpop_proof): check the system clock, and that " + config.CLIEdgeBaseEnv},
		{name: "bearer root", answers: []func(http.ResponseWriter){func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]any{"access_token": testEdgeRoot, "token_type": "bearer"})
		}}, want: "does not support key-bound device login yet", revoked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newStub(t)
			seed(t, srv, map[string]any{"refresh_token": "RT-KEEP", "id_token": validIDToken()})
			srv.startEdge(t)
			srv.edgeIssueHandler = tc.issue
			srv.edgePollAnswers = tc.answers

			_, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device"}) })
			if code == 0 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("login = exit %d stderr %q, want %q", code, errOut, tc.want)
			}
			if strings.Contains(errOut, testEdgeRoot) {
				t.Fatal("the refusal printed the root")
			}
			assertPriorKeycloakLoginIntact(t, "RT-KEEP")
			if files := keyFiles(t); len(files) != 0 {
				t.Fatalf("a refused login left keys behind: %v", files)
			}
			if got := len(srv.reqs("/sts/v0/context")) + len(srv.reqs("/protocol/openid-connect/revoke")); got != 0 {
				t.Fatalf("a refused device flow went on to the STS or revoked the prior login (%d requests)", got)
			}
			revokes := srv.reqs("/gc/v0/session")
			if tc.revoked {
				if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+testEdgeRoot || revokes[0].dpop != "" {
					t.Fatalf("revocations = %+v", revokes)
				}
			} else if len(revokes) != 0 {
				t.Fatalf("revocations = %+v", revokes)
			}
		})
	}
}

// When the STS will not take the freshly redeemed root (no session path yet, the exchange
// switched off, or an org the caller did not ask for), the root is revoked with proof of
// possession and the prior login is untouched.
func TestEdgeDeviceLoginRevokesARootTheSTSRefuses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		discovery func(http.ResponseWriter, *http.Request)
		args      []string
		want      string
	}{
		{name: "STS without the session path", discovery: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		}, want: "the STS does not accept edge-device sessions yet (HTTP 400 invalid_request)"},
		{name: "exchange switched off", discovery: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		}, want: "edge-device login is not enabled on this server — sign in with `gasworks login`"},
		{name: "STS unavailable", discovery: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "temporarily_unavailable"})
		}, want: "could not confirm the edge-device session with the STS"},
		{name: "approved in another org", args: []string{"--org", "beta"},
			want: "the browser approved this device in org acme (org_a), not beta: switch to beta in the browser"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newStub(t)
			srv.sessionContextHandler = tc.discovery
			seed(t, srv, map[string]any{"refresh_token": "RT-KEEP", "id_token": validIDToken()})
			srv.startEdge(t)

			_, errOut, code := capture(t, func() int {
				return run(append([]string{"login", "--edge-device"}, tc.args...))
			})
			if code == 0 || !strings.Contains(errOut, tc.want) || !strings.Contains(errOut, "nothing was changed") {
				t.Fatalf("login = exit %d stderr %q, want %q", code, errOut, tc.want)
			}
			assertPriorKeycloakLoginIntact(t, "RT-KEEP")
			if files := keyFiles(t); len(files) != 0 {
				t.Fatalf("a refused login left keys behind: %v", files)
			}
			revokes := srv.reqs("/gc/v0/session")
			if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+testEdgeRoot {
				t.Fatalf("revocations = %+v", revokes)
			}
			claims := proofPayload(t, revokes[0].dpop)
			if claims["htm"] != "DELETE" || claims["htu"] != srv.edge.URL+"/gc/v0/session" || claims["ath"] != wantATH(testEdgeRoot) ||
				proofJWK(t, revokes[0].dpop) != proofJWK(t, srv.reqs("/gc/v0/auth/device/token")[0].dpop) {
				t.Fatalf("revocation proof = %v", claims)
			}
		})
	}
}

func TestEdgeDeviceLoginWithMatchingOrgRemembersIt(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{})
	srv.startEdge(t)
	if _, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device", "--org", "acme"}) }); code != 0 {
		t.Fatalf("login = exit %d stderr %q", code, errOut)
	}
	if data := loadStore(t); data.DefaultOrg != "org_a" {
		t.Fatalf("default_org = %q, want the matched org's id", data.DefaultOrg)
	}
}

// slow_down widens the interval by the RFC 8628 step (or to the server's larger value); pending
// never narrows it.
func TestEdgeDeviceLoginHonoursSlowDown(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{})
	srv.startEdge(t)
	srv.edgePollAnswers = []func(http.ResponseWriter){
		edgePollError("slow_down", 0), edgePollError("authorization_pending", 0), edgePollError("slow_down", 20),
	}
	if _, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device"}) }); code != 0 {
		t.Fatalf("login = exit %d stderr %q", code, errOut)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 10 * time.Second, 20 * time.Second}
	if len(srv.edgeSleeps) != len(want) {
		t.Fatalf("poll pacing = %v, want %v", srv.edgeSleeps, want)
	}
	for i := range want {
		if srv.edgeSleeps[i] != want[i] {
			t.Fatalf("poll pacing = %v, want %v", srv.edgeSleeps, want)
		}
	}
}

func TestEdgeDeviceIsExclusiveWithTheKeycloakFlows(t *testing.T) {
	for _, extra := range []string{"--device", "--browser", "--staff"} {
		srv := newStub(t)
		seed(t, srv, map[string]any{"refresh_token": "RT-KEEP", "id_token": validIDToken()})
		srv.startEdge(t)
		_, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device", extra}) })
		if code == 0 || !strings.Contains(errOut, "--edge-device cannot be combined with --device, --browser or --staff") {
			t.Fatalf("login --edge-device %s = exit %d stderr %q", extra, code, errOut)
		}
		srv.mu.Lock()
		requests := len(srv.requests)
		srv.mu.Unlock()
		if requests != 0 {
			t.Fatalf("login --edge-device %s made %d requests", extra, requests)
		}
		assertPriorKeycloakLoginIntact(t, "RT-KEEP")
	}
}

// A plain Keycloak login replaces an edge-device login: the edge file is removed, the root is
// revoked at the cli-edge with proof of possession, and its key is deleted.
func TestKeycloakLoginRetiresTheEdgeRoot(t *testing.T) {
	srv := newStub(t)
	srv.refreshTok = map[string]any{"id_token": validIDTokenIss(srv.srv.URL + "/realms/g"), "refresh_token": "RT-NEW"}
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	srv.startEdge(t)
	key := seedEdgeSession(t, srv, testCredentialGenerationA)
	edge := loadEdgeFile(t)

	if _, errOut, code := capture(t, func() int { return run([]string{"login", "--device"}) }); code != 0 {
		t.Fatalf("login --device = exit %d stderr %q", code, errOut)
	}
	if loadEdgeFile(t) != nil {
		t.Fatal("the Keycloak login left the edge session in place")
	}
	if data := loadStore(t); data.RefreshToken != "RT-NEW" || data.CredentialGeneration == testCredentialGenerationA {
		t.Fatalf("credentials = %+v", data)
	}
	revokes := srv.reqs("/gc/v0/session")
	if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+testEdgeRoot {
		t.Fatalf("revocations = %+v", revokes)
	}
	if claims := proofPayload(t, revokes[0].dpop); claims["ath"] != wantATH(testEdgeRoot) || proofJWK(t, revokes[0].dpop) != jwkJSON(t, key) {
		t.Fatalf("revocation proof = %v", claims)
	}
	if _, err := loadSessionKey(edge.Key); err == nil {
		t.Fatal("the retired root's key is still enrolled")
	}
}

func TestLogoutRetiresTheEdgeRoot(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	srv.startEdge(t)
	seedEdgeSession(t, srv, testCredentialGenerationA)

	out, errOut, code := capture(t, func() int { return run([]string{"logout"}) })
	if code != 0 || !strings.Contains(out, "Logged out.") {
		t.Fatalf("logout = exit %d %q %q", code, out, errOut)
	}
	for _, path := range []string{store.CredsPath(), store.EdgeSessionPath()} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived logout: %v", path, err)
		}
	}
	revokes := srv.reqs("/gc/v0/session")
	if len(revokes) != 1 || revokes[0].auth != "Bearer "+testEdgeRoot || proofPayload(t, revokes[0].dpop)["ath"] != wantATH(testEdgeRoot) {
		t.Fatalf("revocations = %+v", revokes)
	}
	if files := keyFiles(t); len(files) != 0 {
		t.Fatalf("logout left keys behind: %v", files)
	}
	if len(srv.reqs("/protocol/openid-connect/revoke")) != 0 {
		t.Fatal("logout revoked a refresh token the edge login does not hold")
	}
}

// bd-enterprise decodes credentials.json into its own struct and writes it back without the
// fields it does not know. That must not lose the edge-device login: the root is not in that
// file, and the generation bd carries through still names it. A bd login or logout — which
// rewrites or removes the generation — fences it out.
func TestBdRewritingCredentialsJSONKeepsTheEdgeRoot(t *testing.T) {
	type bdSession struct {
		SessionToken string `json:"session_token"`
		DPoPPEM      string `json:"dpop_pem"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	type bdEIACacheEntry struct {
		EIA       string   `json:"eia"`
		ExpiresAt int64    `json:"expires_at"`
		Scopes    []string `json:"scopes,omitempty"`
	}
	type bdData struct {
		IDToken              string                     `json:"id_token,omitempty"`
		RefreshToken         string                     `json:"refresh_token,omitempty"`
		CredentialGeneration string                     `json:"credential_generation,omitempty"`
		DefaultOrg           string                     `json:"default_org,omitempty"`
		Sessions             map[string]bdSession       `json:"sessions,omitempty"`
		EIACache             map[string]bdEIACacheEntry `json:"eia_cache,omitempty"`
	}
	bdRewrite := func(t *testing.T, mutate func(*bdData)) {
		t.Helper()
		var d bdData
		if raw, err := os.ReadFile(store.CredsPath()); err == nil {
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
		}
		mutate(&d)
		raw, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.CredsPath(), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	srv := newStub(t)
	seed(t, srv, map[string]any{})
	srv.startEdge(t)
	if _, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device"}) }); code != 0 {
		t.Fatalf("login = exit %d stderr %q", code, errOut)
	}
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken = exit %d stderr %q", code, errOut)
	}

	// A bd write that carries the generation through (bd caching its own session, say).
	bdRewrite(t, func(d *bdData) {
		if d.Sessions == nil {
			d.Sessions = map[string]bdSession{}
		}
		d.Sessions["bd-session"] = bdSession{SessionToken: "gcs_user_BD", DPoPPEM: "BD-KEY", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	})
	if out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--refresh"}) }); code != 0 || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("getToken after a bd rewrite = exit %d %q %q", code, out, errOut)
	}
	if logins := srv.reqs("/sts/v0/login"); len(logins) != 0 {
		t.Fatal("the edge root was lost to a bd rewrite: getToken fell back to /sts/v0/login")
	}
	if tokens := srv.reqs("/sts/v0/token"); len(tokens) != 2 || tokens[1].form.Get("subject_token") != testEdgeRoot {
		t.Fatalf("exchanges = %+v", tokens)
	}
	if data := loadStore(t); data.Sessions["bd-session"].InlineKeyPEM != "BD-KEY" {
		t.Fatal("the edge mint dropped bd's own session")
	}

	// A bd login: a new generation and Keycloak tokens. The edge root is fenced out and the
	// Keycloak path is used again.
	bdRewrite(t, func(d *bdData) {
		d.IDToken, d.RefreshToken, d.CredentialGeneration = validIDToken(), "RT-BD", testCredentialGenerationB
		d.Sessions, d.EIACache = nil, nil
	})
	if out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("getToken after a bd login = exit %d %q %q", code, out, errOut)
	}
	if logins := srv.reqs("/sts/v0/login"); len(logins) != 1 {
		t.Fatalf("after a bd login getToken should establish a Keycloak session, got %d logins", len(logins))
	}
	if tokens := srv.reqs("/sts/v0/token"); tokens[len(tokens)-1].form.Get("subject_token") == testEdgeRoot {
		t.Fatal("a fenced-out edge root was used after a bd login")
	}
	out, _, _ := capture(t, func() int { return run([]string{"inspect"}) })
	if !strings.Contains(out, "stale") || !strings.Contains(out, "session kind: keycloak") {
		t.Fatalf("inspect after a bd login:\n%s", out)
	}

	// A bd logout removes credentials.json: nothing is in force any more.
	if err := os.Remove(store.CredsPath()); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code == 0 || !strings.Contains(errOut, "not logged in") {
		t.Fatalf("getToken after a bd logout = exit %d stderr %q", code, errOut)
	}
}

func TestInspectShowsTheEdgeDeviceSession(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	key := seedEdgeSession(t, srv, testCredentialGenerationA)
	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken = exit %d stderr %q", code, errOut)
	}
	edge := loadEdgeFile(t)

	out, errOut, code := capture(t, func() int { return run([]string{"inspect"}) })
	if code != 0 {
		t.Fatalf("inspect = exit %d stderr %q", code, errOut)
	}
	for _, want := range []string{
		"session kind: edge-device", "edge-device session:", "active", "acme (org_a)", "usr_1",
		edge.Key.Backend + ":" + edge.Key.Handle, key.Thumbprint(), store.EdgeSessionPath(),
		"via      the edge-device session", "audience manifold",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect does not report %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, testEdgeRoot) || strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "login:") {
		t.Fatalf("inspect printed a credential or a Keycloak login block:\n%s", out)
	}

	out, _, code = capture(t, func() int { return run([]string{"inspect", "--json"}) })
	if code != 0 {
		t.Fatalf("inspect --json = exit %d", code)
	}
	if strings.Contains(out, testEdgeRoot) {
		t.Fatal("inspect --json printed the root")
	}
	var report inspection
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("inspect --json: %v\n%s", err, out)
	}
	if !report.LoggedIn || report.SessionKind != edgeCredentialKind || report.Login != nil || report.EdgeSession == nil ||
		!report.EdgeSession.Active || report.EdgeSession.KeyStatus != "enrolled" || report.EdgeSession.KeyJKT != key.Thumbprint() ||
		report.EdgeSession.OrgID != "org_a" || report.EdgeSession.TokenType != "DPoP" || len(report.CachedEIAs) != 1 ||
		report.CachedEIAs[0].Via != edgeCredentialKind {
		t.Fatalf("inspect --json = %+v / %+v", report, report.EdgeSession)
	}
}

func TestWhoamiAndKeycloakOnlyCommandsWithAnEdgeSession(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	seedEdgeSession(t, srv, testCredentialGenerationA)

	out, errOut, code := capture(t, func() int { return run([]string{"whoami"}) })
	if code != 0 || !strings.Contains(out, "edge device") || !strings.Contains(out, "acme (org_a)") || !strings.Contains(out, "usr_1") {
		t.Fatalf("whoami = exit %d %q %q", code, out, errOut)
	}
	_, errOut, code = capture(t, func() int { return run([]string{"rotate-key"}) })
	if code == 0 || !strings.Contains(errOut, "does not work with an edge-device session") || !strings.Contains(errOut, "login --edge-device") {
		t.Fatalf("rotate-key = exit %d stderr %q", code, errOut)
	}
	srv.startMint(t)
	_, errOut, code = capture(t, func() int {
		return run([]string{"sp", "mint-key", "--sp", "sp_1", "--scope", "forge:city.create", "--no-browser"})
	})
	if code == 0 || !strings.Contains(errOut, "does not work with an edge-device session") || !strings.Contains(errOut, "gcs_user_") {
		t.Fatalf("sp mint-key = exit %d stderr %q", code, errOut)
	}
	for _, path := range []string{"/sts/v0/login", "/v0/cli/mint/challenges"} {
		if got := srv.reqs(path); len(got) != 0 {
			t.Fatalf("a refused command reached %s", path)
		}
	}
}

// Signing in with --edge-device again replaces the previous edge-device login: only after the
// new root has committed is the old one revoked (with ITS key's proof) and its key deleted.
func TestEdgeDeviceLoginRetiresThePreviousRoot(t *testing.T) {
	const oldRoot = "gcs_cli_oldoldoldoldoldoldoldoldoldoldol"
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	srv.startEdge(t)
	oldKey := seedEdgeSessionWithRoot(t, srv, testCredentialGenerationA, oldRoot)
	oldRef := loadEdgeFile(t).Key

	if _, errOut, code := capture(t, func() int { return run([]string{"login", "--edge-device"}) }); code != 0 {
		t.Fatalf("login = exit %d stderr %q", code, errOut)
	}
	edge := loadEdgeFile(t)
	if edge == nil || edge.RootToken != testEdgeRoot || edge.Key == oldRef {
		t.Fatalf("edge session after re-login = %+v", edge)
	}
	if _, err := loadSessionKey(edge.Key); err != nil {
		t.Fatalf("the new root's key: %v", err)
	}
	if _, err := loadSessionKey(oldRef); err == nil {
		t.Fatal("the replaced root's key is still enrolled")
	}
	revokes := srv.reqs("/gc/v0/session")
	if len(revokes) != 1 || revokes[0].auth != "Bearer "+oldRoot ||
		proofPayload(t, revokes[0].dpop)["ath"] != wantATH(oldRoot) || proofJWK(t, revokes[0].dpop) != jwkJSON(t, oldKey) {
		t.Fatalf("revocations = %+v", revokes)
	}
}
