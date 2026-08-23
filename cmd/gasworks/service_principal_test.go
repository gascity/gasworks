package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
)

type servicePrincipalRequest struct {
	path    string
	form    url.Values
	headers http.Header
}

type servicePrincipalStub struct {
	mu              sync.Mutex
	requests        []servicePrincipalRequest
	server          *httptest.Server
	machineResponse map[string]any
	tokenResponse   map[string]any
}

func newServicePrincipalStub(t *testing.T) *servicePrincipalStub {
	t.Helper()
	stub := &servicePrincipalStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/sts/v0/machine", func(w http.ResponseWriter, r *http.Request) {
		stub.record(r)
		response := stub.machineResponse
		if response == nil {
			response = map[string]any{
				"session_token": "SERVICE.SESSION", "session_id": "ses_service", "org_id": "org_a",
				"token_type": "DPoP", "expires_in": 3600,
			}
		}
		writeJSON(w, http.StatusCreated, response)
	})
	mux.HandleFunc("/sts/v0/token", func(w http.ResponseWriter, r *http.Request) {
		stub.record(r)
		response := stub.tokenResponse
		if response == nil {
			response = map[string]any{
				"access_token": "SERVICE.EIA", "token_type": "Bearer", "expires_in": 90,
				"scope": r.FormValue("scope"),
			}
		}
		writeJSON(w, http.StatusOK, response)
	})
	stub.server = httptest.NewServer(mux)
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *servicePrincipalStub) record(r *http.Request) {
	form := url.Values{}
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, servicePrincipalRequest{path: r.URL.Path, form: form, headers: r.Header.Clone()})
}

func (s *servicePrincipalStub) snapshot() []servicePrincipalRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]servicePrincipalRequest(nil), s.requests...)
}

func servicePrincipalArgs(credentialFile string) []string {
	return []string{
		"--service-principal-credential-file", credentialFile,
		"--service-principal-audience", "manifold",
		"--service-principal-org", "org_a",
		"--service-principal-scope", "manifold:proxy",
		"--service-principal-scope", "manifold:pool:acme",
	}
}

func runServicePrincipalProvider(t *testing.T, cfg config.Config, argv []string, request string) (credentialProviderTestResponse, string, int) {
	t.Helper()
	originalStdin := stdin
	stdin = strings.NewReader(request)
	defer func() { stdin = originalStdin }()
	out, errOut, code := capture(t, func() int { return cmdCredentialProvider(cfg, argv) })
	return decodeProcessResponse(t, out), errOut, code
}

func proofPayload(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed DPoP proof %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode DPoP payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode DPoP payload JSON: %v", err)
	}
	return payload
}

func proofJWK(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed DPoP proof %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode DPoP header: %v", err)
	}
	var header struct {
		JWK map[string]string `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("decode DPoP header JSON: %v", err)
	}
	encoded, err := json.Marshal(header.JWK)
	if err != nil {
		t.Fatalf("encode JWK: %v", err)
	}
	return string(encoded)
}

func wantATH(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestServicePrincipalCredentialProviderMintsWithoutHumanStore(t *testing.T) {
	stub := newServicePrincipalStub(t)
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	const serviceKey = "svc_key_A"
	if err := os.WriteFile(credentialFile, []byte(serviceKey), 0o600); err != nil {
		t.Fatal(err)
	}

	configDir := t.TempDir()
	t.Setenv("GASWORKS_CONFIG_DIR", configDir)
	credentialsPath := filepath.Join(configDir, "credentials.json")
	const untouchedCredentials = "{not human credentials}"
	if err := os.WriteFile(credentialsPath, []byte(untouchedCredentials), 0o600); err != nil {
		t.Fatal(err)
	}

	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`
	response, errOut, code := runServicePrincipalProvider(t, config.Config{STSBase: stub.server.URL}, servicePrincipalArgs(credentialFile), request)
	if code != 0 || errOut != "" || response.Kind != "Credential" || response.AccessToken != "SERVICE.EIA" ||
		response.AuthorizationScheme != "Bearer" || response.Audience != "manifold" || !slices.Equal(response.Scopes, []string{"manifold:proxy"}) {
		t.Fatalf("machine response = exit %d stderr %q %+v", code, errOut, response)
	}
	if expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt); err != nil || !expiresAt.After(time.Now()) {
		t.Fatalf("expires_at = %q (%v), want a positive RFC3339 expiry", response.ExpiresAt, err)
	}
	if got, err := os.ReadFile(credentialsPath); err != nil || string(got) != untouchedCredentials {
		t.Fatalf("human credentials changed or read path failed: bytes %q err %v", got, err)
	}

	requests := stub.snapshot()
	if len(requests) != 2 || requests[0].path != "/sts/v0/machine" || requests[1].path != "/sts/v0/token" {
		t.Fatalf("STS requests = %#v, want only machine then token", requests)
	}
	if got := requests[0].form; got.Get("grant_type") != "client_credentials" || got.Get("client_secret") != serviceKey || len(got) != 2 {
		t.Fatalf("machine form = %v, want exactly client_credentials + key", got)
	}
	if got := requests[1].form; got.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		got.Get("subject_token") != "SERVICE.SESSION" || got.Get("audience") != "manifold" ||
		got.Get("scope") != "manifold:proxy" || len(got) != 4 {
		t.Fatalf("token form = %v", got)
	}
	machineProof, tokenProof := requests[0].headers.Get("DPoP"), requests[1].headers.Get("DPoP")
	if proofPayload(t, machineProof)["ath"] != wantATH(serviceKey) || proofPayload(t, tokenProof)["ath"] != wantATH("SERVICE.SESSION") {
		t.Fatal("DPoP ath did not bind each exact presented credential")
	}
	if proofJWK(t, machineProof) != proofJWK(t, tokenProof) {
		t.Fatal("machine and token proofs did not reuse one fresh DPoP key")
	}
}

func TestServicePrincipalCredentialProviderRereadsKeyAndUsesFreshState(t *testing.T) {
	stub := newServicePrincipalStub(t)
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`
	args := servicePrincipalArgs(credentialFile)

	for _, key := range []string{"svc_key_A", "svc_key_B"} {
		if err := os.WriteFile(credentialFile, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		if response, errOut, code := runServicePrincipalProvider(t, config.Config{STSBase: stub.server.URL}, args, request); code != 0 || errOut != "" || response.AccessToken != "SERVICE.EIA" {
			t.Fatalf("key %q response = exit %d stderr %q %+v", key, code, errOut, response)
		}
	}

	requests := stub.snapshot()
	if len(requests) != 4 {
		t.Fatalf("STS requests = %d, want four", len(requests))
	}
	for invocation, wantKey := range []string{"svc_key_A", "svc_key_B"} {
		machine, token := requests[invocation*2], requests[invocation*2+1]
		if machine.form.Get("client_secret") != wantKey {
			t.Fatalf("invocation %d used key %q, want %q", invocation, machine.form.Get("client_secret"), wantKey)
		}
		if proofJWK(t, machine.headers.Get("DPoP")) != proofJWK(t, token.headers.Get("DPoP")) {
			t.Fatalf("invocation %d changed DPoP key between legs", invocation)
		}
	}
	if proofJWK(t, requests[0].headers.Get("DPoP")) == proofJWK(t, requests[2].headers.Get("DPoP")) {
		t.Fatal("separate invocations reused a DPoP key")
	}
}

func TestServicePrincipalCredentialProviderRejectsMismatchesBeforeNetwork(t *testing.T) {
	stub := newServicePrincipalStub(t)
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	if err := os.WriteFile(credentialFile, []byte("svc_key_A"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]string{
		"audience": `{"version":"gascity.dev/credential-provider/v1","audience":"other","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`,
		"org":      `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_b","interactive":false}`,
		"scope":    `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:admin"],"org":"org_a","interactive":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			response, errOut, code := runServicePrincipalProvider(t, config.Config{STSBase: stub.server.URL}, servicePrincipalArgs(credentialFile), request)
			if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorDenied {
				t.Fatalf("mismatch response = exit %d stderr %q %+v", code, errOut, response)
			}
		})
	}
	if requests := stub.snapshot(); len(requests) != 0 {
		t.Fatalf("request mismatches made STS calls: %#v", requests)
	}
}

func TestServicePrincipalCredentialProviderRejectsIncompleteFlags(t *testing.T) {
	response, errOut, code := runServicePrincipalProvider(t, config.Config{}, []string{"--service-principal-audience", "manifold"},
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorInvalid {
		t.Fatalf("partial flags response = exit %d stderr %q %+v", code, errOut, response)
	}
}

func TestServicePrincipalCredentialProviderRejectsInvalidSTSResponseWithoutLeakingKey(t *testing.T) {
	stub := newServicePrincipalStub(t)
	stub.machineResponse = map[string]any{
		"session_token": "SERVICE.SESSION", "session_id": "ses_service", "org_id": "other_org", "token_type": "DPoP", "expires_in": 3600,
	}
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	const serviceKey = "svc_key_must_not_leak"
	if err := os.WriteFile(credentialFile, []byte(serviceKey), 0o600); err != nil {
		t.Fatal(err)
	}
	response, errOut, code := runServicePrincipalProvider(t, config.Config{STSBase: stub.server.URL}, servicePrincipalArgs(credentialFile),
		`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`)
	encoded, _ := json.Marshal(response)
	if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorDenied || strings.Contains(string(encoded), serviceKey) {
		t.Fatalf("invalid machine response = exit %d stderr %q body %s", code, errOut, encoded)
	}
	if requests := stub.snapshot(); len(requests) != 1 || requests[0].path != "/sts/v0/machine" {
		t.Fatalf("wrong-org response made requests %#v", requests)
	}
}

func TestServicePrincipalCredentialProviderRejectsInvalidTokenResponses(t *testing.T) {
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	if err := os.WriteFile(credentialFile, []byte("svc_key_A"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tokenResponse := range map[string]map[string]any{
		"non-bearer":     {"access_token": "SERVICE.EIA", "token_type": "DPoP", "expires_in": 90, "scope": "manifold:proxy"},
		"widened-scope":  {"access_token": "SERVICE.EIA", "token_type": "Bearer", "expires_in": 90, "scope": "manifold:proxy manifold:admin"},
		"invalid-expiry": {"access_token": "SERVICE.EIA", "token_type": "Bearer", "expires_in": 0, "scope": "manifold:proxy"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := newServicePrincipalStub(t)
			stub.tokenResponse = tokenResponse
			response, errOut, code := runServicePrincipalProvider(t, config.Config{STSBase: stub.server.URL}, servicePrincipalArgs(credentialFile),
				`{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`)
			if code == 0 || errOut != "" || response.Kind != "Error" || response.Code != credentialErrorDenied {
				t.Fatalf("response = exit %d stderr %q %+v", code, errOut, response)
			}
		})
	}
}
