package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/store"
)

// runGasworksBinary runs the built CLI with args and stdin, in this test's environment.
func runGasworksBinary(binary, input string, env []string, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdin = strings.NewReader(input)
	command.Env = append(os.Environ(), env...)
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err := command.Run()
	if ctx.Err() != nil {
		return stdoutBuffer.String(), stderrBuffer.String(), -1, ctx.Err()
	}
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return stdoutBuffer.String(), stderrBuffer.String(), -1, err
		}
		code = exitError.ExitCode()
	}
	return stdoutBuffer.String(), stderrBuffer.String(), code, nil
}

// The built binary — real keystore registry, real cross-process store lock — mints from an
// edge-device root with the root's own key. Two processes at once both succeed, neither
// establishes a /sts/v0/login session, and neither moves the root into credentials.json.
func TestEdgeDeviceRootMintsInRealProcesses(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"credential_generation": testCredentialGenerationA})
	key := seedEdgeSession(t, srv, testCredentialGenerationA)
	edgeBefore, err := os.ReadFile(store.EdgeSessionPath())
	if err != nil {
		t.Fatal(err)
	}
	binary := buildGasworksCLI(t)
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`

	results := make(chan credentialProviderProcessResult, 2)
	for range 2 {
		go func() {
			out, errOut, code, err := runGasworksCLIProcess(binary, request)
			results <- credentialProviderProcessResult{stdout: out, stderr: errOut, code: code, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("run process: %v", result.err)
		}
		response := decodeProcessResponse(t, result.stdout)
		if result.code != 0 || result.stderr != "" || response.Kind != "Credential" || response.AccessToken != "EIA.JWT" {
			t.Fatalf("process = exit %d stderr %q response %+v", result.code, result.stderr, response)
		}
	}

	out, errOut, code, err := runGasworksBinary(binary, "", nil, "getToken", "manifold", "--json", "--refresh")
	if err != nil || code != 0 || errOut != "" || !strings.Contains(out, `"access_token":"EIA.JWT"`) {
		t.Fatalf("getToken process = exit %d %q %q %v", code, out, errOut, err)
	}

	for _, path := range []string{"/sts/v0/login", "/protocol/openid-connect/token"} {
		if got := srv.reqs(path); len(got) != 0 {
			t.Fatalf("an edge-device process reached %s", path)
		}
	}
	tokens := srv.reqs("/sts/v0/token")
	if len(tokens) < 2 || len(tokens) > 3 {
		t.Fatalf("token requests = %d, want one per process that missed the cache", len(tokens))
	}
	for _, token := range tokens {
		if token.form.Get("subject_token") != testEdgeRoot || proofJWK(t, token.dpop) != jwkJSON(t, key) ||
			proofPayload(t, token.dpop)["ath"] != wantATH(testEdgeRoot) {
			t.Fatalf("exchange = %+v", token)
		}
	}
	edgeAfter, err := os.ReadFile(store.EdgeSessionPath())
	if err != nil || !bytes.Equal(edgeAfter, edgeBefore) {
		t.Fatalf("minting rewrote the edge session: %v", err)
	}
	creds, err := os.ReadFile(store.CredsPath())
	if err != nil || strings.Contains(string(creds), testEdgeRoot) {
		t.Fatalf("credentials.json after the processes: %v\n%s", err, creds)
	}
	if data := loadStore(t); data.CredentialGeneration != testCredentialGenerationA || len(data.Sessions) != 0 {
		t.Fatalf("credentials after the processes = %+v", data)
	}
}

// The whole `login --edge-device` in a child process, over real TLS to the stub cli-edge.
// SSL_CERT_FILE is how a child process is made to trust the stub's CA, and only the Unix root
// loader (not macOS's platform verifier, not Windows') honours it.
func TestEdgeDeviceLoginInARealProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the child process trusts the stub CA through SSL_CERT_FILE, which only Linux honours")
	}
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT-OLD", "id_token": validIDToken()})
	srv.startEdge(t)
	srv.edgeIssueHandler = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"device_code": testEdgeDeviceCode, "user_code": "BDWK-JQPX",
			"verification_uri_complete": srv.edge.URL + "/gc/v0/device?code=BDWK-JQPX",
			"expires_in":                60, "interval": 1,
		})
	}
	caFile := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.edge.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := buildGasworksCLI(t)

	out, errOut, code, err := runGasworksBinary(binary, "", []string{"SSL_CERT_FILE=" + caFile}, "login", "--edge-device")
	if err != nil || code != 0 || !strings.Contains(out, "Logged in with an edge-device session for org acme (org_a).") {
		t.Fatalf("login process = exit %d %q %q %v", code, out, errOut, err)
	}
	if !strings.Contains(errOut, srv.edge.URL+"/gc/v0/device?code=BDWK-JQPX") || strings.Contains(out+errOut, testEdgeRoot) {
		t.Fatalf("login process stderr = %q", errOut)
	}
	edge := loadEdgeFile(t)
	if edge == nil || edge.RootToken != testEdgeRoot || edge.CredentialGeneration != loadStore(t).CredentialGeneration {
		t.Fatalf("edge session = %+v", edge)
	}
	if polls := srv.reqs("/gc/v0/auth/device/token"); len(polls) != 1 || proofPayload(t, polls[0].dpop)["ath"] != nil {
		t.Fatalf("polls = %+v", polls)
	}

	out, errOut, code, err = runGasworksBinary(binary, "", nil, "getToken", "manifold")
	if err != nil || code != 0 || strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("getToken process = exit %d %q %q %v", code, out, errOut, err)
	}
	if got := srv.reqs("/sts/v0/login"); len(got) != 0 {
		t.Fatal("the edge-device process established an STS session")
	}

	out, errOut, code, err = runGasworksBinary(binary, "", []string{"SSL_CERT_FILE=" + caFile}, "logout")
	if err != nil || code != 0 || !strings.Contains(out, "Logged out.") {
		t.Fatalf("logout process = exit %d %q %q %v", code, out, errOut, err)
	}
	if revokes := srv.reqs("/gc/v0/session"); len(revokes) != 1 || revokes[0].auth != "Bearer "+testEdgeRoot {
		t.Fatalf("revocations = %+v", revokes)
	}
	if loadEdgeFile(t) != nil {
		t.Fatal("logout left the edge session")
	}
}
