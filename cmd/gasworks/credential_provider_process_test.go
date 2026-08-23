package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
)

type credentialProviderProcessResult struct {
	stdout string
	stderr string
	code   int
	err    error
}

func buildGasworksCLI(t *testing.T) string {
	t.Helper()
	name := "gasworks-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-mod=vendor", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("build gasworks CLI: %v", ctx.Err())
		}
		t.Fatalf("build gasworks CLI: %v\n%s", err, output)
	}
	return binary
}

func runCredentialProviderWaiterProcess(request, readyURL string) credentialProviderProcessResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialProviderWaiterHelperProcess$")
	command.Env = append(os.Environ(),
		"GASWORKS_TEST_WAITER_PROCESS=1",
		"GASWORKS_TEST_WAITER_REQUEST="+request,
		"GASWORKS_TEST_WAITER_READY_URL="+readyURL,
	)
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err := command.Run()
	if ctx.Err() != nil {
		return credentialProviderProcessResult{stdout: stdoutBuffer.String(), stderr: stderrBuffer.String(), code: -1, err: ctx.Err()}
	}
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return credentialProviderProcessResult{stdout: stdoutBuffer.String(), stderr: stderrBuffer.String(), code: -1, err: err}
		}
		exitCode = exitError.ExitCode()
	}
	return credentialProviderProcessResult{
		stdout: stdoutBuffer.String(), stderr: stderrBuffer.String(), code: exitCode,
	}
}

func credentialProviderWaiterBarrier(t *testing.T) (string, <-chan struct{}, <-chan struct{}, func()) {
	t.Helper()
	ready := make(chan struct{})
	armed := make(chan struct{})
	release := make(chan struct{})
	var readyOnce, armedOnce, releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/armed" {
			armedOnce.Do(func() { close(armed) })
			w.WriteHeader(http.StatusNoContent)
			return
		}
		readyOnce.Do(func() { close(ready) })
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	releaseWaiter := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseWaiter()
		server.Close()
	})
	return server.URL, ready, armed, releaseWaiter
}

func TestCredentialProviderWaiterHelperProcess(t *testing.T) {
	if os.Getenv("GASWORKS_TEST_WAITER_PROCESS") != "1" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	_, err := ensureIDTokenBeforeRefreshTransaction(config.FromEnv(), func() {
		response, requestErr := client.Get(os.Getenv("GASWORKS_TEST_WAITER_READY_URL"))
		if requestErr != nil {
			os.Exit(90)
		}
		_ = response.Body.Close()
		response, requestErr = client.Get(os.Getenv("GASWORKS_TEST_WAITER_READY_URL") + "/armed")
		if requestErr != nil {
			os.Exit(92)
		}
		_ = response.Body.Close()
	})
	if err != nil {
		os.Exit(91)
	}
	stdin = strings.NewReader(os.Getenv("GASWORKS_TEST_WAITER_REQUEST"))
	os.Exit(run([]string{"credential-provider"}))
}

func runGasworksCLIProcess(binary, request string) (string, string, int, error) {
	return runGasworksCLIProcessStarted(binary, request, nil)
}

func runGasworksCLIProcessStarted(binary, request string, started chan<- struct{}) (string, string, int, error) {
	return runGasworksCLIProcessStartedWithArgs(binary, request, started)
}

func runGasworksCLIProcessWithArgs(binary, request string, args ...string) (string, string, int, error) {
	return runGasworksCLIProcessStartedWithArgs(binary, request, nil, args...)
}

func runGasworksCLIProcessStartedWithArgs(binary, request string, started chan<- struct{}, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append([]string{"credential-provider"}, args...)...)
	command.Stdin = strings.NewReader(request)
	command.Env = os.Environ()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	if err := command.Start(); err != nil {
		return stdoutBuffer.String(), stderrBuffer.String(), -1, err
	}
	if started != nil {
		close(started)
	}
	err := command.Wait()
	if ctx.Err() != nil {
		return stdoutBuffer.String(), stderrBuffer.String(), -1, ctx.Err()
	}
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return stdoutBuffer.String(), stderrBuffer.String(), -1, err
		}
		exitCode = exitError.ExitCode()
	}
	return stdoutBuffer.String(), stderrBuffer.String(), exitCode, nil
}

func TestServicePrincipalCredentialProviderRealProcessesAreIndependent(t *testing.T) {
	stub := newServicePrincipalStub(t)
	credentialFile := filepath.Join(t.TempDir(), "service-principal-key")
	const serviceKey = "service-key-not-in-output"
	if err := os.WriteFile(credentialFile, []byte(serviceKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configDir := t.TempDir()
	credentialsPath := filepath.Join(configDir, "credentials.json")
	const humanCredentials = "not-a-human-credential-store"
	if err := os.WriteFile(credentialsPath, []byte(humanCredentials), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GASWORKS_STS_URL", stub.server.URL)
	t.Setenv("GASWORKS_CONFIG_DIR", configDir)
	binary := buildGasworksCLI(t)
	args := servicePrincipalArgs(credentialFile)
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"org":"org_a","interactive":false}`

	results := make(chan credentialProviderProcessResult, 2)
	for range 2 {
		go func() {
			out, errOut, code, err := runGasworksCLIProcessWithArgs(binary, request, args...)
			results <- credentialProviderProcessResult{stdout: out, stderr: errOut, code: code, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("run service-principal process: %v", result.err)
		}
		response := decodeProcessResponse(t, result.stdout)
		if result.code != 0 || result.stderr != "" || response.Kind != "Credential" || response.AccessToken != "SERVICE.EIA" ||
			response.AuthorizationScheme != "Bearer" || strings.Contains(result.stdout+result.stderr, serviceKey) {
			t.Fatalf("service-principal process = exit %d stderr %q response %+v", result.code, result.stderr, response)
		}
	}
	requests := stub.snapshot()
	if len(requests) != 4 {
		t.Fatalf("STS requests = %d, want four", len(requests))
	}
	machineProofs := make([]string, 0, 2)
	for _, request := range requests {
		if request.path == "/sts/v0/machine" {
			machineProofs = append(machineProofs, proofJWK(t, request.headers.Get("DPoP")))
		}
	}
	if len(machineProofs) != 2 || machineProofs[0] == machineProofs[1] {
		t.Fatalf("machine proof keys = %v, want one distinct fresh key per process", machineProofs)
	}
	if got, err := os.ReadFile(credentialsPath); err != nil || string(got) != humanCredentials {
		t.Fatalf("human credentials changed or read path failed: bytes %q err %v", got, err)
	}
}

func decodeProcessResponse(t *testing.T, output string) credentialProviderTestResponse {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	var response credentialProviderTestResponse
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode process response: %v (output=%q)", err, output)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("process emitted more than one JSON object: %v (output=%q)", err, output)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &fields); err != nil {
		t.Fatalf("decode process response fields: %v (output=%q)", err, output)
	}
	var expected []string
	switch response.Kind {
	case "Credential":
		expected = []string{"version", "kind", "access_token", "authorization_scheme", "expires_at", "audience", "scopes"}
	case "Error":
		expected = []string{"version", "kind", "code", "message"}
	default:
		t.Fatalf("process response has invalid kind %q", response.Kind)
	}
	if len(fields) != len(expected) {
		t.Fatalf("process response fields = %v, want exactly %v", fieldNames(fields), expected)
	}
	for _, field := range expected {
		if _, ok := fields[field]; !ok {
			t.Fatalf("process response fields = %v, missing %q", fieldNames(fields), field)
		}
	}
	return response
}

func fieldNames(fields map[string]json.RawMessage) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func TestCredentialProviderRealProcessProtocol(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	binary := buildGasworksCLI(t)
	validRequest := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`

	stdoutText, stderrText, code, err := runGasworksCLIProcess(binary, validRequest)
	if err != nil {
		t.Fatalf("run success process: %v", err)
	}
	response := decodeProcessResponse(t, stdoutText)
	if code != 0 || stderrText != "" || response.Kind != "Credential" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("success process = exit %d stderr %q response %+v", code, stderrText, response)
	}

	requestSecret := "REQUEST-SECRET-SENTINEL"
	invalidRequest := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"token":"` + requestSecret + `"}`
	stdoutText, stderrText, code, err = runGasworksCLIProcess(binary, invalidRequest)
	if err != nil {
		t.Fatalf("run invalid process: %v", err)
	}
	response = decodeProcessResponse(t, stdoutText)
	if code == 0 || stderrText != "" || response.Kind != "Error" || response.Code != "invalid_request" {
		t.Fatalf("invalid process = exit %d stderr %q response %+v", code, stderrText, response)
	}
	if strings.Contains(stdoutText+stderrText, requestSecret) {
		t.Fatalf("invalid process leaked request secret: stdout=%q stderr=%q", stdoutText, stderrText)
	}

	upstreamSecret := "UPSTREAM-SECRET-SENTINEL"
	srv.contextStatus = http.StatusInternalServerError
	srv.contextErrorBody = map[string]any{"error": "temporarily_unavailable", "error_description": upstreamSecret}
	stdoutText, stderrText, code, err = runGasworksCLIProcess(binary, validRequest)
	if err != nil {
		t.Fatalf("run upstream-failure process: %v", err)
	}
	response = decodeProcessResponse(t, stdoutText)
	if code == 0 || stderrText != "" || response.Kind != "Error" || response.Code != "temporarily_unavailable" {
		t.Fatalf("upstream process = exit %d stderr %q response %+v", code, stderrText, response)
	}
	if strings.Contains(stdoutText+stderrText, upstreamSecret) {
		t.Fatalf("process leaked upstream secret: stdout=%q stderr=%q", stdoutText, stderrText)
	}
}

func TestCredentialProviderSerializesRefreshRotationAcrossProcesses(t *testing.T) {
	srv := newStub(t)
	var refreshes atomic.Int32
	firstRefreshStarted := make(chan struct{})
	secondRefreshStarted := make(chan struct{})
	releaseFirstRefresh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirstRefresh) }) }
	defer release()
	srv.refreshHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		attempt := refreshes.Add(1)
		if attempt == 2 {
			close(secondRefreshStarted)
		}
		if form.Get("refresh_token") != "RT-OLD" || attempt != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		close(firstRefreshStarted)
		<-releaseFirstRefresh
		writeJSON(w, http.StatusOK, map[string]any{
			"id_token": validIDToken(), "refresh_token": "RT-NEW",
		})
	}
	seed(t, srv, map[string]any{"refresh_token": "RT-OLD", "id_token": expiredIDToken()})
	binary := buildGasworksCLI(t)
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`

	results := make(chan credentialProviderProcessResult, 2)
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		stdoutText, stderrText, code, err := runGasworksCLIProcess(binary, request)
		results <- credentialProviderProcessResult{stdout: stdoutText, stderr: stderrText, code: code, err: err}
	}()
	select {
	case <-firstRefreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first process did not enter refresh transaction")
	}

	readyURL, waiterReady, waiterArmed, releaseWaiter := credentialProviderWaiterBarrier(t)
	wait.Add(1)
	go func() {
		defer wait.Done()
		results <- runCredentialProviderWaiterProcess(request, readyURL)
	}()
	select {
	case <-waiterReady:
	case <-time.After(5 * time.Second):
		t.Fatal("second process did not reach the pre-lock refresh barrier")
	}
	releaseWaiter()
	select {
	case <-waiterArmed:
	case <-time.After(5 * time.Second):
		t.Fatal("second process did not arm immediately before lock acquisition")
	}
	select {
	case <-secondRefreshStarted:
		t.Fatal("second process entered refresh while the first transaction held the store lock")
	case <-time.After(time.Second):
	}
	release()
	wait.Wait()
	close(results)

	for result := range results {
		if result.err != nil {
			t.Fatalf("run concurrent process: %v", result.err)
		}
		response := decodeProcessResponse(t, result.stdout)
		expiresAt, expiryErr := time.Parse(time.RFC3339, response.ExpiresAt)
		if result.code != 0 || result.stderr != "" || response.Kind != "Credential" ||
			response.AccessToken != "EIA.JWT" || response.AuthorizationScheme != "Bearer" ||
			response.Audience != "manifold" || !slices.Equal(response.Scopes, []string{"manifold:proxy"}) ||
			expiryErr != nil || !expiresAt.After(time.Now()) {
			t.Fatalf("concurrent process = exit %d stderr %q response %+v", result.code, result.stderr, response)
		}
	}
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("refresh transactions = %d, want 1", got)
	}
	credentials := loadStore(t)
	if credentials.RefreshToken != "RT-NEW" || tokenExp(credentials.IDToken)-time.Now().Unix() <= idTokenSkewSecs {
		t.Fatalf("persisted refresh state = refresh_token %q id_token_exp %d", credentials.RefreshToken, tokenExp(credentials.IDToken))
	}
}

func TestCredentialProviderRecoversRefreshLockAfterProcessTermination(t *testing.T) {
	srv := newStub(t)
	var refreshes atomic.Int32
	firstRefreshStarted := make(chan struct{})
	firstRefreshCanceled := make(chan struct{})
	secondRefreshStarted := make(chan struct{})
	srv.refreshHandler = func(w http.ResponseWriter, request *http.Request, form url.Values) {
		attempt := refreshes.Add(1)
		if form.Get("refresh_token") != "RT-OLD" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		if attempt == 1 {
			close(firstRefreshStarted)
			<-request.Context().Done()
			close(firstRefreshCanceled)
			return
		}
		close(secondRefreshStarted)
		writeJSON(w, http.StatusOK, map[string]any{
			"id_token": validIDToken(), "refresh_token": "RT-NEW",
		})
	}
	seed(t, srv, map[string]any{"refresh_token": "RT-OLD", "id_token": expiredIDToken()})
	binary := buildGasworksCLI(t)
	request := `{"version":"gascity.dev/credential-provider/v1","audience":"manifold","required_scopes":["manifold:proxy"],"interactive":false}`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	holder := exec.CommandContext(ctx, binary, "credential-provider")
	holder.Stdin = strings.NewReader(request)
	holder.Env = os.Environ()
	var holderStdout, holderStderr bytes.Buffer
	holder.Stdout = &holderStdout
	holder.Stderr = &holderStderr
	if err := holder.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	defer func() {
		if holder.ProcessState == nil {
			_ = holder.Process.Kill()
			_ = holder.Wait()
		}
	}()
	select {
	case <-firstRefreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("lock holder did not enter refresh transaction")
	}
	readyURL, waiterReady, waiterArmed, releaseWaiter := credentialProviderWaiterBarrier(t)
	waiterResult := make(chan credentialProviderProcessResult, 1)
	go func() { waiterResult <- runCredentialProviderWaiterProcess(request, readyURL) }()
	select {
	case <-waiterReady:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery process did not reach the pre-lock refresh barrier")
	}
	releaseWaiter()
	select {
	case <-waiterArmed:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery process did not arm immediately before lock acquisition")
	}
	select {
	case <-secondRefreshStarted:
		t.Fatal("recovery process entered refresh before the lock holder terminated")
	case <-time.After(time.Second):
	}
	if err := holder.Process.Kill(); err != nil {
		t.Fatalf("terminate lock holder: %v", err)
	}
	if err := holder.Wait(); err == nil {
		t.Fatal("terminated lock holder exited successfully")
	}
	select {
	case <-firstRefreshCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("terminated process did not cancel its in-flight refresh")
	}

	var result credentialProviderProcessResult
	select {
	case result = <-waiterResult:
	case <-time.After(10 * time.Second):
		t.Fatal("recovery process did not finish after lock-holder termination")
	}
	if result.err != nil {
		t.Fatalf("run recovery process: %v", result.err)
	}
	response := decodeProcessResponse(t, result.stdout)
	if result.code != 0 || result.stderr != "" || response.AccessToken != "EIA.JWT" {
		t.Fatalf("recovery process = exit %d stderr %q response %+v", result.code, result.stderr, response)
	}
	if got := refreshes.Load(); got != 2 {
		t.Fatalf("refresh attempts = %d, want canceled holder plus successful recovery", got)
	}
	credentials := loadStore(t)
	if credentials.RefreshToken != "RT-NEW" || tokenExp(credentials.IDToken)-time.Now().Unix() <= idTokenSkewSecs {
		t.Fatalf("recovered refresh state = refresh_token %q id_token_exp %d", credentials.RefreshToken, tokenExp(credentials.IDToken))
	}
}
