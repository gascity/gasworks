package upload

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func planFor(t *testing.T, first, last int64) Plan {
	t.Helper()
	ack := newAckState(t, last)
	p := &Planner{Store: newMemStore(t, first, last, 0), Ack: ack, SourceID: testSourceID}
	plan, ok, err := p.Next()
	if err != nil || !ok {
		t.Fatalf("form plan: ok=%v err=%v", ok, err)
	}
	return plan
}

func TestHTTPSMandatory(t *testing.T) {
	// Plain HTTP without dev mode is refused.
	_, err := NewClient(Config{Endpoint: mustURL(t, "http://collector.example.com"), Credential: staticToken("t")})
	if !errors.Is(err, ErrInsecureScheme) {
		t.Fatalf("plain http = %v, want ErrInsecureScheme", err)
	}
	// Plain HTTP to a non-loopback host, even with dev mode, is refused.
	_, err = NewClient(Config{Endpoint: mustURL(t, "http://collector.example.com"), Credential: staticToken("t"), AllowLoopbackHTTP: true})
	if !errors.Is(err, ErrInsecureScheme) {
		t.Fatalf("non-loopback http+dev = %v, want ErrInsecureScheme", err)
	}
	// Loopback HTTP with dev mode is allowed.
	if _, err := NewClient(Config{Endpoint: mustURL(t, "http://127.0.0.1:8080"), SourceID: testSourceID, Credential: staticToken("t"), AllowLoopbackHTTP: true}); err != nil {
		t.Fatalf("loopback http+dev = %v, want ok", err)
	}
	// HTTPS is always allowed.
	if _, err := NewClient(Config{Endpoint: mustURL(t, "https://collector.example.com"), SourceID: testSourceID, Credential: staticToken("t")}); err != nil {
		t.Fatalf("https = %v, want ok", err)
	}
}

func TestRedirectRefusedNoCredentialLeak(t *testing.T) {
	// Server B is the redirect target; it must never receive the request or the credential.
	bHandler := &recordingHandler{}
	bURL := newHTTPServer(t, bHandler)

	aHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, bURL+ingestPath, http.StatusFound)
	})
	aURL := newHTTPServer(t, aHandler)

	client := loopbackClient(t, aURL, staticToken("secret-token-xyz"))
	_, err := client.Send(context.Background(), planFor(t, 1, 2))
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("Send across redirect = %v, want ErrRedirectRefused", err)
	}
	if got := bHandler.snapshot(); len(got) != 0 {
		t.Fatalf("redirect target received %d requests (credential leak!)", len(got))
	}
	if strings.Contains(err.Error(), "secret-token-xyz") {
		t.Fatalf("credential leaked into error: %v", err)
	}
}

func TestTLSFloorAndCustomCAAccepted(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.issueLeaf(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	h := &recordingHandler{respond: func(int, recordedRequest) (int, http.Header, []byte) {
		return http.StatusOK, nil, ackJSON(t, testSourceID, 1, 2)
	}}
	base := startTLSServer(t, leaf, h)

	// The additive customer CA lets the client verify the server leaf; system roots stay in
	// force and verification is never disabled.
	client, err := NewClient(Config{
		Endpoint:   mustURL(t, base),
		SourceID:   testSourceID,
		Credential: staticToken("tok"),
		CustomCAs:  caCerts(ca),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	att, err := client.Send(context.Background(), planFor(t, 1, 2))
	if err != nil {
		t.Fatalf("Send over custom-CA TLS: %v", err)
	}
	if att.StatusCode != 200 || att.Ack == nil {
		t.Fatalf("attempt = %+v, want 200 with ack", att)
	}
}

func TestTLSUntrustedCARejected(t *testing.T) {
	serverCA := newTestCA(t)
	otherCA := newTestCA(t)
	leaf := serverCA.issueLeaf(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	h := &recordingHandler{}
	base := startTLSServer(t, leaf, h)

	// Trust only an unrelated CA: verification must fail (never InsecureSkipVerify).
	client, err := NewClient(Config{
		Endpoint:   mustURL(t, base),
		SourceID:   testSourceID,
		Credential: staticToken("tok"),
		CustomCAs:  caCerts(otherCA),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Send(context.Background(), planFor(t, 1, 2)); err == nil {
		t.Fatalf("Send with untrusted CA succeeded, want TLS verification failure")
	}
}

func TestRotatingTokenFileRereadPerAttempt(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("token-one\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	h := &recordingHandler{respond: func(int, recordedRequest) (int, http.Header, []byte) {
		return http.StatusOK, nil, ackJSON(t, testSourceID, 1, 1)
	}}
	base := newHTTPServer(t, h)
	client := loopbackClient(t, base, TokenFileSource{Path: tokPath})

	if _, err := client.Send(context.Background(), planFor(t, 1, 1)); err != nil {
		t.Fatalf("Send#1: %v", err)
	}
	// Rotate the token atomically, then send again.
	rotate := filepath.Join(dir, "token.new")
	if err := os.WriteFile(rotate, []byte("token-two\n"), 0o600); err != nil {
		t.Fatalf("write rotate: %v", err)
	}
	if err := os.Rename(rotate, tokPath); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := client.Send(context.Background(), planFor(t, 1, 1)); err != nil {
		t.Fatalf("Send#2: %v", err)
	}

	reqs := h.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	if reqs[0].authz != "Bearer token-one" {
		t.Fatalf("attempt 1 authz = %q, want Bearer token-one", reqs[0].authz)
	}
	if reqs[1].authz != "Bearer token-two" {
		t.Fatalf("attempt 2 authz = %q, want Bearer token-two (rotation not observed)", reqs[1].authz)
	}
}

func TestTokenFileEmptyIsError(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if _, err := (TokenFileSource{Path: tokPath}).Token(context.Background()); !errors.Is(err, ErrEmptyCredential) {
		t.Fatalf("empty token file = %v, want ErrEmptyCredential", err)
	}
}

func writeHelperScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return path
}

func TestHelperFixedArgvProducesToken(t *testing.T) {
	helper := writeHelperScript(t, `printf 'workload-token-123'`)
	tok, err := (HelperSource{Argv: []string{helper}}).Token(context.Background())
	if err != nil {
		t.Fatalf("helper token: %v", err)
	}
	if tok != "workload-token-123" {
		t.Fatalf("token = %q, want workload-token-123", tok)
	}
}

func TestFailingHelperLeaksNoToken(t *testing.T) {
	// A failing helper prints a token-shaped value to BOTH stdout and stderr then exits 1;
	// the sanitized error must retain none of it.
	secret := "leaked-token-should-not-appear"
	helper := writeHelperScript(t, fmt.Sprintf("printf '%s'; printf '%s' 1>&2; exit 1", secret, secret))
	_, err := (HelperSource{Argv: []string{helper}}).Token(context.Background())
	if err == nil {
		t.Fatalf("failing helper returned no error")
	}
	if !errors.Is(err, ErrHelperFailed) {
		t.Fatalf("err = %v, want ErrHelperFailed", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("token leaked into helper error: %q", err.Error())
	}
}

func TestHelperOutputBounded(t *testing.T) {
	// A helper that floods stdout past the cap fails without leaking the overflow.
	helper := writeHelperScript(t, `while true; do printf 'AAAAAAAAAAAAAAAA'; done`)
	_, err := (HelperSource{Argv: []string{helper}, MaxOutput: 256}).Token(context.Background())
	if !errors.Is(err, ErrHelperFailed) {
		t.Fatalf("flooding helper = %v, want ErrHelperFailed", err)
	}
	if strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("overflow output leaked into error: %q", err.Error())
	}
}

func TestHelperTimeoutBounded(t *testing.T) {
	helper := writeHelperScript(t, `sleep 30`)
	start := time.Now()
	_, err := (HelperSource{Argv: []string{helper}, Timeout: 200 * time.Millisecond}).Token(context.Background())
	if !errors.Is(err, ErrHelperFailed) {
		t.Fatalf("slow helper = %v, want ErrHelperFailed", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("helper timeout not honored: took %v", time.Since(start))
	}
}

func TestRequestTimeoutHonored(t *testing.T) {
	// The handler stalls well past the client's attempt timeout, but never indefinitely, so
	// the server always shuts down cleanly.
	slow := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	base := newHTTPServer(t, slow)

	client, err := NewClient(Config{
		Endpoint:          mustURL(t, base),
		SourceID:          testSourceID,
		Credential:        staticToken("tok"),
		AllowLoopbackHTTP: true,
		AttemptTimeout:    150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	start := time.Now()
	if _, err := client.Send(context.Background(), planFor(t, 1, 1)); err == nil {
		t.Fatalf("Send against a hung server returned no error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("attempt timeout not honored: took %v", time.Since(start))
	}
}

func TestContentEncodingRejected(t *testing.T) {
	h := &recordingHandler{respond: func(int, recordedRequest) (int, http.Header, []byte) {
		hdr := http.Header{}
		hdr.Set("Content-Encoding", "gzip") // unsupported; we did not request it
		return http.StatusOK, hdr, []byte("not-actually-gzip")
	}}
	base := newHTTPServer(t, h)
	client := loopbackClient(t, base, staticToken("tok"))
	if _, err := client.Send(context.Background(), planFor(t, 1, 1)); !errors.Is(err, ErrUnsupportedContentEncoding) {
		t.Fatalf("Send = %v, want ErrUnsupportedContentEncoding", err)
	}
}

func TestSourceMismatchRefusedBeforeSend(t *testing.T) {
	h := &recordingHandler{}
	base := newHTTPServer(t, h)
	// Client bound to a different source than the batch body.
	u := mustURL(t, base)
	client, err := NewClient(Config{Endpoint: u, SourceID: "src_bound_identity", Credential: staticToken("tok"), AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Send(context.Background(), planFor(t, 1, 2)); !errors.Is(err, ErrSourceMismatch) {
		t.Fatalf("Send = %v, want ErrSourceMismatch", err)
	}
	if len(h.snapshot()) != 0 {
		t.Fatalf("mismatched-source batch was sent")
	}
}

func TestSendDecodesTypedErrorBody(t *testing.T) {
	h := &recordingHandler{respond: func(int, recordedRequest) (int, http.Header, []byte) {
		return http.StatusConflict, nil, errorJSON(t, wire.ObserverErrorBodyCodeSEQUENCECONFLICT, false)
	}}
	base := newHTTPServer(t, h)
	client := loopbackClient(t, base, staticToken("tok"))
	att, err := client.Send(context.Background(), planFor(t, 1, 2))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if att.StatusCode != http.StatusConflict || att.ErrorBody == nil {
		t.Fatalf("attempt = %+v, want 409 with typed error body", att)
	}
	if att.ErrorBody.Code != wire.ObserverErrorBodyCodeSEQUENCECONFLICT {
		t.Fatalf("code = %s, want SEQUENCE_CONFLICT", att.ErrorBody.Code)
	}
}

func TestCapabilitiesProbeClampsCaps(t *testing.T) {
	h := &recordingHandler{respond: func(_ int, r recordedRequest) (int, http.Header, []byte) {
		caps := wire.CapabilitiesResponse{
			SchemaVersions:              []int32{1},
			MaxObservationsPerBatch:     500,
			MaxBatchBytes:               2 << 20,
			MaxRecordBytes:              1 << 20,
			MaxReferencesPerObservation: 32,
			AcknowledgementMode:         wire.CapabilitiesResponseAcknowledgementModeCONTIGUOUS,
			SourceBinding:               wire.SourceBinding{SourceId: testSourceID, State: "ENROLLED"},
			ServerTime:                  time.Unix(0, 0).UTC(),
		}
		b, _ := jsonMarshal(caps)
		return http.StatusOK, nil, b
	}}
	base := newHTTPServer(t, h)
	client := loopbackClient(t, base, staticToken("tok"))
	caps, _, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	// min(local default, server) on each axis.
	if caps.MaxObservations != 500 {
		t.Fatalf("MaxObservations = %d, want 500 (server < default)", caps.MaxObservations)
	}
	if caps.MaxBatchBytes != 2<<20 {
		t.Fatalf("MaxBatchBytes = %d, want 2MiB (server < default)", caps.MaxBatchBytes)
	}
	reqs := h.snapshot()
	if len(reqs) != 1 || reqs[0].path != capabilitiesPath {
		t.Fatalf("capabilities path = %v", reqs)
	}
}

// TestEgressProxyPath exercises the corporate egress-proxy path: an explicit CONNECT proxy
// that TLS-terminates the tunnel with a custom-CA-signed target certificate. The client
// must traverse the proxy, verify the re-signed cert against the additive CA, and keep
// redirect refusal in force.
func TestEgressProxyPath(t *testing.T) {
	ca := newTestCA(t)
	const targetHost = "collector.internal.example"

	h := &recordingHandler{respond: func(_ int, r recordedRequest) (int, http.Header, []byte) {
		if r.host != targetHost {
			return http.StatusBadGateway, nil, []byte("{}")
		}
		return http.StatusOK, nil, ackJSON(t, testSourceID, 1, 2)
	}}
	proxyURL := startMITMProxy(t, ca, targetHost, h)

	client, err := NewClient(Config{
		Endpoint:   mustURL(t, "https://"+targetHost),
		SourceID:   testSourceID,
		Credential: staticToken("proxy-tok"),
		Proxy:      mustURL(t, proxyURL),
		CustomCAs:  caCerts(ca),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	att, err := client.Send(context.Background(), planFor(t, 1, 2))
	if err != nil {
		t.Fatalf("Send through egress proxy: %v", err)
	}
	if att.StatusCode != 200 || att.Ack == nil {
		t.Fatalf("attempt = %+v, want 200 with ack via proxy", att)
	}
	reqs := h.snapshot()
	if len(reqs) != 1 || reqs[0].host != targetHost {
		t.Fatalf("proxied request host = %v, want %s", reqs, targetHost)
	}
	if reqs[0].authz != "Bearer proxy-tok" {
		t.Fatalf("authz through proxy = %q", reqs[0].authz)
	}
}
