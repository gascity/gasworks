//go:build linux

package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// certPEMFile PEM-encodes an httptest TLS server's self-signed leaf into a -ca-file bundle.
func certPEMFile(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
}

func TestLoadCAFiles(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pem")
	certPEMFile(t, srv, good)

	// A valid single-cert bundle yields one anchor.
	if certs, err := loadCAFiles([]string{good}); err != nil || len(certs) != 1 {
		t.Fatalf("loadCAFiles(good) = %d certs, %v; want 1, nil", len(certs), err)
	}
	// Repeatable flag: two files → two anchors.
	if certs, err := loadCAFiles([]string{good, good}); err != nil || len(certs) != 2 {
		t.Fatalf("loadCAFiles(good,good) = %d certs, %v; want 2, nil", len(certs), err)
	}
	// Empty list → no anchors, no error (system trust only).
	if certs, err := loadCAFiles(nil); err != nil || certs != nil {
		t.Fatalf("loadCAFiles(nil) = %v, %v; want nil, nil", certs, err)
	}
	// Missing path → fail closed.
	if _, err := loadCAFiles([]string{filepath.Join(dir, "nope.pem")}); err == nil {
		t.Fatal("a missing -ca-file must fail closed")
	}
	// A file with no CERTIFICATE block → fail closed (never silently narrow to system-only trust).
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCAFiles([]string{empty}); err == nil {
		t.Fatal("a -ca-file with no certificate must fail closed")
	}
	// A CERTIFICATE block with garbage DER → hard error (no partial trust).
	badDER := filepath.Join(dir, "bad.pem")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")})
	if err := os.WriteFile(badDER, badPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCAFiles([]string{badDER}); err == nil {
		t.Fatal("a malformed certificate block must fail closed")
	}
}

// TestBuildCollectorClientCAFileThreadsTrust proves the -ca-file anchors actually reach the
// collector client's TLS trust: a self-signed collector is UNtrusted without -ca-file (certificate
// error) and trusted with it (the TLS handshake succeeds and the request reaches the server).
func TestBuildCollectorClientCAFileThreadsTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPEMFile(t, srv, caPath)
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Without the CA the self-signed collector is untrusted → a certificate error.
	noCA, err := buildCollectorClient(srv.URL, "src-1", tokPath, false, nil)
	if err != nil {
		t.Fatalf("buildCollectorClient (no ca): %v", err)
	}
	if _, _, err := noCA.Capabilities(ctx); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected an untrusted-certificate error without -ca-file, got: %v", err)
	}

	// With the CA threaded through -ca-file the handshake succeeds (no certificate error): the
	// request reaches the server and decodes the empty capabilities body.
	withCA, err := buildCollectorClient(srv.URL, "src-1", tokPath, false, []string{caPath})
	if err != nil {
		t.Fatalf("buildCollectorClient (with ca): %v", err)
	}
	if _, _, err := withCA.Capabilities(ctx); err != nil && strings.Contains(err.Error(), "certificate") {
		t.Fatalf("-ca-file did not thread into TLS trust (still a certificate error): %v", err)
	}
}
