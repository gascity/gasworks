package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/store"
)

func TestEnsureSessionPrefersPreferredCachedOrigin(t *testing.T) {
	oldNow := now
	now = func() int64 { return 1_000 }
	t.Cleanup(func() { now = oldNow })

	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("dpop.NewKey: %v", err)
	}
	pem, err := key.ToPEM()
	if err != nil {
		t.Fatalf("key.ToPEM: %v", err)
	}
	canonical := "https://api.gascity.com"
	legacy := "https://works.gascity.com"
	cfg := (config.Config{STSCanonical: canonical, STSBase: legacy}).WithSTSBase(legacy)
	data := &store.Data{Sessions: map[string]store.Session{
		sessionCacheKey(legacy, "acme", "g1:test"):    {SessionToken: "legacy-session", DPoPPEM: pem, ExpiresAt: 2_000},
		sessionCacheKey(canonical, "acme", "g1:test"): {SessionToken: "canonical-session", DPoPPEM: pem, ExpiresAt: 2_000},
	}}

	token, _, origin, err := ensureSession(cfg, data, "acme", "id-token", "g1:test", legacy)
	if err != nil {
		t.Fatalf("ensureSession: %v", err)
	}
	if token != "legacy-session" || origin != legacy {
		t.Fatalf("selected session = (%q, %q), want legacy cached session", token, origin)
	}
}

func TestEnsureSessionDoesNotReuseCachedSessionFromAnotherOrigin(t *testing.T) {
	oldNow := now
	now = func() int64 { return 1_000 }
	t.Cleanup(func() { now = oldNow })

	key, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("dpop.NewKey: %v", err)
	}
	pem, err := key.ToPEM()
	if err != nil {
		t.Fatalf("key.ToPEM: %v", err)
	}
	canonical := "https://api.gascity.com"
	legacyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sts/v0/login" {
			t.Errorf("legacy path = %q, want /sts/v0/login", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(legacyServer.Close)
	legacy := legacyServer.URL
	cfg := (config.Config{STSCanonical: canonical, STSBase: legacy}).WithSTSBase(legacy)
	data := &store.Data{Sessions: map[string]store.Session{
		sessionCacheKey(canonical, "acme", "g1:test"): {SessionToken: "canonical-session", DPoPPEM: pem, ExpiresAt: 2_000},
	}}

	token, _, origin, err := ensureSession(cfg, data, "acme", "id-token", "g1:test", legacy)
	if err == nil {
		t.Fatal("ensureSession unexpectedly reused a session cached for another origin")
	}
	if token != "" || origin != "" {
		t.Fatalf("selected session = (%q, %q), want no session after selected-origin failure", token, origin)
	}
}
