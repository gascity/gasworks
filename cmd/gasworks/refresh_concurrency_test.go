package main

import (
	"sync"
	"testing"

	"github.com/gascity/gasworks/internal/config"
)

// TestEnsureIDTokenSerializesRefresh is exit test 7: N concurrent callers sharing one
// credentials file must trigger exactly ONE Keycloak refresh (the double-checked pattern),
// never N — otherwise Keycloak's refresh-token rotation reuse-detection revokes the whole
// offline-session family and strands every caller into an interactive re-login.
//
// This uses N goroutines with the process-shared store lock. That is a faithful proxy for the
// cross-process case: the store lock is an flock, and flock discriminates by open file
// description (each store.WithLock opens its own fd), so goroutines block each other exactly as
// separate processes do.
func TestEnsureIDTokenSerializesRefresh(t *testing.T) {
	srv := newStub(t)
	// The refresh grant returns a FRESH id_token so the waiters' re-check under the lock passes
	// and they skip their own refresh.
	srv.refreshTok = map[string]any{"id_token": validIDToken(), "refresh_token": "RT2"}
	// Seed an EXPIRED id_token so every caller's fast path falls through to the slow path.
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": expiredIDToken()})

	cfg := config.FromEnv()
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	toks := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = ensureIDToken(cfg)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if toks[i] == "" {
			t.Fatalf("caller %d got an empty id_token", i)
		}
	}
	if refreshes := len(srv.reqs("/protocol/openid-connect/token")); refreshes != 1 {
		t.Fatalf("want exactly 1 refresh across %d concurrent callers, got %d (rotation reuse risk)", n, refreshes)
	}
	// The rotated refresh token is persisted exactly once and is the new one.
	if data := loadStore(t); data.RefreshToken != "RT2" {
		t.Fatalf("refresh_token = %q, want the rotated RT2 persisted", data.RefreshToken)
	}
}
