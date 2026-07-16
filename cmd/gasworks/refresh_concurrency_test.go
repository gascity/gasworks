package main

import (
	"sync"
	"testing"
	"time"

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
			toks[i], errs[i] = ensureIDToken(cfg, time.Now().Add(overallBudget))
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

// TestEnsureIDTokenRefreshFailurePileUp is the FIX 5 property: N concurrent callers hitting a
// slow-FAILING Keycloak must NOT each burn the full refreshTimeout serially re-presenting the
// same refresh token. The first caller's transient failure sets a short cooldown marker; every
// peer within the window observes it under the lock and fails fast (serve-last-good eligible),
// so exactly ONE refresh reaches Keycloak and the whole burst is bounded — not N×refreshDelay.
func TestEnsureIDTokenRefreshFailurePileUp(t *testing.T) {
	srv := newStub(t)
	srv.refreshDelay = 300 * time.Millisecond // slow...
	srv.refreshStatus = 503                   // ...and failing (transient)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": expiredIDToken()})

	cfg := config.FromEnv()
	deadline := time.Now().Add(overallBudget)
	const n = 12
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = ensureIDToken(cfg, deadline)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Every caller fails (no cached credential here), but transiently — not with a login remedy.
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d unexpectedly succeeded against a failing Keycloak", i)
		}
	}
	refreshes := len(srv.reqs("/protocol/openid-connect/token"))
	if refreshes > 2 {
		t.Fatalf("want ~1 refresh across %d racers (cooldown suppresses the pile-up), got %d", n, refreshes)
	}
	// Without the cooldown, N callers would serialize N×refreshDelay (~3.6s) re-presenting the
	// same RT; with it, only the first pays the ~300ms failing refresh.
	if elapsed > 3*time.Second {
		t.Fatalf("pile-up took %s — peers serialized full refresh timeouts instead of failing fast", elapsed)
	}
	// A cooldown marker is left behind so the next burst also fails fast.
	if data := loadStore(t); data.RefreshCooldownUntil <= now() {
		t.Fatalf("want a live cooldown marker after the transient failure, got %d (now=%d)",
			data.RefreshCooldownUntil, now())
	}
}
