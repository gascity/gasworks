package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestOverallDeadlineBoundsMintChain is the FIX 4 regression. Before the fix the per-step
// timeouts did not sum-bound (refresh 10s + context 5s + login 5s + ladder 15s = 35s, and 45s on
// the 401-relogin path), so a brownout where every leg is slow-but-progressing pushed one
// getToken past bd's ~30s exec cap (beads internal/creds/command.go credCommandTimeout=30s) and
// bd SIGKILLed the helper before serve-last-good could run.
//
// Now a single overall deadline clamps every step to the remaining budget, so the whole chain
// finishes within the budget (plus a small slack for the one in-flight leg that was already past
// its clamp). The budget is shrunk here so the test is fast; each brownout leg is scaled under it.
func TestOverallDeadlineBoundsMintChain(t *testing.T) {
	restore := overallBudget
	overallBudget = 3 * time.Second
	t.Cleanup(func() { overallBudget = restore })

	leg := 1000 * time.Millisecond // every leg is slow-but-within its own per-step timeout
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token"):
			time.Sleep(leg)
			writeJSON(w, http.StatusOK, map[string]any{"id_token": validIDToken(), "refresh_token": "RT2"})
		case strings.HasSuffix(r.URL.Path, "/sts/v0/context"):
			time.Sleep(leg)
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id": "usr_1", "default_org_id": "org_a", "orgs": []any{
					map[string]any{
						"org_id": "org_a", "slug": "acme", "role": "owner", "is_default": true,
						"products": map[string]any{
							"manifold": map[string]any{"audience": "manifold", "scopes": []string{"manifold:proxy"}},
						},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/sts/v0/login"):
			time.Sleep(leg)
			writeJSON(w, http.StatusCreated, map[string]any{"session_token": "SESS", "session_id": "ses_1", "expires_in": 28800})
		case strings.HasSuffix(r.URL.Path, "/sts/v0/token"):
			time.Sleep(leg)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "nope"})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	t.Setenv("GASWORKS_STS_URL", srv.URL)
	t.Setenv("GASWORKS_OIDC_ISSUER", srv.URL+"/realms/g")
	t.Setenv("GASWORKS_CLIENT_ID", "gasworks-cli")
	// Expired id_token forces the refresh leg; no session forces login; no cached EIA.
	writeCreds(t, map[string]any{"refresh_token": "RT", "id_token": expiredIDToken()})

	start := time.Now()
	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--json"}) })
	elapsed := time.Since(start)

	t.Logf("elapsed=%s exit=%d stderr=%q", elapsed, code, errOut)
	if elapsed > overallBudget+2*time.Second {
		t.Fatalf("mint chain ran %s — exceeds the overall budget %s; the deadline is not sum-bounding the steps",
			elapsed, overallBudget)
	}
}
