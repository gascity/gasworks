package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/gateway"
)

// execInfoJSON builds a BEADS_EXEC_INFO payload for the given origin + dialHost (either may be
// empty to omit it).
func execInfoJSON(origin, dialHost string) string {
	spec := map[string]any{"dialPort": 3306, "database": "bd_prj_x"}
	if dialHost != "" {
		spec["dialHost"] = dialHost
	}
	m := map[string]any{"apiVersion": gateway.ExecInfoAPIVersion, "spec": spec}
	if origin != "" {
		m["origin"] = origin
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func seededGetToken(t *testing.T, srv *stubServer) {
	t.Helper()
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
}

// Exit test 6 (and 1): an untrusted --gateway is refused BEFORE any mint or discovery.
func TestGetTokenUntrustedGatewayEnforceRefusesPreMint(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "enforce")

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--gateway", "evil.example"})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	want := "refusing to mint a beads credential for unknown gateway 'evil.example' — trusted gateways: gw.beads.gascity.com. Add one with 'gasworks trust-gateway evil.example' only if you operate it."
	if !strings.Contains(errOut, want) {
		t.Fatalf("stderr = %q\nwant substring %q", errOut, want)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 0 {
		t.Fatalf("must not mint for an untrusted gateway, got %d mints", n)
	}
	if n := len(srv.reqs("/sts/v0/context")); n != 0 {
		t.Fatalf("gate must run before discovery, got %d context calls", n)
	}
}

func TestGetTokenTrustedGatewayMints(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "enforce")

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--gateway", "gw.beads.gascity.com"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q", out)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 1 {
		t.Fatalf("want 1 mint, got %d", n)
	}
}

func TestGetTokenUntrustedGatewayWarnMints(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "warn")

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--gateway", "evil.example"})
	})
	if code != 0 {
		t.Fatalf("warn mode must mint, exit=%d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errOut, "WOULD REFUSE") || !strings.Contains(errOut, "evil.example") {
		t.Fatalf("warn stderr = %q, want a WOULD REFUSE warning", errOut)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 1 {
		t.Fatalf("warn mode still mints once, got %d", n)
	}
}

// Exit test 6 via exec-info: bd's injected untrusted host is refused; bd surfaces the stderr.
func TestGetTokenExecInfoUntrustedEnforceRefuses(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "enforce")
	t.Setenv(execInfoEnvVar, execInfoJSON(gateway.OriginBD, "evil.example"))

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "unknown gateway 'evil.example'") {
		t.Fatalf("stderr = %q", errOut)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 0 {
		t.Fatalf("must not mint, got %d", n)
	}
}

// Exit test 1c: origin=bd with no dialHost fails closed even in warn mode.
func TestGetTokenExecInfoBDNoDestinationFailsClosed(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "warn") // even in warn, a bd mint with no destination refuses
	t.Setenv(execInfoEnvVar, execInfoJSON(gateway.OriginBD, ""))

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (fail closed)", code)
	}
	if !strings.Contains(errOut, "carried no destination") {
		t.Fatalf("stderr = %q", errOut)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 0 {
		t.Fatalf("must not mint, got %d", n)
	}
}

func TestGetTokenExecInfoVsGatewayDisagreementHardError(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "warn") // disagreement is a hard error regardless of mode
	t.Setenv(execInfoEnvVar, execInfoJSON(gateway.OriginBD, "gw.beads.gascity.com"))

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--gateway", "gw.other.example"})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "conflicting mint destinations") {
		t.Fatalf("stderr = %q", errOut)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 0 {
		t.Fatalf("must not mint, got %d", n)
	}
}

// Exit test 5: a token minted for gateway A is never served for gateway B (cache-key gateway
// dimension). Both gateways are trusted, so the only thing separating them is the cache key.
func TestGetTokenGatewayCacheIsolation(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)
	t.Setenv(gateway.EnforceEnvVar, "enforce")
	if _, _, err := gateway.AddGateway("gw.two.example"); err != nil {
		t.Fatalf("AddGateway: %v", err)
	}

	run1 := func(gw string) int {
		_, _, code := capture(t, func() int {
			return run([]string{"getToken", "manifold", "--gateway", gw})
		})
		return code
	}
	if c := run1("gw.beads.gascity.com"); c != 0 {
		t.Fatalf("A mint exit=%d", c)
	}
	if c := run1("gw.beads.gascity.com"); c != 0 { // cache HIT, no new mint
		t.Fatalf("A re-mint exit=%d", c)
	}
	if c := run1("gw.two.example"); c != 0 { // different gateway → cache MISS → new mint
		t.Fatalf("B mint exit=%d", c)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 2 {
		t.Fatalf("want 2 mints (A once, B once; A's second call is a cache hit), got %d", n)
	}
}

func TestGetTokenProjectFlagValidation(t *testing.T) {
	srv := newStub(t)
	seededGetToken(t, srv)

	_, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--project", "not-a-project"})
	})
	if code != 1 || !strings.Contains(errOut, "invalid --project") {
		t.Fatalf("bad project: exit=%d stderr=%q", code, errOut)
	}

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--project", "prj_0123456789abcdef"})
	})
	if code != 0 {
		t.Fatalf("valid project rejected: exit=%d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q", out)
	}
}

// B4: --json emits the REAL expires_in (not a hardcoded 90).
func TestGetTokenJSONRealExpiresIn(t *testing.T) {
	srv := newStub(t)
	srv.tokenExpiresIn = 120
	seededGetToken(t, srv)

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold", "--json"}) })
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	var env struct {
		ExpiresIn int `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if env.ExpiresIn != 120 {
		t.Fatalf("expires_in = %d, want the server's real 120 (not hardcoded 90)", env.ExpiresIn)
	}
}

// B4: the exchange retry ladder rides out transient 5xx and eventually succeeds.
func TestGetTokenRetryLadderSucceedsAfterTransient(t *testing.T) {
	srv := newStub(t)
	srv.tokenFails = 2
	srv.tokenFailStatus = 503
	seededGetToken(t, srv)

	out, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q", out)
	}
	if n := len(srv.reqs("/sts/v0/token")); n != 3 {
		t.Fatalf("want 3 token attempts (2 fail + 1 success), got %d", n)
	}
}

// B4: serve-last-good — a still-valid cached EIA is emitted (with a warning) when a forced
// re-mint fails, instead of dying.
func TestGetTokenServeLastGoodOnMintFailure(t *testing.T) {
	srv := newStub(t)
	srv.tokenFails = 99 // every mint attempt fails
	srv.tokenFailStatus = 503
	cacheKey := "org_a|manifold|manifold:proxy manifold:pool:acme|" // human path: empty gateway dim
	seed(t, srv, map[string]any{
		"refresh_token": "RT",
		"id_token":      validIDToken(),
		"eia_cache": map[string]any{
			cacheKey: map[string]any{"eia": "CACHED.EIA", "expires_at": now() + 60},
		},
	})

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--refresh"})
	})
	if code != 0 {
		t.Fatalf("serve-last-good must exit 0, got %d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "CACHED.EIA" {
		t.Fatalf("stdout = %q, want the cached EIA", out)
	}
	if !strings.Contains(errOut, "serving the still-valid cached credential") {
		t.Fatalf("stderr = %q, want a serve-last-good warning", errOut)
	}
}
