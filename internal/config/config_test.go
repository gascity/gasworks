package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	for _, k := range []string{"GASWORKS_STS_URL", "GASWORKS_STS_CANONICAL_URL", "GASWORKS_OIDC_ISSUER", "GASWORKS_CLIENT_ID", "GASWORKS_LOOPBACK_PORT"} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	if cfg.STSBase != "https://works.gascity.com" {
		t.Errorf("STSBase = %q", cfg.STSBase)
	}
	if cfg.STSCanonical != "https://api.gascity.com" {
		t.Errorf("STSCanonical = %q", cfg.STSCanonical)
	}
	if cfg.OIDCIssuer != "https://auth.gascity.com/realms/gasworks-customers" {
		t.Errorf("OIDCIssuer = %q", cfg.OIDCIssuer)
	}
	if cfg.ClientID != "gasworks-cli" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.LoopbackPort != 0 {
		t.Errorf("LoopbackPort = %d, want 0 for an ephemeral port", cfg.LoopbackPort)
	}
}

func TestFromEnvOverridesAndTrimsSlash(t *testing.T) {
	t.Setenv("GASWORKS_STS_URL", "http://localhost:8080/")
	t.Setenv("GASWORKS_STS_CANONICAL_URL", "https://api.example/")
	t.Setenv("GASWORKS_OIDC_ISSUER", "http://localhost:8080/realms/g/")
	t.Setenv("GASWORKS_CLIENT_ID", "custom-cli")
	t.Setenv("GASWORKS_LOOPBACK_PORT", "1234")
	cfg := FromEnv()
	if cfg.STSBase != "http://localhost:8080" {
		t.Errorf("STSBase = %q, want trailing slash trimmed", cfg.STSBase)
	}
	if cfg.STSCanonical != "https://api.example" {
		t.Errorf("STSCanonical = %q", cfg.STSCanonical)
	}
	if cfg.OIDCIssuer != "http://localhost:8080/realms/g" {
		t.Errorf("OIDCIssuer = %q", cfg.OIDCIssuer)
	}
	if cfg.ClientID != "custom-cli" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.LoopbackPort != 1234 {
		t.Errorf("LoopbackPort = %d", cfg.LoopbackPort)
	}
}

func TestExplicitLegacyOverrideDisablesImplicitCanonical(t *testing.T) {
	t.Setenv("GASWORKS_STS_URL", "http://localhost:8080")
	t.Setenv("GASWORKS_STS_CANONICAL_URL", "")
	if cfg := FromEnv(); cfg.STSCanonical != "" {
		t.Fatalf("STSCanonical = %q, want empty for explicit legacy override", cfg.STSCanonical)
	}
}

func TestSTSEndpointsCanonicalFirstAndDeduplicated(t *testing.T) {
	cfg := Config{STSCanonical: "https://api.example/", STSBase: "https://legacy.example/"}
	got := cfg.STSEndpoints()
	if len(got) != 2 || got[0] != "https://api.example" || got[1] != "https://legacy.example" {
		t.Fatalf("STSEndpoints = %#v", got)
	}
	got = (Config{STSCanonical: "https://same/", STSBase: "https://same"}).STSEndpoints()
	if len(got) != 1 || got[0] != "https://same" {
		t.Fatalf("deduplicated endpoints = %#v", got)
	}
}

func TestFromEnvBadPortFallsBack(t *testing.T) {
	t.Setenv("GASWORKS_LOOPBACK_PORT", "not-a-number")
	if cfg := FromEnv(); cfg.LoopbackPort != 0 {
		t.Errorf("LoopbackPort = %d, want ephemeral default 0 on bad input", cfg.LoopbackPort)
	}
}

func TestURLAccessors(t *testing.T) {
	cfg := Config{STSBase: "https://sts.example", OIDCIssuer: "https://kc.example/realms/g"}
	cases := map[string]string{
		cfg.LoginURL():      "https://sts.example/sts/v0/login",
		cfg.MachineURL():    "https://sts.example/sts/v0/machine",
		cfg.TokenURL():      "https://sts.example/sts/v0/token",
		cfg.ContextURL():    "https://sts.example/sts/v0/context",
		cfg.DeviceAuthURL(): "https://kc.example/realms/g/protocol/openid-connect/auth/device",
		cfg.AuthorizeURL():  "https://kc.example/realms/g/protocol/openid-connect/auth",
		cfg.OIDCTokenURL():  "https://kc.example/realms/g/protocol/openid-connect/token",
		cfg.RevokeURL():     "https://kc.example/realms/g/protocol/openid-connect/revoke",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
