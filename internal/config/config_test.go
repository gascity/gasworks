package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	for _, k := range []string{"GASWORKS_STS_URL", "GASWORKS_OIDC_ISSUER", "GASWORKS_CLIENT_ID", "GASWORKS_LOOPBACK_PORT"} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	if cfg.STSBase != "https://works.gascity.com" {
		t.Errorf("STSBase = %q", cfg.STSBase)
	}
	if cfg.OIDCIssuer != "https://auth.gascity.com/realms/gascity" {
		t.Errorf("OIDCIssuer = %q", cfg.OIDCIssuer)
	}
	if cfg.ClientID != "gasworks-cli" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.LoopbackPort != 9822 {
		t.Errorf("LoopbackPort = %d, want 9822", cfg.LoopbackPort)
	}
}

func TestFromEnvOverridesAndTrimsSlash(t *testing.T) {
	t.Setenv("GASWORKS_STS_URL", "http://localhost:8080/")
	t.Setenv("GASWORKS_OIDC_ISSUER", "http://localhost:8080/realms/g/")
	t.Setenv("GASWORKS_CLIENT_ID", "custom-cli")
	t.Setenv("GASWORKS_LOOPBACK_PORT", "1234")
	cfg := FromEnv()
	if cfg.STSBase != "http://localhost:8080" {
		t.Errorf("STSBase = %q, want trailing slash trimmed", cfg.STSBase)
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

func TestFromEnvBadPortFallsBack(t *testing.T) {
	t.Setenv("GASWORKS_LOOPBACK_PORT", "not-a-number")
	if cfg := FromEnv(); cfg.LoopbackPort != 9822 {
		t.Errorf("LoopbackPort = %d, want default 9822 on bad input", cfg.LoopbackPort)
	}
}

func TestURLAccessors(t *testing.T) {
	cfg := Config{STSBase: "https://sts.example", OIDCIssuer: "https://kc.example/realms/g"}
	cases := map[string]string{
		cfg.LoginURL():      "https://sts.example/sts/v0/login",
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
