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

// TestFromEnvDefaultOIDCEndpointsStayInCustomerRealm guards the complete native-CLI
// OIDC surface, not just the issuer field.  A partial realm rollback would otherwise
// leave one grant (for example device auth or revoke) talking to the old gascity realm
// while login appears correctly configured.
func TestFromEnvDefaultOIDCEndpointsStayInCustomerRealm(t *testing.T) {
	for _, k := range []string{"GASWORKS_STS_URL", "GASWORKS_STS_CANONICAL_URL", "GASWORKS_OIDC_ISSUER", "GASWORKS_CLIENT_ID", "GASWORKS_LOOPBACK_PORT"} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	const issuer = "https://auth.gascity.com/realms/gasworks-customers"
	want := map[string]string{
		"device":    issuer + "/protocol/openid-connect/auth/device",
		"authorize": issuer + "/protocol/openid-connect/auth",
		"token":     issuer + "/protocol/openid-connect/token",
		"revoke":    issuer + "/protocol/openid-connect/revoke",
	}
	got := map[string]string{
		"device":    cfg.DeviceAuthURL(),
		"authorize": cfg.AuthorizeURL(),
		"token":     cfg.OIDCTokenURL(),
		"revoke":    cfg.RevokeURL(),
	}
	for name, wantURL := range want {
		if got[name] != wantURL {
			t.Errorf("%s endpoint = %q, want customer-realm endpoint %q", name, got[name], wantURL)
		}
	}
}

func TestNarrowedConfigsPreserveCanonicalOriginRole(t *testing.T) {
	c := Config{STSCanonical: "https://api.gascity.com", STSBase: "https://works.gascity.com"}
	assertEndpoints := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s endpoints = %#v, want %#v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s endpoints = %#v, want %#v", name, got, want)
			}
		}
	}
	assertEndpoints("dual", c.STSEndpoints(), []string{"https://api.gascity.com", "https://works.gascity.com"})

	preferredLegacy := c.WithPreferredSTS("https://works.gascity.com")
	assertEndpoints("preferred legacy", preferredLegacy.STSEndpoints(), []string{"https://works.gascity.com", "https://api.gascity.com"})
	if got := preferredLegacy.STSCanonical; got != "https://api.gascity.com" {
		t.Fatalf("canonical origin was rewritten to %q", got)
	}
	if got := preferredLegacy.CanonicalOrigin(); got != "https://api.gascity.com" {
		t.Fatalf("canonical origin after legacy preference = %q, want canonical origin", got)
	}

	narrowedLegacy := c.WithSTSBase("https://works.gascity.com")
	assertEndpoints("narrow legacy", narrowedLegacy.STSEndpoints(), []string{"https://works.gascity.com"})
	if got := narrowedLegacy.CanonicalOrigin(); got != "https://api.gascity.com" {
		t.Fatalf("canonical origin after legacy narrowing = %q, want canonical origin", got)
	}

	narrowedCanonical := c.WithSTSBase(c.STSCanonical)
	assertEndpoints("narrow canonical", narrowedCanonical.STSEndpoints(), []string{"https://api.gascity.com"})
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
