package config

import (
	"strings"
	"testing"
)

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

func TestClimintBaseDefaultsToTheIssuerOrigin(t *testing.T) {
	t.Setenv(ClimintBaseEnv, "")
	t.Setenv("GASWORKS_OIDC_ISSUER", "")
	if got, want := FromEnv().ClimintBase, "https://auth.gascity.com"; got != want {
		t.Fatalf("ClimintBase = %q, want %q", got, want)
	}
	// climint rides the issuer host, but only its origin — never the realm path.
	t.Setenv("GASWORKS_OIDC_ISSUER", "https://auth.staging.example/realms/gasworks-customers")
	if got, want := FromEnv().ClimintBase, "https://auth.staging.example"; got != want {
		t.Fatalf("ClimintBase = %q, want the issuer origin %q", got, want)
	}
}

func TestClimintBaseEnvOverride(t *testing.T) {
	t.Setenv("GASWORKS_OIDC_ISSUER", "https://auth.gascity.com/realms/gasworks-customers")
	t.Setenv(ClimintBaseEnv, "https://mint.example/")
	cfg := FromEnv()
	if got, want := cfg.ClimintBase, "https://mint.example"; got != want {
		t.Fatalf("ClimintBase = %q, want %q with the trailing slash trimmed", got, want)
	}
	if got, err := cfg.MintChallengesURL(); err != nil || got != "https://mint.example/v0/cli/mint/challenges" {
		t.Fatalf("MintChallengesURL = %q, %v", got, err)
	}
}

// A non-https issuer (a local Keycloak) yields a base that cannot be signed as an htu. The
// CLI must fail closed and name the override, not silently upgrade the scheme.
func TestClimintBaseFromNonHTTPSIssuerFailsClosed(t *testing.T) {
	t.Setenv(ClimintBaseEnv, "")
	t.Setenv("GASWORKS_OIDC_ISSUER", "http://localhost:8080/realms/g")
	cfg := FromEnv()
	if got, want := cfg.ClimintBase, "http://localhost:8080"; got != want {
		t.Fatalf("ClimintBase = %q, want %q", got, want)
	}
	_, err := cfg.MintChallengesURL()
	if err == nil {
		t.Fatal("MintChallengesURL accepted a plain-http origin")
	}
	if !strings.Contains(err.Error(), ClimintBaseEnv) {
		t.Errorf("error %q does not name %s", err, ClimintBaseEnv)
	}
}

func TestCanonicalOriginRejectsNonCanonicalShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"plain http", "http://auth.gascity.com"},
		{"uppercase scheme", "HTTPS://auth.gascity.com"},
		{"scheme relative", "//auth.gascity.com"},
		{"no scheme", "auth.gascity.com"},
		{"uppercase host", "https://Auth.GasCity.com"},
		{"default port spelled out", "https://auth.gascity.com:443"},
		{"empty port", "https://auth.gascity.com:"},
		{"userinfo", "https://user:pw@auth.gascity.com"},
		{"trailing slash path", "https://auth.gascity.com/"},
		{"path", "https://auth.gascity.com/v0"},
		{"query", "https://auth.gascity.com?a=b"},
		{"bare query marker", "https://auth.gascity.com?"},
		{"fragment", "https://auth.gascity.com#f"},
		{"percent escape", "https://auth.gascity.com%2f"},
		{"no host", "https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := canonicalOrigin(tc.raw); err == nil {
				t.Fatalf("canonicalOrigin(%q) = %q, want an error", tc.raw, got)
			}
		})
	}

	for _, ok := range []string{"https://auth.gascity.com", "https://auth.staging.example:8443"} {
		got, err := canonicalOrigin(ok)
		if err != nil {
			t.Errorf("canonicalOrigin(%q): %v", ok, err)
		}
		if got != ok {
			t.Errorf("canonicalOrigin(%q) = %q, want it returned verbatim", ok, got)
		}
	}
}

func TestMintURLAccessors(t *testing.T) {
	cfg := Config{ClimintBase: "https://auth.gascity.com"}

	got, err := cfg.MintChallengesURL()
	if err != nil {
		t.Fatalf("MintChallengesURL: %v", err)
	}
	if want := "https://auth.gascity.com/v0/cli/mint/challenges"; got != want {
		t.Errorf("MintChallengesURL = %q, want %q", got, want)
	}

	got, err = cfg.MintCompleteURL("chal_01JQ8Z9-abc")
	if err != nil {
		t.Fatalf("MintCompleteURL: %v", err)
	}
	if want := "https://auth.gascity.com/v0/cli/mint/challenges/chal_01JQ8Z9-abc/complete"; got != want {
		t.Errorf("MintCompleteURL = %q, want %q", got, want)
	}

	// An id that would need escaping (or escape the endpoint) never reaches the wire: the
	// request URL and the server's reconstructed htu would disagree.
	for _, bad := range []string{"", "chal/../other", "chal id", "chal%2f", "chal?a=b", "chal#f"} {
		if got, err := cfg.MintCompleteURL(bad); err == nil {
			t.Errorf("MintCompleteURL(%q) = %q, want an error", bad, got)
		}
	}

	for _, broken := range []Config{{}, {ClimintBase: "http://auth.gascity.com"}} {
		if _, err := broken.MintChallengesURL(); err == nil {
			t.Errorf("MintChallengesURL accepted base %q", broken.ClimintBase)
		}
		if _, err := broken.MintCompleteURL("chal_1"); err == nil {
			t.Errorf("MintCompleteURL accepted base %q", broken.ClimintBase)
		}
	}
}
