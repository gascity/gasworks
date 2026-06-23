// Package config holds endpoint + client configuration, with GASWORKS_* env overrides
// for dev/testing. Defaults target production (works.gascity.com + auth.gascity.com).
package config

import (
	"os"
	"strconv"
	"strings"
)

const (
	defaultSTSBase      = "https://works.gascity.com"
	defaultOIDCIssuer   = "https://auth.gascity.com/realms/gascity"
	defaultClientID     = "gasworks-cli"
	defaultLoopbackPort = 9822
)

// Config is the resolved endpoint + client configuration. Treat it as immutable after
// FromEnv; the URL accessors derive everything from the two base URLs.
type Config struct {
	STSBase      string
	OIDCIssuer   string
	ClientID     string
	LoopbackPort int
}

// FromEnv builds a Config from defaults plus GASWORKS_* env overrides. Trailing slashes on
// the base URLs are trimmed so the accessors never emit a double slash. A non-numeric
// GASWORKS_LOOPBACK_PORT falls back to the default.
func FromEnv() Config {
	port := defaultLoopbackPort
	if v := os.Getenv("GASWORKS_LOOPBACK_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	return Config{
		STSBase:      strings.TrimRight(env("GASWORKS_STS_URL", defaultSTSBase), "/"),
		OIDCIssuer:   strings.TrimRight(env("GASWORKS_OIDC_ISSUER", defaultOIDCIssuer), "/"),
		ClientID:     env("GASWORKS_CLIENT_ID", defaultClientID),
		LoopbackPort: port,
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- STS (works.gascity.com) ---

// LoginURL is the DPoP-bound session-establishment endpoint.
func (c Config) LoginURL() string { return c.STSBase + "/sts/v0/login" }

// TokenURL is the RFC 8693 token-exchange endpoint (mints the EIA).
func (c Config) TokenURL() string { return c.STSBase + "/sts/v0/token" }

// ContextURL is the discovery endpoint (orgs + per-org mintable scopes).
func (c Config) ContextURL() string { return c.STSBase + "/sts/v0/context" }

// --- Keycloak (auth.gascity.com) ---

// DeviceAuthURL is the device-authorization-grant endpoint.
func (c Config) DeviceAuthURL() string { return c.OIDCIssuer + "/protocol/openid-connect/auth/device" }

// AuthorizeURL is the browser authorization-code endpoint.
func (c Config) AuthorizeURL() string { return c.OIDCIssuer + "/protocol/openid-connect/auth" }

// OIDCTokenURL is the Keycloak token endpoint (device/code/refresh grants).
func (c Config) OIDCTokenURL() string { return c.OIDCIssuer + "/protocol/openid-connect/token" }

// RevokeURL is the Keycloak token-revocation endpoint.
func (c Config) RevokeURL() string { return c.OIDCIssuer + "/protocol/openid-connect/revoke" }
