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
	defaultCanonicalSTS = "https://api.gascity.com"
	defaultOIDCIssuer   = "https://auth.gascity.com/realms/gasworks-customers"
	defaultClientID     = "gasworks-cli"
	defaultLoopbackPort = 0
)

// Config is the resolved endpoint + client configuration. Treat it as immutable after
// FromEnv; the URL accessors derive everything from the two base URLs.
type Config struct {
	STSBase string
	// STSCanonical is the preferred machine origin. STSBase remains the
	// compatibility/legacy origin and is used when the canonical origin is
	// unavailable. An empty STSCanonical disables dual-origin behavior.
	STSCanonical string
	// STSTelemetry receives fixed-label events from the STS client. It must not
	// be used to emit URLs, credentials, subjects, or proofs.
	STSTelemetry func(operation, origin, outcome, reason string)
	// selectedSTS narrows one operation to a previously successful origin. It
	// is internal state carried by WithSTSBase; STSCanonical remains immutable
	// so telemetry can classify the selected origin correctly.
	selectedSTS string
	// preferredSTS reorders the configured dual-host set without changing the
	// canonical-vs-legacy classification.
	preferredSTS string
	OIDCIssuer   string
	ClientID     string
	LoopbackPort int
}

// FromEnv builds a Config from defaults plus GASWORKS_* env overrides. Trailing slashes on
// the base URLs are trimmed so the accessors never emit a double slash. By default the
// browser callback uses an OS-assigned ephemeral port; GASWORKS_LOOPBACK_PORT is an
// explicit fixed-port override for tests and development. A non-numeric override falls
// back to the ephemeral default.
func FromEnv() Config {
	port := defaultLoopbackPort
	if v := os.Getenv("GASWORKS_LOOPBACK_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	legacy := strings.TrimRight(env("GASWORKS_STS_URL", defaultSTSBase), "/")
	canonical := strings.TrimRight(os.Getenv("GASWORKS_STS_CANONICAL_URL"), "/")
	// An explicit GASWORKS_STS_URL is a complete local/test override. Do not
	// unexpectedly probe production before honoring that override.
	if canonical == "" && os.Getenv("GASWORKS_STS_URL") == "" {
		canonical = defaultCanonicalSTS
	}
	return Config{
		STSBase:      legacy,
		STSCanonical: canonical,
		OIDCIssuer:   strings.TrimRight(env("GASWORKS_OIDC_ISSUER", defaultOIDCIssuer), "/"),
		ClientID:     env("GASWORKS_CLIENT_ID", defaultClientID),
		LoopbackPort: port,
	}
}

// STSEndpoints returns the deterministic canonical-first origin set. Duplicate
// or empty origins are removed while preserving order.
func (c Config) STSEndpoints() []string {
	if c.selectedSTS != "" {
		return []string{strings.TrimRight(c.selectedSTS, "/")}
	}
	seen := make(map[string]struct{}, 2)
	var out []string
	configured := []string{strings.TrimRight(c.STSCanonical, "/"), strings.TrimRight(c.STSBase, "/")}
	if c.preferredSTS != "" {
		configured = append([]string{strings.TrimRight(c.preferredSTS, "/")}, configured...)
	}
	for _, origin := range configured {
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	return out
}

// WithSTSBase narrows a config to one selected STS origin, preserving all
// unrelated identity settings. It is used to keep a session and its exchange
// on the same origin after fallback.
func (c Config) WithSTSBase(origin string) Config {
	origin = strings.TrimRight(origin, "/")
	c.STSBase = origin
	c.selectedSTS = origin
	// A narrowed config is single-origin; discard any transient preference that
	// may have been carried from a prior dual-origin config.
	c.preferredSTS = ""
	return c
}

// CanonicalOrigin returns the immutable configured canonical origin, if any.
// Narrowing or reordering endpoints must not rewrite this classification.
func (c Config) CanonicalOrigin() string { return strings.TrimRight(c.STSCanonical, "/") }

// WithPreferredSTS returns a config whose endpoint order starts at origin and
// retains the other configured origin as a fallback.
func (c Config) WithPreferredSTS(origin string) Config {
	origin = strings.TrimRight(origin, "/")
	if origin == "" {
		return c
	}
	// Preferences apply to the configured dual-origin set, not to a prior
	// single-origin narrowing. Clear transient selection before evaluating the
	// available origins so repeated config transforms remain composable.
	c.selectedSTS = ""
	for _, candidate := range c.STSEndpoints() {
		if candidate != origin {
			c.preferredSTS = origin
			return c
		}
	}
	c.preferredSTS = origin
	return c
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

// MachineURL is the DPoP-bound service-principal session-establishment endpoint.
func (c Config) MachineURL() string { return c.STSBase + "/sts/v0/machine" }

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
