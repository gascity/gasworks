// Package config holds endpoint + client configuration, with GASWORKS_* env overrides
// for dev/testing. Defaults target production (works.gascity.com + auth.gascity.com).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// AllowFileKeystoreEnv opts the DPoP private key into the plaintext-file credential store.
// It is named here (rather than inline) because the fail-closed enrolment error quotes it.
const AllowFileKeystoreEnv = "GASWORKS_ALLOW_FILE_KEYSTORE"

// ClimintBaseEnv overrides the climint external-mint origin. It is named here because the
// fail-closed origin error quotes it: a dev pointing the CLI at a local, non-https Keycloak
// has to set this explicitly rather than have the CLI guess an origin.
const ClimintBaseEnv = "GASWORKS_CLIMINT_URL"

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
	// STSCanonical is the preferred STS origin. STSBase remains the
	// compatibility/legacy origin and is used as a fallback for the
	// non-provisioning (read-only) context discovery request, and for a
	// provisioning discovery or session-establishment (login/machine) request only
	// when the canonical host's name does not resolve. The token exchange is bound
	// to the origin that issued the session and is always single-origin.
	// An empty STSCanonical disables dual-origin behavior.
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
	// ClimintBase is the origin serving the climint external-mint ceremony. It is a
	// DIFFERENT origin from the STS (auth.gascity.com, not works/api.gascity.com) and must
	// never be routed through the STS client: the mint legs are signed with single-use DPoP
	// proofs, and the STS client's cross-origin retry would burn one. It defaults to the
	// origin of OIDCIssuer; the URL accessors validate it before it can be signed as an htu.
	ClimintBase  string
	ClientID     string
	LoopbackPort int
	// AllowFileKeystore opts the DPoP private key into the plaintext-file credential
	// store (GASWORKS_ALLOW_FILE_KEYSTORE, or the --allow-file-keystore flag on the
	// commands that enrol a key). Auth Access v1 forbids falling back to a plain file
	// silently, so where this build has a platform keystore the SDK fails closed without
	// it; where it has none (Linux, Windows) the file store is the only one there is and
	// this only silences the notice. See internal/keystore.
	AllowFileKeystore bool
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
	issuer := strings.TrimRight(env("GASWORKS_OIDC_ISSUER", defaultOIDCIssuer), "/")
	climint := strings.TrimRight(os.Getenv(ClimintBaseEnv), "/")
	if climint == "" {
		climint = originOf(issuer)
	}
	return Config{
		STSBase:           legacy,
		STSCanonical:      canonical,
		OIDCIssuer:        issuer,
		ClimintBase:       climint,
		ClientID:          env("GASWORKS_CLIENT_ID", defaultClientID),
		LoopbackPort:      port,
		AllowFileKeystore: boolEnv(AllowFileKeystoreEnv),
	}
}

// originOf reduces a URL to its scheme://host origin, or "" if it has neither. climint is
// served by the same host as the OIDC issuer, so the issuer override carries the CLI to a
// staging deployment without a second env var — but only its origin: the issuer's realm path
// is not part of the mint API. An origin that is not canonical (a plain-http dev issuer, say)
// is returned as-is and rejected later, by the accessor that would have signed it as an htu.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// boolEnv reads a boolean env override. An unset or unparseable value is false: a typo must
// never look like an opt-in to a weaker credential store.
func boolEnv(key string) bool {
	on, err := strconv.ParseBool(os.Getenv(key))
	return err == nil && on
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
// retains the other configured origin as a fallback for non-provisioning (read-only)
// discovery. Provisioning context and state-changing callers should use WithSTSBase to pin
// one origin before making the request.
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

// --- climint external mint (auth.gascity.com) ---

// MintChallengesURL is leg A of the external-mint ceremony: it opens a challenge and returns
// the confirm code the user types into the browser.
func (c Config) MintChallengesURL() (string, error) {
	origin, err := c.ClimintOrigin()
	if err != nil {
		return "", err
	}
	return origin + "/v0/cli/mint/challenges", nil
}

// MintCompleteURL is leg C: the poll that redeems an approved challenge for the credential.
// The challenge id is a path segment, so the URL — and therefore the DPoP htu signed over it
// — differs per challenge and a fresh proof is required per request.
func (c Config) MintCompleteURL(challengeID string) (string, error) {
	origin, err := c.ClimintOrigin()
	if err != nil {
		return "", err
	}
	if err := checkPathSegment(challengeID); err != nil {
		return "", fmt.Errorf("challenge id: %w", err)
	}
	return origin + "/v0/cli/mint/challenges/" + challengeID + "/complete", nil
}

// ClimintOrigin is the validated scheme://host the mint plane is served at, quoting the
// override that fixes a bad one. It is exported because it is the only origin the ceremony
// may talk to: the CLI checks the server-supplied approval URL against it before handing that
// URL to a browser, so nothing the mint plane returns can send the human to another host.
func (c Config) ClimintOrigin() (string, error) {
	origin, err := canonicalOrigin(c.ClimintBase)
	if err != nil {
		return "", fmt.Errorf("climint base URL: %w (set %s to a canonical https origin)", err, ClimintBaseEnv)
	}
	return origin, nil
}

// canonicalOrigin accepts only the origin form the climint server itself canonicalises to
// before it compares a DPoP htu byte for byte: https, lowercase scheme and host, no spelled
// out :443, and no userinfo, path, query, fragment or percent-escape. Anything else is
// REJECTED rather than normalised — a client that quietly rewrote the operator's origin
// would sign an htu against a host the operator did not name, and every proof the server
// then rejects has already spent its single-use jti.
func canonicalOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("is not configured")
	}
	if !strings.HasPrefix(raw, "https://") {
		return "", fmt.Errorf("%q must start with a lowercase https:// scheme", raw)
	}
	if strings.Contains(raw, "%") {
		return "", fmt.Errorf("%q must not contain a percent-escape", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", raw, err)
	}
	switch {
	case u.User != nil:
		return "", fmt.Errorf("%q must not carry userinfo", raw)
	case u.Host == "":
		return "", fmt.Errorf("%q has no host", raw)
	case u.Host != strings.ToLower(u.Host):
		return "", fmt.Errorf("%q must use a lowercase host", raw)
	case strings.HasSuffix(u.Host, ":"):
		return "", fmt.Errorf("%q has an empty port", raw)
	case u.Port() == "443":
		return "", fmt.Errorf("%q must not spell out the default port :443", raw)
	case u.Path != "":
		return "", fmt.Errorf("%q must be a bare origin, with no path", raw)
	case u.RawQuery != "" || u.ForceQuery:
		return "", fmt.Errorf("%q must not carry a query", raw)
	case u.Fragment != "":
		return "", fmt.Errorf("%q must not carry a fragment", raw)
	}
	return raw, nil
}

// checkPathSegment rejects an id that could not appear verbatim in a URL path. A percent
// escape or a stray slash would make the request URL differ from the htu the server
// reconstructs — or address a different endpoint entirely.
func checkPathSegment(s string) error {
	if s == "" {
		return errors.New("is empty")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return fmt.Errorf("contains %q, which does not survive a URL path unescaped", r)
		}
	}
	return nil
}
