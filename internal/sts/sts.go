// Package sts is the STS client: discovery (context), session establishment (login), and the
// EIA exchange (token).
//
// Each minting call carries a DPoP proof bound to the exact endpoint URL, signed by ONE key
// per session (reused across login + token so the STS's session jkt-pin holds). Discovery
// carries no DPoP — it mints nothing.
package sts

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
)

// grantTokenExchange is the RFC 8693 token-exchange grant.
const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// grantClientCredentials establishes an STS session for a configured service principal.
const grantClientCredentials = "client_credentials"

// defaultSessionExpiresIn is the fallback session lifetime (8h) when the server omits
// expires_in.
const defaultSessionExpiresIn = 28800

var errNoSTSEndpoint = errors.New("sts: no endpoint configured")

// Product is a per-org mintable product: the EIA audience and the scopes the caller may
// request for it.
type Product struct {
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
}

// OrgContext is one org the caller belongs to, with its role and mintable products.
type OrgContext struct {
	OrgID     string             `json:"org_id"`
	Slug      string             `json:"slug"`
	Role      string             `json:"role"`
	IsDefault bool               `json:"is_default"`
	Products  map[string]Product `json:"products"`
}

// ContextResolution is the /sts/v0/context response: the caller's identity, default org, and
// per-org mintable scopes.
type ContextResolution struct {
	UserID       string       `json:"user_id"`
	DefaultOrgID string       `json:"default_org_id"`
	Orgs         []OrgContext `json:"orgs"`
	// Origin is the STS origin that served this response (not part of the wire
	// contract); callers use it to pin subsequent session/exchange requests.
	Origin string `json:"-"`
}

// Session is the /sts/v0/login response: a DPoP-bound session.
type Session struct {
	SessionToken string `json:"session_token"`
	SessionID    string `json:"session_id"`
	OrgID        string `json:"org_id"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Origin       string `json:"-"`
}

// EIA is the /sts/v0/token response: the Exchanged Identity Assertion (the access_token) and
// its granted scope/lifetime.
type EIA struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
	Origin      string `json:"-"`
}

// Event is a low-cardinality STS client telemetry record. Consumers should
// export only these fixed labels; URLs, tokens, subjects, and DPoP proofs are
// intentionally absent.
type Event struct {
	Operation string // context, login, machine, token
	Origin    string // canonical or legacy
	Outcome   string // success, fallback, failure
	Reason    string // success, network, 404, 5xx, 401, 403, invalid_request, other
}

// Telemetry is an optional callback for recording STS endpoint selection. It
// is deliberately a function on Config so libraries and CLIs can wire their
// own metrics without a global logger.
type Telemetry func(Event)

// Context fetches /sts/v0/context — the caller's orgs + per-org mintable scopes. It carries
// the id_token as a Bearer and NO DPoP (it mints nothing). On a non-2xx it returns the raw
// *httpc.HTTPError so the caller can branch on status.
func Context(cfg config.Config, idToken string, provision bool) (ContextResolution, error) {
	var last error
	endpoints := cfg.STSEndpoints()
	if len(endpoints) == 0 {
		return ContextResolution{}, errNoSTSEndpoint
	}
	for i, origin := range endpoints {
		u := origin + "/sts/v0/context"
		if provision {
			u += "?provision=true"
		}
		_, body, err := httpc.GetJSON(u, map[string]string{"Authorization": "Bearer " + idToken})
		if err == nil {
			var res ContextResolution
			if err := remarshal(body, &res); err != nil {
				return ContextResolution{}, fmt.Errorf("context: %w", err)
			}
			res.Origin = origin
			emit(cfg, Event{Operation: "context", Origin: originClass(cfg, origin), Outcome: outcome(i, false), Reason: "success"})
			return res, nil
		}
		last = err
		if !retryable(err) || i == len(endpoints)-1 {
			emit(cfg, Event{Operation: "context", Origin: originClass(cfg, origin), Outcome: failureOutcome(i), Reason: reason(err)})
			return ContextResolution{}, err
		}
	}
	return ContextResolution{}, last
}

// Login establishes a DPoP-bound session at /sts/v0/login. The DPoP proof is bound to the
// login URL and signed by key; pass the SAME key to Exchange so the server's jkt-pin holds.
// On a non-2xx it returns the raw *httpc.HTTPError.
func Login(cfg config.Config, idToken, org string, key *dpop.Key) (Session, error) {
	var last error
	endpoints := cfg.STSEndpoints()
	if len(endpoints) == 0 {
		return Session{}, errNoSTSEndpoint
	}
	for i, origin := range endpoints {
		u := origin + "/sts/v0/login"
		proof, err := key.Proof("POST", u, idToken)
		if err != nil {
			return Session{}, err
		}
		_, body, err := httpc.PostForm(u, url.Values{"subject_token": {idToken}, "org": {org}}, map[string]string{"DPoP": proof})
		if err == nil {
			var sess Session
			if err := remarshal(body, &sess); err != nil {
				return Session{}, fmt.Errorf("login: %w", err)
			}
			if sess.ExpiresIn == 0 {
				sess.ExpiresIn = defaultSessionExpiresIn
			}
			sess.Origin = origin
			emit(cfg, Event{Operation: "login", Origin: originClass(cfg, origin), Outcome: outcome(i, false), Reason: "success"})
			return sess, nil
		}
		last = err
		if !retryable(err) || i == len(endpoints)-1 {
			emit(cfg, Event{Operation: "login", Origin: originClass(cfg, origin), Outcome: failureOutcome(i), Reason: reason(err)})
			return Session{}, err
		}
	}
	return Session{}, last
}

// Machine establishes a DPoP-bound service-principal session at /sts/v0/machine. The same
// key must be passed to Exchange so the STS session's jkt pin holds.
func Machine(cfg config.Config, clientSecret string, key *dpop.Key) (Session, error) {
	var last error
	endpoints := cfg.STSEndpoints()
	if len(endpoints) == 0 {
		return Session{}, errNoSTSEndpoint
	}
	for i, origin := range endpoints {
		u := origin + "/sts/v0/machine"
		proof, err := key.Proof("POST", u, clientSecret)
		if err != nil {
			return Session{}, err
		}
		_, body, err := httpc.PostForm(u, url.Values{"grant_type": {grantClientCredentials}, "client_secret": {clientSecret}}, map[string]string{"DPoP": proof})
		if err == nil {
			var sess Session
			if err := remarshal(body, &sess); err != nil {
				return Session{}, fmt.Errorf("machine: %w", err)
			}
			sess.Origin = origin
			emit(cfg, Event{Operation: "machine", Origin: originClass(cfg, origin), Outcome: outcome(i, false), Reason: "success"})
			return sess, nil
		}
		last = err
		if !retryable(err) || i == len(endpoints)-1 {
			emit(cfg, Event{Operation: "machine", Origin: originClass(cfg, origin), Outcome: failureOutcome(i), Reason: reason(err)})
			return Session{}, err
		}
	}
	return Session{}, last
}

// Exchange performs the RFC 8693 token-exchange at /sts/v0/token, returning the EIA
// (access_token). subject_token_type is intentionally OMITTED: the STS accepts only empty or
// the gascity session URN, so the RFC-canonical access_token default would 400. The DPoP
// proof is bound to the token URL and MUST be signed by the same key as Login. On a non-2xx
// it returns the raw *httpc.HTTPError.
func Exchange(cfg config.Config, sessionToken, audience, scope string, key *dpop.Key) (EIA, error) {
	var last error
	endpoints := cfg.STSEndpoints()
	if len(endpoints) == 0 {
		return EIA{}, errNoSTSEndpoint
	}
	for i, origin := range endpoints {
		u := origin + "/sts/v0/token"
		proof, err := key.Proof("POST", u, sessionToken)
		if err != nil {
			return EIA{}, err
		}
		_, body, err := httpc.PostForm(u, url.Values{"grant_type": {grantTokenExchange}, "subject_token": {sessionToken}, "audience": {audience}, "scope": {scope}}, map[string]string{"DPoP": proof})
		if err == nil {
			var eia EIA
			if err := remarshal(body, &eia); err != nil {
				return EIA{}, fmt.Errorf("exchange: %w", err)
			}
			eia.Origin = origin
			emit(cfg, Event{Operation: "token", Origin: originClass(cfg, origin), Outcome: outcome(i, false), Reason: "success"})
			return eia, nil
		}
		last = err
		if !retryable(err) || i == len(endpoints)-1 {
			emit(cfg, Event{Operation: "token", Origin: originClass(cfg, origin), Outcome: failureOutcome(i), Reason: reason(err)})
			return EIA{}, err
		}
	}
	return EIA{}, last
}

func emit(cfg config.Config, e Event) {
	if cfg.STSTelemetry != nil {
		cfg.STSTelemetry(e.Operation, e.Origin, e.Outcome, e.Reason)
	}
}
func originClass(cfg config.Config, origin string) string {
	if cfg.CanonicalOrigin() != "" && cfg.CanonicalOrigin() == origin {
		return "canonical"
	}
	return "legacy"
}
func outcome(i int, _ bool) string {
	if i == 0 {
		return "success"
	}
	return "fallback"
}

func failureOutcome(i int) string {
	if i == 0 {
		return "failure"
	}
	return "fallback"
}

func retryable(err error) bool {
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		return he.Status == http.StatusNotFound || he.Status >= 500
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		var ne net.Error
		return errors.As(ue.Err, &ne)
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true // transport and connection errors
	}
	return false
}

func reason(err error) string {
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		switch {
		case he.Status == http.StatusNotFound:
			return "404"
		case he.Status >= 500:
			return "5xx"
		case he.Status == http.StatusUnauthorized:
			return "401"
		case he.Status == http.StatusForbidden:
			return "403"
		case strings.EqualFold(he.OAuthError(), "invalid_request"):
			return "invalid_request"
		default:
			return "other"
		}
	}
	return "network"
}
