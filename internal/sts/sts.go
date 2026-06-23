// Package sts is the STS client: discovery (context), session establishment (login), and the
// EIA exchange (token).
//
// Each minting call carries a DPoP proof bound to the exact endpoint URL, signed by ONE key
// per session (reused across login + token so the STS's session jkt-pin holds). Discovery
// carries no DPoP — it mints nothing.
package sts

import (
	"fmt"
	"net/url"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
)

// grantTokenExchange is the RFC 8693 token-exchange grant.
const grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// defaultSessionExpiresIn is the fallback session lifetime (8h) when the server omits
// expires_in.
const defaultSessionExpiresIn = 28800

// defaultEIAExpiresIn is the fallback EIA lifetime (90s) when the server omits expires_in.
const defaultEIAExpiresIn = 90

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
}

// Session is the /sts/v0/login response: a DPoP-bound session.
type Session struct {
	SessionToken string `json:"session_token"`
	SessionID    string `json:"session_id"`
	ExpiresIn    int    `json:"expires_in"`
}

// EIA is the /sts/v0/token response: the Exchanged Identity Assertion (the access_token) and
// its granted scope/lifetime.
type EIA struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
}

// Context fetches /sts/v0/context — the caller's orgs + per-org mintable scopes. It carries
// the id_token as a Bearer and NO DPoP (it mints nothing). On a non-2xx it returns the raw
// *httpc.HTTPError so the caller can branch on status.
func Context(cfg config.Config, idToken string, provision bool) (ContextResolution, error) {
	u := cfg.ContextURL()
	if provision {
		u += "?provision=true"
	}
	_, body, err := httpc.GetJSON(u, map[string]string{"Authorization": "Bearer " + idToken})
	if err != nil {
		return ContextResolution{}, err
	}
	var res ContextResolution
	if err := remarshal(body, &res); err != nil {
		return ContextResolution{}, fmt.Errorf("context: %w", err)
	}
	return res, nil
}

// Login establishes a DPoP-bound session at /sts/v0/login. The DPoP proof is bound to the
// login URL and signed by key; pass the SAME key to Exchange so the server's jkt-pin holds.
// On a non-2xx it returns the raw *httpc.HTTPError.
func Login(cfg config.Config, idToken, org string, key *dpop.Key) (Session, error) {
	proof, err := key.Proof("POST", cfg.LoginURL())
	if err != nil {
		return Session{}, err
	}
	_, body, err := httpc.PostForm(cfg.LoginURL(), url.Values{
		"subject_token": {idToken},
		"org":           {org},
	}, map[string]string{"DPoP": proof})
	if err != nil {
		return Session{}, err
	}
	var sess Session
	if err := remarshal(body, &sess); err != nil {
		return Session{}, fmt.Errorf("login: %w", err)
	}
	if sess.ExpiresIn == 0 {
		sess.ExpiresIn = defaultSessionExpiresIn
	}
	return sess, nil
}

// Exchange performs the RFC 8693 token-exchange at /sts/v0/token, returning the EIA
// (access_token). subject_token_type is intentionally OMITTED: the STS accepts only empty or
// the gascity session URN, so the RFC-canonical access_token default would 400. The DPoP
// proof is bound to the token URL and MUST be signed by the same key as Login. On a non-2xx
// it returns the raw *httpc.HTTPError.
func Exchange(cfg config.Config, sessionToken, audience, scope string, key *dpop.Key) (EIA, error) {
	proof, err := key.Proof("POST", cfg.TokenURL())
	if err != nil {
		return EIA{}, err
	}
	_, body, err := httpc.PostForm(cfg.TokenURL(), url.Values{
		"grant_type":    {grantTokenExchange},
		"subject_token": {sessionToken},
		"audience":      {audience},
		"scope":         {scope},
	}, map[string]string{"DPoP": proof})
	if err != nil {
		return EIA{}, err
	}
	var eia EIA
	if err := remarshal(body, &eia); err != nil {
		return EIA{}, fmt.Errorf("exchange: %w", err)
	}
	if eia.ExpiresIn == 0 {
		eia.ExpiresIn = defaultEIAExpiresIn
	}
	return eia, nil
}
