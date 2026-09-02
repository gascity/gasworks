package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/jwtutil"
	"github.com/gascity/gasworks/internal/keystore"
	"github.com/gascity/gasworks/internal/store"
)

// cmdInspect prints what the SDK is holding: the login, the DPoP-bound sessions and where
// their keys live, and the Auth Access v1 claims of every cached EIA.
//
// It is entirely LOCAL and makes no network call, and it decodes the cached assertions
// WITHOUT verifying their signatures — the CLI is never the verifier (products verify the
// EIA offline against the edge JWKS). Read it as "what did I receive", never as an
// authorization decision. No credential value is ever printed: only claims, expiries, and
// the thumbprint of the session key.
func cmdInspect(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	asJSON := fs.Bool("json", false, "emit the inspection as a JSON document")
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}

	data, err := store.Load()
	if err != nil {
		return die("could not read credentials: %s", err)
	}
	report := inspectReport(cfg, data, now())
	if *asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return die("could not render the inspection: %s", err)
		}
		stdoutLine(string(encoded))
		return nil
	}
	printInspection(report)
	return nil
}

// inspection is the machine-readable shape of `gasworks inspect --json`.
type inspection struct {
	CredentialsPath string             `json:"credentials_path"`
	KeystoreVersion string             `json:"keystore_registry"`
	Keystores       []keystoreReport   `json:"keystores"`
	LoggedIn        bool               `json:"logged_in"`
	Login           *loginReport       `json:"login,omitempty"`
	Sessions        []sessionReport    `json:"sessions"`
	CachedEIAs      []cachedEIAReport  `json:"cached_eias"`
	RefreshPolicy   refreshPolicyBlock `json:"refresh_policy"`
}

type keystoreReport struct {
	ID            string `json:"id"`
	Summary       string `json:"summary"`
	Status        string `json:"status"`
	Exportability string `json:"exportability"`
	Backup        string `json:"backup"`
	AccessControl string `json:"access_control"`
	Deletion      string `json:"deletion"`
}

type loginReport struct {
	Subject      string   `json:"subject,omitempty"`
	Email        string   `json:"email,omitempty"`
	Username     string   `json:"username,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	ACR          string   `json:"acr,omitempty"`
	AMR          []string `json:"amr,omitempty"`
	AuthTime     string   `json:"auth_time,omitempty"`
	Generation   string   `json:"credential_generation,omitempty"`
	HasRefresh   bool     `json:"refresh_token_present"`
	IDTokenExp   string   `json:"id_token_expires_at,omitempty"`
	SecondsLeft  int64    `json:"id_token_seconds_remaining"`
	DefaultOrg   string   `json:"default_org,omitempty"`
	DecodeErrMsg string   `json:"id_token_decode_error,omitempty"`
}

type sessionReport struct {
	Org         string `json:"org"`
	Origin      string `json:"sts_origin"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	SecondsLeft int64  `json:"seconds_remaining"`
	KeyBackend  string `json:"key_backend,omitempty"`
	KeyHandle   string `json:"key_handle,omitempty"`
	KeyJKT      string `json:"key_jkt,omitempty"`
	KeyStatus   string `json:"key_status"`
}

type cachedEIAReport struct {
	Audience    string     `json:"audience"`
	Org         string     `json:"org"`
	Origin      string     `json:"sts_origin"`
	Scopes      []string   `json:"scopes,omitempty"`
	ExpiresAt   string     `json:"expires_at,omitempty"`
	SecondsLeft int64      `json:"seconds_remaining"`
	Claims      *eiaClaims `json:"claims,omitempty"`
	ClaimsErr   string     `json:"claims_error,omitempty"`
}

// eiaClaims is the Auth Access v1 authentication context carried by an EIA, read straight
// off the (unverified) payload. Claim names follow the EIA wire contract; acr/amr are
// included because a step-up-aware caller wants to see what the login leg asserted, and are
// simply absent when the assertion does not carry them.
//
// These names duplicate the gascity/eia Claims contract (acr/amr/auth_time landed there in
// v0.10.0) and must be kept in step with it. The module is not imported: it exposes only
// Verify/VerifyClaims, which need the edge JWKS and an audience, and `inspect` is an offline
// decode of what is already cached.
type eiaClaims struct {
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	OrgID          string   `json:"org_id,omitempty"`
	SubjectType    string   `json:"subject_type,omitempty"`
	AuthnClass     string   `json:"authn_class,omitempty"`
	AuthTime       string   `json:"auth_time,omitempty"`
	ACR            string   `json:"acr,omitempty"`
	AMR            []string `json:"amr,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
	PlacementClass string   `json:"placement_class,omitempty"`
	Delegation     string   `json:"delegation,omitempty"`
	IssuedAt       string   `json:"iat,omitempty"`
	NotAfter       string   `json:"exp,omitempty"`
}

// refreshPolicyBlock states who owns renewal. The SDK renews every layer before it expires;
// a caller holds a credential and never implements a refresh loop.
type refreshPolicyBlock struct {
	Owner                   string `json:"owner"`
	IDTokenRefreshAtSeconds int    `json:"id_token_refresh_at_seconds_remaining"`
	SessionRenewAtSeconds   int    `json:"session_renew_at_seconds_remaining"`
	EIARemintAtSeconds      int    `json:"eia_remint_at_seconds_remaining"`
}

func inspectReport(cfg config.Config, data *store.Data, instant int64) inspection {
	report := inspection{
		CredentialsPath: store.CredsPath(),
		KeystoreVersion: keystore.Version,
		LoggedIn:        data.IDToken != "" || data.RefreshToken != "",
		Sessions:        []sessionReport{},
		CachedEIAs:      []cachedEIAReport{},
		RefreshPolicy: refreshPolicyBlock{
			Owner:                   "sdk",
			IDTokenRefreshAtSeconds: idTokenSkewSecs,
			SessionRenewAtSeconds:   sessionSkewSecs,
			EIARemintAtSeconds:      eiaSkewSecs,
		},
	}
	for _, backend := range keystoreRegistry() {
		d := backend.Descriptor()
		report.Keystores = append(report.Keystores, keystoreReport{
			ID:            d.ID,
			Summary:       d.Summary,
			Status:        keystore.Status(backend, cfg.AllowFileKeystore),
			Exportability: d.Exportability,
			Backup:        d.Backup,
			AccessControl: d.AccessControl,
			Deletion:      d.Deletion,
		})
	}
	if report.LoggedIn {
		report.Login = loginBlock(data, instant)
	}
	report.Sessions = sessionBlocks(data, instant)
	report.CachedEIAs = cachedEIABlocks(data, instant)
	return report
}

func loginBlock(data *store.Data, instant int64) *loginReport {
	block := &loginReport{
		Generation: data.CredentialGeneration,
		HasRefresh: data.RefreshToken != "",
		DefaultOrg: data.DefaultOrg,
	}
	if data.IDToken == "" {
		return block
	}
	claims, err := jwtutil.DecodeClaims(data.IDToken)
	if err != nil {
		block.DecodeErrMsg = err.Error()
		return block
	}
	block.Subject = claimString(claims, "sub")
	block.Email = claimString(claims, "email")
	block.Username = claimString(claims, "preferred_username")
	block.Issuer = jwtutil.Issuer(claims)
	block.ACR = claimString(claims, "acr")
	block.AMR = claimStrings(claims, "amr")
	block.AuthTime = claimTimestamp(claims, "auth_time")
	if exp := jwtutil.Exp(claims); exp != 0 {
		block.IDTokenExp = utcRFC3339(exp)
		block.SecondsLeft = exp - instant
	}
	return block
}

func sessionBlocks(data *store.Data, instant int64) []sessionReport {
	blocks := make([]sessionReport, 0, len(data.Sessions))
	for _, key := range sortedKeys(data.Sessions) {
		session := data.Sessions[key]
		identity, ok := parseSessionCacheKey(key)
		if !ok {
			continue
		}
		block := sessionReport{
			Org:         identity.Org,
			Origin:      identity.STSAuthority,
			SecondsLeft: session.ExpiresAt - instant,
			KeyBackend:  session.Key.Backend,
			KeyHandle:   session.Key.Handle,
		}
		if session.ExpiresAt != 0 {
			block.ExpiresAt = utcRFC3339(session.ExpiresAt)
		}
		switch dpopKey, err := loadSessionKey(session.Key); {
		case err != nil && !session.Key.Enrolled():
			block.KeyStatus = "not enrolled (session predates split credential storage)"
		case err != nil:
			block.KeyStatus = "unreadable: " + err.Error()
		default:
			block.KeyStatus = "enrolled"
			block.KeyJKT = dpopKey.Thumbprint()
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func cachedEIABlocks(data *store.Data, instant int64) []cachedEIAReport {
	blocks := make([]cachedEIAReport, 0, len(data.EIACache))
	for _, key := range sortedKeys(data.EIACache) {
		entry := data.EIACache[key]
		identity, ok := parseEIACacheKey(key)
		if !ok {
			continue
		}
		block := cachedEIAReport{
			Audience:    identity.Audience,
			Org:         identity.Org,
			Origin:      identity.STSAuthority,
			Scopes:      identity.Scopes,
			SecondsLeft: entry.ExpiresAt - instant,
		}
		if entry.ExpiresAt != 0 {
			block.ExpiresAt = utcRFC3339(entry.ExpiresAt)
		}
		claims, err := jwtutil.DecodeClaims(entry.EIA)
		if err != nil {
			block.ClaimsErr = "not a decodable assertion (" + err.Error() + ")"
		} else {
			block.Claims = readEIAClaims(claims)
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func readEIAClaims(claims map[string]any) *eiaClaims {
	out := &eiaClaims{
		Issuer:         jwtutil.Issuer(claims),
		Subject:        claimString(claims, "sub"),
		Audience:       jwtutil.Audiences(claims),
		OrgID:          claimString(claims, "org_id"),
		SubjectType:    claimString(claims, "subject_type"),
		AuthnClass:     claimString(claims, "authn_class"),
		AuthTime:       claimTimestamp(claims, "auth_time"),
		ACR:            claimString(claims, "acr"),
		AMR:            claimStrings(claims, "amr"),
		SessionID:      claimString(claims, "session_id"),
		PlacementClass: claimString(claims, "placement_class"),
	}
	if exp := jwtutil.Exp(claims); exp != 0 {
		out.NotAfter = utcRFC3339(exp)
	}
	if iat, ok := jwtutil.Int64(claims, "iat"); ok {
		out.IssuedAt = utcRFC3339(iat)
	}
	if delegation, ok := claims["delegation"].(map[string]any); ok {
		out.Delegation = fmt.Sprintf("id=%s delegator_sub=%s depth=%s",
			claimString(delegation, "id"), claimString(delegation, "delegator_sub"),
			claimNumber(delegation, "depth"))
	}
	return out
}

func printInspection(report inspection) {
	stdoutf("credentials:  %s", report.CredentialsPath)
	stdoutf("dpop keys:    %s", report.KeystoreVersion)
	for _, k := range report.Keystores {
		stdoutf("  - %-9s %s [%s]", k.ID, k.Summary, k.Status)
	}
	stdoutf("refresh:      owned by the SDK — id_token at %ds left, session at %ds, EIA at %ds",
		report.RefreshPolicy.IDTokenRefreshAtSeconds, report.RefreshPolicy.SessionRenewAtSeconds,
		report.RefreshPolicy.EIARemintAtSeconds)

	if !report.LoggedIn {
		stdoutLine("")
		stdoutLine("not logged in — run `gasworks login`")
		return
	}

	login := report.Login
	stdoutLine("")
	stdoutLine("login:")
	printField("subject", login.Subject)
	printField("email", login.Email)
	printField("username", login.Username)
	printField("issuer", login.Issuer)
	printField("acr", login.ACR)
	printField("amr", strings.Join(login.AMR, " "))
	printField("auth_time", login.AuthTime)
	printField("generation", login.Generation)
	printField("default org", login.DefaultOrg)
	printField("refresh token", presence(login.HasRefresh))
	if login.DecodeErrMsg != "" {
		printField("id_token", "undecodable: "+login.DecodeErrMsg)
	} else if login.IDTokenExp != "" {
		printField("id_token", login.IDTokenExp+" ("+remaining(login.SecondsLeft)+")")
	}

	stdoutLine("")
	stdoutf("sessions (%d):", len(report.Sessions))
	for _, s := range report.Sessions {
		stdoutf("  - org %s at %s", s.Org, s.Origin)
		stdoutf("      expires  %s (%s)", s.ExpiresAt, remaining(s.SecondsLeft))
		stdoutf("      dpop key %s [%s]", keyLocation(s), s.KeyStatus)
		if s.KeyJKT != "" {
			stdoutf("      jkt      %s", s.KeyJKT)
		}
	}

	stdoutLine("")
	stdoutf("cached EIAs (%d):", len(report.CachedEIAs))
	for _, e := range report.CachedEIAs {
		stdoutf("  - audience %s  org %s  at %s", e.Audience, e.Org, e.Origin)
		stdoutf("      scopes   %s", strings.Join(e.Scopes, " "))
		stdoutf("      expires  %s (%s)", e.ExpiresAt, remaining(e.SecondsLeft))
		if e.ClaimsErr != "" {
			stdoutf("      claims   %s", e.ClaimsErr)
			continue
		}
		for _, line := range claimLines(e.Claims) {
			stdoutf("      %s", line)
		}
	}
}

func claimLines(c *eiaClaims) []string {
	if c == nil {
		return nil
	}
	pairs := []struct{ label, value string }{
		{"iss", c.Issuer},
		{"sub", c.Subject},
		{"aud", strings.Join(c.Audience, " ")},
		{"org_id", c.OrgID},
		{"subject_type", c.SubjectType},
		{"authn_class", c.AuthnClass},
		{"auth_time", c.AuthTime},
		{"acr", c.ACR},
		{"amr", strings.Join(c.AMR, " ")},
		{"session_id", c.SessionID},
		{"placement", c.PlacementClass},
		{"delegation", c.Delegation},
		{"iat", c.IssuedAt},
		{"exp", c.NotAfter},
	}
	var lines []string
	for _, p := range pairs {
		if p.value != "" {
			lines = append(lines, fmt.Sprintf("%-13s%s", p.label, p.value))
		}
	}
	return lines
}

func keyLocation(s sessionReport) string {
	if s.KeyBackend == "" {
		return "(none)"
	}
	return s.KeyBackend + ":" + s.KeyHandle
}

func printField(label, value string) {
	if value != "" {
		stdoutf("  %-15s%s", label+":", value)
	}
}

func presence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}

// remaining renders a signed second count as a short human duration.
func remaining(seconds int64) string {
	if seconds <= 0 {
		return "expired"
	}
	return "in " + (time.Duration(seconds) * time.Second).String()
}

func utcRFC3339(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }

func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func claimTimestamp(claims map[string]any, key string) string {
	if v, ok := jwtutil.Int64(claims, key); ok && v > 0 {
		return utcRFC3339(v)
	}
	return ""
}

func claimNumber(claims map[string]any, key string) string {
	if v, ok := jwtutil.Int64(claims, key); ok {
		return fmt.Sprintf("%d", v)
	}
	return ""
}

// sortedKeys returns the map's keys in a stable order so inspect output is deterministic.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
