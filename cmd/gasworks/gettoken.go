package main

import (
	"encoding/json"
	"errors"
	"flag"
	"sort"
	"strings"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

// The three lifecycle freshness thresholds. (M11) They are DISTINCT — do not collapse them.
const (
	idTokenSkewSecs = 60 // refresh the id_token when it has <60s left
	sessionSkewSecs = 30 // re-establish the STS session when it has <30s left
	eiaSkewSecs     = 15 // re-mint the EIA when the cached one has <15s left
)

func cmdGetToken(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("getToken", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	orgFlag := fs.String("org", "", "org id or slug (defaults to your default/sole org)")
	scopeFlag := fs.String("scope", "", "override the discovered scopes (space-separated)")
	asJSON := fs.Bool("json", false, "emit a JSON envelope instead of the raw EIA")
	refresh := fs.Bool("refresh", false, "bypass the local EIA cache")

	// argparse interleaves flags and the positional <product>; stdlib flag stops at the first
	// bareword. Hoist the product out so `getToken manifold --json` and `getToken --json
	// manifold` both work.
	product, rest := hoistPositional(argv)
	if err := fs.Parse(rest); err != nil {
		return die("%s", err)
	}
	if product == "" {
		return die("usage: gasworks getToken <product> [--org ...] [--scope ...] [--json] [--refresh]")
	}

	idToken, err := ensureIDToken(cfg)
	if err != nil {
		return err
	}

	ctx, err := sts.Context(cfg, idToken, true)
	if err != nil {
		return die("discovery failed: %s", err)
	}

	data, err := store.Load()
	if err != nil {
		return die("could not read credentials: %s", err)
	}

	org, err := pickOrg(ctx, *orgFlag, data)
	if err != nil {
		return err
	}
	orgCtx := orgByID(ctx, org)
	if orgCtx == nil {
		return die("you are not a member of org %s", org)
	}

	// The product must be a mintable product for this org regardless of --scope, so an
	// explicit scope can't bypass this into a confusing raw STS 400 invalid_target.
	prod, ok := orgCtx.Products[product]
	if !ok || len(prod.Scopes) == 0 {
		return die("no mintable '%s' scope for org %s (entitled products: %s)",
			product, orgCtx.Slug, productNames(orgCtx.Products))
	}
	scope := *scopeFlag
	if scope == "" {
		scope = strings.Join(prod.Scopes, " ") // default to the discovered scopes
	}

	cacheKey := org + "|" + product + "|" + scope
	if !*refresh {
		if cached, ok := data.EIACache[cacheKey]; ok && cached.ExpiresAt-now() > eiaSkewSecs {
			emit(cached.EIA, scope, *asJSON)
			return nil
		}
	}

	sessionToken, key, err := ensureSession(cfg, data, org, idToken)
	if err != nil {
		return err
	}

	res, err := sts.Exchange(cfg, sessionToken, product, scope, key)
	if err != nil {
		var he *httpc.HTTPError
		switch {
		case errors.As(err, &he) && he.Status == 401:
			// Session not resolvable — re-establish ONCE (fresh key) and retry exactly once.
			sessionToken, key, err = newSession(cfg, org, idToken)
			if err != nil {
				return err
			}
			res, err = sts.Exchange(cfg, sessionToken, product, scope, key)
			if err != nil {
				return die("getToken failed: %s", err)
			}
		case errors.As(err, &he) && he.Status == 403:
			return die("getToken denied: %s (%s)", he.OAuthError(), he)
		default:
			return die("getToken failed: %s", err)
		}
	}

	eia := res.AccessToken
	if err := store.Update(func(d *store.Data) error {
		if d.EIACache == nil {
			d.EIACache = map[string]store.EIACacheEntry{}
		}
		d.EIACache[cacheKey] = store.EIACacheEntry{EIA: eia, ExpiresAt: now() + int64(res.ExpiresIn)}
		return nil
	}); err != nil {
		return die("could not cache EIA: %s", err)
	}

	grantedScope := res.Scope
	if grantedScope == "" {
		grantedScope = scope
	}
	emit(eia, grantedScope, *asJSON)
	return nil
}

// ensureIDToken returns a valid id_token, refreshing (and persisting the rotated refresh
// token) if needed. (M10) The refresh rotation is persisted in its OWN locked write BEFORE any
// later mint step, so a crash mid-getToken cannot lose the new refresh token.
func ensureIDToken(cfg config.Config) (string, error) {
	data, err := store.Load()
	if err != nil {
		return "", die("could not read credentials: %s", err)
	}
	if data.IDToken != "" && tokenExp(data.IDToken)-now() > idTokenSkewSecs {
		return data.IDToken, nil
	}
	if data.RefreshToken == "" {
		return "", die("not logged in — run `gasworks login`")
	}

	tok, err := oidc.Refresh(cfg, data.RefreshToken)
	if err != nil {
		var he *httpc.HTTPError
		detail := err.Error()
		if errors.As(err, &he) {
			if oe := he.OAuthError(); oe != "" {
				detail = oe
			}
		}
		return "", die("session expired (%s) — run `gasworks login` again", detail)
	}

	var idToken string
	if err := store.Update(func(d *store.Data) error {
		if tok.RefreshToken != "" {
			d.RefreshToken = tok.RefreshToken // Keycloak rotates — persist it
		}
		if tok.IDToken != "" {
			d.IDToken = tok.IDToken
		}
		idToken = d.IDToken
		return nil
	}); err != nil {
		return "", die("could not persist refreshed token: %s", err)
	}
	return idToken, nil
}

// pickOrg resolves the org to mint for: --org (id or slug) ▸ stored default_org ▸ the context
// default ▸ the sole org ▸ else a loud multi-org error listing every org's slug+id.
func pickOrg(ctx sts.ContextResolution, requested string, data *store.Data) (string, error) {
	orgs := ctx.Orgs
	if requested != "" {
		for _, o := range orgs {
			if requested == o.OrgID || requested == o.Slug {
				return o.OrgID, nil
			}
		}
		return "", die("you are not a member of org '%s'. Your orgs: %s", requested, orgList(orgs))
	}
	if data.DefaultOrg != "" && orgByIDIn(orgs, data.DefaultOrg) {
		return data.DefaultOrg, nil
	}
	if ctx.DefaultOrgID != "" && orgByIDIn(orgs, ctx.DefaultOrgID) {
		return ctx.DefaultOrgID, nil
	}
	if len(orgs) == 1 {
		return orgs[0].OrgID, nil
	}
	if len(orgs) == 0 {
		return "", die("no orgs for this account")
	}
	return "", die("you belong to multiple orgs — pass --org. Your orgs: %s", orgList(orgs))
}

// newSession generates a FRESH DPoP key, establishes a new STS session, and persists it
// (locked). A fresh key per new session matches the server's per-session jkt-pin.
func newSession(cfg config.Config, org, idToken string) (string, *dpop.Key, error) {
	key, err := dpop.NewKey()
	if err != nil {
		return "", nil, die("could not generate a session key: %s", err)
	}
	sess, err := sts.Login(cfg, idToken, org, key)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 403 {
			return "", nil, die("not a member of org %s (%s)", org, he.OAuthError())
		}
		return "", nil, die("login to org %s failed: %s", org, err)
	}
	pem, err := key.ToPEM()
	if err != nil {
		return "", nil, die("could not serialize the session key: %s", err)
	}
	if err := store.Update(func(d *store.Data) error {
		if d.Sessions == nil {
			d.Sessions = map[string]store.Session{}
		}
		d.Sessions[org] = store.Session{
			SessionToken: sess.SessionToken,
			DPoPPEM:      pem,
			ExpiresAt:    now() + int64(sess.ExpiresIn),
		}
		return nil
	}); err != nil {
		return "", nil, die("could not save the session: %s", err)
	}
	return sess.SessionToken, key, nil
}

// ensureSession reuses the stored per-org session when it has >30s left (loading its DPoP key
// from PEM), otherwise establishes a fresh one.
func ensureSession(cfg config.Config, data *store.Data, org, idToken string) (string, *dpop.Key, error) {
	if sess, ok := data.Sessions[org]; ok && sess.ExpiresAt-now() > sessionSkewSecs {
		key, err := dpop.FromPEM(sess.DPoPPEM)
		if err == nil {
			return sess.SessionToken, key, nil
		}
		// A corrupt stored key falls through to a fresh session rather than crashing.
	}
	return newSession(cfg, org, idToken)
}

// hoistPositional pulls the single bareword product out of argv (in any position, like
// argparse) and returns it plus the remaining flag args for flag.Parse. Value-taking flags
// (--org, --scope, and their = / space forms) are skipped so their value is never mistaken for
// the product. The first remaining bareword wins; later ones stay in rest for flag.Parse to
// reject.
func hoistPositional(argv []string) (product string, rest []string) {
	valueFlags := map[string]bool{"-org": true, "--org": true, "-scope": true, "--scope": true}
	rest = make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" { // everything after -- is positional
			for _, p := range argv[i+1:] {
				if product == "" {
					product = p
				} else {
					rest = append(rest, p)
				}
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			// A "--org value" form (no '=') consumes the next token as its value.
			if valueFlags[a] && i+1 < len(argv) {
				rest = append(rest, argv[i+1])
				i++
			}
			continue
		}
		if product == "" {
			product = a
		} else {
			rest = append(rest, a)
		}
	}
	return product, rest
}

func emit(eia, scope string, asJSON bool) {
	if asJSON {
		env := struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}{eia, "DPoP", 90, scope}
		b, _ := json.Marshal(env)
		stdoutLine(string(b))
		return
	}
	stdoutLine(eia) // raw EIA, pipeable
}

func orgByID(ctx sts.ContextResolution, id string) *sts.OrgContext {
	for i := range ctx.Orgs {
		if ctx.Orgs[i].OrgID == id {
			return &ctx.Orgs[i]
		}
	}
	return nil
}

func orgByIDIn(orgs []sts.OrgContext, id string) bool {
	for _, o := range orgs {
		if o.OrgID == id {
			return true
		}
	}
	return false
}

func productNames(products map[string]sts.Product) string {
	if len(products) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(products))
	for k := range products {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
