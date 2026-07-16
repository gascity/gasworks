package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/gateway"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

// execInfoEnvVar is the environment variable bd injects to name the destination it is about to
// dial; ABSENCE marks a direct human invocation (see internal/gateway).
const execInfoEnvVar = "BEADS_EXEC_INFO"

// projectIDPattern validates the --project shape (prj_ + 16 hex). It is recorded/validated now;
// scope-pinning against it is a later slice.
var projectIDPattern = regexp.MustCompile(`^prj_[0-9a-f]{16}$`)

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
	gatewayFlag := fs.String("gateway", "", "the hosted gateway host this credential will dial (bd supplies it via BEADS_EXEC_INFO)")
	projectFlag := fs.String("project", "", "the hosted beads project id (prj_...) this credential targets")

	// argparse interleaves flags and the positional <product>; stdlib flag stops at the first
	// bareword. Hoist the product out so `getToken manifold --json` and `getToken --json
	// manifold` both work.
	product, rest := hoistPositional(argv)
	if err := fs.Parse(rest); err != nil {
		return die("%s", err)
	}
	if product == "" {
		return die("usage: gasworks getToken <product> [--org ...] [--scope ...] [--gateway <host>] [--project <prj_...>] [--json] [--refresh]")
	}
	if *projectFlag != "" && !projectIDPattern.MatchString(*projectFlag) {
		return die("invalid --project %q — want a hosted project id like prj_0123456789abcdef", *projectFlag)
	}

	// Destination gate (S2-DESIGN §5.0/§5.2). Resolve the mint destination — bd's exec-info
	// host is authoritative, --gateway is the manual fallback — and gate it against the
	// trusted-gateway allowlist BEFORE any mint or cache read, so a warm cached token can
	// never be served to an untrusted destination.
	warn := func(s string) { eprintf("gasworks: %s", s) }
	dest, err := gateway.Resolve(*gatewayFlag, os.Getenv(execInfoEnvVar), warn)
	if err != nil {
		return die("%s", err)
	}
	mode, known := gateway.ModeFromEnv(os.Getenv(gateway.EnforceEnvVar))
	if !known {
		warn(gateway.EnforceEnvVar + " is not a recognized value; using the compiled default")
	}
	if err := gateway.Gate(dest, mode, warn); err != nil {
		return die("%s", err)
	}

	idToken, err := ensureIDToken(cfg)
	if err != nil {
		return err
	}

	ctx, err := sts.Context(cfg, idToken, true, contextTimeout)
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

	// The gateway dimension is a SECURITY key component: a token minted for destination A must
	// never be served for destination B. The human path (no destination) keys on empty.
	cacheKey := org + "|" + product + "|" + scope + "|" + dest.Host
	cached, hadCache := data.EIACache[cacheKey]
	if !*refresh {
		if hadCache && cached.ExpiresAt-now() > eiaReadSkew() {
			emit(cached.EIA, scope, int(cached.ExpiresAt-now()), *asJSON)
			return nil
		}
	}

	sessionToken, key, err := ensureSession(cfg, data, org, idToken)
	if err != nil {
		return err
	}

	res, err := resilientExchange(cfg, sessionToken, product, scope, key)
	if err != nil {
		var he *httpc.HTTPError
		switch {
		case errors.As(err, &he) && he.Status == 401:
			// Session not resolvable — re-establish ONCE (fresh key) and retry the ladder.
			sessionToken, key, err = newSession(cfg, org, idToken)
			if err != nil {
				return err
			}
			res, err = resilientExchange(cfg, sessionToken, product, scope, key)
			if err != nil {
				return serveLastGoodOrDie(err, cached, hadCache, scope, *asJSON)
			}
		case errors.As(err, &he) && he.Status == 403:
			return die("getToken denied: %s (%s)", he.OAuthError(), he)
		default:
			return serveLastGoodOrDie(err, cached, hadCache, scope, *asJSON)
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
	emit(eia, grantedScope, res.ExpiresIn, *asJSON)
	return nil
}

// serveLastGoodOrDie salvages a mint failure by emitting a still-valid cached EIA (above the
// true-validity floor) with a stderr warning, instead of dying — so a transient STS outage
// does not break a caller that already holds a usable token. Below the floor it dies.
func serveLastGoodOrDie(err error, cached store.EIACacheEntry, hadCache bool, scope string, asJSON bool) error {
	if hadCache {
		if remain := cached.ExpiresAt - now(); remain > serveLastGoodFloorSecs {
			eprintf("gasworks: mint failed (%s); serving the still-valid cached credential (%ds left)", err, remain)
			emit(cached.EIA, scope, int(remain), asJSON)
			return nil
		}
	}
	return die("getToken failed: %s", err)
}

// ensureIDToken returns a valid id_token, refreshing (and persisting the rotated refresh
// token) if needed. (M10) The refresh rotation is persisted BEFORE any later mint step, so a
// crash mid-getToken cannot lose the new refresh token.
//
// (§5.5) The refresh is serialized across PROCESSES with the double-checked pattern. Keycloak
// rotates the refresh token on every use; if N racing getToken processes each present the same
// stored token, the 2nd..Nth are reuse-detected and Keycloak can revoke the whole offline
// session family — stranding the durable session and forcing an interactive re-login fleet-wide.
// So: a fast unlocked freshness check (no lock, no refresh when the id_token is still fresh),
// then under the store lock a RE-load + RE-check (a peer may have refreshed while we blocked)
// and a refresh only if still stale, with the round-trip bounded so the lock is never held for
// long. The first waiter refreshes once; the rest re-read the fresh token and skip.
func ensureIDToken(cfg config.Config) (string, error) {
	// Fast path: an unlocked read — a still-fresh id_token needs neither lock nor refresh.
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

	var idToken string
	lockErr := store.WithLock(func() error {
		// RE-load + RE-check under the lock: a peer may have refreshed while we blocked.
		d, err := store.Load()
		if err != nil {
			return die("could not read credentials: %s", err)
		}
		if d.IDToken != "" && tokenExp(d.IDToken)-now() > idTokenSkewSecs {
			idToken = d.IDToken
			return nil
		}
		if d.RefreshToken == "" {
			return die("not logged in — run `gasworks login`")
		}
		tok, err := oidc.Refresh(cfg, d.RefreshToken, refreshTimeout)
		if err != nil {
			var he *httpc.HTTPError
			detail := err.Error()
			if errors.As(err, &he) {
				if oe := he.OAuthError(); oe != "" {
					detail = oe
				}
			}
			return die("session expired (%s) — run `gasworks login` again", detail)
		}
		if tok.RefreshToken != "" {
			d.RefreshToken = tok.RefreshToken // Keycloak rotates — persist it
		}
		if tok.IDToken != "" {
			d.IDToken = tok.IDToken
		}
		idToken = d.IDToken
		if err := store.Save(d); err != nil {
			return die("could not persist refreshed token: %s", err)
		}
		return nil
	})
	if lockErr != nil {
		if ce, ok := lockErr.(*cmdError); ok {
			return "", ce
		}
		return "", die("could not refresh session: %s", lockErr)
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
		return "", die("no orgs for this account — run `gasworks whoami` to check, or ask an admin to add you to an org")
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
	sess, err := sts.Login(cfg, idToken, org, key, loginTimeout)
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
	valueFlags := map[string]bool{
		"-org": true, "--org": true,
		"-scope": true, "--scope": true,
		"-gateway": true, "--gateway": true,
		"-project": true, "--project": true,
	}
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

// emit writes the EIA to stdout — raw (pipeable) or, with --json, an envelope carrying the
// REAL expires_in (a thin bd trusts this for its own cache TTL, so a hardcoded value would be
// a lie). For a cache hit / serve-last-good, expiresIn is the cached token's true remaining
// seconds; for a fresh mint it is res.ExpiresIn.
func emit(eia, scope string, expiresIn int, asJSON bool) {
	if asJSON {
		if expiresIn < 0 {
			expiresIn = 0
		}
		env := struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}{eia, "DPoP", expiresIn, scope}
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
