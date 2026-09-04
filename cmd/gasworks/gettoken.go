package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

// The three lifecycle freshness thresholds. (M11) They are DISTINCT — do not collapse them.
const (
	idTokenSkewSecs            = 60 // refresh the id_token when it has <60s left
	sessionSkewSecs            = 30 // re-establish the STS session when it has <30s left
	eiaSkewSecs                = 15 // re-mint the EIA when the cached one has <15s left
	eiaCacheKeyVersion         = "gasworks.dev/eia-cache/v4"
	humanCredentialKind        = "human"
	sessionKeyVersion          = "gasworks.dev/sts-session/v3"
	credentialGenerationPrefix = "g1:"
	credentialGenerationBytes  = 16
)

var errCredentialGenerationChanged = errors.New("credential generation changed while minting")

type humanCredentialSnapshot struct {
	IDToken    string
	Generation string
}

type mintResult struct {
	AccessToken string
	Audience    string
	Scopes      []string
	ExpiresAt   int64
}

func cmdGetToken(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("getToken", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	orgFlag := fs.String("org", "", "org id or slug (defaults to your default/sole org)")
	scopeFlag := fs.String("scope", "", "override the discovered scopes (space-separated)")
	asJSON := fs.Bool("json", false, "emit a JSON envelope instead of the raw EIA")
	refresh := fs.Bool("refresh", false, "bypass the local EIA cache")
	allowFileKeystore := fs.Bool("allow-file-keystore", false, "permit storing the DPoP key in a 0600 file when no platform keystore is available")

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

	cfg.AllowFileKeystore = cfg.AllowFileKeystore || *allowFileKeystore

	scope := *scopeFlag
	result, err := mintEIA(cfg, product, "", *orgFlag, scope, *refresh, false)
	if err != nil {
		return err
	}
	emit(result, *asJSON)
	return nil
}

func mintEIA(
	cfg config.Config,
	product string,
	audience string,
	requestedOrg string,
	scope string,
	forceRefresh bool,
	requireAllowedScopes bool,
) (mintResult, error) {
	if forceRefresh {
		if err := store.Update(func(data *store.Data) error {
			data.EIACache = nil
			return nil
		}); err != nil {
			return mintResult{}, die("could not invalidate cached EIAs: %s", err)
		}
	}

	credential, err := ensureHumanCredential(cfg, nil)
	if err != nil {
		return mintResult{}, err
	}
	idToken := credential.IDToken
	generation := credential.Generation

	ctx, err := sts.Context(cfg, idToken, true)
	if err != nil {
		return mintResult{}, die("discovery failed: %s", err)
	}

	data, err := store.Load()
	if err != nil {
		return mintResult{}, die("could not read credentials: %s", err)
	}
	if data.CredentialGeneration != generation {
		return mintResult{}, credentialChangedError()
	}

	org, err := pickOrg(ctx, requestedOrg, data)
	if err != nil {
		return mintResult{}, err
	}
	orgCtx := orgByID(ctx, org)
	if orgCtx == nil {
		return mintResult{}, dieCredential(credentialErrorDenied, "you are not a member of org %s", org)
	}

	var prod sts.Product
	var ok bool
	if product == "" {
		product, prod, ok = productByAudience(orgCtx.Products, audience)
	} else {
		prod, ok = orgCtx.Products[product]
	}
	if !ok || len(prod.Scopes) == 0 {
		requestedProduct := product
		if requestedProduct == "" {
			requestedProduct = audience
		}
		return mintResult{}, dieCredential(credentialErrorDenied, "no mintable '%s' scope for org %s (entitled products: %s)",
			requestedProduct, orgCtx.Slug, productNames(orgCtx.Products))
	}
	canonicalAudience := prod.Audience
	if canonicalAudience == "" {
		canonicalAudience = product
	}
	if audience != "" && canonicalAudience != audience {
		return mintResult{}, dieCredential(credentialErrorDenied, "no mintable '%s' scope for org %s (entitled products: %s)",
			audience, orgCtx.Slug, productNames(orgCtx.Products))
	}

	if scope == "" {
		scope = strings.Join(prod.Scopes, " ")
	}
	requestedScopes := strings.Fields(scope)
	if requireAllowedScopes {
		sort.Strings(requestedScopes)
	}
	if hasDuplicateScopes(requestedScopes) {
		return mintResult{}, dieCredential(credentialErrorInvalid, "requested scopes contain duplicates")
	}
	if requireAllowedScopes && !scopeSubset(requestedScopes, prod.Scopes) {
		return mintResult{}, dieCredential(credentialErrorDenied, "requested scopes are not mintable for '%s' in org %s", canonicalAudience, orgCtx.Slug)
	}

	cacheOrigin := cfg.STSBase
	if ctx.Origin != "" {
		cacheOrigin = ctx.Origin
	}
	cacheKey := eiaCacheKey(cacheOrigin, org, canonicalAudience, generation, requestedScopes)
	if !forceRefresh {
		if cached, ok := data.EIACache[cacheKey]; ok &&
			validOpaqueToken(cached.EIA) && credentialFreshAt(cached.ExpiresAt, now(), eiaSkewSecs) {
			return mintResult{
				AccessToken: cached.EIA,
				Audience:    canonicalAudience,
				Scopes:      requestedScopes,
				ExpiresAt:   cached.ExpiresAt,
			}, nil
		}
	}

	// Pin all state-changing session operations to the origin that served discovery. The STS
	// client may fall back between origins for the read-only context request, but login and token
	// exchange must never replay an uncertain POST at a second host.
	stsCfg := cfg.WithSTSBase(cacheOrigin)
	sessionToken, key, sessionOrigin, err := ensureSession(stsCfg, data, org, idToken, generation, cacheOrigin)
	if err != nil {
		return mintResult{}, err
	}

	exchangeStartedAt := now()
	res, err := sts.Exchange(cfg.WithSTSBase(sessionOrigin), sessionToken, canonicalAudience, strings.Join(requestedScopes, " "), key)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 401 {
			// A 401 is a definitive authentication rejection, not an uncertain transport
			// outcome. Re-establish once with a fresh key and retry the exchange on the SAME
			// pinned origin — stsCfg is already narrowed to it, and Login/Exchange never
			// replay an uncertain response at another host.
			var established establishedSession
			established, err = newSession(stsCfg, org, idToken, generation)
			if err != nil {
				return mintResult{}, err
			}
			sessionToken, key, sessionOrigin = established.Token, established.Key, established.Origin
			exchangeStartedAt = now()
			res, err = sts.Exchange(cfg.WithSTSBase(sessionOrigin), sessionToken, canonicalAudience, strings.Join(requestedScopes, " "), key)
		}
	}
	if err != nil {
		return mintResult{}, classifyExchangeError(err)
	}
	if res.Origin != "" && res.Origin != cacheOrigin {
		cacheKey = eiaCacheKey(res.Origin, org, canonicalAudience, generation, requestedScopes)
	}
	if !validOpaqueToken(res.AccessToken) {
		return mintResult{}, die("getToken returned an invalid credential")
	}

	grantedScopes := strings.Fields(res.Scope)
	if len(grantedScopes) == 0 {
		grantedScopes = requestedScopes
	}
	if !sameScopeSet(grantedScopes, requestedScopes) {
		return mintResult{}, dieCredential(credentialErrorDenied, "getToken returned unexpected scopes")
	}
	expiresAt, ok := credentialExpiry(exchangeStartedAt, res.ExpiresIn)
	if !ok || !credentialFreshAt(expiresAt, now(), 0) {
		return mintResult{}, die("getToken returned an invalid credential expiry")
	}
	pruneAt := now()
	if err := store.Update(func(d *store.Data) error {
		if d.CredentialGeneration != generation {
			return errCredentialGenerationChanged
		}
		if d.EIACache == nil {
			d.EIACache = map[string]store.EIACacheEntry{}
		}
		pruneEIACache(d.EIACache, pruneAt)
		d.EIACache[cacheKey] = store.EIACacheEntry{EIA: res.AccessToken, ExpiresAt: expiresAt}
		return nil
	}); err != nil {
		if errors.Is(err, errCredentialGenerationChanged) {
			return mintResult{}, credentialChangedError()
		}
		return mintResult{}, die("could not cache EIA: %s", err)
	}

	return mintResult{
		AccessToken: res.AccessToken,
		Audience:    canonicalAudience,
		Scopes:      grantedScopes,
		ExpiresAt:   expiresAt,
	}, nil
}

func classifyExchangeError(err error) *cmdError {
	var httpErr *httpc.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden {
		return dieCredential(credentialErrorDenied, "getToken denied: %s (%s)", httpErr.OAuthError(), httpErr)
	}
	return dieCredential(credentialErrorUnavailable, "getToken is temporarily unavailable")
}

func credentialExpiry(startedAt int64, expiresIn int) (int64, bool) {
	if expiresIn <= 0 {
		return 0, false
	}
	lifetime := int64(expiresIn)
	if startedAt > math.MaxInt64-lifetime {
		return 0, false
	}
	expiresAt := startedAt + lifetime
	if expiresAt <= startedAt || !credentialExpiryIsRFC3339(expiresAt) {
		return 0, false
	}
	return expiresAt, true
}

func credentialFreshAt(expiresAt, instant, minimumRemaining int64) bool {
	if minimumRemaining < 0 || !credentialExpiryIsRFC3339(expiresAt) ||
		instant > math.MaxInt64-minimumRemaining {
		return false
	}
	return expiresAt > instant+minimumRemaining
}

func credentialExpiryIsRFC3339(expiresAt int64) bool {
	formatted := time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)
	parsed, err := time.Parse(time.RFC3339, formatted)
	return err == nil && parsed.Unix() == expiresAt
}

func pruneEIACache(cache map[string]store.EIACacheEntry, instant int64) {
	for key, entry := range cache {
		if !strings.HasPrefix(key, eiaCacheKeyVersion+":") ||
			!validOpaqueToken(entry.EIA) || !credentialFreshAt(entry.ExpiresAt, instant, 0) {
			delete(cache, key)
		}
	}
}

// ensureIDToken returns a valid id_token, refreshing (and persisting the rotated refresh
// token) if needed. (M10) The refresh rotation is persisted in its OWN locked write BEFORE any
// later mint step, so a crash mid-getToken cannot lose the new refresh token.
func ensureIDToken(cfg config.Config) (string, error) {
	credential, err := ensureHumanCredential(cfg, nil)
	return credential.IDToken, err
}

func ensureIDTokenBeforeRefreshTransaction(cfg config.Config, beforeTransaction func()) (string, error) {
	credential, err := ensureHumanCredential(cfg, beforeTransaction)
	return credential.IDToken, err
}

func ensureHumanCredential(cfg config.Config, beforeTransaction func()) (humanCredentialSnapshot, error) {
	if beforeTransaction != nil {
		beforeTransaction()
	}
	data, err := store.Load()
	if err != nil {
		return humanCredentialSnapshot{}, die("could not read credentials: %s", err)
	}
	if data.IDToken != "" && tokenExp(data.IDToken)-now() > idTokenSkewSecs &&
		validCredentialGeneration(data.CredentialGeneration) {
		return humanCredentialSnapshot{IDToken: data.IDToken, Generation: data.CredentialGeneration}, nil
	}

	var credential humanCredentialSnapshot
	var orphanedKeys []store.KeyRef
	err = store.Update(func(d *store.Data) error {
		// Re-check under the cross-process store lock. Another process may have refreshed and
		// persisted a rotated refresh token after the optimistic read above.
		if d.IDToken != "" && tokenExp(d.IDToken)-now() > idTokenSkewSecs {
			generation, orphaned, generationErr := ensureCredentialGeneration(d)
			if generationErr != nil {
				return generationErr
			}
			orphanedKeys = orphaned
			credential = humanCredentialSnapshot{IDToken: d.IDToken, Generation: generation}
			return nil
		}
		if d.RefreshToken == "" {
			return dieCredential(credentialErrorInteraction, "not logged in — run `gasworks login`")
		}
		generation, orphaned, generationErr := ensureCredentialGeneration(d)
		if generationErr != nil {
			return generationErr
		}
		orphanedKeys = orphaned

		tok, refreshErr := oidc.Refresh(cfg, d.RefreshToken)
		if refreshErr != nil {
			return classifyRefreshError(refreshErr)
		}
		if tok.IDToken == "" {
			return dieCredential(credentialErrorUnavailable, "identity provider returned no ID token")
		}
		if tok.RefreshToken != "" {
			d.RefreshToken = tok.RefreshToken // Keycloak rotates — persist it
		}
		d.IDToken = tok.IDToken
		credential = humanCredentialSnapshot{IDToken: d.IDToken, Generation: generation}
		return nil
	})
	if err != nil {
		var commandErr *cmdError
		if errors.As(err, &commandErr) {
			return humanCredentialSnapshot{}, commandErr
		}
		return humanCredentialSnapshot{}, die("could not persist refreshed token: %s", err)
	}
	// The write landed, so the sessions those keys belonged to are gone from disk.
	forgetSessionKeys(orphanedKeys)
	return credential, nil
}

func newCredentialGeneration() (string, error) {
	random := make([]byte, credentialGenerationBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return credentialGenerationPrefix + hex.EncodeToString(random), nil
}

func validCredentialGeneration(generation string) bool {
	if len(generation) != len(credentialGenerationPrefix)+(credentialGenerationBytes*2) ||
		!strings.HasPrefix(generation, credentialGenerationPrefix) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(generation, credentialGenerationPrefix))
	return err == nil
}

// ensureCredentialGeneration stamps a generation on a document that has none. That fences
// out every session written before it, so it also returns the DPoP keys those sessions held:
// the caller deletes them once the write has landed, rather than leaving a private key on
// the host for a session nothing can reach any more.
func ensureCredentialGeneration(data *store.Data) (string, []store.KeyRef, error) {
	if validCredentialGeneration(data.CredentialGeneration) {
		return data.CredentialGeneration, nil, nil
	}
	generation, err := newCredentialGeneration()
	if err != nil {
		return "", nil, err
	}
	data.CredentialGeneration = generation
	return generation, dropSessions(data), nil
}

// dropSessions clears every stored session and the EIA cache minted from them, returning the
// key references that are now unreachable.
func dropSessions(data *store.Data) []store.KeyRef {
	orphaned := make([]store.KeyRef, 0, len(data.Sessions))
	for _, session := range data.Sessions {
		if session.Key.Enrolled() {
			orphaned = append(orphaned, session.Key)
		}
	}
	data.Sessions = nil
	data.EIACache = nil
	return orphaned
}

func credentialChangedError() *cmdError {
	return dieCredential(credentialErrorUnavailable, "login changed while minting a credential; retry the command")
}

func classifyRefreshError(err error) *cmdError {
	var httpErr *httpc.HTTPError
	if errors.As(err, &httpErr) && httpErr.OAuthError() == "invalid_grant" {
		return dieCredential(credentialErrorInteraction, "session expired (invalid_grant) — run `gasworks login` again")
	}
	return dieCredential(credentialErrorUnavailable, "identity provider refresh is temporarily unavailable")
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
		return "", dieCredential(credentialErrorDenied, "you are not a member of org '%s'. Your orgs: %s", requested, orgList(orgs))
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
		return "", dieCredential(credentialErrorDenied, "no orgs for this account — run `gasworks whoami` to check, or ask an admin to add you to an org")
	}
	return "", dieCredential(credentialErrorInvalid, "you belong to multiple orgs — pass --org. Your orgs: %s", orgList(orgs))
}

// establishedSession is one session establishment's result: the token to present, the key it
// is JKT-bound to, the origin it is pinned to, and when it expires. The expiry is carried out
// rather than left on disk because a caller that holds one session across several requests
// (the mint ceremony does) has to know how long it may keep holding it.
type establishedSession struct {
	Token     string
	Key       *dpop.Key
	Origin    string
	ExpiresAt int64
}

// newSession generates a FRESH DPoP key, establishes a new STS session, and persists the
// session (locked) with a reference to the credential store the key went into. A fresh key
// per new session matches the server's per-session jkt-pin.
//
// The credential store is selected BEFORE the STS round-trip: a host with no approved store
// must fail closed on the enrolment error rather than mint a session whose key it cannot
// keep.
func newSession(cfg config.Config, org, idToken, generation string) (establishedSession, error) {
	backend, err := enrollmentKeystore(cfg)
	if err != nil {
		return establishedSession{}, err
	}
	key, err := dpop.NewKey()
	if err != nil {
		return establishedSession{}, die("could not generate a session key: %s", err)
	}
	sess, err := sts.Login(cfg, idToken, org, key)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 403 {
			return establishedSession{}, dieCredential(credentialErrorDenied, "not a member of org %s (%s)", org, he.OAuthError())
		}
		return establishedSession{}, die("login to org %s failed: %s", org, err)
	}
	origin := sess.Origin
	if origin == "" {
		origin = cfg.STSBase
	}
	expiresAt := now() + int64(sess.ExpiresIn)
	cacheKey := sessionCacheKey(origin, org, generation)
	var ref store.KeyRef
	if err := store.Update(func(d *store.Data) error {
		if d.CredentialGeneration != generation {
			return errCredentialGenerationChanged
		}
		if d.Sessions == nil {
			d.Sessions = map[string]store.Session{}
		}
		// Enrol INSIDE the locked read-modify-write. The handle is derived from the cache
		// key, so two concurrent first-time getToken runs would otherwise race on the same
		// handle and one could persist a session bound to the other's key. Replacing this
		// entry is also what erases a pre-split-storage inline key: the entries this CLI
		// did not write (bd-enterprise shares this document) are left alone.
		enrolled, err := enrollSessionKey(backend, sessionKeyHandle(cacheKey), key)
		if err != nil {
			return err
		}
		ref = enrolled
		d.Sessions[cacheKey] = store.Session{
			SessionToken: sess.SessionToken,
			Key:          ref,
			ExpiresAt:    expiresAt,
		}
		return nil
	}); err != nil {
		// The session was not persisted, so nothing references the key we just enrolled.
		forgetSessionKey(ref)
		if errors.Is(err, errCredentialGenerationChanged) {
			return establishedSession{}, credentialChangedError()
		}
		var commandErr *cmdError
		if errors.As(err, &commandErr) {
			return establishedSession{}, commandErr
		}
		return establishedSession{}, die("could not save the session: %s", err)
	}
	return establishedSession{Token: sess.SessionToken, Key: key, Origin: origin, ExpiresAt: expiresAt}, nil
}

// ensureSession reuses the stored per-org session at the selected origin when it has >30s left
// (loading its DPoP key from the credential store it was enrolled in), otherwise establishes
// a fresh one at that same origin. A
// session cached for another origin is deliberately not a fallback: the origin is part of the
// session's security binding and switching hosts could replay a state-changing request.
func ensureSession(cfg config.Config, data *store.Data, org, idToken, generation, preferredOrigin string) (string, *dpop.Key, string, error) {
	origin := preferredOrigin
	if origin == "" {
		endpoints := cfg.STSEndpoints()
		if len(endpoints) > 0 {
			origin = endpoints[0]
		}
	}
	if origin != "" {
		if sess, ok := data.Sessions[sessionCacheKey(origin, org, generation)]; ok && sess.ExpiresAt-now() > sessionSkewSecs {
			key, err := loadSessionKey(sess.Key)
			if err == nil {
				return sess.SessionToken, key, origin, nil
			}
			// A missing, unreadable, or pre-split-storage key falls through to a fresh
			// session rather than crashing.
		}
	}
	established, err := newSession(cfg.WithSTSBase(origin), org, idToken, generation)
	return established.Token, established.Key, established.Origin, err
}

// sessionIdentity is what a session cache key encodes. `gasworks inspect` decodes the key
// back through this type, so the writer and the reader cannot drift.
type sessionIdentity struct {
	CredentialKind string `json:"credential_kind"`
	Generation     string `json:"generation"`
	STSAuthority   string `json:"sts_authority"`
	Org            string `json:"org"`
}

func sessionCacheKey(stsAuthority, org, generation string) string {
	payload, _ := json.Marshal(sessionIdentity{
		CredentialKind: humanCredentialKind,
		Generation:     generation,
		STSAuthority:   strings.TrimRight(stsAuthority, "/"),
		Org:            org,
	})
	return sessionKeyVersion + ":" + string(payload)
}

// parseSessionCacheKey reverses sessionCacheKey. An unrecognized key yields ok=false.
func parseSessionCacheKey(key string) (sessionIdentity, bool) {
	raw, ok := strings.CutPrefix(key, sessionKeyVersion+":")
	if !ok {
		return sessionIdentity{}, false
	}
	var id sessionIdentity
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		return sessionIdentity{}, false
	}
	return id, true
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

func emit(result mintResult, asJSON bool) {
	if asJSON {
		remaining := result.ExpiresAt - now()
		if remaining < 0 {
			remaining = 0
		}
		env := struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			ExpiresAt   string `json:"expires_at"`
			Audience    string `json:"audience"`
			Scope       string `json:"scope"`
		}{
			AccessToken: result.AccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(remaining),
			ExpiresAt:   time.Unix(result.ExpiresAt, 0).UTC().Format(time.RFC3339),
			Audience:    result.Audience,
			Scope:       strings.Join(result.Scopes, " "),
		}
		b, _ := json.Marshal(env)
		stdoutLine(string(b))
		return
	}
	stdoutLine(result.AccessToken) // raw EIA, pipeable
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

func productByAudience(products map[string]sts.Product, audience string) (string, sts.Product, bool) {
	var productName string
	var product sts.Product
	for name, candidate := range products {
		candidateAudience := candidate.Audience
		if candidateAudience == "" {
			candidateAudience = name
		}
		if candidateAudience != audience {
			continue
		}
		if productName != "" {
			return "", sts.Product{}, false
		}
		productName = name
		product = candidate
	}
	return productName, product, productName != ""
}

func scopeSubset(requested, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}
	return len(requested) > 0
}

func sameScopeSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	return scopeSubset(left, right) && scopeSubset(right, left)
}

func hasDuplicateScopes(scopes []string) bool {
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, duplicate := seen[scope]; duplicate {
			return true
		}
		seen[scope] = struct{}{}
	}
	return false
}

func validOpaqueToken(token string) bool {
	return token != "" && token == strings.TrimSpace(token) && !strings.ContainsAny(token, " \t\r\n")
}

// eiaIdentity is what an EIA cache key encodes; `gasworks inspect` decodes it back.
type eiaIdentity struct {
	CredentialKind string   `json:"credential_kind"`
	Generation     string   `json:"generation"`
	STSAuthority   string   `json:"sts_authority"`
	Org            string   `json:"org"`
	Audience       string   `json:"audience"`
	Scopes         []string `json:"scopes"`
}

func eiaCacheKey(stsAuthority, org, audience, generation string, scopes []string) string {
	canonicalScopes := append([]string(nil), scopes...)
	sort.Strings(canonicalScopes)
	payload, _ := json.Marshal(eiaIdentity{
		CredentialKind: humanCredentialKind,
		Generation:     generation,
		STSAuthority:   strings.TrimRight(stsAuthority, "/"),
		Org:            org,
		Audience:       audience,
		Scopes:         canonicalScopes,
	})
	return eiaCacheKeyVersion + ":" + string(payload)
}

// parseEIACacheKey reverses eiaCacheKey. An unrecognized key yields ok=false.
func parseEIACacheKey(key string) (eiaIdentity, bool) {
	raw, ok := strings.CutPrefix(key, eiaCacheKeyVersion+":")
	if !ok {
		return eiaIdentity{}, false
	}
	var id eiaIdentity
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		return eiaIdentity{}, false
	}
	return id, true
}
