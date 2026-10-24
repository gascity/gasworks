package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/edgedevice"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/jwtutil"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

// The edge-device login is the OPT-IN `gasworks login --edge-device` (V1-L-01 option (b),
// stage B2). It never becomes the default here: the headless default stays the Keycloak device
// grant, and `--device` keeps meaning that grant.
//
// It replaces the Keycloak id_token + refresh token with ONE cli-edge root session, bound at
// redeem time to a DPoP key this CLI generated for the flow and enrolled in the same approved
// credential store the STS session keys use. The STS takes that root directly as the
// DPoP-bound session for /sts/v0/context and /sts/v0/token, so there is no /sts/v0/login, no
// per-org session and nothing to refresh: when the root ends, the user signs in again.
//
// The root is pinned to the org that was active in the browser that approved it. Every mint
// re-reads that org from the STS and refuses a different --org (or default org) with the
// re-login instructions, rather than minting for an org the caller did not ask for.

const (
	// edgeCredentialKind labels the EIA cache entries minted from an edge-device root.
	edgeCredentialKind = "edge-device"
	// edgeSessionKeyPrefix seeds the credential-store handle of an edge-device root's key.
	// The handle includes the login's generation, so a new login's key never overwrites the
	// key of the root it is replacing before the replacement has committed.
	edgeSessionKeyPrefix = "gasworks.dev/edge-session-key/v1:"
)

// edgeClient drives the cli-edge device plane. A var so the end-to-end tests can point the
// flow at a stub cli-edge with its own CA and a clock that does not sleep.
var edgeClient = edgedevice.New()

// activeEdgeSession reports the edge-device session in force: the one whose generation is the
// generation credentials.json carries. Any login or logout — by this CLI or by bd, which shares
// credentials.json but not edge-session.json — rewrites that generation and so fences a
// superseded root out without having to touch its file.
func activeEdgeSession(snapshot store.Snapshot) (store.EdgeSession, bool) {
	edge, data := snapshot.Edge, snapshot.Data
	if edge == nil || data == nil || !validCredentialGeneration(edge.CredentialGeneration) ||
		edge.CredentialGeneration != data.CredentialGeneration ||
		!validOpaqueToken(edge.RootToken) || !edge.Key.Enrolled() {
		return store.EdgeSession{}, false
	}
	return *edge, true
}

// loadActiveEdgeSession is activeEdgeSession over a fresh snapshot.
func loadActiveEdgeSession() (store.EdgeSession, bool, error) {
	snapshot, err := store.LoadSnapshot()
	if err != nil {
		return store.EdgeSession{}, false, die("could not read credentials: %s", err)
	}
	edge, ok := activeEdgeSession(snapshot)
	return edge, ok, nil
}

// cmdLoginEdgeDevice runs the cli-edge device flow and, only once the STS has accepted the
// root, replaces the current login with it.
//
// The order is the point. Everything that can be judged locally — the edge origin, and whether
// this host has a credential store for the key — is judged before a device code exists: an
// approval costs the human a fresh sign-in. And nothing local changes until the STS has
// answered for the root: a server that has not enabled the exchange yet must not cost the user
// the login they already have.
func cmdLoginEdgeDevice(cfg config.Config, requestedOrg string) error {
	edgeOrigin, err := cfg.CLIEdgeOrigin()
	if err != nil {
		return die("%s", err)
	}
	backend, err := enrollmentKeystore(cfg)
	if err != nil {
		return err
	}
	key, err := dpop.NewKey()
	if err != nil {
		return die("could not generate the device key: %s", err)
	}
	// Said before the code exists, so a bd user can stop here at no cost: the commit below
	// clears the Keycloak tokens bd reads.
	if prior, err := store.Load(); err == nil && hasKeycloakLogin(prior) {
		eprintf("note: this login replaces your current `gasworks login`, which signs bd (bd-enterprise) out: bd " +
			"does not read edge-device sessions yet. Press Ctrl-C now and keep using `gasworks login` if you use bd.")
	}

	authorization, err := edgeClient.Issue(cfg, edgeDeviceLabel())
	if err != nil {
		return edgeDeviceFlowError(edgeOrigin, err)
	}
	printEdgeDevicePrompt(authorization)
	root, err := edgeClient.Await(cfg, authorization, key)
	if err != nil {
		return edgeDeviceFlowError(edgeOrigin, err)
	}
	// From here on the root exists at the cli-edge and is bound to a key nothing but this
	// process holds. Every failure below revokes it before returning.
	abandon := func(cause error) error {
		revokeEdgeRoot(edgeOrigin, root.Token, key)
		return cause
	}

	ctx, err := confirmEdgeRoot(cfg, root.Token, key)
	if err != nil {
		return abandon(edgeLoginRefused(err))
	}
	org, err := edgeSessionOrg(ctx)
	if err != nil {
		return abandon(err)
	}
	if requestedOrg != "" && !orgNamed(org, requestedOrg) {
		return abandon(dieRelayed("the browser approved this device in org %s, not %s: switch to %s in the "+
			"browser, then run `gasworks login --edge-device --org %s` again.%s The device session was revoked "+
			"and nothing was changed.", orgLabel(org), requestedOrg, requestedOrg, requestedOrg,
			edgeOrgIDHint(org, requestedOrg)))
	}

	generation, err := newCredentialGeneration()
	if err != nil {
		return abandon(die("could not create a login generation: %s", err))
	}
	ref, err := enrollSessionKey(backend, sessionKeyHandle(edgeSessionKeyPrefix+generation), key)
	if err != nil {
		return abandon(err)
	}
	issuedAt := now()
	record := store.EdgeSession{
		CredentialGeneration: generation,
		RootToken:            root.Token,
		TokenType:            root.TokenType,
		Key:                  ref,
		EdgeOrigin:           edgeOrigin,
		OrgID:                org.OrgID,
		OrgSlug:              org.Slug,
		UserID:               ctx.UserID,
		IssuedAt:             issuedAt,
	}
	if root.ExpiresIn > 0 {
		record.ExpiresAt = issuedAt + int64(root.ExpiresIn/time.Second)
	}
	defaultOrg := ""
	if requestedOrg != "" {
		defaultOrg = org.OrgID
	}

	var replacedRefresh string
	var signedBdOut bool
	var replacedEdge *store.EdgeSession
	var orphanedKeys []store.KeyRef
	if err := store.Transact(func(tx *store.Tx) error {
		d := tx.Data
		replacedRefresh = d.RefreshToken
		signedBdOut = hasKeycloakLogin(d)
		if tx.Edge != nil {
			previous := *tx.Edge
			replacedEdge = &previous
		}
		// The edge-device root replaces the Keycloak login outright: bd (which reads only
		// these fields) is signed out, and every STS session and cached EIA of the previous
		// login goes with it.
		d.IDToken = ""
		d.RefreshToken = ""
		d.CredentialGeneration = generation
		d.DefaultOrg = defaultOrg
		orphanedKeys = dropSessions(d)
		tx.ReplaceEdge(record)
		return nil
	}); err != nil {
		forgetSessionKey(ref)
		return abandon(die("could not save the edge-device session: %s", err))
	}

	// The new login is committed. Clean up what it replaced, best-effort: nothing on disk
	// reaches those credentials any more.
	forgetSessionKeys(orphanedKeys)
	if replacedEdge != nil {
		retireEdgeSession(*replacedEdge)
	}
	if replacedRefresh != "" {
		oidc.Revoke(cfg, replacedRefresh)
	}

	stdoutRelayed("Logged in with an edge-device session for org %s.", orgLabel(org))
	if signedBdOut {
		eprintf("note: bd (bd-enterprise) does not read edge-device sessions yet; this login signed bd out. " +
			"Keep using `gasworks login` if you use bd.")
	}
	return nil
}

// hasKeycloakLogin reports whether d carries the Keycloak tokens bd reads.
func hasKeycloakLogin(d *store.Data) bool {
	return d != nil && (d.RefreshToken != "" || d.IDToken != "")
}

const (
	// edgeConfirmAttempts bounds how often login presents a just-approved root to the STS. A
	// transient answer (5xx, 429, no answer at all) is retried before the root is given up:
	// revoking costs the user a fresh browser approval. A definitive 4xx is never retried.
	edgeConfirmAttempts = 3
	// edgeConfirmRetryWait is the pause between attempts when the STS names none; a
	// Retry-After it does name is honoured up to edgeConfirmMaxRetryWait.
	edgeConfirmRetryWait    = 1 * time.Second
	edgeConfirmMaxRetryWait = 5 * time.Second
)

// edgeRetrySleep paces confirmEdgeRoot's retries. A var so tests do not wait.
var edgeRetrySleep = time.Sleep

// confirmEdgeRoot is the login's /sts/v0/context for the new root, retried on a transient
// failure. Every attempt is a fresh sts.SessionContext — fresh proofs, starting again at the
// canonical STS origin — and discovery is a read, so a retry cannot change server state.
func confirmEdgeRoot(cfg config.Config, root string, key *dpop.Key) (sts.ContextResolution, error) {
	for attempt := 1; ; attempt++ {
		ctx, err := sts.SessionContext(cfg, root, key)
		if err == nil || attempt >= edgeConfirmAttempts || !transientSTSFailure(err) {
			return ctx, err
		}
		edgeRetrySleep(edgeConfirmWait(err))
	}
}

// transientSTSFailure is a failure that says nothing about the root: a 5xx, a 429, or a
// request that got no HTTP answer.
func transientSTSFailure(err error) bool {
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		return he.Status >= 500 || he.Status == http.StatusTooManyRequests
	}
	var ne net.Error
	return errors.As(err, &ne)
}

func edgeConfirmWait(err error) time.Duration {
	var he *httpc.HTTPError
	if errors.As(err, &he) && he.RetryAfter > 0 {
		return min(he.RetryAfter, edgeConfirmMaxRetryWait)
	}
	return edgeConfirmRetryWait
}

// printEdgeDevicePrompt is the device flow's human half, on stderr like the Keycloak device
// login's. The approval page asks the approver to confirm the code it shows matches this one.
func printEdgeDevicePrompt(auth edgedevice.Authorization) {
	eprintln("")
	eprintln("Sign in to Gas City to authorize this device (edge device login):")
	eprintln("")
	if auth.VerificationURIComplete != "" {
		eprintf("  1. Open:  %s", auth.VerificationURIComplete)
		eprintf("  2. Check that the page shows the code:  %s", auth.UserCode)
	} else {
		eprintf("  1. Open:  %s", auth.VerificationURI)
		eprintf("  2. Enter the code:  %s", auth.UserCode)
	}
	eprintln("")
	eprintln("Approving asks you to sign in again first. Approve only if you started this login.")
	eprintln("Waiting for you to authorize... (Ctrl-C to cancel)")
}

// edgeDeviceLabel names this device on the approval page and the account's session list, the
// way `gc login` does (user@host).
func edgeDeviceLabel() string {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	label := ""
	switch {
	case user != "" && host != "":
		label = user + "@" + host + " (gasworks)"
	case host != "":
		label = host + " (gasworks)"
	}
	if label = edgedevice.CleanLabel(label); label == "" {
		label = "gasworks CLI"
	}
	return label
}

// edgeDeviceFlowError turns a device-plane refusal into what to do about it. Nothing local has
// changed at this point.
func edgeDeviceFlowError(edgeOrigin string, err error) error {
	var flowErr *edgedevice.Error
	if !errors.As(err, &flowErr) {
		return die("%s", err)
	}
	switch flowErr.Kind {
	case edgedevice.NotEnabled:
		return die("the cli-edge device login is not available at %s: edge-device login is not enabled on this "+
			"server yet — sign in with `gasworks login`", edgeOrigin)
	case edgedevice.RateLimited:
		return die("too many device login requests from this address — wait a minute and run " +
			"`gasworks login --edge-device` again")
	case edgedevice.Denied:
		return die("the device login was denied in the browser; nothing was changed")
	case edgedevice.Expired:
		return die("the device code expired before it was approved — run `gasworks login --edge-device` again")
	case edgedevice.InvalidProof:
		return die("the cli-edge rejected this device's proof of possession (invalid_dpop_proof): check the "+
			"system clock, and that %s (%s) is the cli-edge's public origin", config.CLIEdgeBaseEnv, edgeOrigin)
	case edgedevice.NotKeyBound:
		return dieRelayed("the cli-edge at %s issued a %q session instead of a DPoP-bound one: this server does "+
			"not support key-bound device login yet. That session was revoked and nothing was saved — sign in "+
			"with `gasworks login`", edgeOrigin, flowErr.TokenType)
	default:
		return dieRelayed("device login failed: %s", err)
	}
}

// edgeLoginRefused explains an STS that would not take a freshly redeemed root. The root is
// revoked by the caller and the previous login is untouched.
func edgeLoginRefused(err error) error {
	const unchanged = " The device session was revoked and nothing was changed."
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		code := he.OAuthError()
		switch {
		case he.Status == http.StatusUnauthorized:
			return dieRelayed("the STS could not resolve the just-approved edge-device session (HTTP %d %s): it "+
				"may have expired or been revoked before it was confirmed — run `gasworks login --edge-device` "+
				"again; if this keeps happening, sign in with `gasworks login`."+unchanged, he.Status, code)
		case he.Status == http.StatusBadRequest && (code == "invalid_request" || code == "invalid_grant"):
			return dieRelayed("the STS does not accept edge-device sessions yet (HTTP %d %s): edge-device login "+
				"is not enabled on this server — sign in with `gasworks login`."+unchanged, he.Status, code)
		case he.Status == http.StatusBadRequest && code == "invalid_dpop_proof":
			return die("the STS rejected this device's proof of possession (invalid_dpop_proof) — check the " +
				"system clock." + unchanged)
		}
	}
	return dieRelayed("could not confirm the edge-device session with the STS: %s."+unchanged, err)
}

// edgeSessionOrg is the one org an edge-device root is pinned to. The STS answers a session's
// discovery with that org alone; anything else is a server this CLI cannot trust to say which
// org it would mint for.
func edgeSessionOrg(ctx sts.ContextResolution) (sts.OrgContext, error) {
	if len(ctx.Orgs) != 1 || ctx.Orgs[0].OrgID == "" {
		return sts.OrgContext{}, dieCredential(credentialErrorUnavailable,
			"the STS described the edge-device session with %d orgs; an edge-device session is pinned to exactly one",
			len(ctx.Orgs))
	}
	org := ctx.Orgs[0]
	if ctx.DefaultOrgID != "" && ctx.DefaultOrgID != org.OrgID {
		return sts.OrgContext{}, dieCredential(credentialErrorUnavailable,
			"the STS described the edge-device session inconsistently (default org differs from the session's org)")
	}
	return org, nil
}

// edgeOrgIDHint is the extra line for an org refusal the STS could not have matched by slug:
// it reported none, so a value that names the root's org by slug fails all the same. The id
// is the one name that matches.
func edgeOrgIDHint(org sts.OrgContext, value string) string {
	if org.Slug != "" || value == org.OrgID {
		return ""
	}
	return " The STS reported no slug for org " + org.OrgID + ", so only its id matches: if " + value +
		" is that org, use --org " + org.OrgID + "."
}

// orgNamed reports whether value names org by id or slug, as --org does everywhere else.
func orgNamed(org sts.OrgContext, value string) bool {
	return value == org.OrgID || (org.Slug != "" && value == org.Slug)
}

func orgLabel(org sts.OrgContext) string {
	if org.Slug == "" {
		return org.OrgID
	}
	return org.Slug + " (" + org.OrgID + ")"
}

// edgeOrgMismatch refuses a mint for an org the root is not pinned to.
func edgeOrgMismatch(org sts.OrgContext, value, source string) *cmdError {
	refusal := dieRelayed("this edge-device session is pinned to org %s — the org that was active in the "+
		"browser that approved it — not %s (%s). Switch to %s in the browser, then run "+
		"`gasworks login --edge-device` again.%s", orgLabel(org), value, source, value, edgeOrgIDHint(org, value))
	refusal.credentialErrCode = credentialErrorInteraction
	return refusal.withCredentialHint("This edge-device session is pinned to a different org. Switch org in the " +
		"browser and run `gasworks login --edge-device` again.")
}

func edgeSessionEnded() *cmdError {
	return dieCredential(credentialErrorInteraction,
		"the edge-device session has expired or was revoked — run `gasworks login --edge-device` again").
		withCredentialHint("The edge-device session has expired or was revoked. Run `gasworks login --edge-device` again.")
}

func edgeSessionNotAccepted(status int, code string) *cmdError {
	return dieCredential(credentialErrorInteraction,
		"the STS refused the edge-device session (HTTP %d %s): edge-device login is not enabled on this server "+
			"yet — sign in with `gasworks login`", status, code).
		withCredentialHint("This server does not accept edge-device sessions yet. Run `gasworks login`.")
}

func edgeProofRejected() *cmdError {
	return dieCredential(credentialErrorInteraction,
		"the STS rejected the edge-device session's DPoP proof (invalid_dpop_proof) — check the system clock; "+
			"if it keeps failing, run `gasworks login --edge-device` again").
		withCredentialHint("The STS rejected the edge-device session's proof. Check the clock, or run " +
			"`gasworks login --edge-device` again.")
}

func edgeKeyUnavailable(err error) *cmdError {
	return dieCredential(credentialErrorInteraction,
		"the edge-device session's DPoP key is unavailable (%s) — run `gasworks login --edge-device` again", err).
		withCredentialHint("The edge-device session's key is unavailable. Run `gasworks login --edge-device` again.")
}

// classifyEdgeDiscoveryError maps a refused /sts/v0/context for the root. An STS that does not
// know a DPoP-presented session answers 400 invalid_request (it found no Bearer subject_token);
// one with the exchange switched off answers invalid_grant; an expired or revoked root is 401.
func classifyEdgeDiscoveryError(err error) *cmdError {
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		code := he.OAuthError()
		switch {
		case he.Status == http.StatusUnauthorized:
			return edgeSessionEnded()
		case he.Status == http.StatusBadRequest && (code == "invalid_request" || code == "invalid_grant"):
			return edgeSessionNotAccepted(he.Status, code)
		case he.Status == http.StatusBadRequest && code == "invalid_dpop_proof":
			return edgeProofRejected()
		case he.Status == http.StatusForbidden:
			return dieCredentialRelayed(credentialErrorDenied, "discovery denied: %s", code)
		}
	}
	return dieCredentialRelayed(credentialErrorUnavailable, "discovery failed: %s", err)
}

// classifyEdgeExchangeError maps a refused /sts/v0/token for the root. There is no session to
// re-establish on a 401 — the root IS the session — so a definitive rejection asks for a new
// login instead of retrying.
func classifyEdgeExchangeError(err error) *cmdError {
	var he *httpc.HTTPError
	if errors.As(err, &he) {
		code := he.OAuthError()
		switch {
		case he.Status == http.StatusUnauthorized:
			return edgeSessionEnded()
		case he.Status == http.StatusBadRequest && code == "invalid_grant":
			return edgeSessionNotAccepted(he.Status, code)
		case he.Status == http.StatusBadRequest && code == "invalid_dpop_proof":
			return edgeProofRejected()
		}
	}
	return classifyExchangeError(err)
}

// mintEIAWithEdge is mintEIA for an edge-device login: discovery and the exchange present the
// root itself, DPoP-bound by its stored key, in place of an id_token and a /sts/v0/login
// session. requestedOrg and the stored default org must name the root's org.
func mintEIAWithEdge(
	cfg config.Config,
	edge store.EdgeSession,
	product string,
	audience string,
	requestedOrg string,
	scope string,
	forceRefresh bool,
	requireAllowedScopes bool,
) (mintResult, error) {
	key, err := loadSessionKey(edge.Key)
	if err != nil {
		return mintResult{}, edgeKeyUnavailable(err)
	}
	ctx, err := sts.SessionContext(cfg, edge.RootToken, key)
	if err != nil {
		return mintResult{}, classifyEdgeDiscoveryError(err)
	}
	org, err := edgeSessionOrg(ctx)
	if err != nil {
		return mintResult{}, err
	}
	data, err := store.Load()
	if err != nil {
		return mintResult{}, die("could not read credentials: %s", err)
	}
	generation := edge.CredentialGeneration
	if data.CredentialGeneration != generation {
		return mintResult{}, credentialChangedError()
	}
	switch {
	case requestedOrg != "" && !orgNamed(org, requestedOrg):
		return mintResult{}, edgeOrgMismatch(org, requestedOrg, "requested with --org")
	case requestedOrg == "" && data.DefaultOrg != "" && !orgNamed(org, data.DefaultOrg):
		return mintResult{}, edgeOrgMismatch(org, data.DefaultOrg, "the stored default org")
	}

	canonicalAudience, requestedScopes, err := resolveMintRequest(&org, product, audience, scope, requireAllowedScopes)
	if err != nil {
		return mintResult{}, err
	}
	origin := cfg.STSBase
	if ctx.Origin != "" {
		origin = ctx.Origin
	}
	cacheKey := eiaCacheKeyFor(edgeCredentialKind, origin, org.OrgID, canonicalAudience, generation, requestedScopes)
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

	// Pinned to the origin that served discovery, like a /sts/v0/login session's exchange:
	// a state-changing request is never replayed at a second host.
	exchangeStartedAt := now()
	res, err := sts.Exchange(cfg.WithSTSBase(origin), edge.RootToken, canonicalAudience, strings.Join(requestedScopes, " "), key)
	if err != nil {
		return mintResult{}, classifyEdgeExchangeError(err)
	}
	if res.Origin != "" && res.Origin != origin {
		cacheKey = eiaCacheKeyFor(edgeCredentialKind, res.Origin, org.OrgID, canonicalAudience, generation, requestedScopes)
	}
	// A consistency check over the UNVERIFIED assertion, not a trust decision (products verify
	// the EIA): an STS that minted for an org other than the one it just said the root is
	// pinned to is answering for a different session, and its credential is not handed out.
	if minted, ok := eiaOrg(res.AccessToken); ok && minted != org.OrgID {
		return mintResult{}, dieCredential(credentialErrorDenied,
			"the STS minted a credential for a different org than the edge-device session's; refusing to use it")
	}
	return cacheMintedEIA(res, exchangeStartedAt, requestedScopes, cacheKey, generation, canonicalAudience)
}

// eiaOrg reads the org_id claim of an assertion without verifying it, when it has one.
func eiaOrg(token string) (string, bool) {
	claims, err := jwtutil.DecodeClaims(token)
	if err != nil {
		return "", false
	}
	org, ok := claims["org_id"].(string)
	return org, ok && org != ""
}

// whoamiEdge is whoami for an edge-device login: there is no id_token, so the identity is what
// the STS reports for the root.
func whoamiEdge(cfg config.Config, edge store.EdgeSession) error {
	key, err := loadSessionKey(edge.Key)
	if err != nil {
		return edgeKeyUnavailable(err)
	}
	ctx, err := sts.SessionContext(cfg, edge.RootToken, key)
	if err != nil {
		return classifyEdgeDiscoveryError(err)
	}
	org, err := edgeSessionOrg(ctx)
	if err != nil {
		return err
	}
	stdoutLine("session:  edge device (`gasworks login --edge-device`; pinned to one org)")
	stdoutRelayed("subject:  %s", ctx.UserID)
	stdoutRelayed("default org: %s", org.OrgID)
	stdoutRelayed("  - %s (%s) role=%s products=[%s] *", org.Slug, org.OrgID, org.Role, productNames(org.Products))
	return nil
}

// retireEdgeSession revokes a superseded root at the cli-edge that issued it and deletes its
// key, best-effort: the login that replaced it has already committed.
func retireEdgeSession(edge store.EdgeSession) {
	key, err := loadSessionKey(edge.Key)
	if err != nil {
		key = nil
	}
	revokeEdgeRoot(edge.EdgeOrigin, edge.RootToken, key)
	forgetSessionKey(edge.Key)
}

// revokeEdgeRoot is best-effort and silent: it never reports, and so never prints, the root.
func revokeEdgeRoot(origin, root string, key *dpop.Key) {
	if !validOpaqueToken(root) {
		return
	}
	_ = edgeClient.Revoke(origin, root, key)
}

// errEdgeSessionCommand is the refusal of a command that needs a Keycloak login.
func errEdgeSessionCommand(command, why string) *cmdError {
	return die("`gasworks %s` does not work with an edge-device session: %s", command, why)
}
