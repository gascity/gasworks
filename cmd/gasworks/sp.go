package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

const (
	// mintChallengeTTLSecs is the approval window assumed when leg A does not state one. The
	// server's default is 180s; its expires_in wins whenever it sends one.
	mintChallengeTTLSecs = 180
	// mintSessionMarginSecs is the session lifetime demanded ON TOP of the approval window: the
	// human's round trip to the browser, plus the leg C that follows it.
	mintSessionMarginSecs = 120
	// mintRedeemMarginSecs is the session lifetime the LAST leg C needs to land: one 30s
	// request timeout with room to spare. The poll deadline is clamped to leave this much,
	// because a challenge TTL the server raised past what mintSessionMarginSecs assumes would
	// otherwise let the poller outlive the session both legs are pinned to.
	mintRedeemMarginSecs = 60
	// cityLifecycleProduct is the product whose namespace holds city.create / city.delete. The
	// server's per-namespace check is hard: a key minted for another product can never hold a
	// forge:* scope, whatever the audience bundle says.
	cityLifecycleProduct = "forge"
	// defaultMintTTLDays is the requested credential lifetime. The server caps it (7 days
	// today); this client only refuses a lifetime that is not a lifetime at all.
	defaultMintTTLDays = 7
)

// sleep is the poll wait between leg C attempts. A var so tests drive the poll loop without
// real time passing.
var sleep = time.Sleep

// openApprovalURL launches the approval page. A var so a test can observe the launch without
// a browser actually opening on the machine running it.
var openApprovalURL = oidc.OpenBrowser

// mintClient issues both legs. A var so the verb's end-to-end tests can point the ceremony at
// a stub mint plane whose CA nothing else trusts, and still drive the real client, the real
// proofs and the real transport.
var mintClient = climint.New()

const spUsage = `usage: gasworks sp mint-key --sp <service-principal id> --scope <scope> [flags]

Mint a service-principal API key through the climint approval ceremony: the CLI opens a
challenge, you approve it in a browser using the confirm code printed here, and the CLI
redeems it for a credential written to an owner-only (0600) file.

Flags:
  --org <id|slug>         org to mint in (defaults to your default/sole org)
  --sp <id>               service principal the key belongs to (required)
  --product <name>        product namespace the scopes belong to (default ` + cityLifecycleProduct + `)
  --scope <scope>         scope to grant; repeat the flag for each one (required)
                          city lifecycle: --scope forge:city.create --scope forge:city.delete
  --resource-refs <json>  JSON refs to bind the key to; OMIT it to fold in the service
                          principal's own workspace grant
  --ttl-days <n>          requested credential lifetime in days (default 7; the server caps it)
  --out <path>            file to write the secret to (default <minted-keys dir>/<key id>.env)
  --format env|raw        secret rendering (default env: one quoted GASWORKS_SP_SECRET
                          assignment a shell can source; raw is the secret alone)
  --no-browser            print the approval URL instead of opening it
  --dry-run               validate and print the request, without sending anything`

// cmdSP dispatches the service-principal verbs.
//
// `mint-key` is the only one today. Its counterpart, `revoke-key`, is deliberately absent:
// there is no server arm to revoke a minted key yet, and a subcommand that cannot do what it
// says is worse than one that is not there. When that arm lands it slots in here — which is
// why this is a subcommand switch rather than a flag on a single `gasworks mint-key` verb.
func cmdSP(cfg config.Config, argv []string) error {
	if len(argv) == 0 {
		return die("%s", spUsage)
	}
	switch argv[0] {
	case "mint-key":
		return cmdSPMintKey(cfg, argv[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(stderr, spUsage)
		return nil
	default:
		return die("unknown `sp` subcommand %q\n\n%s", argv[0], spUsage)
	}
}

// cmdSPMintKey drives the three-legged external mint: leg A opens the challenge, the human
// approves it in a browser, leg C redeems it.
//
// The order of what follows is the whole point. Everything that can be judged locally — the
// flags, the scope namespace, the resource refs, the destination file, the mint origin — is
// judged BEFORE a session exists, because the server's DPoP jti ledger is single-use and a
// request that was always going to be rejected still spends a proof. Then ONE session and ONE
// key are established and held for both legs: the server pins leg C to leg A's subject and
// thumbprint, so re-establishing anything mid-ceremony ends it.
func cmdSPMintKey(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("sp mint-key", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	orgFlag := fs.String("org", "", "org id or slug (defaults to your default/sole org)")
	spFlag := fs.String("sp", "", "service principal id the key belongs to")
	productFlag := fs.String("product", cityLifecycleProduct, "product namespace the scopes belong to")
	var scopeFlags repeatedFlagValue
	fs.Var(&scopeFlags, "scope", "scope to grant (repeat the flag for each one)")
	refsFlag := fs.String("resource-refs", "", "JSON resource refs; omit to fold in the service principal's workspace grant")
	ttlFlag := fs.Int("ttl-days", defaultMintTTLDays, "requested credential lifetime in days")
	outFlag := fs.String("out", "", "file to write the minted secret to")
	formatFlag := fs.String("format", string(secretFormatEnv), "secret file rendering: env or raw")
	noBrowser := fs.Bool("no-browser", false, "print the approval URL instead of opening it")
	dryRun := fs.Bool("dry-run", false, "validate and print the request without sending it")
	allowFileKeystore := fs.Bool("allow-file-keystore", false, "permit storing the DPoP key in a 0600 file when no platform keystore is available")
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}
	if fs.NArg() != 0 {
		return die("unexpected argument %q — every input to `sp mint-key` is a flag\n\n%s", fs.Arg(0), spUsage)
	}
	cfg.AllowFileKeystore = cfg.AllowFileKeystore || *allowFileKeystore

	format, err := parseSecretFormat(*formatFlag)
	if err != nil {
		return err
	}
	request, err := mintRequest(*spFlag, *productFlag, scopeFlags, *refsFlag, *ttlFlag)
	if err != nil {
		return err
	}
	if *outFlag != "" {
		if err := checkSecretDestination(*outFlag); err != nil {
			return err
		}
	}
	// Validate the mint origin now: it is signed into the proof as htu, so a bad one must fail
	// before a jti is spent — and before a session is established for a ceremony that cannot run.
	challengesURL, err := cfg.MintChallengesURL()
	if err != nil {
		return die("%s", err)
	}
	if *dryRun {
		return printMintDryRun(challengesURL, request, *orgFlag, *outFlag, format)
	}
	// Reserve the destination BEFORE anything is sent. Checking that a path looks free proves
	// only that — not that it can be created, and not that it still will be by the time there
	// is a secret to put in it. So the file is created for real, verified, and held open
	// across the ceremony, while the only cost of a bad destination is retyping the command.
	destination, err := reserveSecretDestination(*outFlag)
	if err != nil {
		return err
	}
	defer destination.discard()

	org, session, err := resolveMintIdentity(cfg, *orgFlag)
	if err != nil {
		return err
	}
	request.OrgID = org

	// The ceremony disarms the reservation and writes leg C's answer into it the moment that
	// answer has been read, so from here on nothing — not the rendering, not an error return,
	// not the deferred cleanup above — unlinks the destination. It also returns HOLDING the
	// interrupt guard: a signal that killed this process between the reveal and the file having
	// its final contents would destroy or tear a credential nothing can re-issue. Nothing
	// between here and the release may return early.
	interrupt := newMintInterrupt()
	minted, err := runMintCeremony(cfg, session, request, *noBrowser, destination, interrupt)
	if err != nil {
		return err
	}

	// One question decides everything below: can this CLI turn what the server sent into the
	// credential file that was asked for? Only a yes rewrites the saved response — and a yes
	// that could not be written puts the response back, which is why `unrendered` is what the
	// file ended up holding rather than a restatement of `problem`.
	problem := mintProblem(minted)
	path, unrendered, saveErr := renderMintedCredential(minted, destination, format, problem)
	if saveErr != nil {
		// Reaching this needs the destination to have been unlinked, replaced, or made
		// unwritable during the approval, on a descriptor this process opened and verified
		// before the ceremony began. The credential still exists and still cannot be re-issued,
		// so it is put somewhere else rather than dropped, and the exit is non-zero either way.
		// The guard is held across the rescue too — that path writes the fallback file and, if
		// even that fails, prints the bytes — and released after it, where a signal that arrived
		// meanwhile changes nothing: the exit is already non-zero and the message already says
		// where the credential went.
		rescued := rescueMintedSecret(minted, format, problem, saveErr)
		interrupt.release()
		return rescued
	}
	interrupted := interrupt.release()
	if unrendered != nil {
		// A partial SUCCESS, not a failure: leg C answered with bytes, they are on the disk at
		// 0600, and the secret is in them. The exit is non-zero because this is not the file the
		// user asked for and no tooling should treat it as one.
		if interrupted != nil {
			eprintf("(%s arrived while the credential was being written; it was held until the "+
				"write finished, and the file below is what it left.)", interrupted)
		}
		return reportUnrenderedMint(minted, path, unrendered)
	}
	printMintedKey(minted.Credential, org, path, format)
	if interrupted != nil {
		return die("%s arrived while the minted credential was being written, so it was held "+
			"until the write finished: the credential IS saved, in %s. Nothing needs re-running.",
			interrupted, displayPath(path))
	}
	return nil
}

// mintProblem is why leg C's answer cannot become the credential file the user asked for, or
// nil when it can. Three things can be wrong with it, and they have the same answer: an envelope
// this CLI could not read, a body that stopped arriving, and a secret it read and cannot use. In
// every case the bytes the server sent are the truth and a rendering built from them would be a
// worse copy — so the file keeps what arrived, and this sentence tells the operator what to do
// with it.
//
// The read error is asked about even when the body happened to parse. A body cut short is not a
// credential this command may announce as one: the secret it carries may be missing its tail,
// and a success banner over half a secret is the one report nobody can act on.
func mintProblem(minted climint.Redemption) error {
	if minted.ParseErr != nil {
		return minted.ParseErr
	}
	// Truncated, not ReadErr. A read that stopped after the last byte of a complete JSON
	// document has lost nothing — the framing was cut, the envelope was not — and refusing to
	// render a credential that provably arrived whole would leave the operator with a raw
	// response and a warning about a tail that is not missing. See Redemption.Truncated.
	if minted.Truncated {
		return fmt.Errorf("the response body stopped arriving before it was complete: %w", minted.ReadErr)
	}
	if why := unusableSecret(minted.Credential.Secret); why != "" {
		return fmt.Errorf("the secret in it is not usable as one: %s", why)
	}
	return nil
}

// renderMintedCredential turns leg C's answer — already on the disk as the bytes the server
// sent — into the file the operator was promised, when there is nothing wrong with it.
//
// When there IS, the file is left exactly as it arrived. A rendering built from an envelope
// this client does not recognise, or from a secret that decoded into something other than what
// was on the wire, is how a recoverable credential gets overwritten with a broken one.
//
// It returns three things: where the credential is, why that file is not the rendering that was
// asked for (nil when it is), and whether the SAVE failed. The middle one is not just `problem`
// handed back — a rendering this CLI could build and could not write leaves the response in
// place too, and the operator has to be told that as clearly as an envelope nobody could read.
// The last one means the FILE failed, and sends the caller to the rescue.
func renderMintedCredential(minted climint.Redemption, destination *secretFile, format secretFormat, problem error) (path string, unrendered, failed error) {
	if minted.SinkErr != nil {
		return "", nil, minted.SinkErr
	}
	// Now, and not before the bytes were saved: a file unlinked or replaced while the human was
	// at the approval page is no longer the one this process created and vouched for, and what
	// it holds is not what the operator will open.
	if err := destination.stillTheReservation(); err != nil {
		return "", nil, err
	}
	if problem != nil {
		destination.keepResponse()
		return destination.settle(minted.Credential.KeyID, secretFormatResponse), problem, nil
	}
	if err := destination.rewrite([]byte(format.render(minted.Credential.Secret))); err != nil {
		var kept *responseKept
		if !errors.As(err, &kept) {
			return "", nil, err
		}
		// The rendering could not be written and the response it was replacing is verified still
		// in the file. The credential is saved; it is saved in the server's shape rather than
		// the one that was asked for, which is a report, not a rescue.
		return destination.settle(minted.Credential.KeyID, secretFormatResponse), kept.cause, nil
	}
	return destination.settle(minted.Credential.KeyID, format), nil, nil
}

// reportUnrenderedMint is the message for an answer that could not become a credential file.
//
// It says the things the operator needs and nothing else: which file holds what arrived, what the
// key id and challenge id are, and that the file must not be deleted. What it never says is that
// the mint did not happen — leg C returned bytes, and a message that sends someone away to run
// the command again abandons a live key.
//
// It also never says more than it knows, and there are three different amounts to know. When a
// secret was actually read out of the answer, a credential exists, this CLI has it, and saying so
// is a fact. When the answer stopped arriving part way through, the bytes in the file may be part
// of a secret and may be nothing — the outcome is open. And when the answer arrived whole and
// carried no secret this client could find — a 200 with an authorization_pending body, a captive
// portal, an LB page, an envelope that drifted — "a credential was minted" is a guess, and the
// honest report is the status that was received and an outcome that is not known.
//
// Saying "a credential was minted" over the last two is how an operator is sent to protect a key
// nobody issued; saying "nothing was minted" over any of them is how a live one is abandoned.
func reportUnrenderedMint(minted climint.Redemption, path string, problem error) error {
	held := minted.Credential.Secret != ""
	challenge := challengeOrUnknown(minted.ChallengeID)
	eprintf("")
	switch {
	case held:
		eprintf("!! A CREDENTIAL WAS MINTED, and this CLI could not render the mint plane's answer as one.")
		eprintf("!! That answer was saved BEFORE it was parsed, so nothing is lost:")
	case minted.Truncated:
		eprintRelayed("!! THE MINT PLANE ANSWERED %d AND ITS ANSWER STOPPED ARRIVING PART WAY THROUGH.", minted.Status)
		eprintf("!! No credential could be read out of what did arrive, so whether one was issued is")
		eprintf("!! NOT known. Those bytes may hold PART of a secret:")
	default:
		eprintRelayed("!! THE MINT PLANE ANSWERED %d WITH A BODY THIS CLI COULD NOT READ AS A CREDENTIAL.", minted.Status)
		eprintf("!! Whether one was issued is NOT known. The answer was saved BEFORE it was parsed, so")
		eprintf("!! nothing that arrived is lost:")
	}
	eprintf("")
	eprintRelayed("  file:       %s (owner-only, %d bytes, the raw server response)", displayPath(path), len(minted.Body))
	eprintRelayed("  key id:     %s", keyIDOrUnknown(minted.Credential.KeyID))
	eprintRelayed("  challenge:  %s", challenge)
	eprintRelayed("  reason:     %s", problem)
	eprintf("")
	if held {
		eprintf("!! The secret is INSIDE that file. It cannot be re-issued, re-read or revoked, so do")
		eprintf("!! not delete it: read the secret out of it and store it where you need it.")
		eprintf("")
		return dieRelayed("key %s was minted; its raw response is saved at %s and could not be rendered "+
			"as a credential", keyIDOrUnknown(minted.Credential.KeyID), displayPath(path))
	}
	eprintf("!! Whatever arrived is in that file — do not delete it — but it is not a credential this")
	eprintf("!! CLI could read. A key issued for that challenge would be live for its whole lifetime")
	eprintRelayed("!! and cannot be re-issued, re-read or revoked: reconcile challenge %s against the", challenge)
	eprintf("!! service principal's keys.")
	eprintf("")
	if minted.Truncated {
		return dieRelayed("the mint plane answered %d for challenge %s and its answer was cut short: %s holds "+
			"only the %d bytes that arrived, which may be part of a secret — reconcile challenge %s",
			minted.Status, challenge, displayPath(path), len(minted.Body), challenge)
	}
	return dieRelayed("the mint plane answered %d for challenge %s with a body this CLI could not read as "+
		"a credential; it is saved at %s — reconcile challenge %s",
		minted.Status, challenge, displayPath(path), challenge)
}

// resolveMintIdentity settles who is minting, in which org, with which session — the three
// things both legs are pinned to — and when that session expires, which bounds how long the
// ceremony may run. The session and key it returns are the ones the whole ceremony runs on;
// nothing after this point establishes another.
func resolveMintIdentity(cfg config.Config, requestedOrg string) (string, establishedSession, error) {
	credential, err := ensureHumanCredential(cfg, nil)
	if err != nil {
		return "", establishedSession{}, err
	}
	ctx, err := sts.Context(cfg, credential.IDToken, false)
	if err != nil {
		return "", establishedSession{}, die("discovery failed: %s", err)
	}
	data, err := store.Load()
	if err != nil {
		return "", establishedSession{}, die("could not read credentials: %s", err)
	}
	if data.CredentialGeneration != credential.Generation {
		return "", establishedSession{}, credentialChangedError()
	}
	org, err := pickOrg(ctx, requestedOrg, data)
	if err != nil {
		return "", establishedSession{}, err
	}
	// Pin the session to the origin that served discovery, as getToken does: the origin is part
	// of the session's binding, and a state-changing request must not be replayed at a second
	// host.
	origin := cfg.STSBase
	if ctx.Origin != "" {
		origin = ctx.Origin
	}
	session, err := ensureMintSession(cfg, data, org, credential.IDToken, credential.Generation, origin)
	if err != nil {
		return "", establishedSession{}, err
	}
	if !strings.HasPrefix(session.Token, climint.UserSessionPrefix) {
		return "", establishedSession{}, die("the session established at %s is not a user session, and the mint legs "+
			"accept only %s... tokens — sign in as yourself with `gasworks login`", origin, climint.UserSessionPrefix)
	}
	return org, session, nil
}

// mintRequest validates the flags and builds the leg A body. Everything it refuses, it refuses
// with a message naming the fix: the alternative is a server 400 that costs a round trip and a
// spent proof to learn the same thing.
func mintRequest(spID, product string, scopes []string, resourceRefs string, ttlDays int) (climint.ChallengeRequest, error) {
	if strings.TrimSpace(spID) == "" {
		return climint.ChallengeRequest{}, die("--sp is required: the id of the service principal the key belongs to")
	}
	if strings.TrimSpace(product) == "" {
		return climint.ChallengeRequest{}, die("--product cannot be empty: it is the namespace the scopes belong to (e.g. %s)", cityLifecycleProduct)
	}
	if len(scopes) == 0 {
		return climint.ChallengeRequest{}, die("--scope is required: repeat it once per scope, e.g. " +
			"`--scope forge:city.create --scope forge:city.delete`")
	}
	for _, scope := range scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return climint.ChallengeRequest{}, die("--scope %q must be a single scope: repeat --scope for each one", scope)
		}
	}
	if hasDuplicateScopes(scopes) {
		return climint.ChallengeRequest{}, die("--scope was given the same scope twice: %s", strings.Join(scopes, " "))
	}
	for _, scope := range scopes {
		if namespace, _, found := strings.Cut(scope, ":"); !found || namespace != product {
			return climint.ChallengeRequest{}, die("scope %q is not in the %q namespace, so a %q key can never hold it "+
				"(the server checks the namespace, not the audience bundle).\n"+
				"City lifecycle is `--product %s --scope %s:city.create --scope %s:city.delete`.",
				scope, product, product, cityLifecycleProduct, cityLifecycleProduct, cityLifecycleProduct)
		}
	}
	if ttlDays <= 0 {
		return climint.ChallengeRequest{}, die("--ttl-days must be at least 1 (got %d)", ttlDays)
	}
	refs, err := mintResourceRefs(resourceRefs)
	if err != nil {
		return climint.ChallengeRequest{}, err
	}
	return climint.ChallengeRequest{
		SPID:          spID,
		Product:       product,
		Scopes:        append([]string(nil), scopes...),
		ExpiresInDays: ttlDays,
		ResourceRefs:  refs,
	}, nil
}

// mintResourceRefs validates --resource-refs and returns the exact bytes to send.
//
// What goes on the wire is a re-marshalling of the value that was WALKED for wildcards, not a
// compaction of the caller's text: the two can differ — a duplicate key survives compaction
// but collapses on decode — and the server must be sent the representation this checked, not
// a second one that merely came from the same input. Numbers are decoded as json.Number so
// re-marshalling reproduces the caller's digits rather than a float64 round trip.
//
// An omitted flag stays OMITTED on the wire, which is what makes the server fold in the
// service principal's own workspace grant. An explicit JSON null is not the same thing — it is
// a value the server can see — so it is refused here rather than quietly rewritten into an
// absence the user did not ask for.
func mintResourceRefs(raw string) (json.RawMessage, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, die("--resource-refs is not valid JSON: %s", err)
	}
	// json.Unmarshal rejects trailing content; a Decoder stops at the first value, so a
	// second value after the first would be validated and never sent.
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, die("--resource-refs must be a single JSON value")
	}
	if decoded == nil {
		return nil, die("--resource-refs null is not the same as leaving the flag off: omit it entirely " +
			"to fold in the service principal's own workspace grant")
	}
	if where := findWildcard(decoded, "resource-refs"); where != "" {
		return nil, die(`--resource-refs has a wildcard at %s: a minted key is bound to refs it names, never to "*"`, where)
	}
	wire, err := json.Marshal(decoded)
	if err != nil {
		return nil, die("--resource-refs could not be re-encoded: %s", err)
	}
	return json.RawMessage(wire), nil
}

// findWildcard walks decoded JSON and returns the path of the first "*" it finds — in a key or
// in a string, at any depth — or "" when there is none. Keys are walked in sorted order so the
// path reported for a given input never changes between runs.
func findWildcard(value any, path string) string {
	switch v := value.(type) {
	case string:
		if strings.Contains(v, "*") {
			return path
		}
	case []any:
		for i, item := range v {
			if found := findWildcard(item, fmt.Sprintf("%s[%d]", path, i)); found != "" {
				return found
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := path + "." + key
			if strings.Contains(key, "*") {
				return child
			}
			if found := findWildcard(v[key], child); found != "" {
				return found
			}
		}
	}
	return ""
}

// ensureMintSession returns the session BOTH legs will be signed with, and its DPoP key.
//
// The demand on remaining lifetime is far stricter than getToken's 30s. The server pins leg C
// to leg A's subject and JKT, so a session that expires while the human is at the approval
// page cannot be replaced — the ceremony would have to start over with a new challenge. So the
// session must outlive the whole approval window plus a margin, or it is replaced HERE, before
// leg A, where replacing it costs nothing.
//
// The same demand is made of a FRESH session, which is not a formality: an STS that issues a
// short session issues it to this ceremony too, and finding that out here — before leg A —
// costs nothing, where finding it out at the approval page costs the human's round trip.
func ensureMintSession(cfg config.Config, data *store.Data, org, idToken, generation, origin string) (establishedSession, error) {
	if cached, ok := data.Sessions[sessionCacheKey(origin, org, generation)]; ok &&
		outlivesTheCeremony(cached.ExpiresAt) {
		if key, err := loadSessionKey(cached.Key); err == nil {
			return establishedSession{
				Token:     cached.SessionToken,
				Key:       key,
				Origin:    origin,
				ExpiresAt: cached.ExpiresAt,
			}, nil
		}
		// A missing or unreadable key falls through to a fresh session, as getToken's does.
	}
	established, err := newSession(cfg.WithSTSBase(origin), org, idToken, generation)
	if err != nil {
		return establishedSession{}, err
	}
	if !outlivesTheCeremony(established.ExpiresAt) {
		return establishedSession{}, die("the session %s issued expires in %ds, which does not cover the approval "+
			"window (%ds) and the redemption that follows it — nothing was minted",
			origin, established.ExpiresAt-now(), mintChallengeTTLSecs)
	}
	return established, nil
}

// outlivesTheCeremony is the lifetime demand both branches make.
func outlivesTheCeremony(expiresAt int64) bool {
	return expiresAt-now() > mintChallengeTTLSecs+mintSessionMarginSecs
}

// runMintCeremony opens the challenge, sends the human to the approval page, and polls for the
// credential. The session is held across both legs and never re-established, and its expiry
// bounds how long the poll may run: the server pins leg C to leg A's subject and thumbprint,
// so a poll that outlives the session is polling for a 401.
//
// The reservation is passed in for one reason. Leg C's response bytes are the instant the
// credential starts existing, and they go INTO that reservation before this function — or
// anything under it — parses them, judges them or renders them. The destination stops being
// disposable at the same instant, for the same reason: a response this client dislikes still
// carries a credential nothing can re-issue.
//
// The interrupt guard brackets each leg C attempt for the span that write cannot cover: from
// the request going out until the bytes are synced, a signal would kill the process while the
// answer is on the wire or in memory. It is never shortened. Leg C consumes the challenge and
// mints a key, so a signal that cancelled the request in flight would leave the server
// committed and the client with nothing — the loss this whole file is arranged to prevent, by
// the hand of the guard meant to prevent it. The signal is RECORDED, the request runs to the
// leg's own timeout, whatever arrived is saved, and the answer decides what the operator is
// told. An attempt that reveals nothing and is answered releases the guard immediately, so a
// Ctrl-C during the wait that follows is honoured at once; an attempt that reveals bytes returns
// with the guard STILL HELD, and the caller releases it once the file holds what it is going to
// hold.
func runMintCeremony(cfg config.Config, session establishedSession, request climint.ChallengeRequest, noBrowser bool, destination *secretFile, interrupt *mintInterrupt) (climint.Redemption, error) {
	challenge, err := mintClient.CreateChallenge(cfg, session.Token, session.Key, request)
	if err != nil {
		return climint.Redemption{}, mintFailure("could not open the mint challenge", err)
	}
	if challenge.ChallengeID == "" || challenge.ConfirmCode == "" || challenge.ApproveURL == "" {
		return climint.Redemption{}, die("the mint plane returned a challenge with no id, code, or approval URL")
	}
	if err := checkApprovalURL(cfg, challenge.ApproveURL); err != nil {
		return climint.Redemption{}, err
	}
	// The window is the server's number. climint clamps it to [0, MaxChallengeTTLSecs] as it
	// decodes it, because the line below turns it into an int64 deadline and an unclamped 1e19
	// seconds lands in the PAST — a deadline no comparison can ever reach. Anything outside that
	// range is not a window this client can act on, so it falls back to the assumed one.
	window := challenge.ExpiresIn
	if window <= 0 || window > climint.MaxChallengeTTLSecs {
		window = mintChallengeTTLSecs
	}
	// The challenge's TTL is the server's; the session's expiry is this client's. Poll until
	// whichever comes first, so a TTL raised past what ensureMintSession assumed cannot leave
	// the poller waiting on a session that has already ended.
	deadline := now() + int64(window)
	sessionBound := false
	if limit := session.ExpiresAt - mintRedeemMarginSecs; session.ExpiresAt > 0 && limit < deadline {
		deadline, sessionBound = limit, true
	}
	promptForApproval(challenge, window, noBrowser)

	for {
		// Each attempt mints its own proof, which is what makes polling possible at all: the
		// previous attempt's jti is spent, so this is a fresh call and never a retry. The first
		// one fires immediately — the interval is carried by the 425, not by leg A, so there is
		// nothing to wait for yet.
		//
		// The guard goes up BEFORE the request and comes down only once its answer has been
		// handled. Nothing between the two cancels it — see mintInterrupt.
		interrupt.hold()
		minted, err := mintClient.CompleteChallenge(context.Background(), cfg, session.Token, session.Key,
			challenge.ChallengeID, destination.persist)
		if minted.Revealed() {
			// The bytes are on the disk and the reservation is disarmed — destination.persist
			// did both, before this line and before anything parsed them. The guard stays held:
			// releasing it before the file has its final contents is what a signal would use to
			// tear the credential in half.
			//
			// A missing key id is a naming problem, not a reason to refuse the credential: the
			// secret is the thing that cannot be re-issued, and defaultSecretPath falls back to
			// a timestamped name for exactly this.
			if minted.ParseErr == nil && minted.Credential.KeyID == "" {
				eprintf("warning: the mint plane returned a credential with no key id; the secret is saved anyway")
			}
			return minted, nil
		}
		// Nothing was revealed. Whether that is a fact or a guess is the mint plane's to settle,
		// and only its own answer settles it — with one thing this CLI settles for itself: a
		// redeem whose bytes never reached the network cannot have minted anything, whatever the
		// error looks like. A dial that never connected and a connection that died holding the
		// answer produce the same error and opposite truths.
		if !legCSettled(err) {
			if !minted.Sent {
				// Nothing left this machine, so the challenge is untouched and no key came out of
				// it. Saying so is not a guess, and warning about a credential that cannot exist
				// would send the operator to reconcile a key nobody minted.
				if sig := interrupt.release(); sig != nil {
					destination.discard()
					cancelAsInterrupted(sig)
				}
				return climint.Redemption{}, dieRelayed("the redeem for challenge %s never left this machine "+
					"(%s) — nothing was minted and the challenge was not spent; run the command again",
					challenge.ChallengeID, err)
			}
			// The redeem went out and what came back does not say what the server did with it.
			// The report is printed with the guard STILL HELD: it names a challenge that may
			// have minted a live key, and a second Ctrl-C must not take that sentence with it.
			reportUnresolvedRedemption(challenge.ChallengeID, minted, err, interrupt.recorded())
			interrupt.release()
			if planeSaysConsumed(err) {
				return climint.Redemption{}, dieRelayed("the mint plane says challenge %s was already redeemed "+
					"and this CLI captured no credential from it — reconcile challenge %s against %s's keys "+
					"before minting again", challenge.ChallengeID, challenge.ChallengeID, request.SPID)
			}
			if challengeWasConsumed(err) {
				return climint.Redemption{}, dieRelayed("the mint plane answered %d for challenge %s without "+
					"saying what it did with it, and this CLI captured no credential — that status can mean "+
					"the challenge was already redeemed, so reconcile challenge %s against %s's keys before "+
					"minting again", minted.Status, challenge.ChallengeID, challenge.ChallengeID, request.SPID)
			}
			return climint.Redemption{}, dieRelayed("the redeem for challenge %s revealed no credential this "+
				"CLI could capture, and its answer does not say whether one was issued — reconcile challenge "+
				"%s against %s's keys before minting again",
				challenge.ChallengeID, challenge.ChallengeID, request.SPID)
		}
		// The mint plane answered, and its answer is that this attempt minted nothing. So a
		// signal that arrived during it is honoured now rather than at the end of a poll that may
		// run for minutes, and saying nothing was minted is repeating what the server just said.
		if sig := interrupt.release(); sig != nil {
			// Still armed, so the reservation goes too — the same cleanup the caller's deferred
			// discard would do if this returned an error instead of ending the process.
			destination.discard()
			cancelAsInterrupted(sig)
		}
		var pending *climint.PendingError
		if !errors.As(err, &pending) {
			return climint.Redemption{}, mintFailure("the mint was not completed", err)
		}
		wait := int64(pending.Interval)
		if now()+wait >= deadline {
			if sessionBound {
				return climint.Redemption{}, die("the session both mint legs are pinned to expires before the "+
					"approval window (%ds) does, and it cannot be replaced mid-ceremony — nothing was minted; "+
					"run `gasworks login` and try again", window)
			}
			return climint.Redemption{}, die("the approval window (%ds) closed before the mint was approved — "+
				"nothing was minted; run the command again", window)
		}
		sleep(time.Duration(wait) * time.Second)
	}
}

// legCSettled reports whether the mint plane's answer to a redeem that revealed nothing settles
// the question of whether a credential came out of it.
//
// A 425 says the human has not approved yet, and most 4xx answers name the reason the request was
// refused: both are the server stating that it did not mint, and the ceremony may wait, end, or
// honour a signal on the strength of them. Everything else is silence about the one thing that
// matters. No response at all — a timeout, a reset, a link that stalled — says nothing about what
// the server did with a request it may well have received. A 2xx that carried no credential says
// the server ACTED and did not tell this client what it produced. And a 5xx is a relay failing:
// the mint plane forwards to accounts, so a gateway error can land with a key already issued
// behind it. Assuming the comfortable half of any of those is how a live credential ends up
// existing with nobody looking for it.
//
// The one 4xx that is not a refusal is `already_consumed`, and it is the sharpest case of all:
// the server is stating that the challenge WAS redeemed. This CLI redeems a challenge once, so
// hearing that means a key came out of an attempt whose answer never got back — the opposite of
// nothing being minted. TerminalError.MayHaveMinted draws that line, including for the 409 and
// 410 whose code this client does not recognise.
func legCSettled(err error) bool {
	var pending *climint.PendingError
	if errors.As(err, &pending) {
		return true
	}
	var terminal *climint.TerminalError
	if errors.As(err, &terminal) {
		return terminal.Status >= 400 && terminal.Status < 500 && !terminal.MayHaveMinted()
	}
	return false
}

// reportUnresolvedRedemption is what the operator is told about a redeem that was sent and whose
// outcome is not known.
//
// The one thing it must never do is claim the mint did not happen. Leg C consumes the challenge
// and mints a key, so from here "the request failed" and "it worked and the answer did not reach
// this process" are the same observation, and only one of them is safe to act on. A CLI that
// picks the reassuring one sends the operator away from a live key holding forge:city.create and
// forge:city.delete, for its full lifetime, with no revoke arm to call.
//
// So it names the challenge id. That is the only identifier tying a key nobody can see back to
// the command that asked for it, and it is what the reconciliation is run against.
func reportUnresolvedRedemption(challengeID string, minted climint.Redemption, cause error, interrupted os.Signal) {
	eprintf("")
	switch {
	case planeSaysConsumed(cause):
		// Not an unknown outcome: the mint plane said the challenge was redeemed. This CLI
		// redeems one exactly once, so the redemption it is talking about is this command's.
		eprintf("!! THE MINT PLANE SAYS THAT CHALLENGE WAS ALREADY REDEEMED.")
	case challengeWasConsumed(cause):
		// A 409 or a 410 with an empty body, or with a code this client does not know. Conflict
		// and Gone are the statuses that CARRY "already redeemed", which is why the outcome is
		// treated as open — but the server did not say it, and reporting a status as a statement
		// is inventing a quote it can be held to.
		eprintRelayed("!! THE MINT PLANE ANSWERED %d WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE.", minted.Status)
		eprintf("!! That status can mean the challenge was already redeemed. THE OUTCOME IS UNKNOWN.")
	default:
		eprintf("!! THE REDEEM WAS SENT AND ITS OUTCOME IS UNKNOWN.")
	}
	eprintf("!! A CREDENTIAL MAY HAVE BEEN ISSUED. If it was, this CLI does not hold it, could not")
	eprintf("!! save it, and cannot revoke it.")
	eprintf("")
	eprintRelayed("  challenge:  %s", challengeID)
	if minted.Status != 0 {
		eprintf("  answered:   %d", minted.Status)
	}
	eprintRelayed("  reason:     %s", unresolvedReason(minted, cause))
	if interrupted != nil {
		eprintRelayed("  interrupt:  %s arrived while the redeem was in flight. It was NOT cancelled —", interrupted.String())
		eprintf("              the request was given its full timeout to answer first.")
	}
	eprintf("")
	eprintRelayed("!! Reconcile challenge %s before minting again: a key issued for it is live for its", challengeID)
	eprintf("!! whole lifetime whether or not anyone is holding it.")
	eprintf("")
}

// unresolvedReason is the sentence under `reason:`. A 2xx this client could make nothing of
// describes itself; anything else is described by the error that ended the attempt.
func unresolvedReason(minted climint.Redemption, cause error) error {
	if minted.ParseErr != nil {
		return minted.ParseErr
	}
	return cause
}

// challengeWasConsumed reports whether the mint plane's answer leaves open that the challenge
// was redeemed — the wide question, the one the control flow turns on.
func challengeWasConsumed(cause error) bool {
	var terminal *climint.TerminalError
	return errors.As(cause, &terminal) && terminal.MayHaveMinted()
}

// planeSaysConsumed reports whether the answer STATED it, which is the narrow question and the
// only one a sentence beginning "the mint plane says" may be written from.
func planeSaysConsumed(cause error) bool {
	var terminal *climint.TerminalError
	return errors.As(cause, &terminal) && terminal.SaysConsumed()
}

// checkApprovalURL refuses an approval URL that is not the mint plane's own.
//
// The URL is composed by the server precisely so a stale client-side path cannot outlive a
// server change — but it is then handed to the OS, which opens whatever it is given. A mint
// plane that was compromised, impersonated, or simply misconfigured could name any host, and
// the human would see a page they were told to trust. So it is checked against the one origin
// this CLI already signs its proofs to: same scheme, same host, same port, or no ceremony.
//
// The value it is given has already been through climint.Display, which is what keeps the URL
// this CLI prints and the URL it hands the OS the same string. A URL carrying a byte a terminal
// would act on comes out of that filter QUOTED, fails to parse or fails the origin check here,
// and the ceremony ends before the human is sent anywhere — which is the right answer: an
// approval URL nobody can safely read is not one to open.
func checkApprovalURL(cfg config.Config, raw string) error {
	origin, err := cfg.ClimintOrigin()
	if err != nil {
		return die("%s", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return dieRelayed("the mint plane returned an approval URL that is not a URL (%s): %s; "+
			"refusing to open it; nothing was minted", raw, err)
	}
	if parsed.Scheme != "https" {
		return die("the mint plane returned an approval URL that is not https (%q); refusing to open it; "+
			"nothing was minted", raw)
	}
	if parsed.User != nil {
		return die("the mint plane returned an approval URL carrying userinfo (%q); refusing to open it; "+
			"nothing was minted", raw)
	}
	if got := parsed.Scheme + "://" + parsed.Host; got != origin {
		return dieRelayed("the mint plane returned an approval URL at %s, which is not the mint origin %s — "+
			"refusing to open it; nothing was minted", got, origin)
	}
	return nil
}

// promptForApproval prints the ceremony's human half. The confirm code is printed HERE and
// nowhere else: leg A's response is the only place it exists, and the approval page
// deliberately does not render it, so this terminal is what the user reads it from. It goes to
// stderr with the rest of the prompts, and into no log line, ever.
func promptForApproval(challenge climint.Challenge, window int, noBrowser bool) {
	eprintf("")
	eprintf("Approve this mint in your browser:")
	eprintf("")
	eprintRelayed("  1. Open:        %s", challenge.ApproveURL)
	eprintRelayed("  2. Enter code:  %s", challenge.ConfirmCode)
	eprintf("")
	eprintf("The code is shown here and nowhere else — the approval page will not display it.")
	eprintf("Waiting for approval... (the request expires in %ds; Ctrl-C to cancel)", window)
	if !noBrowser && hasDisplay() {
		// The server's own URL, verbatim — composing one client-side would let a stale path
		// outlive a server change — but only after checkApprovalURL has established it is
		// the mint plane's own origin.
		openApprovalURL(challenge.ApproveURL)
	}
}

// mintFailure turns a climint error into the CLI's message. Whatever the server said is what
// the user reads — these failures are the server's to explain, not this client's to guess at —
// lifted out of the wrapper chain so the line is one sentence rather than three. The hint per
// status is the only thing added: what to do next, which an error code cannot carry.
func mintFailure(what string, err error) error {
	var terminal *climint.TerminalError
	if !errors.As(err, &terminal) {
		return dieRelayed("%s: %s", what, err)
	}
	detail := terminal.Code
	if terminal.Message != "" {
		if detail != "" {
			detail += " — "
		}
		detail += terminal.Message
	}
	if detail == "" {
		detail = "no reason given"
	}
	// The detail is the server's own words, so it is the argument and never part of the format.
	failure := fmt.Sprintf("%s: %d %s", what, terminal.Status, climint.Display(detail))
	switch terminal.Status {
	case http.StatusUnauthorized:
		return die("%s\nthe mint plane rejected this session — run `gasworks login` and try again", failure)
	case http.StatusForbidden:
		return die("%s\nnothing was minted; this account may not mint that key, or the approval was refused", failure)
	case http.StatusConflict:
		return die("%s\nthat challenge is spent — start a new `gasworks sp mint-key`", failure)
	}
	return die("%s", failure)
}

// printMintedKey reports what was minted. Everything here is non-secret: the secret itself is
// in the file and was never in this process's output.
func printMintedKey(minted climint.Credential, org, path string, format secretFormat) {
	if minted.OrgID != "" {
		org = minted.OrgID
	}
	stdoutRelayed("Minted a service-principal key for org %s.", org)
	stdoutRelayed("  key id:   %s", minted.KeyID)
	if minted.Prefix != "" {
		stdoutRelayed("  prefix:   %s", minted.Prefix)
	}
	stdoutRelayed("  scopes:   %s", strings.Join(minted.Scopes, " "))
	if minted.ExpiresAt != "" {
		stdoutRelayed("  expires:  %s", minted.ExpiresAt)
	}
	stdoutRelayed("  secret:   %s (owner-only, %s format)", displayPath(path), string(format))
	eprintf("The secret is revealed once, by the server. It is in that file and was never printed.")
}

// printMintDryRun prints the exact request the live run would POST, and contacts nothing.
//
// The body is marshalled from the same struct the client sends, with the same tags, so these
// are the same bytes — the resource_refs omission included. TestSPMintKeyDryRunMatchesTheWire
// pins that equality against a real request rather than leaving it to inspection.
func printMintDryRun(challengesURL string, request climint.ChallengeRequest, requestedOrg, out string, format secretFormat) error {
	org := requestedOrg
	if org == "" {
		// A dry run resolves nothing over the network, so the only org it can supply is the one
		// already on disk.
		data, err := store.Load()
		if err != nil {
			return die("could not read credentials: %s", err)
		}
		org = data.DefaultOrg
	}
	if org == "" {
		return die("--dry-run does not contact the STS, so it cannot resolve which org you meant — pass --org")
	}
	request.OrgID = org
	body, err := json.Marshal(request)
	if err != nil {
		return die("could not render the request: %s", err)
	}
	destination := out
	if destination == "" {
		destination = filepath.Join(store.MintedKeyDir(), "<key id>"+format.extension())
	}
	stdoutf("POST %s", challengesURL)
	stdoutLine(string(body))
	eprintf("dry run: nothing was sent, no session was established, and nothing was minted.")
	eprintf("the secret would be written to %s (owner-only, %s format)", displayPath(destination), format)
	eprintf("--org is printed verbatim here; a live run resolves it against your memberships first.")
	return nil
}

// displayPath prefers an absolute path so the user can find the file from anywhere, and falls
// back to what was given when the working directory cannot be resolved.
func displayPath(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}
