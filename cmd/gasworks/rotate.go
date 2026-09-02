package main

import (
	"errors"
	"flag"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

// cmdRotateKey replaces an org's DPoP private key with a fresh one and establishes a new
// session pinned to it.
//
// It is NOT a remedy for a suspected key compromise: the STS has no route that revokes the
// session family the old key proved, so the superseded session stays mintable until it
// expires (up to 8h). Until that route exists this command is scheduled hygiene — it limits
// how long ONE key is in use — and it says so on stderr every time.
//
// The order matters: the credential store is chosen first (so an unenrollable host fails
// before touching the STS), the new session is established next, and only once it exists is
// the stored key replaced. A crash between those steps leaves a session token that no longer
// matches its key, which the next getToken repairs by re-establishing the session on a 401.
func cmdRotateKey(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	orgFlag := fs.String("org", "", "org id or slug (defaults to your default/sole org)")
	allowFileKeystore := fs.Bool("allow-file-keystore", false, "permit storing the DPoP key in a 0600 file when no platform keystore is available")
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}
	cfg.AllowFileKeystore = cfg.AllowFileKeystore || *allowFileKeystore

	credential, err := ensureHumanCredential(cfg, nil)
	if err != nil {
		return err
	}
	ctx, err := sts.Context(cfg, credential.IDToken, false)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 404 {
			return die("no account yet — run `gasworks getToken <product>` once before rotating")
		}
		return die("discovery failed: %s", err)
	}
	data, err := store.Load()
	if err != nil {
		return die("could not read credentials: %s", err)
	}
	if data.CredentialGeneration != credential.Generation {
		return credentialChangedError()
	}
	org, err := pickOrg(ctx, *orgFlag, data)
	if err != nil {
		return err
	}
	origin := cfg.STSBase
	if ctx.Origin != "" {
		origin = ctx.Origin
	}

	backend, err := enrollmentKeystore(cfg)
	if err != nil {
		return err
	}
	key, err := dpop.NewKey()
	if err != nil {
		return die("could not generate a session key: %s", err)
	}
	stsCfg := cfg.WithSTSBase(origin)
	session, err := sts.Login(stsCfg, credential.IDToken, org, key)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 403 {
			return dieCredential(credentialErrorDenied, "not a member of org %s (%s)", org, he.OAuthError())
		}
		return die("re-enrollment at %s failed: %s", origin, err)
	}
	if session.Origin != "" {
		origin = session.Origin
	}
	// sts.Login already substitutes the default session lifetime when the server omits it.
	expiresIn := session.ExpiresIn

	cacheKey := sessionCacheKey(origin, org, credential.Generation)
	previous := data.Sessions[cacheKey]
	var ref store.KeyRef
	if err := store.Update(func(d *store.Data) error {
		if d.CredentialGeneration != credential.Generation {
			return errCredentialGenerationChanged
		}
		if d.Sessions == nil {
			d.Sessions = map[string]store.Session{}
		}
		// Enrol under the store lock so a concurrent getToken cannot bind its session to
		// this key (the handle is shared per session) or the other way round.
		enrolled, keyErr := enrollSessionKey(backend, sessionKeyHandle(cacheKey), key)
		if keyErr != nil {
			return keyErr
		}
		ref = enrolled
		d.Sessions[cacheKey] = store.Session{
			SessionToken: session.SessionToken,
			Key:          ref,
			ExpiresAt:    now() + int64(expiresIn),
		}
		// Every cached EIA was minted from the superseded session. They stay valid at the
		// products until they expire, but the client stops handing them out.
		d.EIACache = nil
		return nil
	}); err != nil {
		// The rotated session was not persisted. Drop the new key too: the stored session
		// token is the superseded one, and its key was already overwritten, so leaving the
		// new key behind would only buy a 401 before the next getToken re-establishes.
		forgetSessionKey(ref)
		if errors.Is(err, errCredentialGenerationChanged) {
			return credentialChangedError()
		}
		var commandErr *cmdError
		if errors.As(err, &commandErr) {
			return commandErr
		}
		return die("could not save the rotated session: %s", err)
	}
	// The handle is stable per session, so the replacement above already overwrote the old
	// key. Clean up only a key that lived somewhere else (a store change between rotations).
	if previous.Key.Enrolled() && previous.Key != ref {
		forgetSessionKey(previous.Key)
	}

	stdoutf("Rotated the DPoP key for org %s at %s.", org, origin)
	stdoutf("  keystore: %s (handle %s)", ref.Backend, ref.Handle)
	stdoutf("  jkt:      %s", key.Thumbprint())
	stdoutf("  session:  new, expires %s", utcRFC3339(now()+int64(expiresIn)))
	if previous.SessionToken != "" {
		eprintf("note: the superseded session and its key stay valid at the STS until they expire — " +
			"there is no route yet that revokes the old session family, so this does not " +
			"contain a compromised key")
	}
	return nil
}
