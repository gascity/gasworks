package main

import (
	"flag"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/jwtutil"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
)

func cmdLogin(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	device := fs.Bool("device", false, "force the device-code flow (headless)")
	browser := fs.Bool("browser", false, "force the browser loopback flow")
	org := fs.String("org", "", "remember a default org for getToken")
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}

	// Default to device-code unless a display is present; --device/--browser force it.
	useDevice := *device || (!*browser && !hasDisplay())

	var tok oidc.Tokens
	var err error
	if useDevice {
		tok, err = oidc.DeviceLogin(cfg, eprintln)
	} else {
		tok, err = oidc.BrowserLogin(cfg, eprintln)
	}
	if err != nil {
		return die("%s", err)
	}

	idt := tok.IDToken
	if idt == "" {
		return die("login returned no id_token (is the 'openid' scope enabled on the client?)")
	}

	// (M9/M3) Advisory sanity checks over the DECODED-BUT-UNVERIFIED id_token. These are
	// NOT a trust boundary — the CLI never verifies the JWT signature; the STS is the real
	// verifier (it validates subject_token before minting), and products verify the EIA
	// offline. The checks below just turn an obviously-wrong token (wrong client, wrong
	// realm, already-expired) into a clear local error at login instead of an opaque STS
	// 401 on the next getToken.
	claims, err := jwtutil.DecodeClaims(idt)
	if err != nil {
		return die("the id_token is not decodable: %s", err)
	}
	aud := jwtutil.Audiences(claims)
	azp, _ := claims["azp"].(string)
	// An empty azp is faithful to the Python: Keycloak omits azp when aud is the single
	// client, so "" is accepted. A NON-empty azp must match our client.
	if !contains(aud, cfg.ClientID) || (azp != cfg.ClientID && azp != "") {
		return die("the id_token is not for %s (aud/azp mismatch)", cfg.ClientID)
	}
	if iss := jwtutil.Issuer(claims); iss != cfg.OIDCIssuer {
		return die("the id_token issuer %q is not the configured OIDC issuer %q", iss, cfg.OIDCIssuer)
	}
	if exp := jwtutil.Exp(claims); exp != 0 && exp <= time.Now().Unix() {
		return die("the id_token is already expired (exp=%d) — check the client clock", exp)
	}

	if err := store.Update(func(d *store.Data) error {
		d.IDToken = idt
		if tok.RefreshToken != "" {
			d.RefreshToken = tok.RefreshToken
		}
		if *org != "" {
			d.DefaultOrg = *org
		}
		// A fresh login invalidates any prior STS sessions / cached EIAs.
		d.Sessions = nil
		d.EIACache = nil
		return nil
	}); err != nil {
		return die("could not save credentials: %s", err)
	}

	who := claimString(claims, "email")
	if who == "" {
		who = claimString(claims, "preferred_username")
	}
	if who == "" {
		who = claimString(claims, "sub")
	}
	stdoutf("Logged in as %s.", who)
	return nil
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}
