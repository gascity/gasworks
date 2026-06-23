package main

import (
	"errors"
	"flag"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/jwtutil"
	"github.com/gascity/gasworks/internal/store"
	"github.com/gascity/gasworks/internal/sts"
)

func cmdWhoami(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}

	data, err := store.Load()
	if err != nil {
		return die("could not read credentials: %s", err)
	}
	if data.IDToken == "" {
		return die("not logged in — run `gasworks login`")
	}

	idToken, err := ensureIDToken(cfg)
	if err != nil {
		return err
	}
	claims, err := jwtutil.DecodeClaims(idToken)
	if err != nil {
		return die("could not decode the id_token: %s", err)
	}

	stdoutf("subject:  %s", claimString(claims, "sub"))
	stdoutf("email:    %s", claimString(claims, "email"))
	if u := claimString(claims, "preferred_username"); u != "" {
		stdoutf("username: %s", u)
	}

	ctx, err := sts.Context(cfg, idToken, false)
	if err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) && he.Status == 404 {
			stdoutLine("orgs:     (no account yet — run `gasworks getToken <product>` to provision one)")
			return nil
		}
		eprintf("  (could not list orgs: %s)", err)
		return nil
	}

	stdoutf("default org: %s", ctx.DefaultOrgID)
	for _, o := range ctx.Orgs {
		star := ""
		if o.IsDefault {
			star = " *"
		}
		stdoutf("  - %s (%s) role=%s products=[%s]%s",
			o.Slug, o.OrgID, o.Role, productNames(o.Products), star)
	}
	return nil
}
