package main

import (
	"flag"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/oidc"
	"github.com/gascity/gasworks/internal/store"
)

func cmdLogout(cfg config.Config, argv []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(stderrWriter())
	if err := fs.Parse(argv); err != nil {
		return die("%s", err)
	}

	data, err := store.Load()
	if err != nil {
		return die("could not read credentials: %s", err)
	}
	if data.RefreshToken != "" {
		oidc.Revoke(cfg, data.RefreshToken) // best-effort server-side revocation BEFORE clearing
	}
	if err := store.Clear(); err != nil {
		return die("could not clear credentials: %s", err)
	}
	stdoutLine("Logged out.")
	return nil
}
