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

	snapshot, err := store.LoadSnapshot()
	if err != nil {
		return die("could not read credentials: %s", err)
	}
	data := snapshot.Data
	if data.RefreshToken != "" {
		oidc.Revoke(cfg, data.RefreshToken) // best-effort server-side revocation BEFORE clearing
	}
	if edge := snapshot.Edge; edge != nil {
		// Best-effort, and before the purge below: the revocation proves possession of the
		// root's key, so the key has to still be there.
		key, err := loadSessionKey(edge.Key)
		if err != nil {
			key = nil
		}
		revokeEdgeRoot(edge.EdgeOrigin, edge.RootToken, key)
	}
	// The DPoP keys live outside credentials.json, so clearing the file is not enough:
	// purge every registered credential store so a sign-out leaves no key material behind.
	purgeSessionKeys()
	if err := store.Clear(); err != nil {
		return die("could not clear credentials: %s", err)
	}
	stdoutLine("Logged out.")
	return nil
}
