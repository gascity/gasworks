package keystore

// Registry returns the closed per-platform backend list, most preferred first: the platform
// keystores this build knows about, then the file backend. Callers pass it to Select (to
// enrol a new key) or ByID (to reach an already enrolled one).
//
// configDir scopes a platform keystore to one gasworks profile (GASWORKS_CONFIG_DIR), so a
// logout in one profile cannot delete another's keys. keyDir is where the file backend keeps
// its PEMs — deliberately not the config dir (see store.KeyDir).
//
// The list is closed on purpose. Adding a backend means adding a Descriptor that documents
// its exportability, backup, access-control and deletion semantics — that documentation is
// what makes a store "approved" under Auth Access v1.
func Registry(configDir, keyDir string) []Backend {
	return append(platformBackends(configDir), NewFile(keyDir, fileBackendRequiresOptIn))
}
