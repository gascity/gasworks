package keystore

// Registry returns the closed per-platform backend list, most preferred first: the platform
// keystores this build knows about, then the opt-in file backend. Callers pass it to Select
// (to enrol a new key) or ByID (to reach an already enrolled one).
//
// The list is closed on purpose. Adding a backend means adding a Descriptor that documents
// its exportability, backup, access-control and deletion semantics — that documentation is
// what makes a store "approved" under Auth Access v1.
func Registry(configDir string) []Backend {
	return append(platformBackends(), NewFile(configDir))
}
