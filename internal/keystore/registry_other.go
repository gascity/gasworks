//go:build !darwin

package keystore

// fileBackendRequiresOptIn: Linux (Secret Service / TPM2-PKCS#11) and Windows (CNG /
// Credential Manager) are registry slots this build does not fill yet, so the file backend
// is the only store on those hosts. Requiring an opt-in there would not improve custody —
// it would only stop every non-interactive caller (agents, CI, sandboxes) from establishing
// a session at all. The key is still split out of credentials.json and out of the config
// dir. This flips back to true for a platform as soon as this build has a keystore for it.
const fileBackendRequiresOptIn = false

func platformBackends(string) []Backend { return nil }
