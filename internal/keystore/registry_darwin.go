//go:build darwin

package keystore

// fileBackendRequiresOptIn: macOS has the login keychain, so a key only lands in a plain
// file when the operator explicitly asks for it.
const fileBackendRequiresOptIn = true

func platformBackends(configDir string) []Backend { return []Backend{NewKeychain(configDir)} }
