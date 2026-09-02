//go:build !darwin

package keystore

// platformBackends is empty away from macOS. Linux (Secret Service / TPM2-PKCS#11) and
// Windows (CNG / Credential Manager) are registry slots this build does not fill yet, so on
// those hosts the only registered store is the opt-in file backend and an operator who has
// not opted in gets the fail-closed enrolment error rather than a silent plaintext write.
func platformBackends() []Backend { return nil }
