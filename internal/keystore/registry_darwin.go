//go:build darwin

package keystore

func platformBackends() []Backend { return []Backend{NewKeychain()} }
