//go:build !windows

package keystore

// lockdownPath is a no-op away from Windows: the POSIX modes the file backend sets (0600 key
// in a 0700 directory) already restrict the key to its owner.
func lockdownPath(string) {}
