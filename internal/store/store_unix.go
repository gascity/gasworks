//go:build !windows

package store

// lockdownFile is a no-op on POSIX: the credentials file is already created mode 0600
// (and the config dir 0700), so the filesystem permission bits already restrict it to the
// owning user. The Windows build replaces this with an ACL lockdown (NTFS ignores the
// POSIX mode bits, so it needs an explicit icacls call).
func lockdownFile(string) {}
