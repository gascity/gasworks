//go:build !windows

// Package lockdown restricts a file or directory to the user that owns it on platforms where
// the POSIX mode bits the rest of the CLI sets are not enough.
package lockdown

// Apply is a no-op away from Windows: every caller has already created the file 0600 (and its
// directory 0700), so the filesystem permission bits restrict it to the owning user. The
// Windows build replaces this with an ACL lockdown, because NTFS ignores the POSIX mode bits.
func Apply(string) {}
