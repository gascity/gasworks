//go:build windows

// Package lockdown restricts a file or directory to the user that owns it on platforms where
// the POSIX mode bits the rest of the CLI sets are not enough.
package lockdown

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// Apply re-applies a user-only ACL to path, mirroring the Python store's
//
//	icacls <path> /inheritance:r /grant:r <user>:F
//
// On NTFS the 0600 chmod the cross-platform code does is a no-op, so a freshly created file
// inherits the parent directory's ACL and could be readable by other local users.
// /inheritance:r strips the inherited ACEs; /grant:r <user>:F then grants ONLY the current
// user full control.
//
// Best-effort: any failure is logged to stderr (never silent) but not returned — every caller
// runs this after the bytes are already on disk, and failing the whole operation over a
// hardening step would discard a successful login, enrolment, or mint.
func Apply(path string) {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		fmt.Fprintf(os.Stderr, "gasworks: warning: could not resolve current user to lock down %s ACL: %v\n", path, err)
		return
	}
	// icacls accepts the DOMAIN\user (or just user) that user.Current() returns in Username.
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", u.Username+":F")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "gasworks: warning: failed to lock down %s ACL (icacls): %v: %s\n", path, err, out)
	}
}
