//go:build windows

package store

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// lockdownFile re-applies a user-only ACL to path, mirroring the Python store's
//
//	icacls <path> /inheritance:r /grant:r <user>:F
//
// On NTFS the 0600 chmod the cross-platform Save does is a no-op, so a freshly created
// credentials file inherits the parent directory's ACL and could be readable by other
// local users. /inheritance:r strips the inherited ACEs; /grant:r <user>:F then grants
// ONLY the current user full control. This is the same control the Go CLI dropped when it
// ported the POSIX-only chmod path from Python.
//
// Best-effort: any failure is logged to stderr (never silent) but not returned — the
// credentials are already written at this point, and failing the whole Save would discard
// a successful login over a hardening step.
func lockdownFile(path string) {
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
