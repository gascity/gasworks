//go:build windows

package keystore

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// lockdownPath re-applies a user-only ACL to path, mirroring what the credential store does
// for credentials.json:
//
//	icacls <path> /inheritance:r /grant:r <user>:F
//
// On NTFS the POSIX mode the cross-platform code sets is a no-op, so a freshly created key
// file (or its directory) inherits the parent's ACL and could be readable by other local
// users. /inheritance:r strips the inherited ACEs; /grant:r <user>:F then grants ONLY the
// current user full control.
//
// Best-effort: a failure is reported on stderr but does not fail the enrolment, which has
// already written the key — the same trade the credential store makes.
func lockdownPath(path string) {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		fmt.Fprintf(os.Stderr, "gasworks: warning: could not resolve current user to lock down %s ACL: %v\n", path, err)
		return
	}
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", u.Username+":F")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "gasworks: warning: failed to lock down %s ACL (icacls): %v: %s\n", path, err, out)
	}
}
