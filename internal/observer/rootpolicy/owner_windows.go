//go:build windows

package rootpolicy

import "os"

// Windows does not expose a Unix uid in os.FileInfo. The owner-only ACL check is delegated to the
// daemon's enclosing owner-only state/config directory there; this package is not linked by the
// Unix observer runtime on that platform.
func ownerSupplied(os.FileInfo) bool { return true }
