//go:build unix

package rootpolicy

import (
	"errors"
	"syscall"
)

// openNoFollowNonBlock makes the policy open refuse a symlinked final component and never block on a
// FIFO; the opened file is then required to be a regular file.
const openNoFollowNonBlock = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isSymlinkRefusal reports whether an open failed because the final component is a symlink.
func isSymlinkRefusal(err error) bool { return errors.Is(err, syscall.ELOOP) }
