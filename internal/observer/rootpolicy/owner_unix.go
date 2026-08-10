//go:build unix

package rootpolicy

import (
	"os"
	"syscall"
)

func ownerSupplied(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}
