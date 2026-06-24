//go:build unix

package usageaxis

import (
	"os"
	"syscall"
)

// fileID returns the ledger's inode as a stable filesystem identity. A new inode
// (rename-and-recreate, or a fresh file at the same path) means the ledger rotated,
// which the byte-offset check alone cannot see. Returns ok=false if the platform's
// FileInfo carries no inode.
func fileID(fi os.FileInfo) (uint64, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino), true
	}
	return 0, false
}
