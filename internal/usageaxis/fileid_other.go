//go:build !unix

package usageaxis

import "os"

// fileID has no portable inode on non-unix platforms; rotation detection there falls
// back to the size<offset truncation check.
func fileID(os.FileInfo) (uint64, bool) { return 0, false }
