//go:build windows

package rootpolicy

// openNoFollowNonBlock has no Windows equivalent; the opened file is still required to be a regular
// file.
const openNoFollowNonBlock = 0

func isSymlinkRefusal(error) bool { return false }
