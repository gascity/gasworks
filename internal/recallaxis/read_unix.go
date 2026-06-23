//go:build !windows

package recallaxis

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// readCappedOS opens path with O_NOFOLLOW (refuse a symlink at the path), fstats the
// open FD (no TOCTOU), requires a regular file, and reads up to maxBytes+1. It DROPS
// the file (ok=false) when the stat size already exceeds maxBytes OR when the file grew
// past maxBytes between stat and read (size-race guard). Source-Size is the stat size;
// Content-Length (set by the caller) is len(data) — distinct values.
func readCappedOS(path string, maxBytes int64) (readResult, bool) {
	// O_NONBLOCK so a FIFO/device opens immediately (a writerless FIFO would otherwise
	// block the reader-open forever); fstat then rejects the non-regular file below.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return readResult{}, false
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return readResult{}, false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return readResult{}, false
	}
	if st.Size > maxBytes {
		return readResult{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return readResult{}, false
	}
	if int64(len(data)) > maxBytes {
		return readResult{}, false // grew between stat and read
	}
	return readResult{data: data, size: st.Size, mtimeNS: st.Mtim.Nano()}, true
}
