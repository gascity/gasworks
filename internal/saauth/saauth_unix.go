//go:build !windows

package saauth

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// TokenFromFile reads a bearer token from path with the hardening from
// recall_forwarder.py:124-147 (M13). It is safe to call on every cycle: a rotated
// file is re-validated and re-read each time.
//
//   - open with O_NOFOLLOW so a SYMLINK at the path is refused (ELOOP);
//   - fstat the OPEN FD, not the path, so the file we validate is the file we read
//     (no TOCTOU window);
//   - require a regular file (reject FIFO/dir/device);
//   - require st_uid == getuid() (owned by us);
//   - require mode & 0o077 == 0 (no group/world access bits);
//   - cap the read at 64 KiB and trim surrounding whitespace.
//
// A path that fails open (missing file, symlink, …) returns ("", nil): the axis
// treats an empty token as "skip this cycle", exactly like the Python's "" return.
// A file that opens but fails a hardening check returns a non-nil error so the
// operator sees WHY; the error text never contains the token value.
func TokenFromFile(path string) (string, error) {
	// O_NONBLOCK so opening a FIFO/device returns immediately (otherwise a reader-open
	// of a writerless FIFO blocks forever); fstat then rejects it as non-regular. For a
	// regular file O_NONBLOCK is a no-op on the read path.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		// Includes ELOOP (path is a symlink) and ENOENT (rotated away): skip cycle.
		return "", nil
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", fmt.Errorf("saauth: fstat token file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", fmt.Errorf("saauth: token file is not a regular file; ignoring")
	}
	if uint32(st.Uid) != uint32(os.Getuid()) {
		return "", fmt.Errorf("saauth: token file is not owned by you (chown to your uid); ignoring")
	}
	if st.Mode&0o077 != 0 {
		return "", fmt.Errorf("saauth: token file is group/world-accessible (chmod 600); ignoring")
	}

	buf := make([]byte, maxTokenBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("saauth: read token file: %w", err)
	}
	return trimToken(buf[:n]), nil
}
