//go:build darwin

package local

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUIDFromSocket reads the connected peer's UID via LOCAL_PEERCRED. A syscall failure is
// returned to the server, which rejects the connection fail-closed.
func peerUIDFromSocket(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("observer local: raw conn: %w", err)
	}
	var cred *unix.Xucred
	var opErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); ctlErr != nil {
		return 0, fmt.Errorf("observer local: peer cred control: %w", ctlErr)
	}
	if opErr != nil {
		return 0, fmt.Errorf("observer local: peer cred: %w", opErr)
	}
	return cred.Uid, nil
}
