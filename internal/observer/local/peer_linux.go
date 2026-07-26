//go:build linux

package local

import (
	"fmt"
	"net"
	"syscall"
)

// peerUIDFromSocket reads the connected peer's UID via Linux SO_PEERCRED. It uses the raw
// connection control seam so it never dups the fd or fights the runtime poller.
func peerUIDFromSocket(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("observer local: raw conn: %w", err)
	}
	var ucred *syscall.Ucred
	var opErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		ucred, opErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctlErr != nil {
		return 0, fmt.Errorf("observer local: peer cred control: %w", ctlErr)
	}
	if opErr != nil {
		return 0, fmt.Errorf("observer local: peer cred: %w", opErr)
	}
	return ucred.Uid, nil
}
