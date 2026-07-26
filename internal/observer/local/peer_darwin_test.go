//go:build darwin

package local

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinPeerUIDFromSocketUsesLocalCredentials(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer func() { _ = listener.Close() }()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("AcceptUnix: %v", err)
	}
	defer func() { _ = server.Close() }()

	uid, err := peerUIDFromSocket(server)
	if err != nil {
		t.Fatalf("peerUIDFromSocket: %v", err)
	}
	if want := uint32(os.Geteuid()); uid != want {
		t.Fatalf("peer uid = %d, want %d", uid, want)
	}
}
