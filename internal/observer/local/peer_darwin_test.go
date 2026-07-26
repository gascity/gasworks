//go:build darwin

package local

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinPeerUIDFromSocketUsesLocalCredentials(t *testing.T) {
	// Darwin limits Unix-domain socket paths to roughly 104 bytes. Go's test temp
	// directory can exceed that on hosted macOS runners, so bind in a deliberately
	// short private directory beneath /tmp.
	socketDir, err := os.MkdirTemp("/tmp", "gw-peer-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDir); err != nil {
			t.Errorf("RemoveAll socket directory: %v", err)
		}
	})
	socketPath := filepath.Join(socketDir, "peer.sock")
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
