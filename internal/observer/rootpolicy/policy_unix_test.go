//go:build unix

package rootpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestPolicyReadRefusesWhatIsNotAnOwnerOnlyRegularFile: every policy read — LoadPolicy and the
// narrowing-only DecodeFileRecords — refuses a FIFO (without blocking on it), a symlink, and an
// oversized document, before reading a byte of policy from it.
func TestPolicyReadRefusesWhatIsNotAnOwnerOnlyRegularFile(t *testing.T) {
	root := t.TempDir()
	valid := writePolicy(t, `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"`+root+`","generation":1,"active":true,"mode":"backfill"}]}`)
	fifo := filepath.Join(t.TempDir(), "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	big := writePolicy(t, `{"schema_version":"gasworks.companion.root-policy/v1","roots":[]}`+strings.Repeat(" ", MaxDocumentBytes))
	for name, path := range map[string]string{"fifo": fifo, "symlink": link, "oversized": big} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy(path); err == nil {
				t.Fatal("LoadPolicy accepted it")
			}
			if _, err := DecodeFileRecords(path); err == nil {
				t.Fatal("DecodeFileRecords accepted it")
			}
		})
	}
	if _, err := LoadPolicy(valid); err != nil {
		t.Fatalf("LoadPolicy(valid): %v", err)
	}
}
