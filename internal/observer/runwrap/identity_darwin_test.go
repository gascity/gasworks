//go:build darwin

package runwrap

import (
	"os"
	"strings"
	"testing"
)

func TestDarwinReadSelfIdentityUsesKernelProcessGeneration(t *testing.T) {
	first, err := readSelfIdentity()
	if err != nil {
		t.Fatalf("readSelfIdentity: %v", err)
	}
	second, err := readSelfIdentity()
	if err != nil {
		t.Fatalf("readSelfIdentity second read: %v", err)
	}
	if first != second {
		t.Fatalf("identity changed between reads: %+v != %+v", first, second)
	}
	if first.Pid != int64(os.Getpid()) || first.ProcessStartTime <= 0 {
		t.Fatalf("identity = %+v", first)
	}
	if !strings.HasPrefix(first.BootId, "darwin-boottime-") {
		t.Fatalf("boot id = %q", first.BootId)
	}
}
