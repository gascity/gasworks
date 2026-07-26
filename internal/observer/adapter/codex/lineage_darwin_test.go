//go:build darwin

package codex

import (
	"os"
	"testing"
)

func TestDarwinProcessIdentitySourcesAreStableAndPositive(t *testing.T) {
	firstBoot, err := hostBootID()
	if err != nil {
		t.Fatalf("hostBootID: %v", err)
	}
	secondBoot, err := hostBootID()
	if err != nil {
		t.Fatalf("hostBootID second read: %v", err)
	}
	if firstBoot == "" || firstBoot != secondBoot {
		t.Fatalf("boot IDs = %q and %q", firstBoot, secondBoot)
	}

	ppid, start, err := readProcStat(os.Getpid())
	if err != nil {
		t.Fatalf("readProcStat: %v", err)
	}
	if ppid <= 0 || start <= 0 {
		t.Fatalf("process identity = ppid %d, start %d", ppid, start)
	}
}
