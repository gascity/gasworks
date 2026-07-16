package gateway

import (
	"os"
	"sync"
	"testing"
)

func TestAllowlistGoldenPathHasDefault(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	al, err := LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if !al.Contains("gw.beads.gascity.com") {
		t.Fatal("compiled default must be trusted with no file")
	}
	if al.Contains("evil.example") {
		t.Fatal("unknown host must not be trusted")
	}
	if _, err := os.Stat(allowlistPath()); !os.IsNotExist(err) {
		t.Fatal("LoadAllowlist must not create the file")
	}
}

func TestAllowlistAddAndCanonicalize(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	canon, added, err := AddGateway("GW.Corp.Example.")
	if err != nil {
		t.Fatalf("AddGateway: %v", err)
	}
	if canon != "gw.corp.example" || !added {
		t.Fatalf("got (%q,%v)", canon, added)
	}
	al, _ := LoadAllowlist()
	if !al.Contains("gw.corp.example") {
		t.Fatal("added gateway not trusted")
	}
	// Adding again (any casing) is a no-op.
	if _, added, _ := AddGateway("gw.corp.example"); added {
		t.Fatal("re-adding must report not-added")
	}
}

func TestAllowlistDefaultsNotRemovable(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	if _, added, _ := AddGateway("gw.beads.gascity.com"); added {
		t.Fatal("adding a default must report not-added (already built-in)")
	}
	if _, err := RemoveGateway("gw.beads.gascity.com"); err == nil {
		t.Fatal("a compiled default must not be removable")
	}
}

func TestAllowlistRemove(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	if _, _, err := AddGateway("gw.corp.example"); err != nil {
		t.Fatalf("AddGateway: %v", err)
	}
	if _, err := RemoveGateway("gw.corp.example"); err != nil {
		t.Fatalf("RemoveGateway: %v", err)
	}
	al, _ := LoadAllowlist()
	if al.Contains("gw.corp.example") {
		t.Fatal("removed gateway still trusted")
	}
	if _, err := RemoveGateway("gw.corp.example"); err == nil {
		t.Fatal("removing an absent gateway must error")
	}
}

func TestAllowlistCorruptFileIsHardError(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	if err := os.MkdirAll(store_ConfigDir(t), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllowlist(); err == nil {
		t.Fatal("a corrupt allowlist file must be a hard error")
	}
}

// store_ConfigDir mirrors store.ConfigDir without importing it into the test (allowlistPath
// already uses it); it just makes the corrupt-file test explicit about where the file lands.
func store_ConfigDir(t *testing.T) string {
	t.Helper()
	return os.Getenv("GASWORKS_CONFIG_DIR")
}

// TestAllowlistConcurrentAddsNoLostEntries proves the flock-guarded RMW does not drop entries
// when many writers race (many agents share one machine).
func TestAllowlistConcurrentAddsNoLostEntries(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	const n = 12
	var wg sync.WaitGroup
	hosts := make([]string, n)
	for i := 0; i < n; i++ {
		hosts[i] = "gw" + string(rune('a'+i)) + ".example"
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if _, _, err := AddGateway(h); err != nil {
				t.Errorf("AddGateway(%q): %v", h, err)
			}
		}(hosts[i])
	}
	wg.Wait()

	al, err := LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	for _, h := range hosts {
		if !al.Contains(h) {
			t.Errorf("concurrent add dropped %q", h)
		}
	}
}
