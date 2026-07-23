//go:build unix

package codex

import (
	"os/exec"
	"strings"
	"testing"
)

// bannedClosureImports are packages that must never appear in the Codex adapter's non-test build
// closure. The adapter depends only on the standard library plus the vendored, self-contained
// internal/observer/{evidence,wire} contract. It must NOT reach the daemon socket package
// directly (internal/observer/local) — E1.10 wires that in behind the DaemonSeam interface — and
// it must never drag in Gas City or the legacy telemetry axes.
var bannedClosureImports = []string{
	"github.com/gastownhall/gascity",
	"github.com/gascity/gasworks/internal/observer/local",
	"github.com/gascity/gasworks/internal/eventsaxis",
	"github.com/gascity/gasworks/internal/usageaxis",
	"github.com/gascity/gasworks/internal/recallaxis",
}

// TestCodexAdapterDependencyClosureIsClean runs `go list -deps` over the package's non-test build
// closure and fails on any banned import. Non-test closure is exactly what enters the
// gasworks-observer binary.
func TestCodexAdapterDependencyClosureIsClean(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-mod=vendor", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		for _, banned := range bannedClosureImports {
			if dep == banned || strings.HasPrefix(dep, banned+"/") {
				t.Errorf("banned import %q reachable from the codex adapter closure (via %q)", banned, dep)
			}
		}
	}
}
