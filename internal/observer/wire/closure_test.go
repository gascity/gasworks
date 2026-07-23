package wire_test

import (
	"os/exec"
	"strings"
	"testing"
)

// bannedClosureImports are packages that must never appear in the
// gasworks-observer binary's dependency closure. The vendored+generated Observer
// wire contract is deliberately self-contained: it must not drag in platform/Gas
// City code or the legacy telemetry axes. E1.11 formalizes this ban for the whole
// endpoint; this guard protects P0.5's generated output now.
var bannedClosureImports = []string{
	"github.com/gastownhall/gascity",
	"github.com/gascity/gasworks/internal/eventsaxis",
	"github.com/gascity/gasworks/internal/usageaxis",
	"github.com/gascity/gasworks/internal/recallaxis",
}

// TestWirePackageDependencyClosureIsClean runs `go list -deps` over the generated
// wire package's non-test build closure and fails if any banned import is present.
// Non-test closure is exactly the binary closure: the test-only schema validator
// (santhosh-tekuri) and the build-time generator (oapi-codegen) never appear here.
func TestWirePackageDependencyClosureIsClean(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-mod=vendor", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")

	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		for _, banned := range bannedClosureImports {
			if dep == banned || strings.HasPrefix(dep, banned+"/") {
				t.Errorf("banned import %q reachable from the wire package closure (via %q)", banned, dep)
			}
		}
		// The build-time generator must not leak into the closure either.
		if strings.Contains(dep, "oapi-codegen/oapi-codegen") {
			t.Errorf("generator %q leaked into the wire package closure", dep)
		}
	}
}
