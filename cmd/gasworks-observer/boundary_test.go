//go:build linux

package main

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// This is the permanent enforcement of the observer's GOVERNING RULE: ZERO Gas City
// dependency (see main.go). It models the committed per-package closure guards
// (TestCodexAdapterDependencyClosureIsClean, TestUploadDependencyClosureIsClean,
// TestWirePackageDependencyClosureIsClean) but scopes the check to the WHOLE endpoint —
// the gasworks-observer binary plus the entire internal/observer tree — and enforces it as
// an explicit ALLOW-LIST rather than a banned-list: every non-stdlib package in the build
// closure must be one we consciously allow, so a future import that pulls in Gas City (or
// any other new dependency) fails the build instead of silently widening the surface.

// boundaryTargets are the two package sets whose non-test build closure IS the observer
// endpoint. Full import paths are used so the check is independent of the test's working
// directory. `-deps` over them yields the union of their transitive build closures — which,
// for a non-test `go list`, is exactly what links into the binary.
var boundaryTargets = []string{
	"github.com/gascity/gasworks/cmd/gasworks-observer",
	"github.com/gascity/gasworks/internal/observer/...",
}

const observerModule = "github.com/gascity/gasworks"

// allowedModulePrefixes are the ONLY first-party import paths the endpoint may reach. The
// binary itself, the Gas-City-free internal/observer tree, and the vendored ingest contract
// artifact (contracts/observer/v1 — the embedded corpus + generated-from schema) are in;
// every other github.com/gascity/gasworks/internal/* or cmd/* path is out.
var allowedModulePrefixes = []string{
	observerModule + "/cmd/gasworks-observer",
	observerModule + "/internal/observer/",
	observerModule + "/internal/observer", // the package itself (no trailing slash)
	observerModule + "/contracts/observer/",
	observerModule + "/contracts/observer",
}

// allowedThirdParty is the closed set of external modules the wire types and the delivery
// transport pull in. Anything else — a new HTTP client, a JSON library, a logging framework
// — must be a conscious, reviewed addition to this list.
var allowedThirdParty = map[string]bool{
	"github.com/apapsch/go-jsonmerge/v2":    true, // oapi-codegen runtime dep (JSON merge for unions)
	"github.com/google/uuid":                true, // observation-id / identifier generation
	"github.com/oapi-codegen/runtime":       true, // generated wire-type runtime helpers
	"github.com/oapi-codegen/runtime/types": true,
	"golang.org/x/sys/unix":                 true, // flock, SO_PEERCRED, boot-id — the daemon's OS seam
}

// bannedPrefixes name the categories the rule forbids, only for a sharper failure message.
// The allow-list above already rejects each of these; this makes the WHY explicit when the
// endpoint accidentally reaches one.
var bannedPrefixes = []struct {
	prefix string
	why    string
}{
	{"github.com/gastownhall/gascity", "Gas City / Gas Town — the endpoint must have ZERO Gas City dependency"},
	{observerModule + "/internal/eventsaxis", "legacy telemetry axis (events)"},
	{observerModule + "/internal/usageaxis", "legacy telemetry axis (usage)"},
	{observerModule + "/internal/recallaxis", "legacy telemetry axis (recall)"},
}

// TestObserverEndpointDependencyClosureIsClean runs `go list -deps` over the whole endpoint
// closure and fails on any non-stdlib package that is not in the explicit allow-list. It is
// the load-bearing guard: a future import of a Gas City package, another cmd, a non-observer
// internal package, or a new third-party library is a red build until it is consciously
// added here.
func TestObserverEndpointDependencyClosureIsClean(t *testing.T) {
	deps := endpointClosure(t)
	if len(deps) < 5 {
		t.Fatalf("go list -deps returned only %d packages; the closure query looks wrong: %v", len(deps), deps)
	}

	for _, dep := range deps {
		if isStdlibPackage(dep) {
			continue
		}
		if allowedModulePackage(dep) || allowedThirdParty[dep] {
			continue
		}
		// Not allowed: fail, and name the forbidden category when we recognise it.
		if why, banned := bannedReason(dep); banned {
			t.Errorf("banned import %q reachable from the observer endpoint closure (%s)", dep, why)
			continue
		}
		t.Errorf("import %q is not in the observer endpoint allow-list; a new dependency must be a conscious decision — "+
			"add it to allowedModulePrefixes/allowedThirdParty in boundary_test.go if it is intended", dep)
	}
}

// TestObserverEndpointAllowListIsExhaustive is a companion sanity check: it proves the
// allow-list actually accounts for the current closure (no stale/dead allow entries would
// hide a regression) by asserting the four expected third-party modules are present. If the
// wire types stop needing one, this catches the drift so the allow-list stays honest.
func TestObserverEndpointAllowListIsExhaustive(t *testing.T) {
	deps := endpointClosure(t)
	present := map[string]bool{}
	for _, d := range deps {
		present[d] = true
	}
	for _, want := range []string{
		"golang.org/x/sys/unix",
		"github.com/google/uuid",
		"github.com/oapi-codegen/runtime",
	} {
		if !present[want] {
			t.Errorf("expected allow-listed third-party %q in the endpoint closure but it is absent; "+
				"the allow-list may be stale", want)
		}
	}
}

// endpointClosure returns the sorted, de-duplicated non-test build closure of the endpoint.
func endpointClosure(t *testing.T) []string {
	t.Helper()
	args := append([]string{"list", "-deps", "-mod=vendor"}, boundaryTargets...)
	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	seen := map[string]bool{}
	var deps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		deps = append(deps, line)
	}
	sort.Strings(deps)
	return deps
}

// isStdlibPackage reports whether an import path is part of the standard library. Stdlib
// import paths have no dot in their first path segment ("os", "net/http",
// "crypto/internal/..."), and the Go toolchain's own vendored std dependencies are reported
// under a "vendor/" first segment ("vendor/golang.org/x/net/http2/hpack") — both have a
// dot-free first segment, so this one rule captures every stdlib package while excluding
// real module dependencies (github.com/..., golang.org/x/sys/unix).
func isStdlibPackage(dep string) bool {
	first := dep
	if i := strings.IndexByte(dep, '/'); i >= 0 {
		first = dep[:i]
	}
	return !strings.Contains(first, ".")
}

// allowedModulePackage reports whether a first-party (this-module) import path is allowed.
// A slash-less allow-list entry matches ONLY exactly (the package itself); prefix matching is
// reserved for subtree entries ending in "/", so a sibling like internal/observerx or a future
// internal/observerctl is NOT silently admitted by the slash-less internal/observer entry.
func allowedModulePackage(dep string) bool {
	if !strings.HasPrefix(dep, observerModule) {
		return false
	}
	for _, p := range allowedModulePrefixes {
		if dep == p {
			return true
		}
		if strings.HasSuffix(p, "/") && strings.HasPrefix(dep, p) {
			return true
		}
	}
	return false
}

// TestAllowedModulePackageRejectsSiblingPrefixes locks the fix for the slash-less allow-list
// prefix escape: a sibling path whose name merely starts with an allowed slash-less entry
// (internal/observerx, contracts/observerctl, cmd/gasworks-observerd) must NOT be admitted, while
// the exact package and its genuine subtree are.
func TestAllowedModulePackageRejectsSiblingPrefixes(t *testing.T) {
	m := observerModule
	allowed := []string{
		m + "/cmd/gasworks-observer",
		m + "/internal/observer",
		m + "/internal/observer/local",
		m + "/internal/observer/adapter/codex",
		m + "/contracts/observer",
		m + "/contracts/observer/v1",
	}
	rejected := []string{
		m + "/internal/observerx",
		m + "/internal/observerctl",
		m + "/internal/observerx/deep",
		m + "/contracts/observerctl",
		m + "/cmd/gasworks-observerd",
		m + "/internal/version",
		m + "/cmd/gasworks",
	}
	for _, d := range allowed {
		if !allowedModulePackage(d) {
			t.Errorf("allowed package rejected: %s", d)
		}
	}
	for _, d := range rejected {
		if allowedModulePackage(d) {
			t.Errorf("sibling/foreign package admitted (prefix escape): %s", d)
		}
	}
}

// bannedReason returns the human reason a dep is forbidden, when it matches a known banned
// category.
func bannedReason(dep string) (string, bool) {
	for _, b := range bannedPrefixes {
		if dep == b.prefix || strings.HasPrefix(dep, b.prefix+"/") {
			return b.why, true
		}
	}
	return "", false
}
