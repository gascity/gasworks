package upload

import (
	"os/exec"
	"strings"
	"testing"
)

// bannedClosureImports must never appear in the gasworks-observer binary's dependency
// closure through the upload package. Delivery is deliberately confined to the standard
// library (net/http, crypto/tls, os/exec) plus the committed observer spool/wire packages;
// it must not drag in platform/Gas City code, the legacy telemetry axes, or a third-party
// HTTP client library (E1.9 mandates net/http). E1.11 formalizes the whole-endpoint ban;
// this guard protects the upload package now.
var bannedClosureImports = []string{
	"github.com/gastownhall/gascity",
	"github.com/gascity/gasworks/internal/eventsaxis",
	"github.com/gascity/gasworks/internal/usageaxis",
	"github.com/gascity/gasworks/internal/recallaxis",
}

// bannedHTTPClientSubstrings flags any third-party HTTP client library sneaking into the
// closure. Delivery uses net/http directly.
var bannedHTTPClientSubstrings = []string{
	"go-resty/resty",
	"parnurzeal/gorequest",
	"valyala/fasthttp",
	"hashicorp/go-retryablehttp",
}

// TestUploadDependencyClosureIsClean runs `go list -deps` over the upload package's
// non-test build closure and fails on any banned or third-party-HTTP-client import.
func TestUploadDependencyClosureIsClean(t *testing.T) {
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
				t.Errorf("banned import %q reachable from the upload package closure (via %q)", banned, dep)
			}
		}
		for _, sub := range bannedHTTPClientSubstrings {
			if strings.Contains(dep, sub) {
				t.Errorf("third-party HTTP client %q leaked into the upload package closure (via %q)", sub, dep)
			}
		}
	}
}
