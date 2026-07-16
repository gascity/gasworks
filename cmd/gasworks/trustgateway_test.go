package main

import (
	"strings"
	"testing"
)

// withStdin swaps the package stdin for the duration of fn.
func withStdin(s string, fn func()) {
	orig := stdin
	stdin = strings.NewReader(s)
	defer func() { stdin = orig }()
	fn()
}

func TestTrustGatewayListShowsDefault(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	out, errOut, code := capture(t, func() int { return run([]string{"trust-gateway", "--list"}) })
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "gw.beads.gascity.com") || !strings.Contains(out, "(built-in)") {
		t.Fatalf("list = %q, want the built-in default", out)
	}
}

func TestTrustGatewayAddWithYes(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	out, errOut, code := capture(t, func() int {
		return run([]string{"trust-gateway", "GW.Corp.Example", "--yes"})
	})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "Trusted gateway gw.corp.example.") {
		t.Fatalf("stdout = %q", out)
	}
	// It now appears in the list.
	lout, _, _ := capture(t, func() int { return run([]string{"trust-gateway", "--list"}) })
	if !strings.Contains(lout, "gw.corp.example") {
		t.Fatalf("list = %q, want the added gateway", lout)
	}
}

func TestTrustGatewayPromptAbortsAndConfirms(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())

	// A "no" answer aborts (exit 1, nothing added).
	var code int
	var errOut string
	withStdin("n\n", func() {
		_, errOut, code = capture(t, func() int { return run([]string{"trust-gateway", "gw.corp.example"}) })
	})
	if code != 1 || !strings.Contains(errOut, "aborted") {
		t.Fatalf("no-answer: exit=%d stderr=%q, want abort", code, errOut)
	}

	// A "y" answer adds it.
	var out string
	withStdin("y\n", func() {
		out, errOut, code = capture(t, func() int { return run([]string{"trust-gateway", "gw.corp.example"}) })
	})
	if code != 0 || !strings.Contains(out, "Trusted gateway gw.corp.example.") {
		t.Fatalf("yes-answer: exit=%d out=%q stderr=%q", code, out, errOut)
	}
}

func TestTrustGatewayRemove(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	if _, _, code := capture(t, func() int { return run([]string{"trust-gateway", "gw.corp.example", "--yes"}) }); code != 0 {
		t.Fatal("add failed")
	}
	out, errOut, code := capture(t, func() int {
		return run([]string{"trust-gateway", "gw.corp.example", "--remove"})
	})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "Removed trusted gateway gw.corp.example.") {
		t.Fatalf("stdout = %q", out)
	}
}

func TestTrustGatewayDefaultNotRemovable(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	_, errOut, code := capture(t, func() int {
		return run([]string{"trust-gateway", "gw.beads.gascity.com", "--remove"})
	})
	if code != 1 || !strings.Contains(errOut, "built-in default") {
		t.Fatalf("exit=%d stderr=%q, want a not-removable error", code, errOut)
	}
}

func TestTrustGatewayInvalidHost(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	_, errOut, code := capture(t, func() int {
		return run([]string{"trust-gateway", "bad host", "--yes"})
	})
	if code != 1 || !strings.Contains(errOut, "invalid host") {
		t.Fatalf("exit=%d stderr=%q, want an invalid-host error", code, errOut)
	}
}
