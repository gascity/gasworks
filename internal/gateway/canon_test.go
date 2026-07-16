package gateway

import "testing"

// TestCanonicalHostGoldenVectors pins the shared canonicalization algorithm. bd's injector
// and eia-helper implement the identical semantics; these vectors are the cross-repo contract.
func TestCanonicalHostGoldenVectors(t *testing.T) {
	ok := []struct{ in, want string }{
		{"GW.Beads.GasCity.com.", "gw.beads.gascity.com"},
		{"beads", "beads"},
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1.evil.example", "127.0.0.1.evil.example"},
		{"localhost.evil.example", "localhost.evil.example"},
		{"[::ffff:127.0.0.1]", "127.0.0.1"},
		{"::FFFF:127.0.0.1", "127.0.0.1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"0.0.0.0", "0.0.0.0"},
		{"localhost", "localhost"},
		{"evil.example.", "evil.example"},
	}
	for _, tc := range ok {
		got, err := CanonicalHost(tc.in)
		if err != nil {
			t.Errorf("CanonicalHost(%q) errored: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{"", "exa mple.com"}
	for _, in := range bad {
		if got, err := CanonicalHost(in); err == nil {
			t.Errorf("CanonicalHost(%q) = %q, want an error", in, got)
		}
	}
}

// TestCanonicalHostIsDeterministicallyIdempotent guards report==dial: canonicalizing the
// canonical form again must be a no-op, so the value fed to exec-info, the DSN, and the
// cache key can never drift on a re-pass.
func TestCanonicalHostIsIdempotent(t *testing.T) {
	for _, in := range []string{"GW.Beads.GasCity.com.", "2001:DB8::1", "::FFFF:127.0.0.1", "beads"} {
		once, err := CanonicalHost(in)
		if err != nil {
			t.Fatalf("CanonicalHost(%q): %v", in, err)
		}
		twice, err := CanonicalHost(once)
		if err != nil {
			t.Fatalf("CanonicalHost(%q): %v", once, err)
		}
		if once != twice {
			t.Errorf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}
