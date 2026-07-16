package gateway

import (
	"strings"
	"testing"
)

func noWarn(string) {}

func execInfo(t *testing.T, origin, dialHost string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`{"apiVersion":"` + ExecInfoAPIVersion + `"`)
	if origin != "" {
		sb.WriteString(`,"origin":"` + origin + `"`)
	}
	sb.WriteString(`,"spec":{`)
	if dialHost != "" {
		sb.WriteString(`"dialHost":"` + dialHost + `",`)
	}
	sb.WriteString(`"dialPort":3306,"database":"bd_prj_x"}}`)
	return sb.String()
}

func TestResolvePrecedenceExecInfoWins(t *testing.T) {
	// exec-info and flag AGREE (canonically) -> fine, exec-info host chosen.
	d, err := Resolve("GW.Beads.GasCity.com", execInfo(t, "bd", "gw.beads.gascity.com"), noWarn)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "gw.beads.gascity.com" || !d.BDOriginated {
		t.Fatalf("got %+v", d)
	}
}

func TestResolveDisagreementIsAlwaysHardError(t *testing.T) {
	_, err := Resolve("gw.other.example", execInfo(t, "bd", "gw.beads.gascity.com"), noWarn)
	if err == nil {
		t.Fatal("want a hard error when exec-info and --gateway disagree")
	}
	if !strings.Contains(err.Error(), "conflicting mint destinations") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveExecInfoOnly(t *testing.T) {
	d, err := Resolve("", execInfo(t, "bd", "evil.example"), noWarn)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "evil.example" || !d.BDOriginated {
		t.Fatalf("got %+v", d)
	}
}

func TestResolveFlagOnly(t *testing.T) {
	d, err := Resolve("gw.beads.gascity.com", "", noWarn)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "gw.beads.gascity.com" || d.BDOriginated {
		t.Fatalf("got %+v", d)
	}
}

func TestResolveNeitherHuman(t *testing.T) {
	// No exec-info, no flag: direct human use -> no destination, not bd-originated.
	d, err := Resolve("", "", noWarn)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "" || d.BDOriginated {
		t.Fatalf("got %+v", d)
	}
}

func TestResolveBDOriginatedNoDialHost(t *testing.T) {
	// exec-info present, origin=bd, but no dialHost -> flagged bd-originated with empty host.
	d, err := Resolve("", execInfo(t, "bd", ""), noWarn)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "" || !d.BDOriginated {
		t.Fatalf("got %+v", d)
	}
}

// TestGateBDOriginatedNoDestinationFailsClosed is exit test 1c: origin=bd with no dialHost
// refuses even in warn mode.
func TestGateBDOriginatedNoDestinationFailsClosed(t *testing.T) {
	dest := Destination{Host: "", BDOriginated: true}
	for _, mode := range []Mode{Warn, Enforce} {
		if err := Gate(dest, mode, noWarn); err == nil {
			t.Fatalf("mode %v: want refusal for bd-originated mint with no destination", mode)
		}
	}
}

func TestGateHumanNoDestinationMints(t *testing.T) {
	if err := Gate(Destination{Host: "", BDOriginated: false}, Enforce, noWarn); err != nil {
		t.Fatalf("human no-destination must mint (fail open), got %v", err)
	}
}

func TestGateUntrustedWarnVsEnforce(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	dest := Destination{Host: "evil.example", BDOriginated: true}

	var warned string
	if err := Gate(dest, Warn, func(s string) { warned = s }); err != nil {
		t.Fatalf("warn mode must mint, got %v", err)
	}
	if !strings.Contains(warned, "WOULD REFUSE") || !strings.Contains(warned, "evil.example") {
		t.Fatalf("warn message = %q", warned)
	}

	err := Gate(dest, Enforce, noWarn)
	if err == nil {
		t.Fatal("enforce mode must refuse an untrusted gateway")
	}
	if _, ok := err.(*RefusalError); !ok {
		t.Fatalf("want *RefusalError, got %T", err)
	}
	if !strings.Contains(err.Error(), "refusing to mint a beads credential for unknown gateway 'evil.example'") {
		t.Fatalf("refusal = %q", err.Error())
	}
}

func TestGateTrustedDefaultMints(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	dest := Destination{Host: "gw.beads.gascity.com", BDOriginated: true}
	if err := Gate(dest, Enforce, noWarn); err != nil {
		t.Fatalf("compiled-default gateway must mint, got %v", err)
	}
}

func TestModeFromEnv(t *testing.T) {
	cases := []struct {
		in    string
		want  Mode
		known bool
	}{
		{"", DefaultMode, true},
		{"enforce", Enforce, true},
		{"ENFORCE", Enforce, true},
		{"1", Enforce, true},
		{"warn", Warn, true},
		{"0", Warn, true},
		{"nonsense", DefaultMode, false},
	}
	for _, tc := range cases {
		got, known := ModeFromEnv(tc.in)
		if got != tc.want || known != tc.known {
			t.Errorf("ModeFromEnv(%q) = (%v,%v), want (%v,%v)", tc.in, got, known, tc.want, tc.known)
		}
	}
}
