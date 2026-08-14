//go:build linux

package observer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShellcheckPackScripts lints install.sh and doctor.sh; any shellcheck finding fails.
func TestShellcheckPackScripts(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed")
	}
	for _, f := range []string{"install.sh", "doctor.sh"} {
		out, err := exec.Command("shellcheck", scriptPath(t, f)).CombinedOutput()
		if err != nil {
			t.Errorf("shellcheck %s reported findings:\n%s", f, out)
		}
	}
}

// TestServiceUnitIsUserScoped asserts the standalone-user-service invariant structurally: the
// unit installs into the user target, hardens against privilege gain, runs the observer binary,
// and never escalates (no User=/Group= root, no system multi-user target).
func TestServiceUnitIsUserScoped(t *testing.T) {
	data, err := os.ReadFile(scriptPath(t, filepath.Join("deploy", "gasworks-companion.service")))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	mustContain := []string{
		"WantedBy=default.target", // user session target, not multi-user.target
		"ExecStart=%h/.local/bin/gasworks-companion",
		"NoNewPrivileges=true",
		"EnvironmentFile=%h/.config/gasworks-companion/observer.env",
	}
	for _, s := range mustContain {
		if !strings.Contains(unit, s) {
			t.Errorf("service unit missing %q", s)
		}
	}
	mustNotContain := []string{
		"WantedBy=multi-user.target", // would make it a system service
		"User=root",
		"Group=root",
		"ExecStartPre=/usr/bin/sudo",
	}
	for _, s := range mustNotContain {
		if strings.Contains(unit, s) {
			t.Errorf("service unit must not contain %q (breaks the standalone-user invariant)", s)
		}
	}
}

// TestServiceUnitSystemdVerify runs `systemd-analyze verify` against the shipped unit with a
// private HOME containing the referenced binary + EnvironmentFile, so the %h paths resolve and
// the only thing under test is the unit's validity.
func TestServiceUnitSystemdVerify(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not installed")
	}
	home := t.TempDir()
	// Place the ExecStart binary and EnvironmentFile at the %h-relative default locations.
	bin := filepath.Join(home, ".local", "bin", companionBinName)
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(home, ".config", "gasworks-companion")
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("systemd-analyze", "verify", "--user", scriptPath(t, filepath.Join("deploy", "gasworks-companion.service")))
	cmd.Env = append(os.Environ(), "HOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("systemd-analyze verify failed: %v\n%s", err, out)
	}
}

// TestDoctorFlagsBadPermsAndDetectsWAL drives doctor.sh against a hand-built install and asserts
// it PASSES a well-formed owner-only install with a nonempty WAL, and FAILS when a secret file
// is world-readable — the owner-only + nonempty-WAL-survives checks the plan requires.
func TestDoctorFlagsBadPermsAndDetectsWAL(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	fx := buildFixture(t, dir)

	if out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0), "--skip-service"); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	p := pathsFor(home)
	// Seed a nonempty WAL so --expect-wal is satisfiable.
	if err := os.WriteFile(filepath.Join(p.state, "wal", "000001.seg"), []byte("SEG"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Good install -> doctor passes.
	if out, err := runScript(t, installEnv(home), scriptPath(t, "doctor.sh"), "--expect-wal"); err != nil {
		t.Fatalf("doctor should pass a well-formed install: %v\n%s", err, out)
	}

	// Break owner-only: make the config env world-readable -> doctor must fail.
	if err := os.Chmod(filepath.Join(p.config, "observer.env"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runScript(t, installEnv(home), scriptPath(t, "doctor.sh"), "--expect-wal")
	if err == nil {
		t.Fatalf("doctor should fail on a group/other-accessible secret\n%s", out)
	}
	if !strings.Contains(out, "[FAIL]") {
		t.Errorf("expected a [FAIL] line; got:\n%s", out)
	}
}

func TestDoctorAdoptsLegacyDefaultPaths(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	bin := filepath.Join(home, ".local", "bin", companionBinName)
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	legacyState := filepath.Join(home, ".local", "state", "gasworks-observer")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(legacyState, "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyState, "wal", "000001.seg"), []byte("DURABLE"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runScript(t, installEnv(home), scriptPath(t, "doctor.sh"), "--expect-wal")
	if err != nil {
		t.Fatalf("doctor did not adopt legacy defaults: %v\n%s", err, out)
	}
}
