//go:build linux

// Package observer_test exercises the O4.2 endpoint installer/doctor and the O4.1 release
// packaging. The tests drive the real gasworks-pack/observer shell scripts (install.sh,
// doctor.sh) against fixture archives with an injected fake cosign, and inspect the goreleaser
// snapshot artifacts. They assert the fail-closed verification chain, owner-only permissions,
// and spool-preserving upgrade/uninstall required by the plan (O4.2), plus the independent
// observer archive inventory (O4.1).
package observer_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	companionBinName      = "gasworks-companion"
	legacyObserverBinName = "gasworks-observer"
)

// scriptPath resolves a pack script relative to the test package dir (the go test cwd).
func scriptPath(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("abs %s: %v", rel, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("missing pack file %s: %v", abs, err)
	}
	return abs
}

// fakeCosign writes a stub cosign that exits with the given code, so the installer's
// verify-blob call can be driven to success (0) or failure (non-zero) hermetically.
func fakeCosign(t *testing.T, dir string, exitCode int) string {
	t.Helper()
	p := filepath.Join(dir, "cosign")
	body := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	return p
}

// fixture bundles a fake signed observer archive plus its checksum/sig/cert side files.
type fixture struct {
	archive       string
	checksums     string
	checksumsSig  string
	checksumsCert string
}

// buildFixture creates a tar.gz containing a stub gasworks-companion binary + LICENSE, then a
// checksums.txt naming it (with placeholder cosign sig/cert the fake cosign ignores).
func buildFixture(t *testing.T, dir string) fixture {
	return buildFixtureForBinary(t, dir, companionBinName)
}

func buildFixtureForBinary(t *testing.T, dir, binName string) fixture {
	t.Helper()
	archive := filepath.Join(dir, binName+"_v9.9.9_linux_amd64.tar.gz")
	writeTarGz(t, archive, map[string][]byte{
		binName:   []byte("#!/bin/sh\necho companion-stub\n"),
		"LICENSE": []byte("MIT\n"),
	})
	sum := sha256File(t, archive)
	checksums := filepath.Join(dir, "checksums.txt")
	line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(archive))
	if err := os.WriteFile(checksums, []byte(line), 0o644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	sig := filepath.Join(dir, "checksums.txt.sig")
	cert := filepath.Join(dir, "checksums.txt.pem")
	mustWrite(t, sig, "signature-placeholder")
	mustWrite(t, cert, "certificate-placeholder")
	return fixture{archive: archive, checksums: checksums, checksumsSig: sig, checksumsCert: cert}
}

func installEnvWithSystemctl(home, systemctlDir, logPath string) []string {
	env := installEnv(home)
	env[1] = "PATH=" + systemctlDir + ":" + os.Getenv("PATH")
	return append(env, "SYSTEMCTL_LOG="+logPath)
}

func fakeSystemctl(t *testing.T, dir string) (string, string) {
	return fakeSystemctlWithBehavior(t, dir, systemctlBehavior{legacyEnabled: true})
}

type systemctlBehavior struct {
	legacyEnabled      bool
	legacyActive       bool
	failCompanionStart bool
	failCompanionStop  bool
	failLegacyStart    bool
}

func fakeSystemctlWithBehavior(t *testing.T, dir string, behavior systemctlBehavior) (string, string) {
	t.Helper()
	logPath := filepath.Join(dir, "systemctl.log")
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "systemctl")
	legacyEnabledExit := 1
	if behavior.legacyEnabled {
		legacyEnabledExit = 0
	}
	legacyActiveExit := 1
	if behavior.legacyActive {
		legacyActiveExit = 0
	}
	companionStartExit := 0
	if behavior.failCompanionStart {
		companionStartExit = 1
	}
	companionStopExit := 0
	if behavior.failCompanionStop {
		companionStopExit = 1
	}
	legacyStartExit := 0
	if behavior.failLegacyStart {
		legacyStartExit = 1
	}
	body := fmt.Sprintf(`#!/usr/bin/env bash
set -eu
printf '%%s\n' "$*" >> "$SYSTEMCTL_LOG"
case "$*" in
  "--user is-enabled --quiet gasworks-observer.service") exit %d ;;
  "--user is-active --quiet gasworks-observer.service") exit %d ;;
  "--user is-active --quiet gasworks-companion.service") exit 1 ;;
  "--user enable --now gasworks-companion.service") exit %d ;;
  "--user disable --now gasworks-companion.service") exit %d ;;
  "--user enable --now gasworks-observer.service") exit %d ;;
esac
exit 0
`, legacyEnabledExit, legacyActiveExit, companionStartExit, companionStopExit, legacyStartExit)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	return binDir, logPath
}

func writeTarGz(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// installEnv returns a hermetic environment: a private HOME and no reachable user systemd
// manager (so a stray call could never touch the tester's real services).
func installEnv(home string) []string {
	env := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	// Deliberately omit DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR / XDG_*_HOME so paths resolve
	// under the private HOME and `systemctl --user` is unreachable.
	return env
}

// runScript runs a pack script with the given env and args, returning combined output.
func runScript(t *testing.T, env []string, script string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// installPaths mirrors install.sh's default layout under a given HOME.
type installPaths struct{ home, bin, config, state string }

func pathsFor(home string) installPaths {
	return installPaths{
		home:   home,
		bin:    filepath.Join(home, ".local", "bin", companionBinName),
		config: filepath.Join(home, ".config", "gasworks-companion"),
		state:  filepath.Join(home, ".local", "state", "gasworks-companion"),
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s perm = %04o, want %04o", path, got, want)
	}
}

func TestInstallHappyPathOwnerOnlyPerms(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	fx := buildFixture(t, dir)
	tok := filepath.Join(dir, "token")
	mustWrite(t, tok, "bearer-token")
	ca := filepath.Join(dir, "ca.pem")
	mustWrite(t, ca, "CA-BUNDLE")

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--collector", "https://collector.example",
		"--token-file", tok, "--custom-ca", ca,
		"--cosign", fakeCosign(t, dir, 0), "--skip-service")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	p := pathsFor(home)
	// Owner-only: 0700 dirs, 0600 secret files, 0700 binary.
	assertPerm(t, p.bin, 0o700)
	assertPerm(t, p.config, 0o700)
	assertPerm(t, p.state, 0o700)
	assertPerm(t, filepath.Join(p.config, "observer.env"), 0o600)
	assertPerm(t, filepath.Join(p.config, "token"), 0o600)
	assertPerm(t, filepath.Join(p.config, "custom-ca.pem"), 0o600)

	env, err := os.ReadFile(filepath.Join(p.config, "observer.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OBSERVER_ARGS=daemon", "-source-id src-1", "-collector https://collector.example", "-token-file " + filepath.Join(p.config, "token")} {
		if !strings.Contains(string(env), want) {
			t.Errorf("observer.env missing %q\n%s", want, env)
		}
	}
}

// binaryAbsent asserts the fail-closed contract: no binary bytes reached the install prefix.
func binaryAbsent(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Stat(pathsFor(home).bin); !os.IsNotExist(err) {
		t.Fatalf("fail-closed violated: binary present at %s (err=%v)", pathsFor(home).bin, err)
	}
}

func TestInstallBadSignatureAbortsBeforePlacement(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	fx := buildFixture(t, dir)

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 1), "--skip-service")
	if err == nil {
		t.Fatalf("expected install to abort on bad signature, but it succeeded\n%s", out)
	}
	if !strings.Contains(out, "aborting before placement") {
		t.Errorf("missing fail-closed message; got:\n%s", out)
	}
	binaryAbsent(t, home)
}

func TestInstallTamperedChecksumAbortsBeforePlacement(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	fx := buildFixture(t, dir)
	// Tamper: rewrite the checksum to a wrong digest (signature still "valid" via fake cosign).
	bad := filepath.Join(dir, "checksums-bad.txt")
	mustWrite(t, bad, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  "+filepath.Base(fx.archive)+"\n")

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", bad,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0), "--skip-service")
	if err == nil {
		t.Fatalf("expected install to abort on tampered checksum, but it succeeded\n%s", out)
	}
	if !strings.Contains(out, "checksum MISMATCH") {
		t.Errorf("missing checksum-mismatch message; got:\n%s", out)
	}
	binaryAbsent(t, home)
}

func TestInstallBadConfigPathAbortsBeforePlacement(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	fx := buildFixture(t, dir)

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--token-file", filepath.Join(dir, "nope"),
		"--cosign", fakeCosign(t, dir, 0), "--skip-service")
	if err == nil {
		t.Fatalf("expected abort on missing token file\n%s", out)
	}
	binaryAbsent(t, home)
}

// seedInstallWithWAL installs, then writes a nonempty WAL segment; returns paths + segment content.
func seedInstallWithWAL(t *testing.T, dir, home string) (installPaths, string, []byte) {
	t.Helper()
	fx := buildFixture(t, dir)
	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0), "--skip-service")
	if err != nil {
		t.Fatalf("seed install failed: %v\n%s", err, out)
	}
	p := pathsFor(home)
	seg := filepath.Join(p.state, "wal", "000001.seg")
	content := []byte("SEG-DURABLE-ACKED-EVIDENCE")
	if err := os.WriteFile(seg, content, 0o600); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}
	return p, seg, content
}

func TestUpgradePreservesNonemptyWAL(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	_, seg, content := seedInstallWithWAL(t, dir, home)
	fx := buildFixture(t, dir)

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"), "--upgrade",
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--cosign", fakeCosign(t, dir, 0), "--skip-service")
	if err != nil {
		t.Fatalf("upgrade failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(seg)
	if err != nil {
		t.Fatalf("WAL segment destroyed by upgrade: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("WAL segment mutated by upgrade: got %q want %q", got, content)
	}
}

// TestInstallAdoptsLegacyDefaultsAndMigratesEnabledUnit guards the rename upgrade path:
// new Companion defaults must keep an existing Observer config/WAL, and an enabled Observer
// unit must be stopped before the new Companion unit is enabled.
func TestInstallAdoptsLegacyDefaultsAndMigratesEnabledUnit(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	legacyState := filepath.Join(home, ".local", "state", "gasworks-observer")
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(legacyState, "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "systemd", "user", "gasworks-observer.service.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	segment := filepath.Join(legacyState, "wal", "000001.seg")
	if err := os.WriteFile(segment, []byte("DURABLE-LEGACY-WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyUnit := filepath.Join(home, ".config", "systemd", "user", "gasworks-observer.service")
	if err := os.WriteFile(legacyUnit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fx := buildFixtureForBinary(t, dir, companionBinName)
	systemctlDir, systemctlLog := fakeSystemctl(t, dir)
	out, err := runScript(t, installEnvWithSystemctl(home, systemctlDir, systemctlLog), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0))
	if err != nil {
		t.Fatalf("Companion install failed: %v\n%s", err, out)
	}

	if got, err := os.ReadFile(segment); err != nil || string(got) != "DURABLE-LEGACY-WAL" {
		t.Fatalf("legacy WAL was not preserved: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", companionBinName)); err != nil {
		t.Errorf("Companion binary missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", legacyObserverBinName)); !os.IsNotExist(err) {
		t.Errorf("retired Observer executable must not be installed, stat err = %v", err)
	}
	if _, err := os.Stat(legacyUnit); !os.IsNotExist(err) {
		t.Errorf("legacy service unit still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "systemd", "user", "gasworks-companion.service")); err != nil {
		t.Errorf("Companion service unit missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "gasworks-companion")); !os.IsNotExist(err) {
		t.Errorf("new config directory should not displace adopted legacy config, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "state", "gasworks-companion")); !os.IsNotExist(err) {
		t.Errorf("new state directory should not displace adopted legacy state, stat err = %v", err)
	}
	log, err := os.ReadFile(systemctlLog)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(log)
	stop := "--user disable --now gasworks-observer.service"
	start := "--user enable --now gasworks-companion.service"
	if !strings.Contains(commands, stop) || !strings.Contains(commands, start) {
		t.Fatalf("expected legacy stop and Companion start, got:\n%s", commands)
	}
	if strings.Index(commands, stop) > strings.Index(commands, start) {
		t.Errorf("legacy service was not stopped before Companion start:\n%s", commands)
	}
}

func TestUpgradeRetiresDisabledActiveLegacyServiceWithoutStartingCompanion(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "state", "gasworks-observer", "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "gasworks-observer.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyBin := filepath.Join(home, ".local", "bin", legacyObserverBinName)
	if err := os.MkdirAll(filepath.Dir(legacyBin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyBin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	fx := buildFixture(t, dir)
	systemctlDir, systemctlLog := fakeSystemctlWithBehavior(t, dir, systemctlBehavior{legacyActive: true})
	out, err := runScript(t, installEnvWithSystemctl(home, systemctlDir, systemctlLog), scriptPath(t, "install.sh"), "--upgrade",
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--cosign", fakeCosign(t, dir, 0))
	if err != nil {
		t.Fatalf("disabled-service upgrade failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(unitDir, "gasworks-observer.service")); !os.IsNotExist(err) {
		t.Errorf("disabled legacy unit was not retired, stat err = %v", err)
	}
	if _, err := os.Stat(legacyBin); !os.IsNotExist(err) {
		t.Errorf("disabled legacy binary was not retired, stat err = %v", err)
	}
	log, err := os.ReadFile(systemctlLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "--user enable --now gasworks-companion.service") {
		t.Fatalf("upgrade revived disabled service:\n%s", log)
	}
	if !strings.Contains(string(log), "--user stop gasworks-observer.service") {
		t.Fatalf("disabled-but-active legacy service was not stopped:\n%s", log)
	}
}

func TestFailedCompanionStartRestoresEnabledLegacyService(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "state", "gasworks-observer", "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyUnit := filepath.Join(unitDir, "gasworks-observer.service")
	if err := os.WriteFile(legacyUnit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fx := buildFixture(t, dir)
	systemctlDir, systemctlLog := fakeSystemctlWithBehavior(t, dir, systemctlBehavior{legacyEnabled: true, failCompanionStart: true})
	out, err := runScript(t, installEnvWithSystemctl(home, systemctlDir, systemctlLog), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0))
	if err == nil {
		t.Fatalf("expected failed Companion start, got success:\n%s", out)
	}
	if _, err := os.Stat(legacyUnit); err != nil {
		t.Fatalf("failed handoff removed legacy unit: %v", err)
	}
	log, readErr := os.ReadFile(systemctlLog)
	if readErr != nil {
		t.Fatal(readErr)
	}
	commands := string(log)
	for _, want := range []string{
		"--user disable --now gasworks-observer.service",
		"--user enable --now gasworks-companion.service",
		"--user disable --now gasworks-companion.service",
		"--user enable --now gasworks-observer.service",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("missing %q from failed handoff:\n%s", want, commands)
		}
	}
}

func TestFailedLegacyRestorePropagatesRollbackFailure(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "state", "gasworks-observer", "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "gasworks-observer.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fx := buildFixture(t, dir)
	systemctlDir, _ := fakeSystemctlWithBehavior(t, dir, systemctlBehavior{legacyEnabled: true, failCompanionStart: true, failLegacyStart: true})
	out, err := runScript(t, installEnvWithSystemctl(home, systemctlDir, filepath.Join(dir, "systemctl.log")), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0))
	if err == nil {
		t.Fatalf("expected failed rollback, got success:\n%s", out)
	}
	if strings.Contains(out, "restored legacy user unit") {
		t.Fatalf("installer claimed a failed rollback was restored:\n%s", out)
	}
	if !strings.Contains(out, "legacy service rollback failed") {
		t.Fatalf("installer did not report rollback failure:\n%s", out)
	}
}

func TestFailedCompanionStopPropagatesRollbackFailure(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "state", "gasworks-observer", "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon -source-id legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "gasworks-observer.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fx := buildFixture(t, dir)
	systemctlDir, _ := fakeSystemctlWithBehavior(t, dir, systemctlBehavior{legacyEnabled: true, failCompanionStart: true, failCompanionStop: true})
	out, err := runScript(t, installEnvWithSystemctl(home, systemctlDir, filepath.Join(dir, "systemctl.log")), scriptPath(t, "install.sh"),
		"--archive", fx.archive, "--checksums", fx.checksums,
		"--checksums-sig", fx.checksumsSig, "--checksums-cert", fx.checksumsCert,
		"--source-id", "src-1", "--cosign", fakeCosign(t, dir, 0))
	if err == nil {
		t.Fatalf("expected failed rollback, got success:\n%s", out)
	}
	if strings.Contains(out, "restored legacy user unit") {
		t.Fatalf("installer claimed a failed rollback was restored:\n%s", out)
	}
	if !strings.Contains(out, "legacy service rollback failed") {
		t.Fatalf("installer did not report rollback failure:\n%s", out)
	}
}

func TestUninstallAdoptsLegacyLayoutAndPurgesWAL(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	legacyState := filepath.Join(home, ".local", "state", "gasworks-observer")
	if err := os.MkdirAll(filepath.Join(legacyState, "wal"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(legacyConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyConfig, "observer.env"), []byte("OBSERVER_ARGS=daemon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyState, "wal", "000001.seg"), []byte("DURABLE"), 0o600); err != nil {
		t.Fatal(err)
	}
	companionBin := filepath.Join(home, ".local", "bin", companionBinName)
	if err := os.MkdirAll(filepath.Dir(companionBin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(companionBin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"), "--uninstall", "--purge-spool", "--skip-service")
	if err != nil {
		t.Fatalf("legacy-layout uninstall failed: %v\n%s", err, out)
	}
	for _, path := range []string{legacyConfig, legacyState, companionBin} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("legacy-layout uninstall left %s behind: %v", path, err)
		}
	}
}

func TestUninstallDoesNotTouchLegacyLayoutWhenCompanionLayoutExists(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	companionConfig := filepath.Join(home, ".config", "gasworks-companion")
	companionState := filepath.Join(home, ".local", "state", "gasworks-companion")
	legacyConfig := filepath.Join(home, ".config", "gasworks-observer")
	legacyState := filepath.Join(home, ".local", "state", "gasworks-observer")
	for _, path := range []string{companionConfig, filepath.Join(companionState, "wal"), legacyConfig, filepath.Join(legacyState, "wal")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(companionState, "wal", "000001.seg"), []byte("COMPANION"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyState, "wal", "000001.seg"), []byte("LEGACY"), 0o600); err != nil {
		t.Fatal(err)
	}
	companionBin := filepath.Join(home, ".local", "bin", companionBinName)
	if err := os.MkdirAll(filepath.Dir(companionBin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(companionBin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"), "--uninstall", "--purge-spool", "--skip-service")
	if err != nil {
		t.Fatalf("Companion-layout uninstall failed: %v\n%s", err, out)
	}
	for _, path := range []string{companionConfig, companionState} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("Companion-layout uninstall left %s behind: %v", path, err)
		}
	}
	for _, path := range []string{legacyConfig, legacyState} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Companion-layout uninstall touched unrelated legacy path %s: %v", path, err)
		}
	}
}

func TestUninstallPreservesNonemptyWALByDefault(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	p, seg, content := seedInstallWithWAL(t, dir, home)

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"), "--uninstall", "--skip-service")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(p.bin); !os.IsNotExist(err) {
		t.Errorf("binary should be removed on uninstall")
	}
	got, err := os.ReadFile(seg)
	if err != nil {
		t.Fatalf("uninstall destroyed a nonempty WAL: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("WAL mutated by uninstall")
	}
	if !strings.Contains(out, "PRESERVED nonempty spool") {
		t.Errorf("expected spool-preservation notice; got:\n%s", out)
	}
}

func TestUninstallPurgeSpoolRemovesWAL(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	p, _, _ := seedInstallWithWAL(t, dir, home)

	out, err := runScript(t, installEnv(home), scriptPath(t, "install.sh"), "--uninstall", "--purge-spool", "--skip-service")
	if err != nil {
		t.Fatalf("uninstall --purge-spool failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(p.state); !os.IsNotExist(err) {
		t.Errorf("--purge-spool should remove the state dir")
	}
}

// TestNoElevationDependencyInPackScripts enforces the governing invariant: the endpoint
// installer, doctor, and service must NOT depend on sudo, tmux, or the gc/City runtime. It
// scans non-comment lines only (comments may legitimately explain the "no sudo" design).
func TestNoElevationDependencyInPackScripts(t *testing.T) {
	files := []string{"install.sh", "doctor.sh", filepath.Join("deploy", "gasworks-companion.service")}
	banned := []string{"sudo", "tmux"}
	for _, f := range files {
		data, err := os.ReadFile(scriptPath(t, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, b := range banned {
				if strings.Contains(line, b) {
					t.Errorf("%s:%d references %q outside a comment: %s", f, i+1, b, trimmed)
				}
			}
			// A `gc` command invocation (whole word at a command position). Excludes substrings
			// like "gasworks" and directives; flags a bare `gc ` token.
			for _, tok := range strings.Fields(line) {
				if tok == "gc" {
					t.Errorf("%s:%d invokes the gc runtime: %s", f, i+1, trimmed)
				}
			}
		}
	}
}
