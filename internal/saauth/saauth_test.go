//go:build !windows

package saauth

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeToken(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	// WriteFile honors the umask, so force the exact mode we are testing.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod %s: %v", p, err)
	}
	return p
}

func TestTokenFromFile_0600Succeeds(t *testing.T) {
	dir := t.TempDir()
	p := writeToken(t, dir, "tok", "  secret-bearer-value\n", 0o600)
	got, err := TokenFromFile(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret-bearer-value" {
		t.Fatalf("token = %q, want trimmed %q", got, "secret-bearer-value")
	}
}

func TestTokenFromFile_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	real := writeToken(t, dir, "real", "secret\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// O_NOFOLLOW refuses the symlink at open: ("", nil) — skip cycle, never the token.
	got, err := TokenFromFile(link)
	if err != nil {
		t.Fatalf("symlink open should be a silent skip, got err: %v", err)
	}
	if got != "" {
		t.Fatalf("symlinked token path must yield no token, got %q", got)
	}
}

func TestTokenFromFile_GroupReadableRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeToken(t, dir, "tok", "secret\n", 0o640) // group-readable
	got, err := TokenFromFile(p)
	if err == nil {
		t.Fatalf("0640 token must be rejected with an error")
	}
	if got != "" {
		t.Fatalf("rejected token must be empty, got %q", got)
	}
}

func TestTokenFromFile_WorldReadableRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeToken(t, dir, "tok", "secret\n", 0o604) // world-readable
	if _, err := TokenFromFile(p); err == nil {
		t.Fatalf("0604 token must be rejected with an error")
	}
}

func TestTokenFromFile_FIFORejected(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	got, err := TokenFromFile(fifo)
	if err == nil {
		t.Fatalf("a FIFO (non-regular file) must be rejected with an error")
	}
	if got != "" {
		t.Fatalf("rejected non-regular file must be empty, got %q", got)
	}
}

func TestTokenFromFile_DirRejected(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := TokenFromFile(sub); err == nil {
		t.Fatalf("a directory (non-regular file) must be rejected with an error")
	}
}

func TestTokenFromFile_MissingIsSilentSkip(t *testing.T) {
	dir := t.TempDir()
	got, err := TokenFromFile(filepath.Join(dir, "nope"))
	if err != nil {
		t.Fatalf("missing file should be a silent skip, got err: %v", err)
	}
	if got != "" {
		t.Fatalf("missing file must yield no token, got %q", got)
	}
}

func TestTokenFromFile_RotationReReads(t *testing.T) {
	dir := t.TempDir()
	p := writeToken(t, dir, "tok", "first-token\n", 0o600)
	prov := FileProvider(p)
	got1, err := prov.Token()
	if err != nil || got1 != "first-token" {
		t.Fatalf("first read = %q, err=%v", got1, err)
	}
	// Rotate the credential in place; the next Token() call must observe the new value.
	if err := os.WriteFile(p, []byte("second-token\n"), 0o600); err != nil {
		t.Fatalf("rotate write: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("rotate chmod: %v", err)
	}
	got2, err := prov.Token()
	if err != nil || got2 != "second-token" {
		t.Fatalf("post-rotation read = %q, err=%v; rotation not picked up", got2, err)
	}
}

func TestTokenFromEnv_PopsAndWarns(t *testing.T) {
	const name = "SAAUTH_TEST_TOKEN_VAR"
	t.Setenv(name, "env-secret")
	tok, ok := TokenFromEnv(name)
	if !ok || tok != "env-secret" {
		t.Fatalf("TokenFromEnv = (%q,%v), want (\"env-secret\", true)", tok, ok)
	}
	// Popped from the environment so a child/proc-environ read can't recover it.
	if v, present := os.LookupEnv(name); present {
		t.Fatalf("env var must be unset after read, still present = %q", v)
	}
}

func TestTokenFromEnv_UnsetReturnsFalse(t *testing.T) {
	const name = "SAAUTH_TEST_UNSET_VAR"
	_ = os.Unsetenv(name)
	if tok, ok := TokenFromEnv(name); ok || tok != "" {
		t.Fatalf("unset env var = (%q,%v), want (\"\", false)", tok, ok)
	}
}

func TestProvider_ConfiguredAndSource(t *testing.T) {
	var zero Provider
	if zero.Configured() {
		t.Fatalf("zero Provider must be unconfigured")
	}
	if zero.Source() != SourceNone {
		t.Fatalf("zero Provider source = %v, want SourceNone", zero.Source())
	}
	if !FileProvider("/x").Configured() || FileProvider("/x").Source() != SourceFile {
		t.Fatalf("FileProvider must be configured with SourceFile")
	}
	if !EnvProvider("t").Configured() || EnvProvider("t").Source() != SourceEnv {
		t.Fatalf("EnvProvider must be configured with SourceEnv")
	}
	tok, err := EnvProvider("captured").Token()
	if err != nil || tok != "captured" {
		t.Fatalf("EnvProvider.Token() = (%q,%v), want (\"captured\", nil)", tok, err)
	}
}
