//go:build linux

package observer_test

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot returns the module root (two levels up from this package dir).
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		if root := strings.TrimSpace(string(out)); root != "" {
			return root
		}
	}
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

func requireGoreleaser(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("goreleaser"); err != nil {
		t.Skip("goreleaser not installed; skipping (structure still validated by goreleaser check in CI)")
	}
}

// TestGoreleaserCheckPasses validates the whole .goreleaser.yaml (including the added observer
// build/archive). The pre-existing `brews` deprecation notice is not an error (exit 0).
func TestGoreleaserCheckPasses(t *testing.T) {
	requireGoreleaser(t)
	cmd := exec.Command("goreleaser", "check")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("goreleaser check failed: %v\n%s", err, out)
	}
}

func readTarGzNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip %s: %v", path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag == tar.TypeReg {
			names = append(names, hdr.Name)
		}
	}
	sort.Strings(names)
	return names
}

func globOne(t *testing.T, pattern string) string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(m) != 1 {
		t.Fatalf("expected exactly one match for %s, got %v", pattern, m)
	}
	return m[0]
}

// TestSnapshotObserverArchiveInventory does a real snapshot build and asserts (O4.1):
//   - the independent observer archive contains ONLY the observer binary + LICENSE, and
//   - the existing CLI/forwarder "default" archive is unchanged (gasworks + gasworks-forwarder
//     + README.md, with NO observer bytes and NO leaked license) — the no-regression proof.
func TestSnapshotObserverArchiveInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping goreleaser snapshot build in -short mode")
	}
	requireGoreleaser(t)
	root := repoRoot(t)
	dist := filepath.Join(root, "dist")
	// dist/ is gitignored; --clean recreates it. Clean up after to keep the tree tidy.
	t.Cleanup(func() { _ = os.RemoveAll(dist) })

	cmd := exec.Command("goreleaser", "release", "--snapshot", "--clean", "--skip=sign,sbom,publish")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("goreleaser snapshot failed: %v\n%s", err, out)
	}

	// Both observer arches must exist and carry exactly {LICENSE, gasworks-observer}.
	for _, arch := range []string{"amd64", "arm64"} {
		obs := globOne(t, filepath.Join(dist, "gasworks-observer_*_linux_"+arch+".tar.gz"))
		got := readTarGzNames(t, obs)
		want := []string{"LICENSE", observerBinName}
		if !equalStrings(got, want) {
			t.Errorf("observer %s archive inventory = %v, want %v", arch, got, want)
		}
	}

	// The CLI/forwarder default archive must be untouched by the additive observer target.
	def := globOne(t, filepath.Join(dist, "gasworks_*_linux_amd64.tar.gz"))
	got := readTarGzNames(t, def)
	want := []string{"README.md", "gasworks", "gasworks-forwarder"}
	if !equalStrings(got, want) {
		t.Errorf("default (CLI/forwarder) archive inventory = %v, want %v (regression!)", got, want)
	}
	for _, n := range got {
		if n == observerBinName {
			t.Errorf("observer binary leaked into the CLI/forwarder archive")
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
