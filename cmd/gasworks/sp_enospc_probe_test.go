//go:build oneshot && !windows

// The other half of the disk-full story, behind the same `oneshot` tag as the probe file next
// to it: a filesystem that fills AFTER leg A, during the minutes the ceremony waits on a human.
//
// TestOneShotDiskFull covers the destination that is full before anything is sent, which costs
// only retyping the command. This one covers the case the reservation exists for — the room was
// proved, and then the disk filled — and it is the reason the proof's blocks are held for the
// whole ceremony instead of being handed back the moment they are proved.
//
// It needs a small filesystem of its own with room left in it — NOT the one TestOneShotDiskFull
// wants, which has to be full before that test starts — and skips when there is none:
//
//	sudo mkdir -p /mnt/atkroom && sudo mount -t tmpfs -o size=256k,mode=0777 tmpfs /mnt/atkroom
//
//	go test -tags oneshot ./cmd/gasworks/ -run TestOneShotFilesystemFills -v

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gascity/gasworks/internal/store"
)

// probeRoomyFS is a filesystem this probe fills itself, mid-ceremony. It is deliberately not
// TestOneShotDiskFull's /mnt/atkfull: that one is full before its test begins.
const probeRoomyFS = "/mnt/atkroom"

// fillFilesystem writes into dir until the filesystem refuses, and returns the ballast file so
// the caller can take it away again. It fails the test if the filesystem never fills, because a
// probe that did not fill the disk proves nothing about a disk that is full.
func fillFilesystem(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "ballast")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create the ballast: %v", err)
	}
	defer file.Close()
	block := make([]byte, 4096)
	for i := range block {
		block[i] = 'b'
	}
	full := false
	for range 4096 { // 16 MiB at most; the mount is meant to be far smaller
		_, err := file.Write(block)
		if err == nil {
			continue
		}
		if !errors.Is(err, syscall.ENOSPC) && !errors.Is(err, syscall.EDQUOT) {
			t.Fatalf("filling %s: %v", dir, err)
		}
		full = true
		break
	}
	if !full {
		t.Fatalf("%s did not fill; mount something small there", dir)
	}
	// A block-sized write stops at the last block that fits, which can leave a few hundred
	// bytes — and a few hundred bytes is more than a rendered secret needs. Take the rest a
	// byte at a time so the filesystem has nothing at all left to give.
	one := []byte{'b'}
	for range spaceProofBytes {
		if _, err := file.Write(one); err != nil {
			return path
		}
	}
	t.Fatalf("%s kept accepting bytes after it reported ENOSPC", dir)
	return ""
}

// hasNoRoom confirms the filesystem cannot take a new file, which is what the CLI's write would
// have hit if the reservation had given its blocks back.
func hasNoRoom(t *testing.T, dir string) bool {
	t.Helper()
	path := filepath.Join(dir, "canary")
	defer os.Remove(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return true
	}
	defer file.Close()
	if _, err := file.Write([]byte{'c'}); err != nil {
		return true
	}
	return file.Sync() != nil
}

func probeRoomyFilesystem(t *testing.T) string {
	t.Helper()
	info, err := os.Stat(probeRoomyFS)
	if err != nil || !info.IsDir() {
		t.Skipf("no scratch filesystem mounted at %s; see the file header", probeRoomyFS)
	}
	dir, err := os.MkdirTemp(probeRoomyFS, "enospc-")
	if err != nil {
		t.Skipf("%s is not writable: %v", probeRoomyFS, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// The reservation proved there was room, the human took their time, and the filesystem filled
// while they did. The write after leg C must still land: it goes over blocks this file already
// holds, so there is nothing left for the allocator to refuse.
func TestOneShotFilesystemFillsDuringTheApproval(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write into a filesystem's reserved blocks")
	}
	dir := probeRoomyFilesystem(t)
	srv, _ := mintSeed(t)
	virtualClock(t)
	// The rescue path writes here, on a DIFFERENT filesystem: if the destination write fails,
	// the secret shows up in this directory and the probe can say so.
	rescueDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	out := filepath.Join(dir, "sp.env")

	filled := false
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			ballast := fillFilesystem(t, dir)
			t.Logf("filled %s while the human was at the approval page (ballast %s)", dir, ballast)
			filled = hasNoRoom(t, dir)
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	a, c := len(srv.reqs("/v0/cli/mint/challenges")), len(srv.reqs("/complete"))
	t.Logf("leg A = %d, leg C = %d, exit = %d", a, c, code)
	if !filled {
		t.Fatalf("%s still had room at leg C, so nothing was proved", dir)
	}
	if c < 2 {
		t.Fatalf("the ceremony did not reach the leg C that reveals the secret\nstderr:%s", stderr)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the secret is not at %s (%v) — ENOSPC reached the write after leg C\nstderr:%s",
			out, err, stderr)
	}
	if want := secretFormatEnv.render("gck_sp_secret_value"); string(body) != want {
		t.Fatalf("%s holds %q, want exactly %q", out, body, want)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the secret is at %s (%d bytes, mode %04o) on a filesystem with no room left",
		out, info.Size(), info.Mode().Perm())
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s is mode %04o", out, info.Mode().Perm())
	}
	if code != 0 {
		t.Fatalf("exit = %d with the secret at its destination\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	if entries, _ := os.ReadDir(rescueDir); len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the rescue path ran (%s), so the destination write failed", strings.Join(names, " "))
	}
}

// The other end of the same window: a response that fits inside the 4 KiB proof and a rendering
// that does NOT, on a filesystem with nothing left to give.
//
// `GASWORKS_SP_SECRET='<secret>'\n` costs 22 bytes around the secret where `{"secret":"..."}`
// costs 13, so the reformat needs exactly NINE bytes the response did not — which on a full
// filesystem is nine bytes it cannot have. The write it manages lands at offset 0, on top of the
// only durable copy of a credential nothing can re-issue.
//
// What must come out of it is the response, intact, reported as where the credential is: never a
// rendering cut short over the thing it failed to replace.
func TestOneShotAFullFilesystemCannotHolePunchTheResponse(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write into a filesystem's reserved blocks")
	}
	// Sized so the response is the last thing that fits in the proof and the rendering is the
	// first that does not.
	secret := strings.Repeat("s", spaceProofBytes-16)
	raw := []byte(`{"secret":"` + secret + `"}`)
	render := secretFormatEnv.render(secret)
	if len(raw) > spaceProofBytes || len(render) <= spaceProofBytes {
		t.Fatalf("mis-sized: response=%d rendering=%d proof=%d", len(raw), len(render), spaceProofBytes)
	}

	dir := probeRoomyFilesystem(t)
	srv, _ := mintSeed(t)
	virtualClock(t)
	rescueDir := filepath.Join(t.TempDir(), "minted-keys") // a DIFFERENT filesystem, with room
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	out := filepath.Join(dir, "sp.env")

	filled := false
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			fillFilesystem(t, dir)
			filled = hasNoRoom(t, dir)
			mintPending(w, "authorization_pending", 5)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(raw)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("response=%d bytes, rendering=%d bytes (%d more), proof=%d bytes; leg A=%d leg C=%d exit=%d",
		len(raw), len(render), len(render)-len(raw), spaceProofBytes,
		len(srv.reqs("/v0/cli/mint/challenges")), len(srv.reqs("/complete")), code)
	if !filled {
		t.Fatalf("%s still had room at leg C, so nothing was proved", dir)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %s is gone (%v)\nstderr:%s", out, err, stderr)
	}
	if string(body) != string(raw) {
		t.Fatalf("%s holds %d bytes that are not the response the mint plane sent; the reformat "+
			"punched through the durable copy", out, len(body))
	}
	t.Logf("%s holds the response verbatim (%d bytes, the whole secret in it)", out, len(body))
	if code == 0 {
		t.Error("exit 0 for a file that is not the credential rendering that was asked for")
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Errorf("the success banner was printed over a raw response:\n%s", stdout)
	}
	for _, want := range []string{"A CREDENTIAL WAS MINTED", out, "not delete it"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stdout+stderr, secret) {
		t.Error("the secret was printed even though it is on the disk")
	}
	if entries, _ := os.ReadDir(rescueDir); len(entries) != 0 {
		t.Errorf("the rescue path ran (%v); the credential was already durable at %s", entries, out)
	}
}
