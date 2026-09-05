//go:build !windows

// The reservation, from the moment it is proved to the moment the file holds its final form —
// and what happens when the filesystem fills in between.
//
// No unprivileged test can fill a real filesystem, so these lower RLIMIT_FSIZE instead: a write
// past the limit short-writes and reports EFBIG, which is the same shape of failure as ENOSPC on
// a full disk and is what the reservation exists to make impossible. /mnt/atkroom drives the
// real thing behind the `oneshot` tag (see sp_enospc_probe_test.go).

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/store"
)

// reservationSecret is 32 characters with no structure to guess from, so a rendering laid over
// the response and cut short is visibly a hole rather than a coincidence.
const reservationSecret = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"

// capFileSize lowers RLIMIT_FSIZE for the rest of the test and restores it afterwards. It
// returns a func that applies the cap, so the caller can fill the "filesystem" at the exact
// moment the ceremony is most exposed.
func capFileSize(t *testing.T, limit uint64) func() {
	t.Helper()
	var was syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &was); err != nil {
		t.Skipf("no RLIMIT_FSIZE here: %v", err)
	}
	restore := func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &was) }
	t.Cleanup(restore)
	return func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: limit, Max: was.Max}); err != nil {
			t.Skipf("cannot lower RLIMIT_FSIZE: %v", err)
		}
	}
}

// fillAfterTheResponseIsDurable applies the cap on the sync that makes leg C's response durable
// — persist's, the second in the run after proveSpace's. That is the exact window the space
// proof is held across: the room was proved before leg A, the human took minutes, and the disk
// filled while they did.
func fillAfterTheResponseIsDurable(t *testing.T, fill func()) {
	t.Helper()
	original := syncSecretFile
	syncs := 0
	syncSecretFile = func(file *os.File) error {
		err := original(file)
		if syncs++; syncs == 2 {
			fill()
		}
		return err
	}
	t.Cleanup(func() { syncSecretFile = original })
}

// fillAfterTheReservationIsProved applies the cap on the FIRST sync of the run — the one that
// proves the reservation — which is the filesystem filling while the human is still at the
// approval page. From that moment the ceremony can write only into blocks it already claimed.
func fillAfterTheReservationIsProved(t *testing.T, fill func()) {
	t.Helper()
	original := syncSecretFile
	syncs := 0
	syncSecretFile = func(file *os.File) error {
		err := original(file)
		if syncs++; syncs == 1 {
			fill()
		}
		return err
	}
	t.Cleanup(func() { syncSecretFile = original })
}

// A credential far bigger than any the mint plane sends today, on a filesystem that fills the
// moment the reservation is proved. The reservation is the only room this ceremony will ever
// get after that point, so it has to be sized for a credential rather than for a guess at one:
// a 4 KiB claim made the ~6 KiB response below short-write inside persist, which is the one
// write that cannot fail.
func TestABigCredentialLandsOnAFilesystemThatFilledDuringTheApproval(t *testing.T) {
	secret := strings.Repeat("Z", 6000) + "TAIL"
	srv, _ := mintSeed(t)
	virtualClock(t)
	rescueDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusCreated, map[string]any{"key_id": "spk_big", "secret": secret})
	}
	// Not one byte past the reservation may be written from here on.
	fillAfterTheReservationIsProved(t, capFileSize(t, spaceProofBytes))

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
	if code != 0 {
		t.Fatalf("exit %d for a credential the reservation was supposed to cover\n%s", code, stderr)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %s (%v)", out, err)
	}
	if want := secretFormatEnv.render(secret); string(body) != want {
		t.Fatalf("%s holds %d bytes, want the whole %d-byte rendering", out, len(body), len(want))
	}
	assertOwnerOnly(t, out)
	assertSecretOnNoStream(t, stdout, stderr, secret)
	if entries, _ := os.ReadDir(rescueDir); len(entries) != 0 {
		t.Errorf("the rescue path ran (%v) for a credential that fitted the reservation", entries)
	}
}

// And when the response really is bigger than the reservation, the reservation GROWS. Its size
// is a starting point, not a ceiling: leg C's length is known before a byte of it is written,
// so the claim is extended and re-proved first.
func TestTheReservationGrowsForAResponseBiggerThanItself(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	secret := strings.Repeat("q", spaceProofBytes+5000)
	// The minimal envelope, so the RENDERING is the longer of the two and the claim has to grow
	// a second time for it: `GASWORKS_SP_SECRET='...'` costs 22 bytes around the secret where
	// `{"secret":"..."}` costs 13.
	raw := []byte(`{"secret":"` + secret + `"}`)
	stored, err := reserved.persist(raw)
	if err != nil {
		t.Fatalf("persist a %d-byte response into a %d-byte reservation: %v", len(raw), spaceProofBytes, err)
	}
	if string(stored) != string(raw) {
		t.Fatalf("persist read back %d bytes, want the %d it was given", len(stored), len(raw))
	}
	if reserved.reserved < len(raw) {
		t.Fatalf("the reservation is %d bytes for a %d-byte response", reserved.reserved, len(raw))
	}
	// The rendering is longer still (the env quoting adds to it), so the claim grows again.
	render := secretFormatEnv.render(secret)
	if len(render) <= len(raw) {
		t.Fatalf("the probe is mis-sized: rendering=%d response=%d", len(render), len(raw))
	}
	if err := reserved.rewrite([]byte(render)); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	body, err := os.ReadFile(reserved.settle("spk_1", secretFormatEnv))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != render {
		t.Fatalf("the file holds %d bytes, want exactly the %d-byte rendering", len(body), len(render))
	}
}

// The other half of growing it: a claim that cannot be extended fails BEFORE the response is
// written, so the response is still whole in the caller's hands and the reservation is still a
// disposable one. A short write halfway through a one-shot secret is the thing this avoids.
func TestAResponseTooBigForTheFilesystemFailsBeforeItIsWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	capFileSize(t, spaceProofBytes)()
	raw := []byte(`{"key_id":"spk_1","secret":"` + strings.Repeat("q", spaceProofBytes) + `"}`)

	stored, err := reserved.persist(raw)
	if err == nil {
		t.Fatalf("persist accepted a %d-byte response on a filesystem that can hold %d",
			len(raw), spaceProofBytes)
	}
	t.Logf("persist refused before writing: %v", err)
	if stored != nil {
		t.Fatalf("persist returned %d bytes alongside its error", len(stored))
	}
	if !strings.Contains(err.Error(), "could not reserve room for a secret") {
		t.Errorf("the error does not name what could not be done: %v", err)
	}
	// Nothing of the response reached the file, and the reservation is still armed: no secret is
	// here, so cleaning it up is a rollback rather than a deletion.
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(body, spaceProof(spaceProofBytes)) {
		t.Fatalf("the file is no longer the untouched placeholder (%d bytes)", len(body))
	}
	if !reserved.armed {
		t.Error("the reservation was disarmed by a write that never happened")
	}
}

// A flush that fails over a file whose bytes read back byte for byte is not a lost credential.
// Calling it one sends the run into the rescue, which writes a second copy and — when that
// cannot be written either — PRINTS a live key over a 0600 file that already holds it.
func TestAFlushFailureOverAByteExactFileIsNotALostCredential(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	rescueDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	tty := usableTerminal(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	raw := []byte(`{"key_id":"spk_1","secret":"` + reservationSecret + `"}`)
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(raw)
	}
	// Everything from the reformat on fails to flush: the rendering's write lands, its flush
	// does not, the response is put back, and that flush fails too.
	original := syncSecretFile
	syncs := 0
	syncSecretFile = func(file *os.File) error {
		if syncs++; syncs >= 3 {
			return fmt.Errorf("simulated fsync failure")
		}
		return original(file)
	}
	t.Cleanup(func() { syncSecretFile = original })

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %s is gone (%v)", out, err)
	}
	if string(body) != string(raw) {
		t.Fatalf("%s holds %q, want the response the file verifiably held", out, body)
	}
	assertOwnerOnly(t, out)
	// The credential is on the disk at 0600, so none of the recoveries for a lost one may run.
	if entries, _ := os.ReadDir(rescueDir); len(entries) != 0 {
		t.Errorf("the rescue ran (%v) over a file that holds the response byte for byte", entries)
	}
	assertSecretOnNoStream(t, stdout, stderr, reservationSecret)
	if onTTY := tty.read(t); strings.Contains(onTTY, reservationSecret) {
		t.Error("the secret was printed to the terminal over a file that already holds it")
	}
	for _, unwanted := range []string{"COULD NOT BE SAVED", "treat the key as compromised", "exists nowhere else"} {
		if strings.Contains(stderr, unwanted) {
			t.Errorf("the report says %q over a credential that is on the disk:\n%s", unwanted, stderr)
		}
	}
	// It is still not the file that was asked for, so it is reported and the exit is non-zero.
	if code == 0 {
		t.Error("exit 0 for a run that left the response rather than the rendering")
	}
	for _, want := range []string{"A CREDENTIAL WAS MINTED", "flushing it reported", out} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
}

// The same rule at the unit seam: restoreResponse decides on the READ-BACK, and a flush error is
// a warning next to it rather than a verdict.
func TestRestoreResponseTrustsTheReadBackNotTheFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	raw := []byte(`{"secret":"` + reservationSecret + `"}`)
	if _, err := reserved.persist(raw); err != nil {
		t.Fatalf("persist: %v", err)
	}
	original := syncSecretFile
	syncSecretFile = func(*os.File) error { return fmt.Errorf("simulated fsync failure") }
	t.Cleanup(func() { syncSecretFile = original })

	_, _, _ = capture(t, func() int {
		err = reserved.restoreResponse(errors.New("the reformat could not be written"))
		return 0
	})
	var kept *responseKept
	if !errors.As(err, &kept) {
		t.Fatalf("restoreResponse = %v, want a responseKept: the file holds the response", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != string(raw) {
		t.Fatalf("the file holds %q, want the response", body)
	}
}

// The reservation is what makes the reformat unable to fail for want of room, so it is held
// until the reformat has succeeded — not handed back the moment the raw response is durable.
func TestTheReservationIsHeldUntilTheFinalFormatIsDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	raw := []byte(`{"secret":"` + reservationSecret + `"}`)
	if _, err := reserved.persist(raw); err != nil {
		t.Fatalf("persist: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after persist: %d bytes on disk for a %d-byte response", info.Size(), len(raw))
	if info.Size() != spaceProofBytes {
		t.Fatalf("the file is %d bytes after persist, want the %d-byte proof still held: the "+
			"rewrite that follows would be writing into space nothing has claimed",
			info.Size(), spaceProofBytes)
	}

	render := secretFormatEnv.render(reservationSecret)
	if err := reserved.rewrite([]byte(render)); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after the reformat: %d bytes, exactly the rendering", len(body))
	if string(body) != render {
		t.Fatalf("the file holds %q, want exactly %q — the proof is cut away only once the "+
			"final format is durable", body, render)
	}
}

// The filesystem fills after the reveal and the reformat cannot be written. The rendering it
// managed lands ON TOP of the only durable copy of the secret, so what must survive is the
// response — put back, verified, and reported as where the credential is.
func TestAFailedReformatLeavesTheDurableResponseIntact(t *testing.T) {
	// A minimal envelope, which is what makes the RENDERING the longer of the two and so the one
	// that needs room the response did not: `GASWORKS_SP_SECRET='...'` costs 22 bytes around the
	// secret where `{"secret":"..."}` costs 13.
	raw := []byte(`{"secret":"` + reservationSecret + `"}`)
	render := secretFormatEnv.render(reservationSecret)
	// Room for the response and for the first 50 bytes of the rendering, which stops five
	// characters into the secret. Wide enough that cutting the file back to the response still
	// works, which is what a genuinely full filesystem allows too.
	limit := uint64(50)
	if uint64(len(raw)) > limit || uint64(len(render)) <= limit {
		t.Fatalf("the probe is mis-sized: response=%d rendering=%d limit=%d", len(raw), len(render), limit)
	}

	srv, _ := mintSeed(t)
	virtualClock(t)
	rescueDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(raw)
	}
	fillAfterTheResponseIsDurable(t, capFileSize(t, limit))

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %s is gone (%v)", out, err)
	}
	t.Logf("%s holds %d bytes: %q", out, len(body), string(body))
	if string(body) != string(raw) {
		t.Fatalf("%s holds %q, want the mint plane's response put back verbatim — a rendering "+
			"that could not be written must not stand in for the copy it overwrote", out, body)
	}
	assertOwnerOnly(t, out)
	if code == 0 {
		t.Error("exit 0 for a run whose destination is not the file that was asked for")
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Errorf("the success banner was printed over a file that is not a credential:\n%s", stdout)
	}
	// The operator is told a key exists, where it is, and not to delete it.
	for _, want := range []string{"A CREDENTIAL WAS MINTED", out, "not delete it"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
	// It is on the disk, so it never has to be printed.
	if strings.Contains(stdout+stderr, reservationSecret) {
		t.Errorf("the secret was printed even though it is in %s", out)
	}
	if entries, _ := os.ReadDir(rescueDir); len(entries) != 0 {
		t.Errorf("the rescue path ran (%v); the credential was already durable at %s", entries, out)
	}
}

// The same failure at the unit seam, with the read-back that decides it made explicit.
func TestRewriteRestoresTheResponseItCouldNotReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	raw := []byte(`{"secret":"` + reservationSecret + `"}`)
	if _, err := reserved.persist(raw); err != nil {
		t.Fatalf("persist: %v", err)
	}
	capFileSize(t, 50)()

	err = reserved.rewrite([]byte(secretFormatEnv.render(reservationSecret)))
	var kept *responseKept
	if !errors.As(err, &kept) {
		t.Fatalf("rewrite = %v, want a responseKept saying the file still holds the response", err)
	}
	t.Logf("rewrite could not finish (%s) and said so without calling it a lost credential", kept)

	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != string(raw) {
		t.Fatalf("the file holds %q, want the response back verbatim", body)
	}
}

// refusingWriter is a stream that will not take the bytes: a pipe whose reader has exited, a
// closed descriptor, a log file on the filesystem that just refused this very secret.
type refusingWriter struct{ err error }

func (w refusingWriter) Write([]byte) (int, error) { return 0, w.err }

// The last resort is the only place this CLI prints a secret, and it runs holding the only copy
// of a live key. A stderr that refuses the write cannot be allowed to swallow it silently.
func TestLastResortFallsBackToTheTerminalWhenStderrRefuses(t *testing.T) {
	tty := usableTerminal(t)
	previous := stderr
	stderr = refusingWriter{err: syscall.EPIPE}
	landed := printSecretOfLastResort(
		climint.Redemption{ChallengeID: "chal_1", Credential: climint.Credential{KeyID: "spk_1", Secret: reservationSecret}},
		secretFormatEnv, nil, errors.New("destination full"), errors.New("fallback full"))
	stderr = previous

	if !landed.terminal {
		t.Fatalf("the last resort gave up while the terminal was still available: %+v", landed)
	}
	if landed.stream {
		t.Error("the last resort claimed stderr took the block after stderr refused it")
	}
	body := tty.read(t)
	t.Logf("stderr refused with EPIPE; %d bytes went to %s instead", len(body), tty.path)
	for _, want := range []string{
		"THE MINTED SECRET COULD NOT BE SAVED",
		mintedSecretEnvVar + "='" + reservationSecret + "'",
		"treat the key as compromised",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the terminal did not get %q:\n%s", want, body)
		}
	}
}

// The check every "is this a terminal" shortcut gets wrong. /dev/null is a character device, and
// so are the other sinks that take a secret and keep it nowhere — calling any of them a terminal
// is exactly how the last resort stops looking for a real screen.
func TestDiscardDevicesAreNotMistakenForATerminal(t *testing.T) {
	for _, device := range []string{os.DevNull, "/dev/zero", "/dev/full", "/dev/urandom"} {
		file, err := os.OpenFile(device, os.O_WRONLY, 0)
		if err != nil {
			t.Logf("skipping %s: %v", device, err)
			continue
		}
		if isTerminal(file) {
			t.Errorf("%s is reported as a terminal, so bytes written there would be read back as "+
				"a delivery", device)
		}
		_ = file.Close()
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if isTerminal(file) {
		t.Error("a regular file is reported as a terminal")
	}
	if isTerminal(refusingWriter{err: syscall.EPIPE}) {
		t.Error("a writer that is not a file at all is reported as a terminal")
	}
	// And the probe does not disturb the stream it is asking about.
	if _, err := file.WriteString("first"); err != nil {
		t.Fatal(err)
	}
	_ = isTerminal(file)
	if _, err := file.WriteString("-second"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first-second" {
		t.Fatalf("the terminal check moved the file offset: %q", body)
	}
}

// The redirect that actually happens. `2>/dev/null` — a cron job, a CI step, a habit — ACCEPTS
// every byte of the last-resort block and keeps none, and reports success doing it. A write that
// returns no error is therefore not evidence of anything, and the terminal a person is sitting
// at has to be reached for anyway.
func TestLastResortReachesTheTerminalWhenStderrIsDiscarded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	tty := usableTerminal(t)
	// Nowhere for the fallback file to go, which is what puts the run on this path at all.
	unwritable := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unwritable, 0o700) })
	t.Setenv(store.MintedKeyDirEnv, unwritable)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			// The reserved destination is taken away while the human is at the approval page.
			if err := os.Remove(out); err != nil {
				t.Errorf("unlink the reservation: %v", err)
			}
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}

	// A real /dev/null, opened the way a shell redirect opens it, so the check that tells it
	// apart from a terminal is the one under test.
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("open %s: %v", os.DevNull, err)
	}
	defer devnull.Close()
	previousOut, previousErr := stdout, stderr
	var out2 strings.Builder
	stdout, stderr = &out2, devnull
	code := run(mintArgs(out))
	stdout, stderr = previousOut, previousErr

	body := tty.read(t)
	t.Logf("2>/dev/null: %d bytes reached the terminal instead", len(body))
	if !strings.Contains(body, mintedSecretEnvVar+"='gck_sp_secret_value'") {
		t.Fatalf("SECRET LOST: stderr discarded it and the terminal did not get it:\n%s", body)
	}
	if !strings.Contains(string(body), "chal_1") {
		t.Errorf("the block does not name the challenge the key came from:\n%s", body)
	}
	if code == 0 {
		t.Error("exit 0 with the secret in no file at all")
	}
	if strings.Contains(out2.String(), "gck_sp_secret_value") {
		t.Errorf("the secret went to stdout:\n%s", out2.String())
	}
}

// And when stderr took the bytes but there is no terminal to confirm it with, that uncertainty
// is the message: a stderr this process cannot read back may have been a log file or may have
// been /dev/null, and only the challenge id lets the operator find out which.
func TestLastResortSaysDeliveryIsUnprovenWithNoTerminalToReachFor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	previousTTY := lastResortTTY
	lastResortTTY = filepath.Join(t.TempDir(), "no-terminal-here")
	t.Cleanup(func() { lastResortTTY = previousTTY })
	unwritable := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.MintedKeyDirEnv, unwritable)

	minted := climint.Redemption{
		ChallengeID: "chal_1",
		Credential:  climint.Credential{KeyID: "spk_1", Secret: reservationSecret},
	}
	_, stderr, _ := capture(t, func() int {
		err := rescueMintedSecret(minted, secretFormatEnv, nil, errors.New("destination full"))
		if err == nil {
			t.Error("rescueMintedSecret returned nil with the secret on no readable stream")
			return 0
		}
		t.Logf("no terminal available -> %v", err)
		for _, want := range []string{"spk_1", "chal_1", "cannot read back", "left to expire"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the message is missing %q: %s", want, err)
			}
		}
		if strings.Contains(err.Error(), "printed on") {
			t.Errorf("the message claims a delivery it could not establish: %s", err)
		}
		if strings.Contains(err.Error(), reservationSecret) {
			t.Error("the failure message carries the secret itself")
		}
		return 0
	})
	// The block itself still went to stderr: a stderr that IS a log file holds the last copy.
	if !strings.Contains(stderr, reservationSecret) {
		t.Errorf("the block was not written to stderr at all:\n%s", stderr)
	}
}

// And when neither stream takes it, that is itself the report: the operator is told the key
// exists, that it is nowhere, and that it can only be waited out.
func TestLastResortSaysSoWhenNoStreamTakesTheSecret(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	previousTTY := lastResortTTY
	lastResortTTY = filepath.Join(t.TempDir(), "no-terminal-here")
	t.Cleanup(func() { lastResortTTY = previousTTY })
	// The fallback file has nowhere to go either, which is what puts the rescue on this path.
	unwritable := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(unwritable, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.MintedKeyDirEnv, unwritable)

	minted := climint.Redemption{ChallengeID: "chal_1", Credential: climint.Credential{KeyID: "spk_1", Secret: reservationSecret}}
	previous := stderr
	stderr = refusingWriter{err: syscall.EBADF}
	landed := printSecretOfLastResort(minted, secretFormatEnv, nil,
		errors.New("destination full"), errors.New("fallback full"))
	if landed.terminal || landed.stream {
		t.Errorf("the last resort reported a delivery with both streams refusing: %+v", landed)
	}
	err := rescueMintedSecret(minted, secretFormatEnv, nil, errors.New("destination full"))
	stderr = previous

	t.Logf("both streams refused -> %v", err)
	if err == nil {
		t.Fatal("rescueMintedSecret returned nil with the secret nowhere")
	}
	// The challenge id is the only handle left on a key nobody is holding, so the message that
	// admits the secret went nowhere has to carry it.
	for _, want := range []string{"spk_1", "chal_1", "in no file and on no stream", "left to expire"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message is missing %q: %s", want, err)
		}
	}
	if strings.Contains(err.Error(), reservationSecret) {
		t.Error("the failure message carries the secret itself")
	}
}
