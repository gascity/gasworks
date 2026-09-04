package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/store"
)

// --- harness -------------------------------------------------------------------------------

// mintSeed wires the whole ceremony up: a stub STS, a logged-in credential store, a stub mint
// plane on its own https origin, and a browser that records instead of opening.
func mintSeed(t *testing.T) (*stubServer, *[]string) {
	t.Helper()
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	srv.startMint(t)
	return srv, recordApprovalURLs(t)
}

// recordApprovalURLs replaces the browser launcher. Every test installs it: a developer's
// machine has DISPLAY set, and a test suite must not open browser windows.
func recordApprovalURLs(t *testing.T) *[]string {
	t.Helper()
	var opened []string
	original := openApprovalURL
	openApprovalURL = func(url string) { opened = append(opened, url) }
	t.Cleanup(func() { openApprovalURL = original })
	return &opened
}

// virtualClock makes the poll loop's waits instant and observable: a sleep records its
// duration and advances the same clock the deadline is measured against, so a ceremony that
// would take minutes of wall time runs in microseconds and still expires when it should.
func virtualClock(t *testing.T) *[]time.Duration {
	t.Helper()
	instant := time.Now().Unix()
	var waits []time.Duration
	originalNow, originalSleep := now, sleep
	now = func() int64 { return instant }
	sleep = func(d time.Duration) {
		waits = append(waits, d)
		instant += int64(d / time.Second)
	}
	t.Cleanup(func() { now, sleep = originalNow, originalSleep })
	return &waits
}

// proofJTI reads the jti out of a DPoP proof's claims (segment 1 of the JWS).
func proofJTI(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("DPoP proof is not a 3-part JWS: %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode proof claims: %v", err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal proof claims: %v", err)
	}
	if claims.JTI == "" {
		t.Fatalf("proof carries no jti: %s", raw)
	}
	return claims.JTI
}

func mintArgs(out string, extra ...string) []string {
	args := []string{
		"sp", "mint-key",
		"--org", "acme",
		"--sp", "sp_1",
		"--scope", "forge:city.create",
		"--scope", "forge:city.delete",
		"--no-browser",
		"--out", out,
	}
	return append(args, extra...)
}

// --- the ceremony --------------------------------------------------------------------------

func TestSPMintKeyMintsAndWritesTheSecret(t *testing.T) {
	srv, opened := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}

	// Leg A carried exactly the request the flags describe, with resource_refs ABSENT (which is
	// what makes the server fold in the service principal's own workspace grant).
	legA := srv.reqs("/v0/cli/mint/challenges")
	if len(legA) != 1 {
		t.Fatalf("leg A requests = %d, want 1", len(legA))
	}
	wantBody := `{"org_id":"org_a","sp_id":"sp_1","product":"forge",` +
		`"scopes":["forge:city.create","forge:city.delete"],"expires_in_days":7}`
	if legA[0].body != wantBody {
		t.Fatalf("leg A body =\n%s\nwant\n%s", legA[0].body, wantBody)
	}

	// The confirm code exists only in leg A's response, so the terminal is where the human
	// reads it. The approval URL is the server's own, verbatim.
	if !strings.Contains(stderr, "WXYZ-4242") {
		t.Fatalf("stderr does not show the confirm code:\n%s", stderr)
	}
	if !strings.Contains(stderr, srv.mint.URL+"/cli/approve?c=chal_1") {
		t.Fatalf("stderr does not show the approval URL:\n%s", stderr)
	}
	if len(*opened) != 0 {
		t.Fatalf("--no-browser opened %v", *opened)
	}

	// The secret went to the file and nowhere else.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	if got, want := string(body), mintedSecretEnvVar+"='gck_sp_secret_value'\n"; got != want {
		t.Fatalf("secret file = %q, want %q", got, want)
	}
	for _, stream := range []string{stdout, stderr} {
		if strings.Contains(stream, "gck_sp_secret_value") {
			t.Fatalf("the secret was printed:\n%s", stream)
		}
	}
	for _, want := range []string{"spk_1", "forge:city.create forge:city.delete", "2026-09-10T00:00:00Z", out} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout is missing %q:\n%s", want, stdout)
		}
	}
}

func TestSPMintKeySecretFileIsOwnerOnly(t *testing.T) {
	mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.secret")

	if _, stderr, code := capture(t, func() int {
		return run(mintArgs(out, "--format", "raw"))
	}); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	info, err := os.Lstat(out)
	if err != nil {
		t.Fatalf("stat secret file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("secret file mode = %04o, want 0600", perm)
		}
	}
	// raw is byte-exact: `credential-provider --service-principal-credential-file` reads the
	// file verbatim, so a trailing newline would corrupt the credential.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	if string(body) != "gck_sp_secret_value" {
		t.Fatalf("raw secret file = %q, want the secret with no trailing newline", body)
	}
}

func TestSPMintKeyOpensTheApprovalURLVerbatim(t *testing.T) {
	if !hasDisplay() {
		t.Setenv("DISPLAY", ":0") // the browser launcher is stubbed; this only selects the path
	}
	srv, opened := mintSeed(t)
	virtualClock(t)
	approveURL := srv.mint.URL + "/cli/approve?c=chal_1&x=1"
	srv.mintChallenge["approve_url"] = approveURL
	out := filepath.Join(t.TempDir(), "sp.env")

	// The same command as everywhere else in this file, minus --no-browser.
	args := []string{
		"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
		"--scope", "forge:city.create", "--out", out,
	}
	if _, stderr, code := capture(t, func() int { return run(args) }); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	if len(*opened) != 1 || (*opened)[0] != approveURL {
		t.Fatalf("opened = %v, want the server's approve_url unchanged", *opened)
	}
}

// The 425 is climint's own, not RFC 8628: no OAuth error field, a status discriminator and an
// interval. The client waits exactly what the server asked for, and each attempt is a fresh
// call carrying a fresh proof — never a retry of the spent one.
func TestSPMintKeyPollsUntilApproved(t *testing.T) {
	srv, _ := mintSeed(t)
	waits := virtualClock(t)
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		switch attempt {
		case 0:
			mintPending(w, "authorization_pending", 5)
		case 1:
			mintPending(w, "slow_down", 7)
		default:
			writeJSON(w, http.StatusCreated, srv.mintCredential)
		}
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	if _, stderr, code := capture(t, func() int { return run(mintArgs(out)) }); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	complete := srv.reqs("/complete")
	if len(complete) != 3 {
		t.Fatalf("leg C attempts = %d, want 425, 425, 201", len(complete))
	}
	if got := *waits; len(got) != 2 || got[0] != 5*time.Second || got[1] != 7*time.Second {
		t.Fatalf("poll waits = %v, want the server's 5s then 7s", got)
	}
	// A spent jti cannot be presented twice: every attempt signs its own proof. Comparing the
	// proofs themselves would prove nothing — ECDSA signatures are randomised, so two signings
	// over identical bytes differ anyway — so this reads the jti out of each one.
	seen := map[string]bool{}
	for i, attempt := range complete {
		jti := proofJTI(t, attempt.dpop)
		if seen[jti] {
			t.Fatalf("leg C attempt %d presented jti %q again; the server's ledger has already spent it", i, jti)
		}
		seen[jti] = true
	}
	if _, err := os.Lstat(out); err != nil {
		t.Fatalf("secret file after a polled approval: %v", err)
	}
}

func TestSPMintKeyStopsAtTheApprovalDeadline(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.mintChallenge["expires_in"] = 10
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		mintPending(w, "authorization_pending", 5)
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit when the approval window closes")
	}
	if !strings.Contains(stderr, "approval window (10s) closed") {
		t.Fatalf("stderr = %q, want the closed-window message", stderr)
	}
	if attempts := len(srv.reqs("/complete")); attempts != 2 {
		t.Fatalf("leg C attempts = %d, want the two that fit in a 10s window at 5s apart", attempts)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("an expired ceremony left %s behind (%v)", out, err)
	}
}

// Leg C is pinned to leg A's subject AND its key thumbprint, so a session established halfway
// through ends the ceremony. One login, one bearer, one key — for the whole run.
func TestSPMintKeyDoesNotReestablishTheSessionMidCeremony(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt < 2 {
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	if _, stderr, code := capture(t, func() int { return run(mintArgs(out)) }); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	if logins := len(srv.reqs("/sts/v0/login")); logins != 1 {
		t.Fatalf("session establishments = %d, want exactly 1 for the whole ceremony", logins)
	}
	legs := append(srv.reqs("/v0/cli/mint/challenges"), srv.reqs("/complete")...)
	if len(legs) != 4 {
		t.Fatalf("mint requests = %d, want leg A plus three leg C attempts", len(legs))
	}
	for i, leg := range legs {
		if leg.auth == "" || leg.auth != legs[0].auth {
			t.Fatalf("mint request %d used Authorization %q, want the same session as leg A (%q)", i, leg.auth, legs[0].auth)
		}
	}
}

func TestSPMintKeyRejectsANonUserSession(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.loginHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"session_token": "gcs_service_SESS", "session_id": "ses_1",
			"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 28800,
		})
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit for a non-user session")
	}
	if !strings.Contains(stderr, "not a user session") {
		t.Fatalf("stderr = %q, want the user-session requirement", stderr)
	}
	if mints := len(srv.reqs("/v0/cli/mint/challenges")); mints != 0 {
		t.Fatalf("a doomed session still made %d mint requests (each spends a jti)", mints)
	}
}

func TestSPMintKeyTerminalErrorWritesNothing(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "denied", "error_description": "the approver rejected this mint",
		})
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit on a terminal mint error")
	}
	// What the server said, not a paraphrase of it, plus what to do next.
	if !strings.Contains(stderr, "403 denied — the approver rejected this mint") ||
		!strings.Contains(stderr, "nothing was minted") {
		t.Fatalf("stderr = %q, want the server's own reason plus what to do about it", stderr)
	}
	if attempts := len(srv.reqs("/complete")); attempts != 1 {
		t.Fatalf("leg C attempts = %d, want no retry of a terminal failure", attempts)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("a failed mint left %s behind (%v)", out, err)
	}
}

// --- the destination file ------------------------------------------------------------------

// The check runs BEFORE leg A: a secret is revealed exactly once, so a destination that was
// always going to be refused must be refused while retyping the command is the only cost.
func TestSPMintKeyRefusesToOverwriteAnExistingFile(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	if err := os.WriteFile(out, []byte("PRIOR"), 0o600); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit when --out already exists")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Fatalf("stderr = %q, want the already-exists refusal", stderr)
	}
	if body, err := os.ReadFile(out); err != nil || string(body) != "PRIOR" {
		t.Fatalf("existing file = (%q, %v), want it untouched", body, err)
	}
	if mints := len(srv.reqs("/v0/cli/mint/challenges")); mints != 0 {
		t.Fatalf("the refusal came AFTER %d mint requests; it must come before any", mints)
	}
}

// A destination that cannot be CREATED is the failure the pre-flight exists for: an Lstat
// that says "nothing there" says nothing about whether this process may put something there,
// and by the time the write fails the server has already revealed a secret it will not reveal
// again. So the file is created for real before leg A opens a challenge.
func TestSPMintKeyRefusesAnUncreatableOutBeforeLegA(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("seed unwritable dir: %v", err)
	}
	out := filepath.Join(dir, "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit when the destination cannot be created")
	}
	if !strings.Contains(stderr, "could not create "+out) {
		t.Fatalf("stderr = %q, want the create failure named", stderr)
	}
	mints := len(srv.reqs("/v0/cli/mint/challenges"))
	t.Logf("recorded: %d requests to /v0/cli/mint/challenges, %d to /complete, %d in total",
		mints, len(srv.reqs("/complete")), len(srv.requests))
	if mints != 0 {
		t.Fatalf("the ceremony ran anyway: %d mint requests, want 0 — a secret was minted with nowhere to go", mints)
	}
	if strings.Contains(stderr, "was minted") {
		t.Fatalf("stderr = %q, want no minted-but-unsaved key", stderr)
	}
}

// The default destination has the same failure mode, and MkdirAll does not catch it: it
// succeeds on a directory that already exists and cannot be written to.
func TestSPMintKeyRefusesAnUnwritableMintedKeyDirBeforeLegA(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(minted, 0o500); err != nil {
		t.Fatalf("seed unwritable minted-keys dir: %v", err)
	}
	t.Setenv(store.MintedKeyDirEnv, minted)

	_, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
			"--scope", "forge:city.create", "--no-browser"})
	})
	if code == 0 {
		t.Fatal("want a non-zero exit when the minted-keys dir cannot be written")
	}
	if !strings.Contains(stderr, "could not create a file in "+minted) {
		t.Fatalf("stderr = %q, want the unwritable directory named", stderr)
	}
	mints := len(srv.reqs("/v0/cli/mint/challenges"))
	t.Logf("recorded: %d requests to /v0/cli/mint/challenges, %d to /complete, %d in total",
		mints, len(srv.reqs("/complete")), len(srv.requests))
	if mints != 0 {
		t.Fatalf("the ceremony ran anyway: %d mint requests, want 0", mints)
	}
	if entries, err := os.ReadDir(minted); err != nil || len(entries) != 0 {
		t.Fatalf("minted-keys dir = (%v, %v), want it untouched and empty", entries, err)
	}
}

// The reservation is held open across the ceremony, so a run that fails after it must take
// the file with it.
func TestSPMintKeyLeavesNoReservationBehind(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "expired"})
	}
	minted := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, minted)

	_, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
			"--scope", "forge:city.create", "--no-browser"})
	})
	if code == 0 {
		t.Fatalf("want a non-zero exit on a terminal mint error, stderr=%q", stderr)
	}
	entries, err := os.ReadDir(minted)
	if err != nil {
		t.Fatalf("read minted-keys dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed ceremony left %v behind in %s", entries, minted)
	}
}

// --- the destination after leg C -------------------------------------------------------------

// Creating a file reserves a name, not blocks, so a full filesystem passes every pre-flight and
// fails on the write — after the secret has been revealed. The reservation now claims
// secret-sized room and gives it straight back, which moves ENOSPC to where retyping the
// command is the only cost.
//
// No unprivileged test can fill a filesystem, so this injects the failure at the placeholder
// write. TestOneShotDiskFull (build tag `oneshot`) drives the same path against a real full
// tmpfs mounted at /mnt/atkfull.
func TestSPMintKeyRefusesADestinationWithNoRoomBeforeLegA(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(out string) []string
	}{
		{"--out", func(out string) []string { return mintArgs(out) }},
		{"the default destination", func(string) []string {
			return []string{"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
				"--scope", "forge:city.create", "--no-browser"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			minted := filepath.Join(t.TempDir(), "minted-keys")
			t.Setenv(store.MintedKeyDirEnv, minted)
			out := filepath.Join(t.TempDir(), "sp.env")

			original := writeSpaceProof
			writeSpaceProof = func(file *os.File, _ []byte, _ int64) error {
				return &os.PathError{Op: "write", Path: file.Name(), Err: syscall.ENOSPC}
			}
			t.Cleanup(func() { writeSpaceProof = original })

			_, stderr, code := capture(t, func() int { return run(tc.args(out)) })
			if code == 0 {
				t.Fatal("want a non-zero exit when the destination has no room for a secret")
			}
			if !strings.Contains(stderr, "could not reserve room for a secret") {
				t.Fatalf("stderr = %q, want the reservation naming what it could not do", stderr)
			}
			a, c := len(srv.reqs("/v0/cli/mint/challenges")), len(srv.reqs("/complete"))
			t.Logf("recorded: leg A = %d, leg C = %d, total = %d", a, c, len(srv.requests))
			if a != 0 || c != 0 {
				t.Fatalf("ENOSPC cost leg A=%d leg C=%d — a secret was minted with nowhere to go", a, c)
			}
			// The reservation that could not be proved takes itself with it: nothing was
			// revealed, so there is nothing to protect.
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("the failed reservation left %s behind (%v)", out, err)
			}
			if entries, _ := os.ReadDir(minted); len(entries) != 0 {
				t.Fatalf("the failed reservation left %v in %s", entries, minted)
			}
		})
	}
}

// The reservation is held open across a ceremony that waits on a human, which is plenty of time
// for something to take the path away. The descriptor survives that and goes on pointing at an
// orphaned inode, so the CLI used to write the secret into a file nobody can open and report
// success. The handle and the path are now compared before the write.
func TestSPMintKeyRescuesTheSecretWhenTheReservationIsUnlinked(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, minted)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			// A tmp reaper, another user, an operator tidying up — while the human approves.
			if err := os.Remove(out); err != nil {
				t.Errorf("unlink the reservation: %v", err)
			}
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatalf("exit 0 with the secret not at --out:\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Fatalf("the success banner was printed for a mint that missed its destination:\n%s", stdout)
	}
	name, mode, body := onlyRescuedSecret(t, minted)
	t.Logf("rescued to %s (mode %04o)", name, mode)
	if mode != 0o600 && runtime.GOOS != "windows" {
		t.Fatalf("the rescue file is mode %04o, want 0600", mode)
	}
	if !strings.Contains(body, "gck_sp_secret_value") {
		t.Fatalf("the rescue file holds %q, not the secret", body)
	}
	if !strings.Contains(stderr, name) {
		t.Fatalf("stderr does not say where the secret went:\n%s", stderr)
	}
}

// The same window, used to swap the path for someone else's file. The secret must not land in
// it — and the file must not be unlinked either: after leg C this CLI removes nothing.
func TestSPMintKeyRescuesTheSecretWhenTheReservationIsReplaced(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, minted)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			if err := os.Remove(out); err != nil {
				t.Errorf("unlink the reservation: %v", err)
			}
			if err := os.WriteFile(out, []byte("NOT THE SECRET"), 0o600); err != nil {
				t.Errorf("plant a replacement: %v", err)
			}
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatalf("exit 0 after the destination was replaced:\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Fatalf("the success banner was printed for a swapped destination:\n%s", stdout)
	}
	if !strings.Contains(stderr, "no longer the file this command created") {
		t.Fatalf("stderr = %q, want the swap named", stderr)
	}
	// The impostor is neither written to nor removed.
	body, err := os.ReadFile(out)
	if err != nil || string(body) != "NOT THE SECRET" {
		t.Fatalf("%s = (%q, %v), want the replacement untouched and still in place", out, body, err)
	}
	name, mode, rescued := onlyRescuedSecret(t, minted)
	t.Logf("rescued to %s (mode %04o)", name, mode)
	if mode != 0o600 && runtime.GOOS != "windows" {
		t.Fatalf("the rescue file is mode %04o, want 0600", mode)
	}
	if !strings.Contains(rescued, "gck_sp_secret_value") {
		t.Fatalf("the rescue file holds %q, not the secret", rescued)
	}
}

// The last resort, and the one place this CLI prints a secret. It is reached only when the
// destination and the fallback have both failed, where the alternative is a live key holding
// forge:city.create and forge:city.delete that nobody has and nothing can revoke.
func TestSPMintKeyPrintsTheSecretWhenNothingCanHoldIt(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(minted, 0o500); err != nil {
		t.Fatalf("seed an unwritable minted-keys dir: %v", err)
	}
	t.Setenv(store.MintedKeyDirEnv, minted)
	// The last resort reaches for the operator's terminal whenever stderr is not verifiably one,
	// and here stderr is a capture buffer. Point it at a file this test owns: nothing may write a
	// secret to the terminal a test suite happens to be running in.
	tty := usableTerminal(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
		if attempt == 0 {
			if err := os.Remove(out); err != nil {
				t.Errorf("unlink the reservation: %v", err)
			}
			mintPending(w, "authorization_pending", 5)
			return
		}
		writeJSON(w, http.StatusCreated, srv.mintCredential)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatalf("exit 0 with the secret in no file at all:\nstdout:%s", stdout)
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Fatalf("the success banner was printed:\n%s", stdout)
	}
	// stdout stays clean even here: a redirected stdout is the log this would become.
	if strings.Contains(stdout, "gck_sp_secret_value") {
		t.Fatalf("the secret went to stdout:\n%s", stdout)
	}
	for _, want := range []string{
		"THE MINTED SECRET COULD NOT BE SAVED",
		"IT IS PRINTED BELOW BECAUSE THERE IS NO",
		mintedSecretEnvVar + "='gck_sp_secret_value'",
		"treat the key as compromised",
		"cannot be revoked",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("the last-resort banner is missing %q:\n%s", want, stderr)
		}
	}
	// And it reached a destination that can be read back, which a successful write to stderr does
	// not establish on its own.
	onTTY := tty.read(t)
	if !strings.Contains(onTTY, "gck_sp_secret_value") {
		t.Fatalf("the terminal did not get the secret (%d bytes):\n%s", len(onTTY), onTTY)
	}
}

// The reservation proves it can hold a secret by holding one, and then KEEPS the room: giving
// the blocks back the moment the proof passes makes the proof a statement about the past, and
// the filesystem can fill during the minutes the ceremony waits on a human. The file is cut
// down to the secret only once the secret is durable, so what is left is exactly the rendering
// and nothing of the placeholder.
func TestReserveSecretFileKeepsItsSpaceProofUntilTheSecretLands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the reservation: %v", err)
	}
	t.Logf("after the proof: %s is %d bytes", path, info.Size())
	if info.Size() != spaceProofBytes {
		t.Fatalf("the reservation is %d bytes, want the %d bytes it proved it could take still held",
			info.Size(), spaceProofBytes)
	}
	proof, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the reservation: %v", err)
	}
	if !bytes.Equal(proof, spaceProof(spaceProofBytes)) {
		t.Fatalf("the reservation holds %d bytes that are not the placeholder", len(proof))
	}

	saved := saveThroughTheCeremony(t, reserved, "spk_1", "gck_sp_secret_value", secretFormatEnv)
	body, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := secretFormatEnv.render("gck_sp_secret_value")
	t.Logf("after the save: %s is %d bytes", saved, len(body))
	if string(body) != want {
		t.Fatalf("the file holds %q, want exactly %q — the placeholder was not cut away, or the "+
			"write did not start at byte 0", body, want)
	}
}

// The raw rendering is read back verbatim by `credential-provider
// --service-principal-credential-file`, so a single leftover placeholder byte is a broken
// credential. This is the same cut, on the format that cannot tolerate a tail.
func TestSavedRawSecretIsExactlyTheSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.secret")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	saved := saveThroughTheCeremony(t, reserved, "spk_1", "gck_sp_secret_value", secretFormatRaw)
	body, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "gck_sp_secret_value" {
		t.Fatalf("the raw file holds %q, want the secret alone", body)
	}
}

// saveThroughTheCeremony puts a reservation through the same two steps the ceremony does: leg
// C's response bytes are made durable FIRST, and the file is rewritten as a rendered credential
// only afterwards, out of what was read back off the disk.
func saveThroughTheCeremony(t *testing.T, reserved *secretFile, keyID, secret string, format secretFormat) string {
	t.Helper()
	stored, err := reserved.persist([]byte(`{"key_id":"` + keyID + `","secret":"` + secret + `"}`))
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if !strings.Contains(string(stored), secret) {
		t.Fatalf("the persisted response read back as %q, which does not hold the secret", stored)
	}
	if err := reserved.rewrite([]byte(format.render(secret))); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	return reserved.settle(keyID, format)
}

// discard() is a rollback for a reservation, and the ceremony disarms it the instant leg C
// reveals a secret. This is the sequence that found it: Sync makes the bytes durable, and the
// Close that follows can still fail on a network or FUSE filesystem — which used to leave the
// reservation looking unwritten, so the deferred cleanup unlinked a secret already on the disk.
func TestSecretFileDiscardCannotRemoveASecretAfterDisarm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.env")
	reserved, err := reserveSecretFile(path)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	reserved.disarm()
	if _, err := reserved.file.WriteString(secretFormatEnv.render("gck_sp_secret_value")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := reserved.file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	reserved.discard()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("discard() removed a durably-synced secret: %v", err)
	}
	if !strings.Contains(string(body), "gck_sp_secret_value") {
		t.Fatalf("%s holds %q", path, body)
	}
}

// onlyRescuedSecret returns the name, mode and contents of the single file the rescue path left
// in dir, and fails if there is not exactly one.
func onlyRescuedSecret(t *testing.T, dir string) (string, os.FileMode, string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("%s holds %d files, want exactly one rescued secret", dir, len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat %s: %v", entries[0].Name(), err)
	}
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read %s: %v", entries[0].Name(), err)
	}
	return entries[0].Name(), info.Mode().Perm(), string(body)
}

// The approval URL is the server's to compose, but it is handed to the OS, so it is checked
// against the one origin this CLI signs proofs to before anything opens it.
func TestSPMintKeyRefusesAnApprovalURLAtAnotherOrigin(t *testing.T) {
	if !hasDisplay() {
		t.Setenv("DISPLAY", ":0") // the browser launcher is stubbed; this only selects the path
	}
	for _, tc := range []struct {
		name    string
		approve func(mintOrigin string) string
	}{
		{"plain http elsewhere", func(string) string { return "http://evil.example/x" }},
		{"https elsewhere", func(string) string { return "https://evil.example/cli/approve?c=chal_1" }},
		{"the real mint plane, which is not the configured one", func(string) string {
			return "https://auth.gascity.com/cli/approve?c=chal_1"
		}},
		{"not a URL", func(string) string { return "not a url at all" }},
		{"the mint origin in the userinfo", func(origin string) string {
			return "https://" + strings.TrimPrefix(origin, "https://") + "@evil.example/x"
		}},
		{"the mint host with userinfo attached", func(origin string) string {
			return strings.Replace(origin, "https://", "https://someone@", 1) + "/cli/approve"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, opened := mintSeed(t)
			virtualClock(t)
			approve := tc.approve(srv.mint.URL)
			srv.mintChallenge["approve_url"] = approve
			out := filepath.Join(t.TempDir(), "sp.env")

			args := []string{
				"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
				"--scope", "forge:city.create", "--out", out,
			}
			_, stderr, code := capture(t, func() int { return run(args) })
			if code == 0 {
				t.Fatalf("approve_url %q was accepted", approve)
			}
			if !strings.Contains(stderr, "refusing to open it") {
				t.Fatalf("stderr = %q, want the refusal", stderr)
			}
			if len(*opened) != 0 {
				t.Fatalf("the browser was launched at %v", *opened)
			}
			if strings.Contains(stderr, "Enter code") {
				t.Fatalf("stderr = %q, want no approval prompt for a URL that was refused", stderr)
			}
			if attempts := len(srv.reqs("/complete")); attempts != 0 {
				t.Fatalf("leg C ran %d times after a refused approval URL", attempts)
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("a refused ceremony left %s behind (%v)", out, err)
			}
		})
	}
}

// The challenge TTL is the server's number and the session's lifetime is this client's; the
// poll must stop at whichever comes first, or it polls on with a session leg C is pinned to
// and can no longer present.
func TestSPMintKeyStopsWhenTheSessionExpiresBeforeTheWindow(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.loginHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"session_token": "gcs_user_SESS", "session_id": "ses_1",
			"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 400,
		})
	}
	// A TTL far past what the session can cover: the clamp is the only thing that ends this.
	srv.mintChallenge["expires_in"] = 100000
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		mintPending(w, "authorization_pending", 60)
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit when the session expires first")
	}
	if !strings.Contains(stderr, "expires before the approval window") {
		t.Fatalf("stderr = %q, want the session, not the window, named as the constraint", stderr)
	}
	// 400s of session, less the 60s the last leg C needs, at 60s a poll.
	if attempts := len(srv.reqs("/complete")); attempts != 6 {
		t.Fatalf("leg C attempts = %d, want the six that fit before the session's expiry", attempts)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("an abandoned ceremony left %s behind (%v)", out, err)
	}
}

// The lifetime demand applies to a FRESH session too. One that cannot cover the ceremony is
// refused here, where nothing has been spent, not at the approval page.
func TestSPMintKeyRefusesAShortFreshSession(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	srv.loginHandler = func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"session_token": "gcs_user_SESS", "session_id": "ses_1",
			"org_id": form.Get("org"), "token_type": "DPoP", "expires_in": 60,
		})
	}
	out := filepath.Join(t.TempDir(), "sp.env")

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	if code == 0 {
		t.Fatal("want a non-zero exit for a session that cannot outlive the ceremony")
	}
	if !strings.Contains(stderr, "does not cover the approval window") {
		t.Fatalf("stderr = %q, want the short-session refusal", stderr)
	}
	if mints := len(srv.reqs("/v0/cli/mint/challenges")); mints != 0 {
		t.Fatalf("a doomed session still opened %d challenges (each spends a jti)", mints)
	}
}

// The env file is documented as source-able, so a secret carrying shell metacharacters has to
// come back out of a `source` byte for byte.
func TestSPMintKeySecretSurvivesAShellSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	const nasty = `gck_sp_$(id)_` + "`id`" + `_'quoted'_"double"_;_&_|_\`
	srv.mintCredential["secret"] = nasty
	out := filepath.Join(t.TempDir(), "sp.env")

	if _, stderr, code := capture(t, func() int { return run(mintArgs(out)) }); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	sourced, err := exec.Command("sh", "-c", ". "+out+` && printf %s "$`+mintedSecretEnvVar+`"`).Output()
	if err != nil {
		t.Fatalf("source the env file: %v", err)
	}
	if string(sourced) != nasty {
		t.Fatalf("sourcing the env file assigned %q, want the secret %q", sourced, nasty)
	}
}

// A mode NARROWER than 0600 is this file's own protection, tightened — not a reason to delete
// an unrepeatable secret. Anything readable beyond the owner is.
func TestVerifySecretFileModeAcceptsTighterModesOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS ignores the POSIX mode bits")
	}
	for _, tc := range []struct {
		mode   os.FileMode
		wantOK bool
	}{
		{0o600, true},
		{0o400, true},
		{0o200, true},
		{0o640, false},
		{0o604, false},
		{0o666, false},
	} {
		path := filepath.Join(t.TempDir(), "secret")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := file.Chmod(tc.mode); err != nil {
			t.Fatalf("chmod %04o: %v", tc.mode, err)
		}
		err = verifySecretFileMode(file, path)
		_ = file.Close()
		if tc.wantOK && err != nil {
			t.Errorf("mode %04o was rejected: %v", tc.mode, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("mode %04o was accepted", tc.mode)
		}
	}
}

// What was validated is what is sent. A duplicate key survives text compaction but collapses
// on decode, so validating the decoded value and transmitting the compacted text can inspect
// one document and send another.
func TestSPMintKeyResourceRefsSendWhatWasValidated(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")

	if _, stderr, code := capture(t, func() int {
		return run(mintArgs(out, "--resource-refs", `{"cities":["city_1"],"cities":["city_2"]}`))
	}); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	legA := srv.reqs("/v0/cli/mint/challenges")
	if len(legA) != 1 {
		t.Fatalf("leg A requests = %d, want 1", len(legA))
	}
	if !strings.Contains(legA[0].body, `"resource_refs":{"cities":["city_2"]}`) {
		t.Fatalf("leg A body = %s, want the single decoded refs value that was validated", legA[0].body)
	}
	if strings.Contains(legA[0].body, "city_1") {
		t.Fatalf("leg A body = %s, still carries the key the validator never saw", legA[0].body)
	}
}

func TestSPMintKeyWritesUnderTheMintedKeyDirByDefault(t *testing.T) {
	mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, minted)

	args := []string{
		"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
		"--scope", "forge:city.create", "--no-browser",
	}
	stdout, stderr, code := capture(t, func() int { return run(args) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	want := filepath.Join(minted, "spk_1.env")
	if _, err := os.Lstat(want); err != nil {
		t.Fatalf("default destination %s: %v", want, err)
	}
	if !strings.Contains(stdout, want) {
		t.Fatalf("stdout does not name the file it wrote:\n%s", stdout)
	}
}

// --- validation ------------------------------------------------------------------------------

// Every one of these is judged locally, before a session exists: the server's jti ledger is
// single-use, so a request that was always going to be rejected must never be sent.
func TestSPMintKeyRejectsBadFlagsBeforeTouchingTheNetwork(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no service principal", []string{"--scope", "forge:city.create"}, "--sp is required"},
		{"no scope", []string{"--sp", "sp_1"}, "--scope is required"},
		{"duplicate scopes", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--scope", "forge:city.create"}, "same scope twice"},
		{"scope list in one flag", []string{"--sp", "sp_1", "--scope", "forge:city.create forge:city.delete"}, "must be a single scope"},
		{"product namespace mismatch", []string{"--sp", "sp_1", "--scope", "crucible:city.config.write"}, `is not in the "forge" namespace`},
		{"crucible product cannot hold forge scopes", []string{"--sp", "sp_1", "--product", "crucible", "--scope", "forge:city.create"}, `a "crucible" key can never hold it`},
		{"zero ttl", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--ttl-days", "0"}, "--ttl-days must be at least 1"},
		{"negative ttl", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--ttl-days", "-3"}, "--ttl-days must be at least 1"},
		{"wildcard ref", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{"cities":["city_1","*"]}`}, "wildcard at resource-refs.cities[1]"},
		{"wildcard key", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{"orgs":{"*":["x"]}}`}, "wildcard at resource-refs.orgs.*"},
		{"wildcard in the value a duplicate key resolves to",
			[]string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{"a":"ok","a":"*"}`},
			"wildcard at resource-refs.a"},
		{"two JSON values", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{} {}`}, "single JSON value"},
		{"wildcard deep in a string", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{"a":{"b":[{"c":"city_*"}]}}`}, "wildcard at resource-refs.a.b[0].c"},
		{"malformed refs", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", `{"cities":`}, "not valid JSON"},
		{"null refs", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--resource-refs", ` null `}, "not the same as leaving the flag off"},
		{"unknown format", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--format", "yaml"}, "unknown --format"},
		{"secret to stdout", []string{"--sp", "sp_1", "--scope", "forge:city.create", "--out", "-"}, "never written to stdout"},
		{"stray argument", []string{"--sp", "sp_1", "--scope", "forge:city.create", "mint"}, "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)

			_, stderr, code := capture(t, func() int {
				return run(append([]string{"sp", "mint-key", "--org", "acme", "--no-browser"}, tc.args...))
			})
			if code == 0 {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, tc.want)
			}
			if len(srv.requests) != 0 {
				t.Fatalf("a rejected command still made %d requests: %v", len(srv.requests), srv.requests)
			}
		})
	}
}

func TestSPUsageNamesTheSubcommand(t *testing.T) {
	for _, argv := range [][]string{{"sp"}, {"sp", "revoke-key"}} {
		_, stderr, code := capture(t, func() int { return run(argv) })
		if code == 0 {
			t.Fatalf("%v exited 0, want a usage failure", argv)
		}
		if !strings.Contains(stderr, "gasworks sp mint-key") {
			t.Fatalf("%v stderr = %q, want the sp usage", argv, stderr)
		}
	}
}

// --- dry run ---------------------------------------------------------------------------------

func TestSPMintKeyDryRunSendsNothing(t *testing.T) {
	srv, opened := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out, "--dry-run")) })
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	if len(srv.requests) != 0 {
		t.Fatalf("--dry-run made %d requests: %v", len(srv.requests), srv.requests)
	}
	if len(*opened) != 0 {
		t.Fatalf("--dry-run opened %v", *opened)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("--dry-run created %s (%v)", out, err)
	}
	if !strings.Contains(stdout, "POST "+srv.mint.URL+"/v0/cli/mint/challenges") {
		t.Fatalf("stdout does not show the request line:\n%s", stdout)
	}
	if !strings.Contains(stderr, out) {
		t.Fatalf("stderr does not say where the secret would go:\n%s", stderr)
	}
	// A dry run resolves nothing over the network, so --org is echoed as given.
	if !strings.Contains(stdout, `"org_id":"acme"`) {
		t.Fatalf("stdout does not carry the requested org:\n%s", stdout)
	}
}

// The dry run's whole purpose is to be trusted while the endpoint is dark, so what it prints is
// pinned to what a live run actually puts on the wire — including the compaction of
// --resource-refs and the omission of every field the request does not carry.
func TestSPMintKeyDryRunMatchesTheWire(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	shared := []string{
		"sp", "mint-key", "--org", "org_a", "--sp", "sp_1",
		"--scope", "forge:city.create", "--ttl-days", "3",
		"--resource-refs", `{"cities": ["city_1"] }`,
		"--no-browser", "--out", out,
	}

	stdout, stderr, code := capture(t, func() int {
		return run(append(append([]string{}, shared...), "--dry-run"))
	})
	if code != 0 {
		t.Fatalf("dry run exit = %d, stderr=%q", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("dry run stdout = %q, want a request line and a body line", stdout)
	}
	printed := lines[1]

	if _, stderr, code := capture(t, func() int { return run(shared) }); code != 0 {
		t.Fatalf("live run exit = %d, stderr=%q", code, stderr)
	}
	legA := srv.reqs("/v0/cli/mint/challenges")
	if len(legA) != 1 {
		t.Fatalf("leg A requests = %d, want 1", len(legA))
	}
	if printed != legA[0].body {
		t.Fatalf("dry run printed\n%s\nbut the wire carried\n%s", printed, legA[0].body)
	}
	if !strings.Contains(printed, `"resource_refs":{"cities":["city_1"]}`) {
		t.Fatalf("resource refs were not passed through compacted: %s", printed)
	}
}

func TestSPMintKeyDryRunFallsBackToTheStoredDefaultOrg(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"default_org": "org_stored"})
	srv.startMint(t)
	recordApprovalURLs(t)

	stdout, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--sp", "sp_1", "--scope", "forge:city.create", "--dry-run"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"org_id":"org_stored"`) {
		t.Fatalf("stdout = %q, want the stored default org", stdout)
	}
}

func TestSPMintKeyDryRunWithNoOrgAnywhereSaysSo(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{})
	srv.startMint(t)
	recordApprovalURLs(t)

	_, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--sp", "sp_1", "--scope", "forge:city.create", "--dry-run"})
	})
	if code == 0 {
		t.Fatal("want a non-zero exit when no org can be resolved offline")
	}
	if !strings.Contains(stderr, "pass --org") {
		t.Fatalf("stderr = %q, want the --org instruction", stderr)
	}
}

// --- the session the ceremony holds ----------------------------------------------------------

// getToken re-establishes a session with <30s left. That is far too generous here: the server
// pins leg C to leg A's subject and thumbprint, so a session must outlive the whole approval
// window plus a margin, or be replaced BEFORE leg A where replacing it is free.
func TestEnsureMintSessionDemandsMoreThanTheApprovalWindow(t *testing.T) {
	cases := []struct {
		name      string
		remaining int64
		wantReuse bool
	}{
		{"outlives the ceremony", mintChallengeTTLSecs + mintSessionMarginSecs + 60, true},
		{"survives getToken's skew but not the ceremony", 60, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			instant := int64(1_000_000)
			originalNow := now
			now = func() int64 { return instant }
			t.Cleanup(func() { now = originalNow })

			useFileKeystore(t)
			// newSession persists under the store lock and fences on the generation, so the
			// document on disk has to agree with the one the caller is holding.
			writeCreds(t, map[string]any{"credential_generation": "g1:test"})
			ref := enrollTestKey(t, "dpop-mint-session")
			var logins int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				logins++
				writeJSON(w, http.StatusCreated, map[string]any{
					"session_token": "gcs_user_FRESH", "org_id": "acme",
					"token_type": "DPoP", "expires_in": 28800,
				})
			}))
			t.Cleanup(srv.Close)
			cfg := (config.Config{STSBase: srv.URL, AllowFileKeystore: true}).WithSTSBase(srv.URL)
			data := &store.Data{
				CredentialGeneration: "g1:test",
				Sessions: map[string]store.Session{
					sessionCacheKey(srv.URL, "acme", "g1:test"): {
						SessionToken: "gcs_user_STORED", Key: ref, ExpiresAt: instant + tc.remaining,
					},
				},
			}

			session, err := ensureMintSession(cfg, data, "acme", "id-token", "g1:test", srv.URL)
			if err != nil {
				t.Fatalf("ensureMintSession: %v", err)
			}
			if session.Key == nil {
				t.Fatal("ensureMintSession returned no key")
			}
			// Whichever branch it took, the session it hands back covers the ceremony.
			if !outlivesTheCeremony(session.ExpiresAt) {
				t.Fatalf("session expiry %d is %ds away, which does not cover the ceremony",
					session.ExpiresAt, session.ExpiresAt-instant)
			}
			token := session.Token
			if tc.wantReuse && (token != "gcs_user_STORED" || logins != 0) {
				t.Fatalf("session = %q after %d logins, want the stored one reused", token, logins)
			}
			if !tc.wantReuse && (token != "gcs_user_FRESH" || logins != 1) {
				t.Fatalf("session = %q after %d logins, want a fresh one established", token, logins)
			}
		})
	}
}
