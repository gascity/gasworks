//go:build !windows

// What the mint plane can and cannot do to this CLI's OUTPUT, and what the CLI is allowed to say
// about an answer it could not turn into a credential. POSIX only: two of these open a device
// node by name.

package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/store"
)

// forged is what a hostile (or compromised, or merely relaying) mint plane puts in a display
// field to write a line of our report itself. The CR returns the cursor so the rest overwrites
// what was already printed; the ESC [ sequences move it and clear the line outright.
const (
	forgedPath   = "/home/you/prod.env"
	forgedSecret = "gck_sp_secret_value"
)

func forgedKeyID() string {
	return "spk_1\r\n  secret:   " + forgedPath + " (owner-only, env format)\r"
}

func forgedExpiry() string {
	return "2026-09-10\x1b[2K\r  secret:   " + forgedPath + "\x1b[1A"
}

// X1. Every field leg C relays — key_id, expires_at, prefix, org_id, scopes — reaches the
// terminal through climint.Display, so none of them can add, overwrite or relocate a line. The
// credential FILE is a separate question and is answered the other way: it holds the secret byte
// for byte, unfiltered.
func TestServerStringsCannotForgeALineOfTheReport(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"key_id":     forgedKeyID(),
			"secret":     forgedSecret,
			"prefix":     "gck_sp\rXX",
			"org_id":     "acme\x1b[31m",
			"scopes":     []string{"forge:city.create", "forge:city.delete\r\nMinted a service-principal key for org evil."},
			"expires_at": forgedExpiry(),
		})
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstdout bytes: %q\nstderr bytes: %q", code, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit %d for a credential whose METADATA is hostile; the secret is fine", code)
	}
	assertNoControlBytes(t, "stdout", stdout)
	assertNoControlBytes(t, "stderr", stderr)
	// The forged line the server was trying to write must not exist anywhere, on any stream.
	for _, stream := range []struct{ name, text string }{{"stdout", stdout}, {"stderr", stderr}} {
		for _, line := range strings.Split(stream.text, "\n") {
			if strings.HasPrefix(line, "  secret:   "+forgedPath) {
				t.Errorf("%s carries a line the SERVER composed: %q", stream.name, line)
			}
			if strings.HasPrefix(line, "Minted a service-principal key for org evil") {
				t.Errorf("%s carries a banner the SERVER composed: %q", stream.name, line)
			}
		}
	}
	// One "secret:" line, and it names the file this command wrote.
	var secretLines []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "  secret:   ") {
			secretLines = append(secretLines, line)
		}
	}
	if len(secretLines) != 1 || !strings.Contains(secretLines[0], out) {
		t.Errorf("stdout has %d secret lines, want exactly one naming %s: %q", len(secretLines), out, secretLines)
	}
	// And the credential itself is untouched: filtering is for what we PRINT.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	if want := secretFormatEnv.render(forgedSecret); string(body) != want {
		t.Fatalf("the credential file holds %q, want the secret byte for byte (%q)", body, want)
	}
	assertOwnerOnly(t, out)
}

// The same rule on leg A, whose two fields are printed before anything has been minted: the
// confirm code the human types, and the approval URL the OS is handed.
func TestLegAStringsCannotForgeALineOfThePrompt(t *testing.T) {
	srv, opened := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintChallengeHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		challenge := map[string]any{}
		for k, v := range srv.mintChallenge {
			challenge[k] = v
		}
		challenge["confirm_code"] = "WXYZ-4242\r\n  1. Open:        https://phish.example/steal\r"
		writeJSON(w, http.StatusCreated, challenge)
	}

	_, stderr, code := capture(t, func() int { return run(mintArgs(out, "--no-browser")) })
	t.Logf("exit=%d\nstderr bytes: %q", code, stderr)
	assertNoControlBytes(t, "stderr", stderr)
	var openLines []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "  1. Open:        ") {
			openLines = append(openLines, line)
		}
	}
	if len(openLines) != 1 {
		t.Errorf("the prompt has %d \"Open:\" lines, want the one this CLI wrote: %q", len(openLines), openLines)
	}
	if strings.Contains(openLines[0], "phish.example") {
		t.Errorf("the confirm code rewrote the URL line: %q", openLines[0])
	}
	// The forged text is still THERE, quoted — the operator can see exactly what the server sent
	// and it is one field of one line, which is the whole point of escaping rather than dropping.
	if !strings.Contains(stderr, `"WXYZ-4242\r\n  1. Open:        https://phish.example/steal\r"`) {
		t.Errorf("the confirm code was dropped rather than quoted:\n%s", stderr)
	}
	if len(*opened) != 0 {
		t.Errorf("a browser was opened with --no-browser: %v", *opened)
	}
}

// The approval URL is the one relayed value that is not only printed — it is handed to the OS,
// which opens whatever it is given. Filtering it at the decode is what keeps the URL this CLI
// PRINTS and the URL it OPENS the same string; a URL that cannot be printed verbatim stops being
// a URL this client will act on, and the ceremony ends before the human is sent anywhere.
func TestAnApprovalURLCarryingControlBytesIsNeverOpened(t *testing.T) {
	srv, opened := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintChallengeHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		challenge := map[string]any{}
		for k, v := range srv.mintChallenge {
			challenge[k] = v
		}
		challenge["approve_url"] = fmt.Sprint(srv.mintChallenge["approve_url"]) + "\x9b2K\rhttps://phish.example/"
		writeJSON(w, http.StatusCreated, challenge)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr bytes: %q", code, stderr)
	if code == 0 {
		t.Fatal("exit 0 for an approval URL carrying control bytes")
	}
	if len(*opened) != 0 {
		t.Fatalf("a browser was opened at %v", *opened)
	}
	assertNoControlBytes(t, "stdout", stdout)
	assertNoControlBytes(t, "stderr", stderr)
	if !strings.Contains(stderr, "nothing was minted") {
		t.Errorf("leg A was refused before leg C and the message does not say so:\n%s", stderr)
	}
}

// An error message is the most obviously attacker-shaped field on either leg: free text, relayed
// from accounts, and printed the moment anything goes wrong.
func TestAServerErrorMessageCannotForgeALine(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":             "denied\rgranted",
			"error_description": "refused\r\nMinted a service-principal key for org evil.\x1b[2K",
		})
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr bytes: %q", code, stderr)
	if code == 0 {
		t.Fatal("exit 0 for a 403")
	}
	assertNoControlBytes(t, "stdout", stdout)
	assertNoControlBytes(t, "stderr", stderr)
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "Minted a service-principal key") {
			t.Errorf("an error_description wrote a success banner: %q", line)
		}
	}
}

// assertNoControlBytes is the whole of X1 in one assertion: whatever the server sent, nothing
// this CLI prints carries a byte a terminal ACTS on. Newline is the one exception — it is how
// our own lines are separated, and no relayed value can contribute one.
func assertNoControlBytes(t *testing.T, stream, text string) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if b := text[i]; b < 0x20 && b != '\n' || b == 0x7f {
			from := max(0, i-40)
			t.Errorf("%s carries the control byte %q at offset %d: ...%q...", stream, b, i, text[from:min(len(text), i+40)])
			return
		}
	}
}

// X3. /dev/tty is not always a terminal. A container with a hand-made /dev, an image that
// symlinks the node, a bind-mount of /dev/null over it: all take the block, return success, and
// keep none of it. Claiming delivery there is worse than claiming nothing — the caller turns it
// into "it was printed on /dev/tty and exists nowhere else", the sentence that stops the operator
// looking any further.
func TestADiscardDeviceStandingInForTheTTYIsNotADelivery(t *testing.T) {
	previous := lastResortTTY
	lastResortTTY = os.DevNull
	t.Cleanup(func() { lastResortTTY = previous })

	discard, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no %s to write to: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = discard.Close() })
	previousErr := stderr
	stderr = discard
	got := writeLastResort([]byte("GASWORKS_SP_SECRET='THE-LIVE-SECRET'\n"))
	stderr = previousErr

	t.Logf("delivery = %+v", got)
	if got.terminal {
		t.Errorf("delivery to a terminal was claimed for %s (where=%q)", os.DevNull, got.where)
	}
	if isTerminal(discard) {
		t.Errorf("isTerminal says %s is a terminal", os.DevNull)
	}
}

// The same thing through the whole ceremony: nothing can hold the secret, and the terminal the
// last resort reaches for is a discard device. The exit line must not name a delivery.
func TestTheCeremonyDoesNotClaimAPrintIntoADiscardDevice(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("POSIX directory permissions do not restrain this user")
	}
	srv, _ := mintSeed(t)
	virtualClock(t)
	dir := t.TempDir()
	rescueDir := filepath.Join(dir, "minted-keys")
	if err := os.Mkdir(rescueDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rescueDir, 0o700) })
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	previous := lastResortTTY
	lastResortTTY = os.DevNull
	t.Cleanup(func() { lastResortTTY = previous })

	out := filepath.Join(dir, "sp.env")
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

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr:\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Fatal("exit 0 with the secret in no file at all")
	}
	if strings.Contains(stderr, "exists nowhere else") {
		t.Errorf("the exit line claims a delivery into %s:\n%s", os.DevNull, stderr)
	}
	for _, want := range []string{"went only to stderr", "Reconcile challenge chal_1"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the honest ending is missing %q:\n%s", want, stderr)
		}
	}
}

// X4. Two 2xx answers that carry no credential. Both used to be announced as a minted key
// because "2xx with bytes" was read as a reveal; the bytes are still saved (the challenge is
// spent either way and this client cannot tell what the server did) and the SENTENCE is now the
// status, plus an outcome nobody knows.
func TestATwoHundredThatCarriesNoCredentialIsNotAnnouncedAsAMint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ctype  string
	}{
		{"200 carrying authorization_pending", 200, `{"status":"authorization_pending","interval":5}`, "application/json"},
		{"a captive portal", 200, "<html><body>Sign in to the network</body></html>", "text/html"},
		{"a load balancer's plain-text note", 200, "OK\n", "text/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Content-Type", tc.ctype)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}

			_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d\nstderr:\n%s", code, strings.TrimSpace(stderr))
			if code == 0 {
				t.Error("exit 0 for an answer that carried no credential")
			}
			if strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
				t.Errorf("a %d carrying no credential is reported as a minted, unrevokable key:\n%s",
					tc.status, stderr)
			}
			for _, want := range []string{
				fmt.Sprintf("THE MINT PLANE ANSWERED %d WITH A BODY THIS CLI COULD NOT READ AS A CREDENTIAL", tc.status),
				"Whether one was issued is NOT known",
				"reconcile challenge chal_1",
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("the report is missing %q:\n%s", want, stderr)
				}
			}
			// The bytes are still kept: the server acted on the challenge, and this client does
			// not get to decide it knows better than the file.
			if body, err := os.ReadFile(out); err != nil || string(body) != tc.body {
				t.Errorf("the answer was not kept verbatim at %s (%v): %q", out, err, body)
			}
		})
	}
}

// A 204 that carries a body anyway — only reachable by writing the response by hand, which is
// what a proxy or a load balancer in front of the mint plane is doing. It reveals nothing, and
// the report says the status and that the outcome is unknown.
func TestATwoHundredAndFourIsNotAnnouncedAsAMint(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	const body = "no content, apparently\n"
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.(net.Conn).Close() }()
		fmt.Fprintf(buf, "HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			len(body), body)
		_ = buf.Flush()
	}

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr:\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Error("exit 0 for a 204")
	}
	if strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
		t.Errorf("a 204 is reported as a minted key:\n%s", stderr)
	}
	if !strings.Contains(stderr, "204") {
		t.Errorf("the report does not name the status that was received:\n%s", stderr)
	}
	if !strings.Contains(stderr, "chal_1") {
		t.Errorf("the report does not name the challenge to reconcile:\n%s", stderr)
	}
}

// A complete response whose HTTP FRAMING was cut — a chunked body with no terminating chunk, a
// dropped proxy, a GOAWAY after the last byte. ReadErr is set and nothing is missing: the JSON
// parses, so the secret's string is closed. Calling that INCOMPLETE leaves the operator with a
// raw response and a warning about a tail that is not missing.
func TestAWholeResponseWithCutFramingIsRenderedNormally(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	raw := `{"key_id":"spk_1","secret":"` + forgedSecret + `","prefix":"gck_sp","org_id":"acme"}`
	srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.(net.Conn).Close() }()
		writeUnterminatedChunk(buf, raw)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr:\n%s", code, strings.TrimSpace(stderr))
	if code != 0 {
		t.Errorf("exit %d for a response whose JSON parsed and whose secret is whole", code)
	}
	for _, untrue := range []string{"STOPPED ARRIVING", "PART of a secret", "cut short"} {
		if strings.Contains(stderr, untrue) {
			t.Errorf("the report says %q about a body that provably arrived whole:\n%s", untrue, stderr)
		}
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %v", err)
	}
	if want := secretFormatEnv.render(forgedSecret); string(body) != want {
		t.Errorf("%s holds %q, want the requested rendering %q", out, body, want)
	}
	assertSecretOnNoStream(t, stdout, stderr, forgedSecret)
}

func writeUnterminatedChunk(buf *bufio.ReadWriter, body string) {
	fmt.Fprint(buf, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
	fmt.Fprintf(buf, "%x\r\n%s\r\n", len(body), body)
	_ = buf.Flush()
}

// X5. The rescue's sentence over a body that stopped mid-secret. sp.go's report draws the
// distinction; this path has to draw the same one, because "the secret is inside it" over half a
// secret is how an operator stops looking for the key that may be live.
func TestTheRescueDistinguishesACutShortBodyFromAWholeOne(t *testing.T) {
	full := `{"key_id":"spk_1","secret":"` + forgedSecret + `","prefix":"gck_sp"}`
	partial := full[:strings.Index(full, forgedSecret)+len(forgedSecret)/2]
	header := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n"

	srv, _ := mintSeed(t)
	virtualClock(t)
	dir := t.TempDir()
	rescueDir := filepath.Join(dir, "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, rescueDir)
	out := filepath.Join(dir, "sp.env")
	attempts := 0
	srv.mintCompleteHandler = func(w http.ResponseWriter, r *http.Request, n int) {
		if attempts++; attempts == 1 {
			// Take the reservation out from under the run, so the answer cannot go where it was
			// asked to and the rescue is what handles it.
			if err := os.Remove(out); err != nil {
				t.Errorf("unlink the reservation: %v", err)
			}
			mintPending(w, "authorization_pending", 5)
			return
		}
		answerRaw(header+partial, false)(w, r, n)
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\nstderr:\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Fatal("exit 0 for a cut-short body that could not go where it was asked")
	}
	for _, untrue := range []string{"the secret is inside it", "was minted and its secret is in"} {
		if strings.Contains(stderr, untrue) {
			t.Errorf("the rescue says %q over a body that stopped mid-secret:\n%s", untrue, stderr)
		}
	}
	for _, want := range []string{
		"stopped arriving part way through",
		"PART of a secret",
		"reconcile challenge chal_1",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the rescue is missing %q:\n%s", want, stderr)
		}
	}
	// And the bytes really are somewhere: the rescue file is the only copy.
	rescued, _, held := onlyRescuedSecret(t, rescueDir)
	if !strings.Contains(held, partial) {
		t.Fatalf("%s does not hold the bytes that arrived: %q", rescued, held)
	}
	assertSecretOnNoStream(t, stdout, stderr, forgedSecret)
}

// The last-resort print is the one place a secret reaches a screen, and the bytes it puts there
// are copied back into a file by hand. A raw response carrying a CR would repaint the banner
// above it, so it is escaped — reversibly, and announced — while a credential this CLI could read
// goes out exactly as it will be pasted.
func TestTheLastResortEscapesAHostileRawResponseAndNotACredential(t *testing.T) {
	hostile := "{\"key\":\"\x1b[2K\rSAVED OK\"}"
	block := recoverableFor(t, []byte(hostile))
	if strings.Contains(block, "\x1b") || strings.Contains(block, "\r") {
		t.Errorf("the raw response reached the block unescaped: %q", block)
	}
	if !strings.Contains(block, `\x1b[2K\r`) {
		t.Errorf("the escaped form does not carry the bytes back: %q", block)
	}
	clean, escaped := recoverableBytes([]byte(`{"key_id":"spk_1"}` + "\n"))
	if escaped || clean != `{"key_id":"spk_1"}` {
		t.Errorf("an ordinary response was escaped: %q (escaped=%v)", clean, escaped)
	}
	// The credential goes to the screen unescaped, which is only safe because unusableSecret has
	// already refused any secret carrying a control character.
	rendered := strings.TrimRight(secretFormatEnv.render("gck_sp_secret_value"), "\n")
	if !climint.Printable(rendered) {
		t.Errorf("the env rendering of an ordinary secret is not printable: %q", rendered)
	}
	if why := unusableSecret("gck_sp\rvalue"); why == "" {
		t.Error("a secret carrying a CR is accepted as usable, so it would reach the screen raw")
	}
}

func recoverableFor(t *testing.T, raw []byte) string {
	t.Helper()
	text, escaped := recoverableBytes(raw)
	if !escaped {
		t.Errorf("a response carrying ESC and CR was not escaped: %q", text)
	}
	return text
}
