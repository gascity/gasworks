package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/climint"
)

// Leg C's answer becomes durable the instant it has been read and BEFORE anything parses it,
// so every way of losing it after that instant stops being a way of losing it. These are the
// ways the transport can go wrong once the secret bytes are already on the wire: the connection
// closes mid-body, the peer resets it, and the client's own timeout expires while the body is
// still arriving. io.ReadAll hands back what it managed to read alongside its error in all
// three, and that is what reaches the disk.

const durableSecret = "gck_sp_durable_marker"

// answerRaw writes literal response bytes onto the socket and then closes it, short of the
// framing it declared. It is how a truncation and a mid-body close are staged; reset says
// whether the close is an orderly FIN or an RST.
func answerRaw(raw string, reset bool) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		_, _ = buf.WriteString(raw)
		_ = buf.Flush()
		if reset {
			// SO_LINGER 0 makes the close an RST rather than a FIN, which is what a load
			// balancer dropping a connection actually looks like to the client.
			if tc, ok := underlyingTCP(conn); ok {
				_ = tc.SetLinger(0)
			}
		}
		_ = conn.Close()
	}
}

func underlyingTCP(conn net.Conn) (*net.TCPConn, bool) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	tc, ok := conn.(*net.TCPConn)
	return tc, ok
}

// impatientMintClient shortens the ceremony client's whole-request timeout, which covers the
// BODY read as well as the headers: a link that stalls after the secret bytes have arrived is
// exactly what this bounds, and 30s of real time is not a thing to put in a test.
func impatientMintClient(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := mintClient
	mintClient = &climint.Client{HTTP: &http.Client{
		Transport:     previous.HTTP.Transport,
		CheckRedirect: previous.HTTP.CheckRedirect,
		Timeout:       timeout,
	}}
	t.Cleanup(func() { mintClient = previous })
}

func TestSPMintKeySavesASecretFromABodyThatNeverFinishes(t *testing.T) {
	// A 201 whose declared length is never delivered. The secret is inside the bytes that DID
	// arrive, which is the whole point: the server has minted, the challenge is spent, and this
	// is the only copy.
	partial := `{"key_id":"spk_1","secret":"` + durableSecret + `","prefix":"gck_sp"`
	header := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n"

	for _, tc := range []struct {
		name    string
		short   time.Duration // non-zero: shorten the client timeout for this case
		handler func(http.ResponseWriter, *http.Request, int)
	}{
		{name: "the connection closes mid-body", handler: answerRaw(header+partial, false)},
		{name: "the connection is reset after the secret bytes", handler: answerRaw(header+partial, true)},
		{
			name:  "the client timeout expires while the body is still arriving",
			short: 400 * time.Millisecond,
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					panic(err)
				}
				defer conn.Close()
				_, _ = buf.WriteString(header + partial)
				_ = buf.Flush()
				// Hold the connection open with the body unfinished until the client gives up.
				time.Sleep(3 * time.Second)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			if tc.short != 0 {
				impatientMintClient(t, tc.short)
			}
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = tc.handler

			stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d", code)

			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("SECRET LOST: leg C revealed a credential and %s does not exist: %v\n%s", out, err, stderr)
			}
			if !strings.Contains(string(body), durableSecret) {
				t.Fatalf("%s holds %q, which does not carry the revealed secret", out, body)
			}
			if string(body) != partial {
				t.Fatalf("%s holds %q, want the bytes that arrived verbatim (%q)", out, body, partial)
			}
			assertOwnerOnly(t, out)
			if code == 0 {
				t.Error("exit 0 for a response this CLI could not render as a credential")
			}
			for _, want := range []string{
				"ITS ANSWER STOPPED ARRIVING PART WAY THROUGH",
				"cut short",
				"reconcile challenge chal_1",
				out,
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr is missing %q:\n%s", want, stderr)
				}
			}
			// The bytes carry the secret, but nothing PARSED one out of them: the envelope stops
			// mid-object. So the report may not state a mint as a fact — only the status, the
			// missing tail, and the challenge to reconcile.
			if strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
				t.Errorf("stderr states a mint as a fact over an envelope it could not read:\n%s", stderr)
			}
			assertSecretOnNoStream(t, stdout, stderr, durableSecret)
		})
	}
}

// The bytes that arrived are saved either way — but what the operator is TOLD about them is not
// the same sentence. A body that stopped inside the secret leaves a file holding part of one,
// and "nothing is lost" and "the secret is INSIDE that file" are both false of it. The read
// error is in hand when that report is written, so there is no excuse for either.
func TestSPMintKeyReportsACutShortResponseAsIncomplete(t *testing.T) {
	full := `{"key_id":"spk_1","secret":"` + durableSecret + `","prefix":"gck_sp"}`
	at := strings.Index(full, durableSecret)
	partial := full[:at+len(durableSecret)/2] // stops halfway through the secret
	header := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n"

	srv, _ := mintSeed(t)
	virtualClock(t)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = answerRaw(header+partial, false)

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Fatal("exit 0 for a response that stopped in the middle of the secret")
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the bytes that did arrive were not saved: %v", err)
	}
	if string(body) != partial {
		t.Fatalf("%s holds %q, want the %d bytes that arrived", out, body, len(partial))
	}
	assertOwnerOnly(t, out)
	// What it must never say about half a secret.
	for _, untrue := range []string{"nothing is lost", "The secret is INSIDE that file"} {
		if strings.Contains(stderr, untrue) {
			t.Errorf("the report claims %q over a body that was cut short:\n%s", untrue, stderr)
		}
	}
	// What it must say instead: which status was answered, that the answer is incomplete, that a
	// key may exist, and which challenge to reconcile it against.
	for _, want := range []string{
		"THE MINT PLANE ANSWERED 201 AND ITS ANSWER STOPPED ARRIVING PART WAY THROUGH",
		"whether one was issued is",
		"PART of a secret",
		"challenge:  chal_1",
		"reconcile challenge chal_1",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the report is missing %q:\n%s", want, stderr)
		}
	}
	assertSecretOnNoStream(t, stdout, stderr, durableSecret)
}

// The envelope half of the same rule. None of these bodies is a credential this CLI can render,
// and not one of them may cost the bytes the server sent.
func TestSPMintKeySavesAResponseItCannotInterpret(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"truncated JSON with an honest Content-Length", `{"key_id":"spk_1","secret":"` + durableSecret + `"`,
			"is not a JSON object"},
		{"a UTF-8 BOM before the JSON", "\xef\xbb\xbf" + `{"key_id":"spk_1","secret":"` + durableSecret + `"}`,
			"is not a JSON object"},
		{"an array wrapping the object", `[{"key_id":"spk_1","secret":"` + durableSecret + `"}]`,
			"is not a JSON object"},
		{"the secret under an unexpected key", `{"key_id":"spk_1","client_secret":"` + durableSecret + `"}`,
			`the only field that could be it is "client_secret"`},
		{"the secret nested under one this client does not walk into", `{"credential":{"secret":"` + durableSecret + `"}}`,
			`the only field that could be it is "credential.secret"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}

			stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d", code)

			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("SECRET LOST: %s does not exist: %v\n%s", out, err, stderr)
			}
			if string(body) != tc.body {
				t.Fatalf("%s holds %q, want the server's bytes verbatim", out, body)
			}
			assertOwnerOnly(t, out)
			if code == 0 {
				t.Error("exit 0 for a response this CLI could not render as a credential")
			}
			for _, want := range []string{
				"THE MINT PLANE ANSWERED 201 WITH A BODY THIS CLI COULD NOT READ AS A CREDENTIAL",
				"reconcile challenge chal_1",
				tc.want,
				out,
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr is missing %q:\n%s", want, stderr)
				}
			}
			if strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
				t.Errorf("stderr states a mint as a fact over an envelope no secret was read out "+
					"of:\n%s", stderr)
			}
			assertSecretOnNoStream(t, stdout, stderr, durableSecret)
		})
	}
}

// A secret this CLI can read and cannot USE is the case that used to exit 0 under a success
// banner with a corrupted credential in the file. It is still the only copy that will ever
// exist, so the server's own bytes stay on the disk — a rendering of the decoded value would be
// a worse copy than the response it came from — and the exit says the run did not go as asked.
func TestSPMintKeyKeepsAndReportsAnUnusableSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			// Raw invalid UTF-8 inside the JSON string. encoding/json substitutes U+FFFD for it,
			// so the value that reaches this process is NOT the value on the wire.
			"invalid UTF-8 in the secret",
			"{\"key_id\":\"spk_1\",\"secret\":\"" + durableSecret + "\xff\xfe\"}",
			"not valid UTF-8 where the secret is",
		},
		{
			"a NUL byte in the secret",
			`{"key_id":"spk_1","secret":"` + durableSecret + `\u0000tail"}`,
			`control character '\x00'`,
		},
		{
			"a newline that would forge a second assignment",
			`{"key_id":"spk_1","secret":"` + durableSecret + `\nGASWORKS_SP_SECRET='attacker'"}`,
			`control character '\n'`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}

			_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d stderr=%q", code, strings.TrimSpace(stderr))

			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("SECRET LOST: %s does not exist: %v", out, err)
			}
			if string(body) != tc.body {
				t.Fatalf("%s holds %q, want the server's bytes verbatim — the decoded value is the "+
					"damaged copy", out, body)
			}
			assertOwnerOnly(t, out)
			if code == 0 {
				t.Fatal("exit 0 with a success banner over a secret that cannot be used as one")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr does not say what is wrong with the secret (%q):\n%s", tc.want, stderr)
			}
			if !strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
				t.Errorf("stderr does not say a credential was minted:\n%s", stderr)
			}
		})
	}
}

// The hard window: from the first byte of the response reaching the reserved file to that write
// being durable, a signal cannot be honoured without destroying the credential. Everything else
// the ceremony does is either before the reveal (where a cancel costs nothing) or after the
// bytes are safe. This measures what is left.
func TestPersistIsTheOnlyWindowASignalMustWaitFor(t *testing.T) {
	if testing.Short() {
		t.Skip("times real fsyncs")
	}
	const trials = 100
	body := []byte(`{"key_id":"spk_1","secret":"` + durableSecret + `","prefix":"gck_sp","org_id":"org_a",` +
		`"scopes":["forge:city.create","forge:city.delete"],"expires_at":"2026-09-10T00:00:00Z"}`)
	dir := t.TempDir()

	var total, worst time.Duration
	for i := range trials {
		reserved, err := reserveSecretFile(filepath.Join(dir, fmt.Sprintf("sp-%d.env", i)))
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		started := time.Now()
		stored, err := reserved.persist(body)
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		if string(stored) != string(body) {
			t.Fatalf("persist read back %q, want the response it was given", stored)
		}
		_ = reserved.file.Close()
		total += elapsed
		if elapsed > worst {
			worst = elapsed
		}
	}
	t.Logf("guard window (write + truncate + fsync + read-back of a %d-byte response): mean %s, worst %s over %d trials",
		len(body), (total / trials).Round(time.Microsecond), worst.Round(time.Microsecond), trials)
	if worst > 100*time.Millisecond {
		t.Fatalf("the window a signal must wait out is %s, which is long enough for a person to "+
			"notice Ctrl-C doing nothing", worst)
	}
}

// What persist returns is read back OUT of the file, not handed through from the caller's
// buffer. Everything the command says afterwards — the key id, the reason, the byte count — is
// then a statement about the file the operator will open.
func TestPersistReturnsWhatTheFileHolds(t *testing.T) {
	reserved, err := reserveSecretFile(filepath.Join(t.TempDir(), "sp.env"))
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	raw := []byte(`{"key_id":"spk_1","secret":"` + durableSecret + `"}`)
	stored, err := reserved.persist(raw)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	// Scribbling on the caller's buffer must not change what was reported. If it does, what
	// came back is the copy in memory and the read-back never happened.
	for i := range raw {
		raw[i] = 'X'
	}
	if want := `{"key_id":"spk_1","secret":"` + durableSecret + `"}`; string(stored) != want {
		t.Fatalf("persist returned %q, want the bytes as the file holds them (%q)", stored, want)
	}
	onDisk, err := os.ReadFile(reserved.path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(onDisk) < len(stored) || string(onDisk[:len(stored)]) != string(stored) {
		t.Fatalf("the file starts with %q and persist reported %q", onDisk, stored)
	}
	// And the reservation is STILL held behind those bytes. persist makes the response durable;
	// it does not settle what the file finally holds, and handing the proven blocks back here
	// would leave the reformat that follows writing into space nothing has claimed.
	if len(onDisk) != spaceProofBytes {
		t.Fatalf("the file is %d bytes after persist, want the %d-byte reservation still held "+
			"behind the response", len(onDisk), spaceProofBytes)
	}
	if !bytes.Equal(onDisk[len(stored):], spaceProof(spaceProofBytes)[len(stored):]) {
		t.Fatalf("what follows the response is not the untouched placeholder: %q", onDisk[len(stored):])
	}
}

// A flush that fails over bytes that READ BACK is not a lost credential, and this is the seam
// where that used to be got wrong. persist's fsync reports an error, its write landed in full,
// and the file provably holds the response — so the run must NOT go to the rescue, which writes
// a second copy of a live key and, when that copy cannot be written either, prints it.
//
// The flush problem is real and is said out loud: what a failed fsync cannot promise is
// durability across a power loss, which is a warning, not a loss. This is the same verdict
// restoreResponse reaches at the reformat seam, reached the same way — by reading the file.
func TestSPMintKeyDoesNotRescueAFlushFailureOverAFileThatHoldsTheResponse(t *testing.T) {
	mintSeed(t)
	virtualClock(t)
	dir := t.TempDir()
	mintedDir := filepath.Join(dir, "minted-keys")
	t.Setenv("GASWORKS_MINTED_KEY_DIR", mintedDir)
	out := filepath.Join(dir, "sp.env")

	// Fail exactly the fsync persist makes, identified by what the file holds at the time: the
	// server's response. The space proof (placeholder text) and the rendering's own flush both
	// still work, so this is the one flush under test.
	original := syncSecretFile
	failed := 0
	syncSecretFile = func(file *os.File) error {
		// A JSON object at byte 0 is persist's write and nothing else: the space proof is
		// placeholder text and every rendering starts with the env var's name.
		head := make([]byte, 1)
		if n, _ := file.ReadAt(head, 0); n == 1 && head[0] == '{' {
			failed++
			return fmt.Errorf("simulated fsync failure")
		}
		return original(file)
	}
	t.Cleanup(func() { syncSecretFile = original })

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d persist flushes failed=%d\nstderr:\n%s", code, failed, strings.TrimSpace(stderr))
	if failed == 0 {
		t.Fatal("the fsync hook never fired, so nothing here was exercised")
	}
	if code != 0 {
		t.Errorf("exit %d over a file that holds the credential", code)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("SECRET LOST: %s is gone (%v)", out, err)
	}
	if want := secretFormatEnv.render("gck_sp_secret_value"); string(body) != want {
		t.Fatalf("%s holds %q, want the requested rendering %q", out, body, want)
	}
	assertOwnerOnly(t, out)
	if entries, _ := os.ReadDir(mintedDir); len(entries) != 0 {
		t.Errorf("the rescue ran (%d file(s) in %s) over a destination that holds the credential",
			len(entries), mintedDir)
	}
	// The flush problem is reported, and none of the rescue's vocabulary is.
	if !strings.Contains(stderr, "read back out of it, byte for byte") {
		t.Errorf("the flush failure was not reported at all:\n%s", stderr)
	}
	for _, untrue := range []string{
		"COULD NOT BE SAVED", "exists nowhere else", "treat the key as compromised",
		"not the destination you gave", "could not be written where you asked",
	} {
		if strings.Contains(stderr, untrue) {
			t.Errorf("the report says %q over a 0600 file that holds the credential:\n%s", untrue, stderr)
		}
	}
	assertSecretOnNoStream(t, stdout, stderr, "gck_sp_secret_value")
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("%s is mode %04o, readable beyond its owner", path, perm)
	}
}

func assertSecretOnNoStream(t *testing.T, stdout, stderr, secret string) {
	t.Helper()
	for name, stream := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if strings.Contains(stream, secret) {
			t.Errorf("the secret was printed on %s:\n%s", name, stream)
		}
	}
}
