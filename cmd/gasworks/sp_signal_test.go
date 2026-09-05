//go:build !windows

// POSIX signals only: the deferral this file proves is about the four signals the guard covers,
// and the child half sends itself one with kill(2). On Windows the guard installs the same
// handler and the re-raise degrades to an exit code, which nothing here can drive.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/store"
)

// A signal is the one failure these tests cannot stage in-process: the default action for
// SIGINT and SIGTERM kills the process, which in a test would take the test runner with it. So
// the ceremony is run in a child, driven by the env below, and the child sends itself a REAL
// signal from inside its own leg C handler — in the window where the minted secret exists only
// in memory. The parent then holds the run to the one invariant that matters: if leg C answered
// 201, the secret is in an owner-only file.
const (
	signalProbeModeEnv  = "GASWORKS_TEST_SIGNAL_PROBE" // "mint", "commit", "wait" or "stall"
	signalProbeSigEnv   = "GASWORKS_TEST_SIGNAL"       // a key of guardedSignals
	signalProbeDelayEnv = "GASWORKS_TEST_SIGNAL_DELAY_US"
	signalProbeOutEnv   = "GASWORKS_TEST_SIGNAL_OUT"
	signalProbeMarkEnv  = "GASWORKS_TEST_SIGNAL_MARK"
	signalProbeStallEnv = "GASWORKS_TEST_SIGNAL_STALL_MS"
	signalProbeDoneEnv  = "GASWORKS_TEST_SIGNAL_SERVED" // written when leg C's handler runs to the end
)

// waitProbeIntervalSecs is the poll interval the "wait" child is told to wait. It is long
// enough that a cancel which had to wait for the next leg C would be obvious in the timings.
const waitProbeIntervalSecs = 5

// The four the guard covers. SIGHUP is a dropped SSH session or a closed tab during the minutes
// this ceremony spends waiting on a human; SIGQUIT is Ctrl-\, which is what a person presses
// when Ctrl-C looks unresponsive. SIGKILL is deliberately absent: it cannot be caught, and no
// design in this repository or any other can save a credential from it.
var guardedSignals = map[string]syscall.Signal{
	"int":  syscall.SIGINT,
	"term": syscall.SIGTERM,
	"hup":  syscall.SIGHUP,
	"quit": syscall.SIGQUIT,
}

// TestMintSignalProbeChild is not a test. It is the child half of the probes below,
// re-executed by them with signalProbeModeEnv set; without it, it does nothing.
func TestMintSignalProbeChild(t *testing.T) {
	mode := os.Getenv(signalProbeModeEnv)
	if mode == "" {
		t.Skip("the child half of the signal probes; the parent re-executes this binary")
	}
	sig, ok := guardedSignals[os.Getenv(signalProbeSigEnv)]
	if !ok {
		t.Fatalf("unknown %s %q", signalProbeSigEnv, os.Getenv(signalProbeSigEnv))
	}
	micros, err := strconv.Atoi(os.Getenv(signalProbeDelayEnv))
	if err != nil {
		t.Fatalf("bad %s: %v", signalProbeDelayEnv, err)
	}
	delay := time.Duration(micros) * time.Microsecond
	raise := func() {
		go func() {
			time.Sleep(delay)
			_ = syscall.Kill(os.Getpid(), sig)
		}()
	}

	srv, _ := mintSeed(t)
	switch mode {
	case "mint":
		// Leg C answers with the credential and the signal is fired into the window that
		// answer opens: from here the secret is in this process's memory and in no file.
		srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
			if err := os.WriteFile(os.Getenv(signalProbeMarkEnv), []byte(sig.String()), 0o600); err != nil {
				// Without the marker the parent cannot hold this run to anything, so do not
				// reveal a secret it will not check.
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "probe could not mark leg C"})
				return
			}
			writeJSON(w, http.StatusCreated, srv.mintCredential)
			raise()
		}
	case "wait":
		// The ceremony parks on the human. Nothing has been minted, so the signal is not the
		// CLI's business: it must end the command then and there.
		srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, attempt int) {
			if attempt == 0 {
				raise()
			}
			mintPending(w, "authorization_pending", waitProbeIntervalSecs)
		}
	case "commit":
		// The mint plane COMMITS — from the marker on, a live key exists — and only then takes
		// its time answering, which is what a real redeem does: a database write, the accounts
		// relay, a signature. The operator hits the key in the middle of that. Leg C is not
		// idempotent, so the request must run to its end however long the answer takes.
		stall, _ := strconv.Atoi(os.Getenv(signalProbeStallEnv))
		srv.mintCompleteHandler = func(w http.ResponseWriter, r *http.Request, _ int) {
			if err := os.WriteFile(os.Getenv(signalProbeMarkEnv), []byte(sig.String()), 0o600); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "probe could not mark leg C"})
				return
			}
			raise()
			time.Sleep(time.Duration(stall) * time.Millisecond)
			if r.Context().Err() != nil {
				// The client hung up on a request that had already minted. Nothing to answer.
				return
			}
			writeJSON(w, http.StatusCreated, srv.mintCredential)
			_ = os.WriteFile(os.Getenv(signalProbeDoneEnv), []byte("served"), 0o600)
		}
	case "stall":
		// The signal lands while a POLL is in flight and the mint plane is slow to answer it.
		// The guard cannot know that a slow answer is a 425 rather than a credential, so it does
		// not cancel — but it must honour the signal the moment the answer says nothing was
		// minted, rather than at the end of the poll interval that follows.
		stall, _ := strconv.Atoi(os.Getenv(signalProbeStallEnv))
		srv.mintCompleteHandler = func(w http.ResponseWriter, r *http.Request, attempt int) {
			if attempt == 0 {
				raise()
				time.Sleep(time.Duration(stall) * time.Millisecond)
				if r.Context().Err() != nil {
					return
				}
				_ = os.WriteFile(os.Getenv(signalProbeDoneEnv), []byte("served"), 0o600)
			}
			mintPending(w, "authorization_pending", waitProbeIntervalSecs)
		}
	default:
		t.Fatalf("unknown probe mode %q", mode)
	}
	// Straight to the real exit code: the parent reads it, and a test framework summary
	// printed after the CLI's own output would only be noise.
	os.Exit(run(mintArgs(os.Getenv(signalProbeOutEnv))))
}

// childRun is what one child process did.
type childRun struct {
	exit     int
	signaled bool
	signal   syscall.Signal
	output   string
}

func (c childRun) String() string {
	if c.signaled {
		return "killed by " + c.signal.String()
	}
	return "exit " + strconv.Itoa(c.exit)
}

// runSignalProbeChild re-executes this test binary as the child described by env.
func runSignalProbeChild(t *testing.T, env map[string]string) childRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMintSignalProbeChild$")
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the child never exited (%s); it was still running after 30s\n%s", ctx.Err(), output)
	}
	run := childRun{output: string(output)}
	switch e := err.(type) {
	case nil:
	case *exec.ExitError:
		status, ok := e.Sys().(syscall.WaitStatus)
		if !ok {
			t.Fatalf("child wait status is %T\n%s", e.Sys(), output)
		}
		run.exit, run.signaled = status.ExitStatus(), status.Signaled()
		if run.signaled {
			run.signal = status.Signal()
		}
	default:
		t.Fatalf("running the child: %v\n%s", err, output)
	}
	return run
}

// secretOnDisk finds the file holding the secret among paths (each a file or a directory to
// scan) and returns it with its contents and mode. It reports "" when the secret is in none of
// them, which for a run whose leg C answered 201 is the loss this whole design exists to
// prevent.
func secretOnDisk(t *testing.T, secret string, paths ...string) (string, string, os.FileMode) {
	t.Helper()
	var candidates []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			candidates = append(candidates, path)
			continue
		}
		entries, _ := os.ReadDir(path)
		for _, entry := range entries {
			candidates = append(candidates, filepath.Join(path, entry.Name()))
		}
	}
	for _, path := range candidates {
		body, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(body), secret) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		return path, string(body), info.Mode().Perm()
	}
	return "", "", 0
}

// Every guarded signal, in the window between leg C answering and the file holding what it is
// going to hold. The default action for all four is to kill the process where it stands: no
// write runs, the secret is neither on the disk nor on a stream, and a live credential nothing
// can revoke exists that nobody holds.
//
// Each trial fires the signal a different distance into that window, so the whole of it is
// covered: the response still on the wire, the body being read, the raw write in flight, the
// file already synced, the rendering going over it. Whatever the timing, a run whose leg C
// answered 201 must leave the secret in an owner-only file.
func TestSPMintKeySurvivesASignalBetweenLegCAndTheSave(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns one process per trial")
	}
	const trialsPerSignal = 25
	want := secretFormatEnv.render("gck_sp_secret_value")
	deferred, late, missed := 0, 0, 0
	for _, sig := range []string{"int", "term", "hup", "quit"} {
		for i := range trialsPerSignal {
			dir := t.TempDir()
			out := filepath.Join(dir, "sp.env")
			mark := filepath.Join(dir, "legc-answered")
			mintedDir := filepath.Join(dir, "minted-keys")
			// 0µs is the response still in the server's hands; 4.6ms is past the sync.
			delay := i * 200

			child := runSignalProbeChild(t, map[string]string{
				signalProbeModeEnv:        "mint",
				signalProbeSigEnv:         sig,
				signalProbeDelayEnv:       strconv.Itoa(delay),
				signalProbeOutEnv:         out,
				signalProbeMarkEnv:        mark,
				"GASWORKS_MINTED_KEY_DIR": mintedDir,
			})
			label := fmt.Sprintf("SIG%s +%dµs: child %s", strings.ToUpper(sig), delay, child)
			if !fileExists(mark) {
				t.Fatalf("%s — the probe never reached leg C, so it proves nothing\n%s", label, child.output)
			}
			where, body, mode := secretOnDisk(t, "gck_sp_secret_value", out, mintedDir)
			if where == "" {
				t.Fatalf("SECRET LOST: %s. Leg C revealed a credential that cannot be re-issued or "+
					"revoked, and it is in no file.\n%s", label, child.output)
			}
			if mode&0o077 != 0 {
				t.Fatalf("%s — the secret is in %s at mode %04o, readable beyond its owner", label, where, mode)
			}
			// Exactly the rendering, not merely containing it: a write cut short between the
			// bytes and the truncation would leave the placeholder's tail behind, which is a
			// broken credential rather than a saved one.
			if body != want {
				t.Fatalf("%s — %s holds %q, want exactly %q", label, where, body, want)
			}

			switch {
			case strings.Contains(child.output, "the credential IS saved"):
				// The signal landed inside the window: deferred across the write, reported
				// after it, and the exit says the command did not go as asked.
				deferred++
				if child.exit == 0 || child.signaled {
					t.Fatalf("%s — a signal held across the write must end in a non-zero exit of "+
						"this CLI's own\n%s", label, child.output)
				}
			case child.signaled:
				// It landed after the window closed, where the default action is the correct
				// one and the credential is already on the disk.
				late++
			case sig == "quit" && strings.Contains(child.output, "SIGQUIT: quit"):
				// The same thing, for the one signal whose "default action" in a Go program is
				// not SIG_DFL: outside the guarded window SIGQUIT reaches the runtime's own
				// handler, which dumps every goroutine's stack and exits 2. The credential is
				// already on the disk, which is what this test is about, and the dump is what
				// Ctrl-\ does to any Go program.
				late++
			case child.exit == 0:
				// It never landed: the command had already finished and exited.
				missed++
			default:
				t.Fatalf("%s — neither a clean mint nor a deferred signal\n%s", label, child.output)
			}
			t.Logf("%s -> secret in %s (mode %04o)", label, filepath.Base(where), mode)
		}
	}
	t.Logf("%d trials across SIGINT/SIGTERM/SIGHUP/SIGQUIT, secret persisted in every one: "+
		"%d signals deferred across the write, %d landed after the window closed, %d after the "+
		"command had exited", 4*trialsPerSignal, deferred, late, missed)
	if deferred == 0 {
		t.Fatal("no trial delivered its signal inside the window, so nothing here was exercised")
	}
}

// The other half of the rule: outside that window a Ctrl-C is a Ctrl-C. Waiting on a human is
// the longest phase of the ceremony and cancelling during it is legitimate — nothing has been
// minted — so the signal must end the command at once and by its own hand, not after the next
// poll and not with an exit code of the CLI's choosing.
func TestSPMintKeyCancelsPromptlyWhileWaitingForApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a process")
	}
	for _, name := range []string{"int", "term"} {
		t.Run(strings.ToUpper("sig"+name), func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "sp.env")
			mintedDir := filepath.Join(dir, "minted-keys")

			started := time.Now()
			child := runSignalProbeChild(t, map[string]string{
				signalProbeModeEnv:        "wait",
				signalProbeSigEnv:         name,
				signalProbeDelayEnv:       "50000", // 50ms into a 5s wait
				signalProbeOutEnv:         out,
				signalProbeMarkEnv:        filepath.Join(dir, "unused"),
				"GASWORKS_MINTED_KEY_DIR": mintedDir,
			})
			elapsed := time.Since(started)
			t.Logf("child %s after %s (the poll interval alone is %ds)", child, elapsed.Round(time.Millisecond),
				waitProbeIntervalSecs)

			if !strings.Contains(child.output, "Waiting for approval") {
				t.Fatalf("the child never reached the approval wait\n%s", child.output)
			}
			if want := guardedSignals[name]; !child.signaled || child.signal != want {
				t.Fatalf("child %s, want it killed by %s — a cancel with nothing minted must look "+
					"like a cancel to the shell\n%s", child, want, child.output)
			}
			if elapsed > 3*time.Second {
				t.Fatalf("the cancel took %s, longer than a poll interval: it was not prompt", elapsed)
			}
			if where, _, _ := secretOnDisk(t, "gck_sp_secret_value", out, mintedDir); where != "" {
				t.Fatalf("a cancel before any approval left a secret in %s", where)
			}
		})
	}
}

// A signal that lands while leg C is IN FLIGHT. This is the one place the ceremony must not do
// what the operator asked: leg C consumes the challenge and mints a key, so a client that hangs
// up on a slow answer hangs up on a server that may already have committed.
//
// So the request is not cancelled — it is answered, and the ANSWER decides. Here the answer is a
// 425: the mint plane says it has not minted, the signal is honoured on the strength of that,
// and the command ends without waiting out the poll interval that would otherwise follow. What
// the timings prove is the opposite of what they used to: the command lasts at least as long as
// the server took, because it waited for the server rather than abandoning it.
func TestSPMintKeyWaitsOutAnInFlightPollBeforeHonouringASignal(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a process per case")
	}
	for _, stallMS := range []int{2000, 8000} {
		t.Run(fmt.Sprintf("the mint plane takes %dms to answer the poll", stallMS), func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "sp.env")
			mintedDir := filepath.Join(dir, "minted-keys")
			served := filepath.Join(dir, "leg-c-served")

			started := time.Now()
			child := runSignalProbeChild(t, map[string]string{
				signalProbeModeEnv:        "stall",
				signalProbeSigEnv:         "int",
				signalProbeDelayEnv:       "50000", // 50ms into a poll that will hang
				signalProbeStallEnv:       strconv.Itoa(stallMS),
				signalProbeOutEnv:         out,
				signalProbeMarkEnv:        filepath.Join(dir, "unused"),
				signalProbeDoneEnv:        served,
				"GASWORKS_MINTED_KEY_DIR": mintedDir,
			})
			elapsed := time.Since(started)
			t.Logf("Ctrl-C 50ms into a poll the server holds for %dms -> child %s after %s",
				stallMS, child, elapsed.Round(time.Millisecond))

			if !strings.Contains(child.output, "Waiting for approval") {
				t.Fatalf("the child never reached the approval wait\n%s", child.output)
			}
			// The server got to finish. A cancelled request would have left r.Context() done and
			// this marker unwritten.
			if !fileExists(served) {
				t.Fatalf("the in-flight leg C was abandoned by the client; a redeem that had "+
					"already minted would be lost here\n%s", child.output)
			}
			// It waited for the answer, and it did not wait for anything after it.
			if budget := time.Duration(stallMS) * time.Millisecond; elapsed < budget {
				t.Fatalf("the command ended in %s, before the %s the server took: the request was "+
					"cancelled rather than answered", elapsed, budget)
			}
			if slack := time.Duration(stallMS)*time.Millisecond + 5*time.Second; elapsed > slack {
				t.Fatalf("the signal was honoured %s after the answer arrived, which is a poll "+
					"interval, not an answer", elapsed-time.Duration(stallMS)*time.Millisecond)
			}
			// The mint plane said it had not minted, so this is the one message that may say so.
			if !strings.Contains(child.output, "cancelled: nothing was minted") {
				t.Fatalf("the child did not cancel\n%s", child.output)
			}
			// And it ended the way a Ctrl-C ends a command: killed by the signal, or — when the
			// re-raise loses the race against the exit that backs it up — the status a shell
			// reports for exactly that. Any other code is the CLI inventing one.
			if want := int(syscall.SIGINT); !child.signaled && child.exit != 128+want {
				t.Fatalf("child %s, want it killed by SIGINT or exiting %d\n%s",
					child, 128+want, child.output)
			}
			if where, _, _ := secretOnDisk(t, "gck_sp_secret_value", out, mintedDir); where != "" {
				t.Fatalf("a cancel before any approval left a secret in %s", where)
			}
		})
	}
}

// The loss the deferral must never cause. The mint plane COMMITS and then takes its time
// answering — a database write, the accounts relay, a signature — and the operator hits the key
// in the middle of it. Cancelling the request there is indistinguishable, from this process, from
// cancelling one that had not minted; the server knows better, and it has already minted.
//
// Every trial's post-commit latency straddles what a 250ms grace would have allowed. Whatever the
// signal and whatever the latency, the secret must be in an owner-only file and the command must
// never say the mint did not happen.
func TestSPMintKeySavesAMintCommittedBeforeASignal(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns one process per trial")
	}
	// 240/260ms straddle the abandonGrace boundary a cancelling guard had; 600 and 1500 are a
	// mint plane behaving normally under load.
	latencies := []int{0, 240, 260, 600, 1500}
	want := secretFormatEnv.render("gck_sp_secret_value")
	trials := 0
	for _, sig := range []string{"int", "term", "hup", "quit"} {
		for _, stallMS := range latencies {
			for range 2 {
				dir := t.TempDir()
				out := filepath.Join(dir, "sp.env")
				mark := filepath.Join(dir, "minted.mark")
				mintedDir := filepath.Join(dir, "minted-keys")

				child := runSignalProbeChild(t, map[string]string{
					signalProbeModeEnv:        "commit",
					signalProbeSigEnv:         sig,
					signalProbeDelayEnv:       "0", // the instant the server commits
					signalProbeStallEnv:       strconv.Itoa(stallMS),
					signalProbeOutEnv:         out,
					signalProbeMarkEnv:        mark,
					signalProbeDoneEnv:        filepath.Join(dir, "leg-c-served"),
					"GASWORKS_MINTED_KEY_DIR": mintedDir,
				})
				trials++
				label := fmt.Sprintf("SIG%s, server commits then takes %dms: child %s",
					strings.ToUpper(sig), stallMS, child)
				if !fileExists(mark) {
					t.Fatalf("%s — the probe never reached the server's commit point\n%s", label, child.output)
				}
				where, body, mode := secretOnDisk(t, "gck_sp_secret_value", out, mintedDir)
				if where == "" {
					t.Fatalf("SECRET LOST: %s. The mint plane committed and the secret is in no "+
						"file.\n%s", label, child.output)
				}
				if mode&0o077 != 0 {
					t.Fatalf("%s — the secret is in %s at mode %04o", label, where, mode)
				}
				if body != want {
					t.Fatalf("%s — %s holds %q, want exactly %q", label, where, body, want)
				}
				if strings.Contains(child.output, "nothing was minted") {
					t.Fatalf("%s — the CLI said nothing was minted after the server had committed\n%s",
						label, child.output)
				}
				if child.exit == 0 && !child.signaled {
					t.Fatalf("%s — a signal held across the write must still end in a non-zero "+
						"exit\n%s", label, child.output)
				}
				t.Logf("%s -> secret in %s (mode %04o)", label, filepath.Base(where), mode)
			}
		}
	}
	t.Logf("%d trials across SIGINT/SIGTERM/SIGHUP/SIGQUIT at %v ms of post-commit latency: the "+
		"secret was saved in every one", trials, latencies)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The other half of the D1 rule, with a signal in it. A guarded signal that lands while an
// UNRESOLVABLE leg C is in flight must not turn the report into a cancel: "cancelled: nothing
// was minted" is exactly the sentence that sends an operator away from a live key.
//
// This one runs in-process rather than in a child, because what it is about is the text, and
// raiseGuardedSignal makes that safe.
func TestSPMintKeyReportsAnInterruptedUnresolvedRedeem(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	raise := raiseGuardedSignal(t)
	mintedDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, mintedDir)
	out := filepath.Join(t.TempDir(), "sp.env")
	srv.mintCompleteHandler = func(_ http.ResponseWriter, r *http.Request, _ int) {
		// The signal lands while the redeem is in flight and the mint plane is silent, which is
		// the exact shape of the loss D1 is about.
		raise()
		<-r.Context().Done()
	}
	mintTimeoutClient(t, srv, 500*time.Millisecond)

	_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Fatal("exit 0 for an interrupted redeem whose outcome is unknown")
	}
	if strings.Contains(stderr, "nothing was minted") {
		t.Fatalf("the CLI claimed nothing was minted after an interrupted, unresolved redeem:\n%s", stderr)
	}
	for _, want := range []string{
		"A CREDENTIAL MAY HAVE BEEN ISSUED",
		"challenge:  chal_1",
		"arrived while the redeem was in flight. It was NOT cancelled",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the report is missing %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Errorf("the reservation was left behind at %s (%v)", out, err)
	}
}

// raiseGuardedSignal returns a func that sends this process a real SIGINT, and makes doing so
// survivable inside a test.
//
// The ceremony's own guard is what defers it. This installs a SECOND registration of the same
// signals for the length of the test: signal.Notify delivers to EVERY registered channel, so it
// cannot take the delivery away from the guard — the guard's own release() relies on the same
// property — and a delivery that lands a moment after the guard has come down finds a handler
// here instead of the default action, which would end the test binary.
func raiseGuardedSignal(t *testing.T) func() {
	t.Helper()
	sink := make(chan os.Signal, 8)
	signal.Notify(sink, mintSignals...)
	t.Cleanup(func() { signal.Stop(sink) })
	return func() { _ = syscall.Kill(os.Getpid(), syscall.SIGINT) }
}

// The in-process half of the same mechanism: a signal that arrives while the guard is held is
// deferred (this test process is still alive to assert it) and reported when it is released.
func TestMintInterruptDefersASignalUntilRelease(t *testing.T) {
	interrupt := newMintInterrupt()
	if sig := interrupt.release(); sig != nil {
		t.Fatalf("release() = %v before anything was held", sig)
	}

	interrupt.hold()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("kill: %v", err)
	}
	// Reaching this line is the assertion: the default action would have ended the process.
	// The runtime hands the signal to the channel from its own goroutine, so wait for it to
	// land — without lifting the deferral, which is what would let it kill this test.
	for deadline := time.Now().Add(2 * time.Second); len(interrupt.ch) == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	caught := interrupt.release()
	if caught != syscall.SIGINT {
		t.Fatalf("release() = %v, want the deferred SIGINT", caught)
	}
	if sig := interrupt.release(); sig != nil {
		t.Fatalf("release() = %v after the signal was already reported", sig)
	}
}
