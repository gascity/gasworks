//go:build linux

package main

import (
	"bufio"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// companionProcess is a real `gasworks-companion daemon` process (this test binary re-run as the
// command, see TestMain), with its stderr collected line by line.
type companionProcess struct {
	cmd     *exec.Cmd
	logs    *lineLog
	exited  chan struct{} // closed once the process has been waited for
	waitErr error         // the process's exit error, valid once exited is closed
}

func startCompanionProcess(t *testing.T, env []string, args ...string) *companionProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"daemon"}, args...)...)
	cmd.Env = append(append(os.Environ(), companionMainEnv+"=1"), env...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the daemon: %v", err)
	}
	p := &companionProcess{cmd: cmd, logs: newLineLog(), exited: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		for sc.Scan() {
			p.logs.add(sc.Text())
		}
		_, _ = io.Copy(io.Discard, stderr) // never leave the daemon blocked on a write to stderr
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		select {
		case <-p.exited:
		default:
			_ = cmd.Process.Kill()
			<-p.exited
		}
	})
	return p
}

// waitFor waits for a log line, failing at once — with the daemon's log — if the daemon exits first.
func (p *companionProcess) waitFor(t *testing.T, sub string, deadline <-chan time.Time) {
	t.Helper()
	for !p.logs.has(sub) {
		select {
		case <-p.logs.arrived:
		case <-p.exited:
			if p.logs.has(sub) {
				return
			}
			t.Fatalf("the daemon exited (%v) before logging %q; log:\n%s", p.waitErr, sub, p.logs.dump())
		case <-deadline:
			t.Fatalf("never logged %q; log:\n%s", sub, p.logs.dump())
		}
	}
}

// stop sends SIGTERM and returns the daemon's exit error (nil for a clean exit). It first waits for
// the "serving at" line, which the daemon prints only once its signal handler is installed, so the
// signal is never delivered to a process that would die of it before handling it.
func (p *companionProcess) stop(t *testing.T, deadline <-chan time.Time) error {
	t.Helper()
	p.waitFor(t, "serving at", deadline)
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.exited:
		if p.waitErr != nil {
			t.Logf("daemon log:\n%s", p.logs.dump())
		}
		return p.waitErr
	case <-deadline:
		t.Fatalf("the daemon did not exit after SIGTERM; log:\n%s", p.logs.dump())
		return nil
	}
}

// TestCompanionDaemonCommandFollowsThePolicyFileLive drives the real command line: with
// -root-policy-file and -collector, the content channel is wired whatever -content-upload says, and
// a v3 policy turns content upload on and off live; the process shuts down cleanly on SIGTERM and
// leaves its consent ledger beside the WAL.
func TestCompanionDaemonCommandFollowsThePolicyFileLive(t *testing.T) {
	root := t.TempDir()
	stub, _ := newConsentStub(t)
	collectorURL, caFile := stub.url, filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stub.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("e2e-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "root-policy.json")
	writePolicy(t, policy, e2ePolicy(false, e2eRoot{root, 1, true}))
	stateDir := t.TempDir()

	p := startCompanionProcess(t, []string{"OBSERVER_CONTENT_UPLOAD="},
		"-dir", stateDir, "-source-id", e2eSourceID,
		"-collector", collectorURL, "-token-file", tokenFile, "-ca-file", caFile,
		"-root-policy-file", policy, "-cursor-dir", t.TempDir(), "-poll-interval", "20ms")
	deadline := time.After(20 * time.Second)
	p.waitFor(t, "loaded: content upload off (stated by the policy)", deadline)
	p.waitFor(t, "applied consent policy version 1: tailing 1 consented roots; content upload off", deadline)
	// The content channel, wired whatever the policy says, follows the collector client's -token-file.
	p.waitFor(t, "a refused credential is retried as soon as the token file "+tokenFile+" is renewed", deadline)

	writePolicy(t, policy, e2ePolicy(true, e2eRoot{root, 1, true}))
	p.waitFor(t, "applied consent policy version 2: tailing 1 consented roots; content upload on", deadline)

	writePolicy(t, policy, e2ePolicy(false, e2eRoot{root, 1, true}))
	p.waitFor(t, "applied consent policy version 3: tailing 1 consented roots; content upload off", deadline)

	if err := p.stop(t, deadline); err != nil {
		t.Fatalf("daemon exit after SIGTERM: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "consent-ledger.json")); err != nil {
		t.Fatalf("no consent ledger after a graceful shutdown: %v", err)
	}
}

// TestCompanionDaemonCommandKeepsTheFlagForPreV3Policies: a v1/v2 policy states no content consent,
// so -content-upload (default OBSERVER_CONTENT_UPLOAD) still decides it, as before this change.
func TestCompanionDaemonCommandKeepsTheFlagForPreV3Policies(t *testing.T) {
	root := t.TempDir()
	stub, _ := newConsentStub(t)
	caFile := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stub.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("e2e-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "root-policy.json")
	writePolicy(t, policy, `{"schema_version":"gasworks.companion.root-policy/v2","roots":[`+
		`{"path":"`+root+`","generation":1,"active":true,"mode":"backfill"}]}`)

	p := startCompanionProcess(t, []string{"OBSERVER_CONTENT_UPLOAD=1"},
		"-dir", t.TempDir(), "-source-id", e2eSourceID,
		"-collector", stub.url, "-token-file", tokenFile, "-ca-file", caFile,
		"-root-policy-file", policy, "-cursor-dir", t.TempDir(), "-poll-interval", "20ms")
	deadline := time.After(20 * time.Second)
	p.waitFor(t, "loaded: content upload on (-content-upload; the policy does not state content consent)", deadline)
	p.waitFor(t, "applied consent policy version 1: tailing 1 consented roots; content upload on", deadline)
	if err := p.stop(t, deadline); err != nil {
		t.Fatalf("daemon exit after SIGTERM: %v", err)
	}
}
