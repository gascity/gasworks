//go:build unix

package runwrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/spool"
)

// TestChildStdoutStderrFidelity proves the observed child's stdout and stderr reach the
// wrapper-supplied streams unchanged.
func TestChildStdoutStderrFidelity(t *testing.T) {
	d := newRecordingDaemon()
	var out, errb bytes.Buffer
	cfg := baseConfig(shPath(t), "-c", `printf 'to-out'; printf 'to-err' 1>&2`)
	cfg.Stdout = &out
	cfg.Stderr = &errb
	if _, err := Run(context.Background(), d, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.String() != "to-out" {
		t.Fatalf("stdout = %q, want to-out", out.String())
	}
	if errb.String() != "to-err" {
		t.Fatalf("stderr = %q, want to-err", errb.String())
	}
}

// TestChildStdinFidelity proves the observed child receives the wrapper's stdin unchanged.
func TestChildStdinFidelity(t *testing.T) {
	d := newRecordingDaemon()
	var out bytes.Buffer
	cfg := baseConfig(shPath(t), "-c", "cat")
	cfg.Stdin = strings.NewReader("piped-input-42")
	cfg.Stdout = &out
	if _, err := Run(context.Background(), d, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.String() != "piped-input-42" {
		t.Fatalf("stdin round-trip = %q, want piped-input-42", out.String())
	}
}

// TestSamePIDIdentity proves the identity the daemon registers is the child's exact OS
// process identity: the child reports its own pid and kernel start time (after execve), and
// they match the REGISTERED evidence to the byte — the same-PID shim guarantee, without a
// time/cwd heuristic.
func TestSamePIDIdentity(t *testing.T) {
	d := newRecordingDaemon()
	var out bytes.Buffer
	// Read the shell's OWN stat by explicit pid: /proc/self would resolve to the `cat`
	// subprocess, not the shell that the shim exec'd into.
	cfg := baseConfig(shPath(t), "-c", "echo $$; cat /proc/$$/stat")
	cfg.Stdout = &out
	res, err := Run(context.Background(), d, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines := strings.SplitN(strings.TrimRight(out.String(), "\n"), "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("child output = %q, want pid + stat lines", out.String())
	}
	childPid, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil {
		t.Fatalf("parse child pid %q: %v", lines[0], err)
	}
	statFile := filepath.Join(t.TempDir(), "child.stat")
	if err := os.WriteFile(statFile, []byte(lines[1]), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	childStart, err := readProcessStartTime(statFile)
	if err != nil {
		t.Fatalf("parse child start time: %v", err)
	}

	regPid, regStart, regBoot := registeredIdentity(t, d)
	if regPid != childPid {
		t.Fatalf("registered pid %d != child pid %d", regPid, childPid)
	}
	if regStart != childStart {
		t.Fatalf("registered start time %d != child start time %d", regStart, childStart)
	}
	if regBoot == "" {
		t.Fatal("registered identity has empty boot id")
	}
	if res.Identity.Pid != childPid || res.Identity.ProcessStartTime != childStart {
		t.Fatalf("result identity %+v != child (pid=%d start=%d)", res.Identity, childPid, childStart)
	}
}

func registeredIdentity(t *testing.T, d *recordingDaemon) (pid, start int64, boot string) {
	t.Helper()
	for _, a := range d.appends {
		if a.label != "REGISTERED" {
			continue
		}
		var p struct {
			ProcessLifecycle struct {
				ProcessIdentity struct {
					BootID           string `json:"boot_id"`
					Pid              int64  `json:"pid"`
					ProcessStartTime int64  `json:"process_start_time"`
				} `json:"process_identity"`
			} `json:"process_lifecycle"`
		}
		if err := json.Unmarshal(a.bytes, &p); err != nil {
			t.Fatalf("unmarshal REGISTERED: %v", err)
		}
		return p.ProcessLifecycle.ProcessIdentity.Pid, p.ProcessLifecycle.ProcessIdentity.ProcessStartTime, p.ProcessLifecycle.ProcessIdentity.BootID
	}
	t.Fatal("no REGISTERED observation recorded")
	return 0, 0, ""
}

// TestExitCodeFidelityThroughWrapper proves a real wrapper process propagates the child's exit
// code as its own exit code.
func TestExitCodeFidelityThroughWrapper(t *testing.T) {
	sh := shPath(t)
	cmd := wrapperCmd(t, wrapperOpts{unobserved: true}, sh, "-c", "exit 7")
	err := cmd.Run()
	if code := exitCode(err); code != 7 {
		t.Fatalf("wrapper exit code = %d (err=%v), want 7", code, err)
	}
}

// TestSignalForwarding proves a signal delivered to the wrapper is forwarded to the child: the
// child traps SIGTERM and exits 42, and the wrapper propagates that exit code.
func TestSignalForwarding(t *testing.T) {
	sh := shPath(t)
	cmd := wrapperCmd(t, wrapperOpts{unobserved: true}, sh, "-c",
		`trap 'exit 42' TERM; echo ready; while true; do sleep 0.05; done`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wrapper: %v", err)
	}
	waitForLine(t, bufio.NewReader(stdout), "ready", 10*time.Second)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal wrapper: %v", err)
	}
	err = cmd.Wait()
	if code := exitCode(err); code != 42 {
		t.Fatalf("wrapper exit code = %d (err=%v), want 42 (signal not forwarded)", code, err)
	}
}

// TestCwdPreserved proves the child runs in the wrapper's working directory (a real wrapper
// process launched with Dir set to a temp dir; its child prints that same directory).
func TestCwdPreserved(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	cmd := wrapperCmd(t, wrapperOpts{unobserved: true}, sh, "-c", "pwd -P")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != real {
		t.Fatalf("child cwd = %q, want %q", got, real)
	}
}

// TestWrapperCrashLeavesRunOpen proves that a wrapper SIGKILLed before RUN_ENDED leaves the run
// durably OPEN with its reserve held and no synthesized boundary: the durable log holds
// RUN_STARTED and REGISTERED but never RUN_ENDED or PROCESS_EXITED, and the reserve sidecar
// still shows the run open. Process disappearance never invents the missing boundary.
func TestWrapperCrashLeavesRunOpen(t *testing.T) {
	sh := shPath(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wal.jsonl")
	reservesDir := filepath.Join(dir, "reserves")
	if err := os.MkdirAll(reservesDir, 0o755); err != nil {
		t.Fatalf("mkdir reserves: %v", err)
	}

	cmd := wrapperCmd(t, wrapperOpts{logPath: logPath, reservesDir: reservesDir},
		sh, "-c", "echo started; exec sleep 60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wrapper: %v", err)
	}
	pgid := cmd.Process.Pid
	defer func() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL) // reap the whole tree, incl. the orphaned sleep
		_, _ = cmd.Process.Wait()
	}()

	waitForLine(t, bufio.NewReader(stdout), "started", 10*time.Second)
	waitForLogLabel(t, logPath, "REGISTERED", 10*time.Second)

	// Crash the wrapper before it can reach the terminal sequence.
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill wrapper: %v", err)
	}
	_, _ = cmd.Process.Wait()

	labels := classifyLogFile(t, logPath)
	has := func(l string) bool {
		for _, x := range labels {
			if x == l {
				return true
			}
		}
		return false
	}
	if !has("RUN_STARTED") || !has("REGISTERED") {
		t.Fatalf("durable log missing start boundary/registration: %v", labels)
	}
	if has("RUN_ENDED") || has("PROCESS_EXITED") {
		t.Fatalf("a boundary was synthesized after a crash: %v", labels)
	}

	runID := runIDFromLog(t, logPath)
	if runID == "" {
		t.Fatal("could not read run id from durable log")
	}
	res, err := spool.LoadReserves(reservesDir, 4096)
	if err != nil {
		t.Fatalf("load reserves: %v", err)
	}
	if !res.IsOpen(runID) {
		t.Fatalf("run %q reserve was not held open after a crash", runID)
	}
}

// ---- subprocess wrapper helpers ----

type wrapperOpts struct {
	unobserved  bool
	logPath     string
	reservesDir string
}

// wrapperCmd builds (but does not start) an *exec.Cmd that re-execs the test binary in wrapper
// helper mode with the given target after "--".
func wrapperCmd(t *testing.T, opts wrapperOpts, target ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	args := append([]string{"--"}, target...)
	cmd := exec.Command(exe, args...)
	env := append(os.Environ(), "RUNWRAP_HELPER_MODE=wrapper")
	if opts.unobserved {
		env = append(env, "RUNWRAP_WRAPPER_UNOBSERVED=1")
	} else {
		env = append(env, "RUNWRAP_WRAPPER_LOG="+opts.logPath, "RUNWRAP_WRAPPER_RESERVES="+opts.reservesDir)
	}
	cmd.Env = env
	return cmd
}

func waitForLine(t *testing.T, r *bufio.Reader, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			ch <- res{strings.TrimRight(line, "\n"), err}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case got := <-ch:
			if strings.Contains(got.line, want) {
				return
			}
			if got.err != nil {
				t.Fatalf("waiting for %q: stream ended (%v)", want, got.err)
			}
		case <-time.After(time.Until(deadline)):
			t.Fatalf("timed out waiting for %q on wrapper stdout", want)
		}
	}
}

func waitForLogLabel(t *testing.T, logPath, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f, err := os.Open(logPath)
		if err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
			for sc.Scan() {
				if len(bytes.TrimSpace(sc.Bytes())) == 0 {
					continue
				}
				if classify(sc.Bytes()) == want {
					f.Close()
					return
				}
			}
			f.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in durable log %s", want, logPath)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
