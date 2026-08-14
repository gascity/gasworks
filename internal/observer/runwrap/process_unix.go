//go:build unix

package runwrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// Same-PID shim handshake descriptors. The parent passes three pipes to the shim as
// ExtraFiles, which the child receives as fds 3/4/5:
//
//	fd 3 (identity): the shim writes its proven OS process-start identity, the parent reads it;
//	fd 4 (ack):      the parent writes one byte AFTER REGISTERED is durable, releasing the shim
//	                 to exec; an EOF (no byte) tells the shim registration failed, so it must not
//	                 exec;
//	fd 5 (status):   launch outcome is POSITIVELY asserted, never inferred from a bare EOF. The
//	                 shim writes shimStatusPreExec immediately before syscall.Exec and marks the
//	                 fd close-on-exec, so the parent reads: preExec-marker then EOF == launched;
//	                 preExec-marker then execFailed == execve returned an error; execFailed first
//	                 == the target could not be resolved; and EOF with NO marker == the shim died
//	                 after the ack but before it reached execve (a pre-exec death). A bare EOF is
//	                 therefore a launch FAILURE, not a launched run.
//
// Because execve preserves the pid and the kernel process-start time, the identity the shim
// reports of ITSELF is exactly the child's identity — no time/cwd heuristic and no race.
const (
	shimIdentityFD = 3
	shimAckFD      = 4
	shimStatusFD   = 5
)

// Status pipe markers. shimStatusPreExec positively asserts the shim completed all pre-exec
// setup and is about to call execve; shimStatusExecFailed reports a failed target
// resolution/execve.
const (
	shimStatusPreExec    byte = 1
	shimStatusExecFailed byte = 2
)

// controlEnvPrefix marks environment variables the shim strips before exec-ing the child, so a
// test-mode trigger (or any future wrapper control variable) never leaks into the child.
const controlEnvPrefix = "RUNWRAP_"

// forwardedSignals are the catchable signals the wrapper relays to the child, so signal
// delivery is transparent through the wrapper. SIGKILL/SIGSTOP are uncatchable and omitted;
// SIGCHLD is the wrapper's own bookkeeping and not forwarded.
var forwardedSignals = []os.Signal{
	syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGTSTP,
	syscall.SIGCONT, syscall.SIGTTIN, syscall.SIGTTOU,
}

// launchError is a typed launch failure carrying the stage and, when known, the proven child
// identity so the caller can stamp PROCESS_LAUNCH_FAILED.
type launchError struct {
	stage    string
	identity wire.ProcessIdentity
	err      error
}

func (e *launchError) Error() string {
	return fmt.Sprintf("observer runwrap: launch failed at %s: %v", e.stage, e.err)
}

// childProc is a launched child with signal forwarding attached.
type childProc struct {
	cmd      *exec.Cmd
	identity wire.ProcessIdentity
	stopFwd  func()
}

// wait blocks for the child to exit, stops signal forwarding, and translates its wait status
// into an exit code / signal. A signal death reports the conventional 128+signal exit code
// plus signaled=true so the terminal sequence records it as a signal, not an exit code.
func (c *childProc) wait() (exitCode int, signaled bool, signal int) {
	waitErr := c.cmd.Wait()
	if c.stopFwd != nil {
		c.stopFwd()
	}
	return interpretState(c.cmd.ProcessState, waitErr)
}

func interpretState(st *os.ProcessState, _ error) (exitCode int, signaled bool, signal int) {
	if st == nil {
		return -1, false, 0
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		sig := int(ws.Signal())
		return 128 + sig, true, sig
	}
	return st.ExitCode(), false, 0
}

func (c Config) stdin() io.Reader {
	if c.Stdin != nil {
		return c.Stdin
	}
	return os.Stdin
}

func (c Config) stdout() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

func (c Config) stderr() io.Writer {
	if c.Stderr != nil {
		return c.Stderr
	}
	return os.Stderr
}

// launchObserved spawns the same-PID shim, reads the child's proven identity, invokes register
// (which durably appends REGISTERED) before releasing the shim to exec, and returns a running
// child with signal forwarding attached. Any failure before the child image exists is returned
// as a *launchError so the caller runs the launch-failure terminal sequence.
func launchObserved(cfg Config, childEnv []string, register func(wire.ProcessIdentity) error) (*childProc, *launchError) {
	spec, err := cfg.Shim.resolve()
	if err != nil {
		return nil, &launchError{stage: "shim-setup", err: err}
	}

	idR, idW, err := os.Pipe()
	if err != nil {
		return nil, &launchError{stage: "pipe", err: err}
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		idR.Close()
		idW.Close()
		return nil, &launchError{stage: "pipe", err: err}
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		idR.Close()
		idW.Close()
		ackR.Close()
		ackW.Close()
		return nil, &launchError{stage: "pipe", err: err}
	}

	args := make([]string, 0, len(spec.PrefixArgs)+len(cfg.Target)+2)
	args = append(args, spec.Path)
	args = append(args, spec.PrefixArgs...)
	args = append(args, "--")
	args = append(args, cfg.Target...)

	cmd := &exec.Cmd{
		Path:       spec.Path,
		Args:       args,
		Env:        append(append([]string(nil), childEnv...), spec.ExtraEnv...),
		Stdin:      cfg.stdin(),
		Stdout:     cfg.stdout(),
		Stderr:     cfg.stderr(),
		ExtraFiles: []*os.File{idW, ackR, statusW},
		// Dir left empty: the child inherits the wrapper's working directory.
	}

	attachForwarding, stopForwarding := startSignalForwarding()
	if err := cmd.Start(); err != nil {
		stopForwarding()
		for _, f := range []*os.File{idR, idW, ackR, ackW, statusR, statusW} {
			f.Close()
		}
		return nil, &launchError{stage: "spawn", err: err}
	}
	forwardingTransferred := false
	defer func() {
		if !forwardingTransferred {
			stopForwarding()
		}
	}()
	attachForwarding(cmd.Process)
	// The parent no longer needs the child-side pipe ends.
	idW.Close()
	ackR.Close()
	statusW.Close()

	id, err := readIdentity(idR)
	idR.Close()
	if err != nil {
		ackW.Close()
		statusR.Close()
		_ = cmd.Wait()
		return nil, &launchError{stage: "identity", err: err}
	}

	if rerr := register(id); rerr != nil {
		// Decline to ack: closing the ack pipe without a byte tells the shim registration was
		// not durable, so it exits before exec. The run is durably started but the child never
		// launched -> a launch failure.
		ackW.Close()
		statusR.Close()
		_ = cmd.Wait()
		return nil, &launchError{stage: "register", identity: id, err: rerr}
	}

	if _, werr := ackW.Write([]byte{1}); werr != nil {
		ackW.Close()
		statusR.Close()
		_ = cmd.Wait()
		return nil, &launchError{stage: "ack", identity: id, err: werr}
	}
	ackW.Close()

	lerr := readLaunchStatus(statusR, id)
	statusR.Close()
	if lerr != nil {
		_ = cmd.Wait()
		return nil, lerr
	}

	forwardingTransferred = true
	return &childProc{cmd: cmd, identity: id, stopFwd: stopForwarding}, nil
}

// readLaunchStatus positively classifies the shim's launch outcome from the status pipe:
//
//   - a preExec marker then EOF        => execve completed (launched);
//   - a preExec marker then execFailed => execve returned an error (launch failure);
//   - an execFailed byte first         => the target could not be resolved (launch failure);
//   - EOF with no marker at all        => the shim died after the ack but before it reached
//     execve — a pre-exec death (kill/OOM/panic). This is a launch FAILURE, never a launched run.
//
// Launch success is thus asserted by the positive preExec marker, never inferred from a bare
// EOF (which a pre-exec death also produces). Residual window: if the shim is killed AFTER
// writing the marker but DURING the execve syscall itself, the parent sees marker+EOF and treats
// it as launched — an irreducible single-syscall window between the marker write and execve.
func readLaunchStatus(r io.Reader, id wire.ProcessIdentity) *launchError {
	b1, n1 := readStatusByte(r)
	if n1 == 0 {
		return &launchError{stage: "exec", identity: id, err: errors.New("shim exited before exec (pre-exec death)")}
	}
	switch b1 {
	case shimStatusExecFailed:
		return &launchError{stage: "exec", identity: id, err: errors.New("child command failed to exec")}
	case shimStatusPreExec:
		b2, n2 := readStatusByte(r)
		if n2 == 0 {
			return nil // marker then EOF: execve completed.
		}
		if b2 == shimStatusExecFailed {
			return &launchError{stage: "exec", identity: id, err: errors.New("child command failed to exec")}
		}
		return &launchError{stage: "exec", identity: id, err: fmt.Errorf("unexpected shim status byte %d after pre-exec marker", b2)}
	default:
		return &launchError{stage: "exec", identity: id, err: fmt.Errorf("unexpected shim status byte %d", b1)}
	}
}

func readStatusByte(r io.Reader) (byte, int) {
	var b [1]byte
	n, _ := io.ReadFull(r, b[:])
	return b[0], n
}

// launchUnobserved spawns the child directly, with full stdio/cwd/signal fidelity but no shim,
// no identity registration, and no daemon contact. It is the --allow-unobserved path.
func launchUnobserved(cfg Config, childEnv []string) (*childProc, error) {
	path, err := exec.LookPath(cfg.Target[0])
	if err != nil {
		return nil, fmt.Errorf("observer runwrap: resolve %q: %w", cfg.Target[0], err)
	}
	cmd := &exec.Cmd{
		Path:   path,
		Args:   cfg.Target,
		Env:    childEnv,
		Stdin:  cfg.stdin(),
		Stdout: cfg.stdout(),
		Stderr: cfg.stderr(),
	}
	attachForwarding, stopForwarding := startSignalForwarding()
	if err := cmd.Start(); err != nil {
		stopForwarding()
		return nil, fmt.Errorf("observer runwrap: start %q: %w", cfg.Target[0], err)
	}
	attachForwarding(cmd.Process)
	return &childProc{cmd: cmd, stopFwd: stopForwarding}, nil
}

// startSignalForwarding registers the wrapper signal handler before a child is started. Signals
// received before attach is called remain buffered until the child process exists, closing the
// launch-time default-action window without dropping the signal.
func startSignalForwarding() (attach func(*os.Process), stop func()) {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, forwardedSignals...)
	done := make(chan struct{})
	procReady := make(chan *os.Process, 1)
	go func() {
		var proc *os.Process
		select {
		case proc = <-procReady:
		case <-done:
			return
		}
		for {
			select {
			case s := <-ch:
				if sig, ok := s.(syscall.Signal); ok {
					_ = proc.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	attach = func(proc *os.Process) {
		select {
		case procReady <- proc:
		case <-done:
		}
	}
	stop = func() {
		signal.Stop(ch)
		close(done)
	}
	return attach, stop
}

// RunShim is the same-PID identity shim entry point. The production `observe run` adapter
// (E1.10) dispatches ShimSubcommand here; tests trigger it from TestMain. It reads its own OS
// process-start identity, reports it to the parent, waits for the parent's durable-REGISTERED
// ack, then execs the target with the child's stdio/cwd/env — so the process the daemon
// registered is byte-for-byte the process that becomes the child.
func RunShim() error {
	idW := os.NewFile(shimIdentityFD, "gasworks-observe-identity")
	ackR := os.NewFile(shimAckFD, "gasworks-observe-ack")
	statusW := os.NewFile(shimStatusFD, "gasworks-observe-status")
	if idW == nil || ackR == nil || statusW == nil {
		return errors.New("observer runwrap: shim missing handshake descriptors")
	}

	id, err := readSelfIdentity()
	if err != nil {
		_, _ = statusW.Write([]byte{shimStatusExecFailed})
		return fmt.Errorf("observer runwrap: shim read identity: %w", err)
	}
	if err := writeIdentity(idW, id); err != nil {
		return fmt.Errorf("observer runwrap: shim report identity: %w", err)
	}
	idW.Close()

	var ack [1]byte
	n, _ := io.ReadFull(ackR, ack[:])
	ackR.Close()
	if n == 0 {
		// Parent declined to ack: registration was not durable. Do not exec; the parent runs
		// the launch-failure terminal sequence.
		statusW.Close()
		return nil
	}

	target := shimTarget()
	if len(target) == 0 {
		_, _ = statusW.Write([]byte{shimStatusExecFailed})
		statusW.Close()
		return errors.New("observer runwrap: shim has no target command")
	}
	path, err := exec.LookPath(target[0])
	if err != nil {
		_, _ = statusW.Write([]byte{shimStatusExecFailed})
		statusW.Close()
		return fmt.Errorf("observer runwrap: shim resolve %q: %w", target[0], err)
	}

	preExecBlock() // test-only synchronization point (no-op in production).

	// Mark the status fd close-on-exec, then POSITIVELY assert "about to exec" before execve.
	// On a successful execve the fd closes (parent reads marker+EOF == launched); if the shim
	// dies before this marker the parent reads a bare EOF == pre-exec death (launch failure).
	syscall.CloseOnExec(int(statusW.Fd()))
	if _, err := statusW.Write([]byte{shimStatusPreExec}); err != nil {
		statusW.Close()
		return fmt.Errorf("observer runwrap: shim signal pre-exec: %w", err)
	}
	execErr := syscall.Exec(path, target, shimChildEnv())
	// syscall.Exec only returns on failure.
	_, _ = statusW.Write([]byte{shimStatusExecFailed})
	statusW.Close()
	return fmt.Errorf("observer runwrap: shim exec %q: %w", path, execErr)
}

// preExecBlock is a test-only synchronization point that lets a probe park the shim squarely in
// the post-ack / pre-execve window (the window finding 2 is about). When
// RUNWRAP_SHIM_PREEXEC_HANG names a file, the shim writes its pid there and blocks, so the probe
// can read the pid and SIGKILL the shim before it writes the pre-exec marker. Production never
// sets this variable, and its RUNWRAP_ prefix strips it from the child environment.
func preExecBlock() {
	path := os.Getenv("RUNWRAP_SHIM_PREEXEC_HANG")
	if path == "" {
		return
	}
	_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600)
	// Block long enough for the probe to kill us; fall through eventually so a misbehaving test
	// fails loudly instead of hanging forever.
	time.Sleep(30 * time.Second)
}

// shimTarget extracts the child argv following the "--" separator in the shim's own args.
func shimTarget() []string {
	for i, a := range os.Args {
		if a == "--" {
			return append([]string(nil), os.Args[i+1:]...)
		}
	}
	return nil
}

// sanitizeUnobservedEnv is the --allow-unobserved counterpart of shimChildEnv: it strips the
// wrapper's run-id variable AND every RUNWRAP_-prefixed control variable, so the unobserved child
// sees the same sanitized environment the observed child gets. The observed path launches through
// the shim, which strips RUNWRAP_ via shimChildEnv before exec; the unobserved path has no shim, so
// without this strip an inherited RUNWRAP_* (e.g. a nested wrapper's RUNWRAP_SHIM) would leak into
// the child. The inherited outer run id is dropped so an independently captured native session stays
// its own inferred run rather than referencing an unknown boundary.
func sanitizeUnobservedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if k == RunIDEnvVar || strings.HasPrefix(k, controlEnvPrefix) {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}

// shimChildEnv is the environment the shim hands the child: its own environment minus every
// wrapper control variable. GASWORKS_RUN_ID (set by the parent) is preserved.
func shimChildEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, controlEnvPrefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// writeIdentity / readIdentity move a ProcessIdentity across the handshake pipe as one JSON
// object followed by close.
func writeIdentity(w io.Writer, id wire.ProcessIdentity) error {
	if err := json.NewEncoder(w).Encode(id); err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	return nil
}

func readIdentity(r io.Reader) (wire.ProcessIdentity, error) {
	var id wire.ProcessIdentity
	if err := json.NewDecoder(r).Decode(&id); err != nil {
		return wire.ProcessIdentity{}, fmt.Errorf("decode identity: %w", err)
	}
	// process_start_time is the component that disambiguates pid reuse in the ancestry proof, so
	// a zero value is as unusable as a missing boot id or pid.
	if id.BootId == "" || id.Pid <= 0 || id.ProcessStartTime <= 0 {
		return wire.ProcessIdentity{}, errors.New("incomplete child identity")
	}
	return id, nil
}
