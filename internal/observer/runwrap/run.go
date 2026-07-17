// Package runwrap is the explicit-run wrapper: it turns `gasworks observe run -- <cmd>`
// into an authoritative Observer run with a durable start boundary, a same-PID
// process-identity registration, and a normative terminal sequence
// (PROCESS_EXITED -> drained transcript records -> RUN_ENDED).
//
// The wrapper owns judgment-free transport only. It never captures the child's argv,
// command text, or environment values; the only thing it hands the child is the minted
// GASWORKS_RUN_ID (and only on the observed path). Everything durable is built through the
// committed evidence constructors (internal/observer/evidence) and appended through the
// DaemonClient seam, so this package holds no wire-format or spool-format knowledge of its
// own.
//
// The DaemonClient seam is deliberately an interface: the owner-only local daemon
// (internal/observer/local, E1.5, built by a sibling) will satisfy it, and the thin
// `observe run` CLI adapter (E1.10) wires the two together. runwrap never imports the local
// socket package, so the durable-append/reserve/drain boundary stays a clean seam rather
// than a compile-time coupling.
//
// Lifecycle contract (spec "Start an explicit run"):
//
//   - hard capacity pressure refuses a NEW explicit run before RUN_STARTED (E1.3); an
//     already-started run keeps its preallocated terminal reserve;
//   - the terminal reserve is preallocated atomically with RUN_STARTED and is consumed only
//     by the terminal records (PROCESS_EXITED / PROCESS_LAUNCH_FAILED, one optional capture
//     diagnostic, and RUN_ENDED);
//   - if the run boundary cannot be durably recorded, the child is NOT started;
//   - a launch failure after RUN_STARTED emits PROCESS_LAUNCH_FAILED then RUN_ENDED with no
//     drain;
//   - the exit code is process evidence only — never a run/task success signal — and every
//     terminating path leaves the run outcome UNKNOWN;
//   - if the wrapper dies before RUN_ENDED the run stays OPEN with no synthesized boundary;
//   - --allow-unobserved is an emergency bypass: it exports no GASWORKS_RUN_ID, registers no
//     ancestry, touches the daemon not at all, and prints a prominent warning.
package runwrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// RunIDEnvVar is the environment variable the wrapper exports to the observed child and the
// variable an inner (nested) wrapper reads to recover an inherited outer run id as
// correlation-only evidence.
const RunIDEnvVar = "GASWORKS_RUN_ID"

// ShimSubcommand is the hidden argv token the production wrapper re-execs itself with so the
// same-PID identity shim runs before exec-ing the child. The `observe run` adapter (E1.10)
// dispatches this token to RunShim. Tests trigger the shim through ShimSpec.ExtraEnv instead.
const ShimSubcommand = "__gasworks_observe_shim__"

// wrapperAdapter / wrapperAdapterVersion identify the wrapper as the capturing adapter on
// every observation it authors. The content policy is always METADATA_ONLY: the wrapper has
// no content to capture.
const (
	wrapperAdapter        = "gasworks-wrapper"
	wrapperAdapterVersion = "0.1.0"
)

// DefaultDrainTimeout is the spec default bound (2s) for the post-exit transcript drain. The
// drain is "configurable only downward": a larger configured value is clamped to this, a
// smaller positive value is honored.
const DefaultDrainTimeout = 2 * time.Second

// Typed lifecycle errors. Callers (the E1.10 adapter) branch on these to choose an exit code
// and message; none of them ever carries child content.
var (
	// ErrCapacityRefused reports that hard byte-ceiling pressure refused a new explicit run
	// before RUN_STARTED. No boundary was written and no child was started.
	ErrCapacityRefused = errors.New("observer runwrap: capacity hard pressure refuses a new explicit run")

	// ErrBoundaryNotDurable reports that RUN_STARTED could not be durably recorded, so the
	// child was NOT started (spec: "refuse to start the child if the boundary cannot be
	// durably recorded"). The reserve is released.
	ErrBoundaryNotDurable = errors.New("observer runwrap: run boundary not durable; child not started")

	// ErrNoTarget reports an empty child command.
	ErrNoTarget = errors.New("observer runwrap: no child command given")

	// ErrIncompleteWorkRef reports that exactly one of the beads project id / work item id was
	// given; a work reference needs both or neither.
	ErrIncompleteWorkRef = errors.New("observer runwrap: beads project id and work item id must be given together")
)

// DrainOutcome is the daemon's report from a post-exit transcript drain: the closed drain
// status and the covered stable watermark. The daemon appends the drained transcript records
// itself; this is only the summary the wrapper stamps onto RUN_ENDED.
type DrainOutcome struct {
	Status           wire.RunEndedBoundaryDrainStatus
	CoveredWatermark wire.Watermark
}

// DaemonClient is the durable-append / capacity / drain seam the wrapper needs from the
// owner-only local daemon. E1.10 wires internal/observer/local's client to this interface;
// runwrap depends only on the interface so it never imports the socket package.
//
// Registration is NOT a distinct method: the wrapper registers the child's OS process-start
// identity by durably Append-ing a PROCESS_LIFECYCLE{REGISTERED} observation, so the daemon
// builds its ancestry index from the same durable frame every other consumer reads.
type DaemonClient interface {
	// ReserveTerminal atomically admits a new explicit run against the byte ceiling and
	// preallocates its terminal reserve. Under hard pressure it MUST refuse (before any
	// RUN_STARTED) with an error satisfying errors.Is(err, ErrCapacityRefused) and reserve
	// nothing. A successful reserve guarantees space for the run's terminal records.
	ReserveTerminal(ctx context.Context, runID string) error

	// Append durably appends one pending observation, returning only after the append is
	// durable. A non-nil error means the observation is NOT durable.
	Append(ctx context.Context, obs evidence.PendingObservation) error

	// Drain drains complete transcript records for runID through a stable provider-file
	// watermark, bounded by ctx's deadline, and reports the closed drain status and covered
	// watermark. The daemon appends the drained records itself.
	Drain(ctx context.Context, runID string) (DrainOutcome, error)

	// ReleaseTerminal frees runID's terminal reserve. The wrapper calls it only after the
	// terminal RUN_ENDED is durable, so an interrupted terminal sequence never strands the
	// run without its terminal capacity.
	ReleaseTerminal(ctx context.Context, runID string) error
}

// ShimSpec describes how to spawn the same-PID identity shim. The zero value re-execs the
// current binary with ShimSubcommand, which is what production wants; tests point Path at the
// test binary and trigger the shim through ExtraEnv.
type ShimSpec struct {
	// Path is the program exec'd as the shim. Empty selects the current executable.
	Path string
	// PrefixArgs are the args before the "--" target separator. Nil selects [ShimSubcommand].
	PrefixArgs []string
	// ExtraEnv is appended to the shim process environment (e.g. a test-mode trigger). The
	// shim strips every RUNWRAP_-prefixed control variable before exec-ing the child, so
	// these never reach the child.
	ExtraEnv []string
}

func (s ShimSpec) resolve() (ShimSpec, error) {
	out := s
	if out.Path == "" {
		exe, err := os.Executable()
		if err != nil {
			return ShimSpec{}, fmt.Errorf("observer runwrap: resolve shim path: %w", err)
		}
		out.Path = exe
	}
	if out.PrefixArgs == nil {
		out.PrefixArgs = []string{ShimSubcommand}
	}
	return out, nil
}

// Config is the input to Run. Only Target is required for an unobserved run; an observed run
// additionally needs the daemon and, when a work reference is desired, both beads ids.
type Config struct {
	// Target is the child command argv; Target[0] is the program, resolved via PATH.
	Target []string

	// BeadsProjectID / WorkItemBeadID are persisted on the RUN_STARTED boundary as a DECLARED
	// work reference. Both or neither must be set.
	BeadsProjectID string
	WorkItemBeadID string

	// AllowUnobserved is the emergency bypass: no run id, no ancestry, no daemon contact.
	AllowUnobserved bool

	// DrainTimeout bounds the post-exit drain. <=0 selects DefaultDrainTimeout; a value above
	// the default is clamped down to it (configurable only downward).
	DrainTimeout time.Duration

	// Shim controls how the same-PID identity shim is spawned (see ShimSpec).
	Shim ShimSpec

	// Stdin/Stdout/Stderr are the child's standard streams. Nil selects os.Stdin/Stdout/Stderr.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Warn receives the prominent --allow-unobserved warning. Nil selects os.Stderr.
	Warn io.Writer

	// Env is the base child environment. Nil selects os.Environ(). The wrapper adds or removes
	// only RunIDEnvVar; it never inspects the rest.
	Env []string

	// now / newRunID are test seams. Nil selects time.Now / a crypto/rand opaque id.
	now      func() time.Time
	newRunID func() (string, error)
}

func (c Config) clock() func() time.Time {
	if c.now != nil {
		return c.now
	}
	return time.Now
}

func (c Config) idGen() func() (string, error) {
	if c.newRunID != nil {
		return c.newRunID
	}
	return newOpaqueRunID
}

func (c Config) warnWriter() io.Writer {
	if c.Warn != nil {
		return c.Warn
	}
	return os.Stderr
}

func (c Config) drainTimeout() time.Duration {
	d := c.DrainTimeout
	if d <= 0 || d > DefaultDrainTimeout {
		return DefaultDrainTimeout
	}
	return d
}

// validate checks the target and work-reference completeness before any side effect.
func (c Config) validate() error {
	if len(c.Target) == 0 || c.Target[0] == "" {
		return ErrNoTarget
	}
	if (c.BeadsProjectID == "") != (c.WorkItemBeadID == "") {
		return ErrIncompleteWorkRef
	}
	return nil
}

// Result is the outcome of Run. It is content-free: it names the run and reports how the
// child ended, never why the work succeeded (outcome is always UNKNOWN in the pilot).
type Result struct {
	// RunID is the minted authoritative run id ("" on the unobserved path).
	RunID string
	// InheritedRunID is the outer GASWORKS_RUN_ID this wrapper started under, retained as
	// correlation-only evidence ("" when none). It is never this run's membership.
	InheritedRunID string
	// Observed is false for --allow-unobserved.
	Observed bool
	// Launched is true once the child image actually exec'd.
	Launched bool
	// ExitCode is the child exit code (meaningful when Launched and not Signaled).
	ExitCode int
	// Signaled / Signal report a signal-terminated child.
	Signaled bool
	Signal   int
	// DrainStatus is the closed drain status stamped on RUN_ENDED ("" on the launch-failure
	// and unobserved paths).
	DrainStatus wire.RunEndedBoundaryDrainStatus
	// Identity is the registered child OS process identity (zero when not launched).
	Identity wire.ProcessIdentity
}

// Run executes the explicit-run lifecycle. It returns a nil error for every path where the
// child ran to completion — a nonzero or signal exit is process evidence, not a Run error.
// It returns a typed error only when the run could not be established (capacity refusal,
// non-durable boundary) or the child could not be launched.
func Run(ctx context.Context, d DaemonClient, cfg Config) (Result, error) {
	if err := cfg.validate(); err != nil {
		return Result{}, err
	}
	if cfg.AllowUnobserved {
		return runUnobserved(cfg)
	}
	if d == nil {
		return Result{}, errors.New("observer runwrap: observed run requires a DaemonClient")
	}

	runID, err := cfg.idGen()()
	if err != nil {
		return Result{}, fmt.Errorf("observer runwrap: mint run id: %w", err)
	}
	inherited := os.Getenv(RunIDEnvVar)
	if cfg.Env != nil {
		inherited = envLookup(cfg.Env, RunIDEnvVar)
	}

	r := &runner{d: d, cfg: cfg, runID: runID}

	// Reserve terminal capacity BEFORE RUN_STARTED. Hard pressure refuses here; nothing is
	// written and no child starts.
	if err := d.ReserveTerminal(ctx, runID); err != nil {
		if errors.Is(err, ErrCapacityRefused) {
			return Result{}, ErrCapacityRefused
		}
		return Result{}, fmt.Errorf("observer runwrap: reserve terminal capacity: %w", err)
	}

	// Durably record RUN_STARTED before spawn; refuse to start the child otherwise.
	started, err := evidence.NewRunStarted(r.common(cfg.clock()()), evidence.RunStartedInput{
		RunID:          runID,
		BoundarySource: wire.RunStartedBoundaryBoundarySourceEXPLICITWRAPPER,
		WorkItemRefs:   r.declaredRefs(),
	})
	if err != nil {
		_ = d.ReleaseTerminal(ctx, runID)
		return Result{}, fmt.Errorf("observer runwrap: build RUN_STARTED: %w", err)
	}
	if err := d.Append(ctx, started); err != nil {
		_ = d.ReleaseTerminal(ctx, runID)
		return Result{}, fmt.Errorf("%w: %v", ErrBoundaryNotDurable, err)
	}

	// Build the child environment: the base env with the minted run id exported (overwriting
	// any inherited outer id — the nearest registered ancestor is authoritative).
	childEnv := withRunID(cfg.baseEnv(), runID)

	// Launch through the same-PID shim; register the proven child identity before it exec's.
	proc, lerr := launchObserved(cfg, childEnv, func(id wire.ProcessIdentity) error {
		return r.appendRegistered(ctx, id)
	})
	if lerr != nil {
		// Launch failed after RUN_STARTED: close the run (PROCESS_LAUNCH_FAILED when an identity
		// was proven, then RUN_ENDED with no drain, then release) and surface the REAL cause —
		// never the constructor error from an unbuildable zero identity. If the close itself hits
		// a durable-append failure, join it so a genuine durability incident is not swallowed.
		res := Result{RunID: runID, InheritedRunID: inherited, Observed: true, Identity: lerr.identity}
		if closeErr := r.terminalLaunchFailure(ctx, lerr.identity); closeErr != nil {
			return res, errors.Join(lerr.err, closeErr)
		}
		return res, lerr.err
	}

	// Child is running. Wait for it, then run the normative terminal sequence.
	exitCode, signaled, signal := proc.wait()
	drainStatus, err := r.terminalExit(ctx, proc.identity, exitCode, signaled, signal)
	res := Result{
		RunID:          runID,
		InheritedRunID: inherited,
		Observed:       true,
		Launched:       true,
		ExitCode:       exitCode,
		Signaled:       signaled,
		Signal:         signal,
		DrainStatus:    drainStatus,
		Identity:       proc.identity,
	}
	return res, err
}

// runUnobserved is the --allow-unobserved bypass: it prints a prominent warning, exports no
// run id, registers no ancestry, and never contacts the daemon. Any inherited outer run id is
// stripped from the child environment so an independently captured native session stays its
// own inferred run rather than referencing an unknown boundary.
func runUnobserved(cfg Config) (Result, error) {
	fmt.Fprintln(cfg.warnWriter(),
		"WARNING: --allow-unobserved bypasses Gas City Observer. This run is UNOBSERVED: "+
			"no run boundary, no process ancestry, and no GASWORKS_RUN_ID are recorded.")

	childEnv := withoutRunID(cfg.baseEnv())
	proc, err := launchUnobserved(cfg, childEnv)
	if err != nil {
		return Result{Observed: false}, err
	}
	exitCode, signaled, signal := proc.wait()
	return Result{
		Observed: false,
		Launched: true,
		ExitCode: exitCode,
		Signaled: signaled,
		Signal:   signal,
	}, nil
}

// runner bundles the daemon seam, config, and run id so the start/terminal builders in this
// file and drain.go share one content-free observation factory.
type runner struct {
	d     DaemonClient
	cfg   Config
	runID string
}

// common builds the shared observation envelope: metadata-only provenance and a run context
// stamped with this run id under DECLARED_BOUNDARY membership (the wrapper declares the run).
// The stamped run_id is what the spool uses to classify a PROCESS_LIFECYCLE frame's run.
func (r *runner) common(now time.Time) evidence.Common {
	return evidence.Common{
		OccurredAt: now,
		CapturedAt: now,
		Provenance: wire.Provenance{
			Adapter:        wrapperAdapter,
			AdapterVersion: wrapperAdapterVersion,
			ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		},
		RunContext: &wire.RunContext{
			RunId:              r.runID,
			MembershipEvidence: wire.RunContextMembershipEvidenceDECLAREDBOUNDARY,
		},
	}
}

// declaredRefs returns the boundary's DECLARED work reference (project + bead) or nil when no
// beads reference was supplied. validate() has already rejected the one-of-two case.
func (r *runner) declaredRefs() []wire.WorkReference {
	if r.cfg.BeadsProjectID == "" {
		return nil
	}
	return []wire.WorkReference{{
		TeamServerProjectId: r.cfg.BeadsProjectID,
		BeadId:              r.cfg.WorkItemBeadID,
		Origin:              wire.WorkReferenceOriginDECLARED,
	}}
}

// appendRegistered durably records the child's proven OS process-start identity as a
// PROCESS_LIFECYCLE{REGISTERED}. It runs inside the launch handshake, before the shim exec's
// the child, so registration is durable before the child image exists.
func (r *runner) appendRegistered(ctx context.Context, id wire.ProcessIdentity) error {
	obs, err := evidence.NewProcessLifecycle(r.common(r.cfg.clock()()), evidence.ProcessLifecycleInput{
		Transition: wire.ProcessLifecyclePayloadTransitionREGISTERED,
		Identity:   id,
	})
	if err != nil {
		return fmt.Errorf("observer runwrap: build REGISTERED: %w", err)
	}
	if err := r.d.Append(ctx, obs); err != nil {
		return fmt.Errorf("observer runwrap: append REGISTERED: %w", err)
	}
	return nil
}

// baseEnv returns the configured base environment or the process environment.
func (c Config) baseEnv() []string {
	if c.Env != nil {
		return c.Env
	}
	return os.Environ()
}

// newOpaqueRunID mints a 128-bit opaque, url-safe run id. It carries no structure a consumer
// could parse for meaning.
func newOpaqueRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "run_" + hex.EncodeToString(b[:]), nil
}
