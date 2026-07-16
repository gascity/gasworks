package gateway

import (
	"fmt"
	"strings"
)

// Mode is the destination-gate enforcement mode of the warn-then-enforce rollout.
type Mode int

const (
	// Warn logs a would-refuse warning for an untrusted destination but still mints, so a
	// new-bd/old-helper or old-bd/new-helper skew never breaks a working setup during rollout.
	Warn Mode = iota
	// Enforce refuses (exit 1) for an untrusted destination.
	Enforce
)

// DefaultMode is the compiled-in default gate mode. It is Warn during the WP-A rollout; flip
// this ONE constant to Enforce once the exec-info-injecting bd tag is the default install
// (S2-DESIGN §5.0 rule 6, §8). Structural contract violations (exec-info/flag disagreement,
// a bd-originated mint with no destination) are ALWAYS hard errors regardless of this mode.
const DefaultMode = Warn

// EnforceEnvVar overrides DefaultMode for tests and early adopters.
const EnforceEnvVar = "GASWORKS_DESTINATION_ENFORCE"

// ModeFromEnv resolves the gate mode from an env value. It accepts "enforce"/"1" and
// "warn"/"0" (case-insensitive); an empty value uses DefaultMode. The bool reports whether the
// value was recognized so the caller can warn on a typo rather than silently defaulting.
func ModeFromEnv(v string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return DefaultMode, true
	case "enforce", "1":
		return Enforce, true
	case "warn", "0":
		return Warn, true
	default:
		return DefaultMode, false
	}
}

// Destination is a resolved mint target.
type Destination struct {
	// Host is the canonical destination, or "" when none was supplied.
	Host string
	// BDOriginated reports that a bd-injected exec-info (origin=bd) drove this invocation, so
	// an absent/untrusted destination must fail closed rather than mint.
	BDOriginated bool
}

// RefusalError is a destination-gate refusal. Its Error() is the exact stderr message bd
// surfaces verbatim (the CLI's die() adds the "gasworks: " prefix). It carries no secrets.
type RefusalError struct{ msg string }

func (e *RefusalError) Error() string { return e.msg }

// Resolve picks the mint destination from bd's exec-info (authoritative — the host bd actually
// dials) and the --gateway flag (manual, for direct human use or an older bd). Precedence is
// exec-info dialHost > --gateway. If both are present and canonically disagree it returns a
// hard error ALWAYS (even in warn mode): the helper never silently picks a destination.
func Resolve(flagGateway, execInfoEnv string, warnf func(string)) (Destination, error) {
	info := ReadExecInfo(execInfoEnv, warnf)

	var flagHost string
	if flagGateway != "" {
		c, err := CanonicalHost(flagGateway)
		if err != nil {
			return Destination{}, fmt.Errorf("--gateway %q is not a valid host: %w", flagGateway, err)
		}
		flagHost = c
	}

	dest := Destination{BDOriginated: info.Present && info.Origin == OriginBD}
	switch {
	case info.DialHost != "" && flagHost != "" && info.DialHost != flagHost:
		return Destination{}, fmt.Errorf(
			"conflicting mint destinations: bd exec-info dialHost %q vs --gateway %q — "+
				"drop --gateway (bd supplies the destination) or reconcile them",
			info.DialHost, flagHost)
	case info.DialHost != "":
		dest.Host = info.DialHost
	default:
		dest.Host = flagHost
	}
	return dest, nil
}

// Gate enforces the destination allowlist for a resolved destination under the given mode.
// It returns a non-nil error only when the caller must refuse (exit 1); on a warn-mode
// allowlist miss it logs a would-refuse warning via warnf and returns nil (the mint proceeds).
//
// A bd-originated mint with no destination ALWAYS refuses (fail closed) regardless of mode —
// a new bd always injects a dialHost, so its absence is a bug or an attack, never legitimate.
// A direct human invocation with no destination mints (fail open).
func Gate(dest Destination, mode Mode, warnf func(string)) error {
	if dest.Host == "" {
		if dest.BDOriginated {
			return &RefusalError{msg: "refusing to mint a beads credential: the delegated (bd) " +
				"invocation carried no destination (BEADS_EXEC_INFO had no dialHost) — this is a bug or an attack"}
		}
		return nil
	}

	al, err := LoadAllowlist()
	if err != nil {
		return err
	}
	if al.Contains(dest.Host) {
		return nil
	}

	refusal := refusalMessage(dest.Host, al.Hosts())
	if mode == Enforce {
		return &RefusalError{msg: refusal}
	}
	warnf("WOULD REFUSE: " + refusal)
	return nil
}

// refusalMessage is the exact untrusted-gateway refusal text (sans the "gasworks: " prefix
// die() adds). eia-helper and bd's tests mirror this string.
func refusalMessage(host string, trusted []string) string {
	list := "(none)"
	if len(trusted) > 0 {
		list = strings.Join(trusted, ", ")
	}
	return fmt.Sprintf("refusing to mint a beads credential for unknown gateway '%s' — "+
		"trusted gateways: %s. Add one with 'gasworks trust-gateway %s' only if you operate it.",
		host, list, host)
}
