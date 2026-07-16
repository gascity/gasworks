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
	// Delegated reports that BEADS_EXEC_INFO was present — i.e. bd (or any delegator) invoked
	// this credential command. This is the SECURITY gate: a delegated call with no usable
	// destination must fail closed regardless of whether the payload parsed as origin=bd. A
	// corrupt or version-skewed payload is still delegated, so it must never fall into the
	// direct-human fail-open branch (S2-DESIGN §5.0 rule 4).
	Delegated bool
	// BDOriginated reports that the exec-info payload cleanly declared origin=bd. It is a
	// messaging/telemetry marker only — NOT the security gate (see Delegated). It implies
	// Delegated.
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

	dest := Destination{
		Delegated:    info.Present,
		BDOriginated: info.Present && info.Origin == OriginBD,
	}
	switch {
	case info.DialHost != "" && flagHost != "" && info.DialHost != flagHost:
		return Destination{}, fmt.Errorf(
			"conflicting mint destinations: bd exec-info dialHost %q vs --gateway %q — "+
				"drop --gateway (bd supplies the destination) or reconcile them",
			info.DialHost, flagHost)
	case info.DialHost != "":
		dest.Host = info.DialHost
	case info.Present:
		// FIX 9: a delegated invocation with no usable exec-info dialHost must NOT fall back to
		// --gateway. A stale/hardcoded --gateway must never rescue a mint whose true destination
		// bd failed to declare — leave the host empty so Gate fails closed (FIX 8, rule 4).
		dest.Host = ""
	default:
		// Only a truly ABSENT env var (direct human use, or an older bd that injects no
		// exec-info) takes the --gateway fallback.
		dest.Host = flagHost
	}
	return dest, nil
}

// Gate enforces the destination allowlist for a resolved destination under the given mode.
// It returns a non-nil error only when the caller must refuse (exit 1); on a warn-mode
// allowlist miss it logs a would-refuse warning via warnf and returns nil (the mint proceeds).
//
// A DELEGATED mint with no destination ALWAYS refuses (fail closed) regardless of mode — a bd
// invocation always injects a dialHost, so its absence (whether the payload said origin=bd,
// was corrupt, or was version-skewed) is a bug or an attack, never legitimate. The gate keys on
// delegation PRESENCE, not on origin==bd, so a corrupt/origin-missing payload cannot fall into
// the fail-open branch (FIX 8). A direct human invocation (no exec-info at all) with no
// destination mints (fail open).
func Gate(dest Destination, mode Mode, warnf func(string)) error {
	if dest.Host == "" {
		if dest.Delegated {
			return &RefusalError{msg: "refusing to mint a beads credential: the delegated (bd) " +
				"invocation carried no destination (BEADS_EXEC_INFO was absent, corrupt, or had no dialHost) — " +
				"this is a bug or an attack"}
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
