package gateway

import (
	"encoding/json"
	"fmt"
)

// ExecInfoAPIVersion is the recognized BEADS_EXEC_INFO wire version. A newer minor/major is
// tolerated best-effort (log + extract dialHost), never a hard failure — the two-repo release
// coupling must not break on an exec-info bump.
const ExecInfoAPIVersion = "beads.dev/credential-exec/v1"

// OriginBD marks a bd-originated mint. Its ABSENCE (no BEADS_EXEC_INFO at all) denotes a
// direct human invocation, which mints without a destination gate (fail open); its presence
// with no usable destination fails closed.
const OriginBD = "bd"

// ExecInfo is the parsed BEADS_EXEC_INFO payload bd injects into the credential command's
// environment. Unknown JSON fields are ignored; a malformed payload degrades to Present=true
// with an empty Origin/DialHost (the caller decides whether that must fail closed).
type ExecInfo struct {
	// Present reports that the env var was set (non-empty) — i.e. a delegated invocation.
	Present bool
	// Origin is the payload's origin marker ("bd" for a bd-originated mint, "" otherwise).
	Origin string
	// DialHost is the canonicalized destination bd is about to dial, or "" if the payload
	// carried none / an un-canonicalizable one.
	DialHost string
}

// execInfoWire is the on-the-wire shape. Only these fields are consumed; anything else in the
// JSON is ignored, per the version-compat contract.
type execInfoWire struct {
	APIVersion string `json:"apiVersion"`
	Origin     string `json:"origin"`
	Spec       struct {
		DialHost string `json:"dialHost"`
		DialPort int    `json:"dialPort"`
		Database string `json:"database"`
	} `json:"spec"`
}

// ReadExecInfo parses a BEADS_EXEC_INFO env value. An empty value means "no exec-info"
// (direct human invocation). Parsing is lenient: invalid JSON or an unrecognized apiVersion
// logs a warning via warnf and still extracts whatever it can, so a future bd never hard-fails
// an older helper. A dialHost that fails canonicalization is dropped (logged) rather than
// fatal — the caller fails closed only when it actually needs a host it cannot obtain.
func ReadExecInfo(raw string, warnf func(string)) ExecInfo {
	if raw == "" {
		return ExecInfo{}
	}
	info := ExecInfo{Present: true}

	var wire execInfoWire
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		warnf("BEADS_EXEC_INFO is set but is not valid JSON; ignoring its contents")
		return info
	}
	info.Origin = wire.Origin
	if wire.APIVersion != "" && wire.APIVersion != ExecInfoAPIVersion {
		warnf(fmt.Sprintf("BEADS_EXEC_INFO apiVersion %q is not recognized (%q); extracting best-effort",
			wire.APIVersion, ExecInfoAPIVersion))
	}
	if wire.Spec.DialHost != "" {
		canon, err := CanonicalHost(wire.Spec.DialHost)
		if err != nil {
			warnf(fmt.Sprintf("BEADS_EXEC_INFO dialHost %q is not a usable host: %v", wire.Spec.DialHost, err))
		} else {
			info.DialHost = canon
		}
	}
	return info
}
