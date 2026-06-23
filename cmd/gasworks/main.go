// Command gasworks is the SSO login + getToken (EIA) CLI for Gas City. It wires the
// internal client packages (oidc, sts, store, dpop, jwtutil, config) into four subcommands.
//
// The token lifecycle has three layers, each cached with its own DISTINCT TTL threshold:
//
//	Keycloak refresh_token -> id_token   (refreshed when <60s left; rotation persisted)
//	id_token               -> STS session per org (8h; DPoP-bound; reused when >30s left)
//	session                -> EIA per (org, product, scope) (90s; reused when >15s left)
//
// Discovery (/sts/v0/context) supplies the concrete org + the exact mintable scopes so the
// strict /login + /token gates can be satisfied without the user guessing.
package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/jwtutil"
	"github.com/gascity/gasworks/internal/sts"
	"github.com/gascity/gasworks/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a subcommand and returns the process exit code. It is separate from main so
// tests can drive it without os.Exit. A nil cmdError yields 0; a *cmdError yields its code.
func run(argv []string) int {
	cfg := config.FromEnv()

	if len(argv) == 0 {
		printUsage()
		return 2
	}

	cmd, rest := argv[0], argv[1:]
	var err error
	switch cmd {
	case "login":
		err = cmdLogin(cfg, rest)
	case "getToken", "get-token":
		err = cmdGetToken(cfg, rest)
	case "whoami":
		err = cmdWhoami(cfg, rest)
	case "logout":
		err = cmdLogout(cfg, rest)
	case "version", "--version":
		stdoutLine("gasworks " + version.String())
		return 0
	case "-h", "--help", "help":
		printUsage()
		return 0
	default:
		eprintf("gasworks: unknown command %q", cmd)
		printUsage()
		return 2
	}
	if err != nil {
		if ce, ok := err.(*cmdError); ok {
			eprintf("gasworks: %s", ce.msg)
			return ce.code
		}
		eprintf("gasworks: %s", err)
		return 1
	}
	return 0
}

// cmdError carries a user-facing message and exit code. It mirrors the Python _die() contract:
// the message is printed to stderr prefixed with "gasworks:" and the process exits non-zero.
type cmdError struct {
	msg  string
	code int
}

func (e *cmdError) Error() string { return e.msg }

// die builds a *cmdError with exit code 1, the only non-zero code the Python CLI uses for
// command failures.
func die(format string, a ...any) *cmdError {
	return &cmdError{msg: fmt.Sprintf(format, a...), code: 1}
}

func now() int64 { return time.Now().Unix() }

// eprintf prints to stderr with a trailing newline (prompts + errors go to stderr; tokens and
// data go to stdout).
func eprintf(format string, a ...any) {
	fmt.Fprintf(stderr, format+"\n", a...)
}

// tokenExp returns the id_token's exp claim, or 0 if it cannot be read (treated as expired).
func tokenExp(tok string) int64 {
	claims, err := jwtutil.DecodeClaims(tok)
	if err != nil {
		return 0
	}
	return jwtutil.Exp(claims)
}

// hasDisplay reports whether a graphical session is present, selecting the browser flow by
// default. macOS/Windows always have one; on others we look at DISPLAY / WAYLAND_DISPLAY.
func hasDisplay() bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// orgList renders an org list as "slug(id), slug(id)" for a multi-org / not-a-member error,
// or "(none)" when empty.
func orgList(orgs []sts.OrgContext) string {
	if len(orgs) == 0 {
		return "(none)"
	}
	out := ""
	for i, o := range orgs {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s(%s)", o.Slug, o.OrgID)
	}
	return out
}

func printUsage() {
	const usage = `gasworks: SSO login + getToken (EIA) for Gas City.

Usage:
  gasworks login [--device|--browser] [--org <id|slug>]
  gasworks getToken <product> [--org <id|slug>] [--scope "<space-sep>"] [--json] [--refresh]
  gasworks whoami
  gasworks logout
  gasworks version`
	fmt.Fprintln(stderr, usage)
}
