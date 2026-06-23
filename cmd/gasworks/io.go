package main

import (
	"fmt"
	"io"
	"os"
)

// stdout and stderr are the CLI's output sinks. They are package vars (defaulting to the real
// streams) so tests can capture them deterministically without spawning a subprocess. Tokens
// and machine-readable data go to stdout; prompts and errors go to stderr.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func stdoutf(format string, a ...any) {
	fmt.Fprintf(stdout, format+"\n", a...)
}

func stdoutLine(s string) {
	fmt.Fprintln(stdout, s)
}

// eprintln is the logf callback passed to oidc flows (it prints prompts to stderr).
func eprintln(s string) {
	fmt.Fprintln(stderr, s)
}

// stderrWriter exposes stderr for flag.FlagSet output so usage/parse errors land on stderr.
func stderrWriter() io.Writer { return stderr }
