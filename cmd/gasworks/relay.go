package main

import (
	"fmt"

	"github.com/gascity/gasworks/internal/climint"
)

// The mint reports print values this process did not choose. climint is a relay — leg C's
// envelope is composed by accounts and forwarded — and a terminal ACTS on control characters
// rather than showing them, so a carriage return or an ESC [ sequence in any relayed value lets
// the SERVER forge a line of our output: a second "secret:   /home/you/prod.env" naming a decoy
// path, or a second "Enter code:" prompt.
//
// climint.Display filters every string that package decodes out of a response, so the fields
// themselves arrive safe. These three wrappers close the rest of the gap — an error built by the
// transport, an OS message, anything a future call site reaches for — by filtering the ARGUMENTS
// of a report line rather than trusting each site to remember. The format strings are this
// program's own literals and are left alone, which is what keeps our own multi-line messages
// readable.
//
// What must NOT come through here is the credential itself. The secret is copied off a screen
// and pasted into a file, so an escape that made it safe to print would make it wrong to paste;
// printSecretOfLastResort prints it directly, over a value unusableSecret has already proved is
// printable.

// relayed filters the arguments of one report line. Strings and errors are the two shapes a
// relayed value ever arrives in; numbers and everything else are this program's own.
func relayed(a []any) []any {
	out := make([]any, len(a))
	for i, v := range a {
		switch t := v.(type) {
		case string:
			out[i] = climint.Display(t)
		case error:
			// Rendered through fmt rather than by calling Error() directly: one of these lines is
			// printed holding the last copy of a credential, and fmt turns an Error() that panics
			// on a nil receiver into a %!v(PANIC=...) string instead of taking the report with it.
			out[i] = climint.Display(fmt.Sprintf("%v", t))
		default:
			out[i] = v
		}
	}
	return out
}

// eprintRelayed is eprintf for a line that carries values the server chose.
func eprintRelayed(format string, a ...any) { eprintf(format, relayed(a)...) }

// stdoutRelayed is stdoutf for one.
func stdoutRelayed(format string, a ...any) { stdoutf(format, relayed(a)...) }

// dieRelayed is die for one. The message it builds is printed by main's own handler, which does
// no filtering of its own — every die in the mint path that names a server value uses this.
func dieRelayed(format string, a ...any) *cmdError { return die(format, relayed(a)...) }
