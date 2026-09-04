package climint

import (
	"fmt"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// Everything in a mint response is a string somebody else chose. climint is a RELAY — leg C's
// envelope is composed by accounts and forwarded — and the CLI prints those strings on a
// terminal that ACTS on control characters rather than showing them. A carriage return in a key
// id rewrites the line the operator is reading; an ESC [ sequence moves the cursor, clears a
// line, or repaints one that was already printed. Either one lets the server forge output: a
// second "secret:   /home/you/prod.env" line naming a decoy path, or a second "Enter code:"
// prompt.
//
// The filtering therefore happens HERE, where the strings enter the program, and not at the call
// sites that print them. There is exactly one exception and it is the whole reason the split
// exists: the secret is written to a file byte for byte, so mangling it would corrupt the one
// thing the server reveals exactly once. text() is display; rawText() is the secret.

// MaxDisplayRunes bounds one server-relayed value in a line this CLI prints. Every display field
// the mint plane sends — a key id, an expires_at, a confirm code, an error message — is short. A
// value past this bound is not one this client can act on, and printing it whole would let the
// server decide how much of the operator's screen it owns.
const MaxDisplayRunes = 512

// Display renders a string the server chose so that it can only ever be PART OF the line it was
// put in.
//
// A value that is printable as it stands is returned as it stands, so the ordinary case reads
// exactly as it always has. A value that is not is returned QUOTED, in Go's quoted-string form:
// that escapes every C0 and C1 control, every Unicode format, line and paragraph separator, and
// every byte that is not valid UTF-8 — and it is REVERSIBLE, so an operator still has exactly
// what the server sent. The quotes are half the point: an attempt to forge a line shows up as an
// obviously quoted one rather than disappearing into the report.
func Display(s string) string {
	head, dropped := headRunes(s, MaxDisplayRunes)
	if dropped == 0 {
		if Printable(head) {
			return head
		}
		return strconv.Quote(head)
	}
	return fmt.Sprintf("%s ...(%d more bytes)", strconv.Quote(head), dropped)
}

// Printable reports whether s can go to a terminal exactly as it is: valid UTF-8 throughout, and
// every rune one that a terminal SHOWS rather than obeys. Tabs and newlines are not printable by
// this test — a report field is one line, and the only caller that prints a multi-line block
// asks this question a line at a time.
func Printable(s string) bool {
	for i, r := range s {
		if r == utf8.RuneError {
			// A real U+FFFD decodes three bytes wide; one byte wide means the input was not
			// valid UTF-8 there, and what a terminal does with the raw byte is its own business.
			if _, width := utf8.DecodeRuneInString(s[i:]); width == 1 {
				return false
			}
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// headRunes returns the first limit runes of s, and how many BYTES were left behind.
func headRunes(s string, limit int) (string, int) {
	n := 0
	for i := range s {
		if n == limit {
			return s[:i], len(s) - i
		}
		n++
	}
	return s, 0
}
