package climint

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Every hostile value here is written as an ESCAPE rather than as the character itself. A raw
// bidi override or ESC in a source file is the trojan-source trick, and this file is about not
// letting one reach a terminal.

func TestDisplayLeavesOrdinaryValuesAlone(t *testing.T) {
	for _, s := range []string{
		"", "spk_1", "gck_sp", "2026-09-10T00:00:00Z", "forge:city.create",
		"https://auth.gascity.com/cli/mint/approve?c=chal_1", "WXYZ-4242",
		"a message with spaces, punctuation and an em dash — like this",
		"a replacement character � is a character",
	} {
		if got := Display(s); got != s {
			t.Errorf("Display(%q) = %q, want it unchanged", s, got)
		}
	}
}

// The whole point: nothing a server can put in a display field may end a line, start one, or
// move the cursor over one already printed.
func TestDisplayEscapesEveryByteATerminalActsOn(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"carriage return", "spk_1\rDECOY"},
		{"line feed", "spk_1\n  secret:   /home/you/prod.env"},
		{"CRLF", "spk_1\r\nMinted a service-principal key"},
		{"escape", "spk_1\x1b[2K"},
		{"C1 CSI", "spk_12K"},
		{"NUL", "spk_1\x00"},
		{"DEL", "spk_1"},
		{"vertical tab", "spk_1\v"},
		{"tab", "spk_1\tDECOY"},
		{"bidi override", "spk_1‮decoy"},
		{"zero width joiner", "spk_1‍"},
		{"line separator", "spk_1 DECOY"},
		{"invalid UTF-8", "spk_1\xff\xfe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Display(tc.in)
			if strings.ContainsAny(got, "\r\n\t\v\f\x00\x1b") {
				t.Fatalf("Display(%q) = %q, which still carries a control byte", tc.in, got)
			}
			if !Printable(got) {
				t.Fatalf("Display(%q) = %q, which is still not printable", tc.in, got)
			}
			// Reversible: the operator can still recover exactly what the server sent.
			back, err := strconv.Unquote(got)
			if err != nil {
				t.Fatalf("Display(%q) = %q, which does not unquote: %v", tc.in, got, err)
			}
			if back != tc.in && tc.name != "invalid UTF-8" {
				t.Fatalf("Display(%q) unquotes to %q", tc.in, back)
			}
		})
	}
}

func TestDisplayBoundsTheLength(t *testing.T) {
	long := strings.Repeat("k", MaxDisplayRunes*3)
	got := Display(long)
	if len(got) >= len(long) {
		t.Fatalf("Display did not bound a %d-byte value (%d bytes out)", len(long), len(got))
	}
	if !strings.Contains(got, "more bytes)") {
		t.Errorf("a truncated value does not say so: %q", got[:80])
	}
	if !Printable(got) {
		t.Errorf("the bounded form is not printable: %q", got[:80])
	}
}

// The credential is the one value that must NOT be filtered: it is written to a file byte for
// byte, and an escape that made it safe to print would make it wrong to use.
func TestTheSecretIsNotDisplayFiltered(t *testing.T) {
	const secret = "gck_sp_‮\x1b[2K_secret"
	const keyID = "spk_1\r\nDECOY"
	body, err := json.Marshal(map[string]string{"key_id": keyID, "secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	credential, parseErr := decodeCredential(body, false)
	if parseErr != nil {
		t.Fatalf("decode %s: %v", body, parseErr)
	}
	if credential.Secret != secret {
		t.Errorf("the secret was filtered: got %q, want %q", credential.Secret, secret)
	}
	if credential.KeyID == keyID {
		t.Errorf("the key id reached the caller unfiltered: %q", credential.KeyID)
	}
	if !Printable(credential.KeyID) {
		t.Errorf("the key id is not printable: %q", credential.KeyID)
	}
}

// The server's error code and message are the two most obviously attacker-shaped fields on
// either leg, and TerminalError.Error() is what the CLI prints.
func TestTerminalErrorTextIsFiltered(t *testing.T) {
	err := statusError(http.StatusForbidden, map[string]any{
		"error":             "denied\rgranted",
		"error_description": "refused\r\nMinted a service-principal key.",
	}, "https://auth.gascity.com/v0/cli/mint/challenges/chal_1/complete")
	if !Printable(err.Error()) {
		t.Fatalf("TerminalError.Error() is not printable: %q", err.Error())
	}
}

// SaysConsumed and MayHaveMinted answer different questions, and the report and the control flow
// each need their own. Reading one as the other is how the CLI ends up quoting a statement the
// server never made — or missing one it did.
func TestSaysConsumedIsNarrowerThanMayHaveMinted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		code     string
		mayMint  bool
		saysSoIt bool
	}{
		{"409 already_consumed", http.StatusConflict, "already_consumed", true, true},
		{"410 redeemed", http.StatusGone, "redeemed", true, true},
		{"a consumed code on a 403", http.StatusForbidden, "already_consumed", true, true},
		{"bare 409", http.StatusConflict, "", true, false},
		{"bare 410", http.StatusGone, "", true, false},
		{"409 with an unknown code", http.StatusConflict, "wat", true, false},
		{"410 with an unknown code", http.StatusGone, "teapot", true, false},
		{"410 expired", http.StatusGone, "expired", false, false},
		{"409 denied", http.StatusConflict, "denied", false, false},
		{"403 refusal", http.StatusForbidden, "forbidden", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &TerminalError{Status: tc.status, Code: tc.code}
			if got := e.MayHaveMinted(); got != tc.mayMint {
				t.Errorf("MayHaveMinted() = %v, want %v", got, tc.mayMint)
			}
			if got := e.SaysConsumed(); got != tc.saysSoIt {
				t.Errorf("SaysConsumed() = %v, want %v", got, tc.saysSoIt)
			}
		})
	}
}

// A body cut anywhere inside a JSON object does not parse, so one that parses arrived whole.
// That is what lets the CLI tell "the framing was cut" from "the secret is missing its tail".
func TestTruncatedIsAboutTheBodyAndNotTheReadError(t *testing.T) {
	whole := []byte(`{"key_id":"spk_1","secret":"gck_sp_value"}`)
	if !json.Valid(whole) {
		t.Fatal("the fixture is not valid JSON")
	}
	if cut := whole[:len(whole)-8]; json.Valid(cut) {
		t.Fatalf("a body cut mid-secret still parses: %s", cut)
	}
	credential, err := decodeCredential(whole, false)
	if err != nil || credential.Secret != "gck_sp_value" {
		t.Fatalf("a whole body did not yield its secret: %q / %v", credential.Secret, err)
	}
	if _, err := decodeCredential(whole[:len(whole)-8], true); err == nil {
		t.Fatal("a cut body yielded a credential")
	} else if !strings.Contains(err.Error(), "cut short") {
		t.Errorf("the reason does not say the body was cut short: %v", err)
	}
}
