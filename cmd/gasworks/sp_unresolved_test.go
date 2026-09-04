package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/climint"
	"github.com/gascity/gasworks/internal/store"
)

// Leg C is not idempotent: it consumes the challenge and mints a key. So the only thing this CLI
// can honestly say about a redeem it sent depends entirely on what came back.
//
// A 425 or a 4xx is the mint plane stating that it did not mint, and repeating that is repeating
// the server. Silence is not. A timeout, a reset, a 2xx carrying no credential and a 5xx from a
// plane that relays to accounts all leave the question open, and the comfortable answer to an
// open question is how a key holding forge:city.create and forge:city.delete ends up live, for
// its whole lifetime, with nobody looking for it and no revoke arm to call.
//
// These pin both halves: what the ceremony may claim, and what it must never claim.

// mintTimeoutClient re-points the ceremony at the same stub mint plane with a per-leg timeout of
// milliseconds rather than 30s, so a mint plane that never answers can be exercised here instead
// of in a 30-second test.
func mintTimeoutClient(t *testing.T, srv *stubServer, timeout time.Duration) {
	t.Helper()
	transport := srv.mint.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.DisableCompression = true
	previous := mintClient
	mintClient = &climint.Client{HTTP: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	t.Cleanup(func() { mintClient = previous })
}

// Every way a redeem can come back without a credential, and what the operator is told about
// each. The split is not by HTTP status but by whether the mint plane said what it did.
func TestSPMintKeySaysNothingWasMintedOnlyWhenTheMintPlaneDid(t *testing.T) {
	for _, tc := range []struct {
		name string
		// settled is true when the mint plane's answer says no credential came out of the
		// attempt, which is the only case in which this CLI may say so too; refusal is the
		// server's own words that the report has to carry.
		settled bool
		refusal string
		timeout time.Duration
		handler func(http.ResponseWriter, *http.Request, int)
	}{
		{
			name:    "the mint plane refuses the redemption (403)",
			settled: true,
			refusal: "403 denied",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "denied"})
			},
		},
		{
			name:    "the challenge has expired (409)",
			settled: true,
			refusal: "409 expired",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusConflict, map[string]any{"error": "expired"})
			},
		},
		{
			name:    "the session is rejected (401)",
			settled: true,
			refusal: "401 invalid_session",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_session"})
			},
		},
		{
			// The server committed and the answer never got out. This is the case that used to
			// print "the mint was not completed" over a live key.
			name:    "the answer never arrives",
			timeout: 300 * time.Millisecond,
			handler: func(_ http.ResponseWriter, r *http.Request, _ int) { <-r.Context().Done() },
		},
		{
			name: "a 201 whose body is empty",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(http.StatusCreated)
			},
		},
		{
			name: "a 204 with no content",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(http.StatusNoContent)
			},
		},
		{
			// climint relays to accounts. A gateway error can land with the key already issued
			// behind it, so a 5xx says nothing about what was minted.
			name: "the relay fails (502)",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": "bad_gateway"})
			},
		},
		{
			name: "the mint plane is unavailable (503)",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			mintedDir := filepath.Join(t.TempDir(), "minted-keys")
			t.Setenv(store.MintedKeyDirEnv, mintedDir)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = tc.handler
			if tc.timeout != 0 {
				mintTimeoutClient(t, srv, tc.timeout)
			}

			stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
			if code == 0 {
				t.Fatal("exit 0 for a redemption that produced no credential file")
			}
			if strings.Contains(stdout, "Minted a service-principal key") {
				t.Fatalf("the success banner was printed:\n%s", stdout)
			}
			// Nothing was revealed either way, so the reservation is rolled back like any
			// pre-reveal failure.
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Errorf("the reservation was left behind at %s (%v)", out, err)
			}
			if entries, _ := os.ReadDir(mintedDir); len(entries) != 0 {
				t.Errorf("%d files left in the minted-keys dir", len(entries))
			}

			if tc.settled {
				// The mint plane refused in its own words, so the report is those words and the
				// question is not left open.
				if strings.Contains(stderr, "MAY HAVE BEEN ISSUED") {
					t.Errorf("a refusal the mint plane spelled out was reported as an open "+
						"question:\n%s", stderr)
				}
				if !strings.Contains(stderr, tc.refusal) {
					t.Errorf("stderr does not carry the mint plane's own reason (%q):\n%s", tc.refusal, stderr)
				}
				return
			}
			// The unresolved half. This is the D1 rule: no claim, the challenge id, and the
			// possibility stated plainly.
			if strings.Contains(stderr, "nothing was minted") {
				t.Errorf("THE CLI CLAIMED NOTHING WAS MINTED for a redeem whose outcome it does "+
					"not know:\n%s", stderr)
			}
			for _, want := range []string{
				"THE REDEEM WAS SENT AND ITS OUTCOME IS UNKNOWN",
				"A CREDENTIAL MAY HAVE BEEN ISSUED",
				"challenge:  chal_1",
				"Reconcile challenge chal_1",
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("the report is missing %q:\n%s", want, stderr)
				}
			}
		})
	}
}

// The mirror image, and the reason "the redeem was sent" may not be printed on faith. A dial
// that never connected sent nothing: the challenge is untouched, no key came out of it, and a
// warning here would send someone to reconcile a credential that cannot exist.
func TestSPMintKeySaysNothingWasMintedWhenTheRedeemNeverLeftTheClient(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	mintedDir := filepath.Join(t.TempDir(), "minted-keys")
	t.Setenv(store.MintedKeyDirEnv, mintedDir)
	out := filepath.Join(t.TempDir(), "sp.env")
	// The mint plane stops listening the moment leg A has been answered. Closing the listener
	// leaves the connection leg A is on alone, and leg C opens a fresh one — keepalives are off,
	// so a single-use proof is never replayed — which finds nothing to connect to.
	srv.mintChallengeHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusCreated, srv.mintChallenge)
		_ = srv.mint.Listener.Close()
	}

	stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
	t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
	if code == 0 {
		t.Fatal("exit 0 for a redeem that never reached the mint plane")
	}
	if served := len(srv.reqs("/complete")); served != 0 {
		t.Fatalf("the mint plane served %d redeems; the probe needs it to have served none", served)
	}
	if strings.Contains(stderr, "THE REDEEM WAS SENT") {
		t.Errorf("the CLI states as fact that the redeem was sent, when nothing reached a "+
			"socket:\n%s", stderr)
	}
	if strings.Contains(stderr, "MAY HAVE BEEN ISSUED") {
		t.Errorf("the CLI warns about a credential that cannot exist:\n%s", stderr)
	}
	for _, want := range []string{"never left this machine", "nothing was minted", "chal_1"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the message is missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stdout, "Minted a service-principal key") {
		t.Fatalf("the success banner was printed:\n%s", stdout)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Errorf("the reservation was left behind at %s (%v)", out, err)
	}
}
