//go:build !windows

// The already-consumed answer, and the signal that used to turn it into a cancel. POSIX only:
// the guarded-signal half raises a real SIGINT with kill(2), which Windows has nothing to do.

package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/store"
)

// `already_consumed` is the one 4xx that is not a refusal, and reading it as one is the worst
// mistake in the set: the mint plane has just said that challenge WAS redeemed, and this CLI
// redeems a challenge exactly once. So a key came out of an attempt whose answer never landed.
//
// A bare 409 or 410, and a 410 whose code this client does not know, are read the SAME way — the
// outcome is treated as open — and reported differently. The server did not say the challenge was
// redeemed; the status merely can mean it, and quoting a statement nobody made is the same class
// of error as suppressing one that was. Every case here therefore pins two things: the classification
// (never "nothing was minted", always the challenge id to reconcile) and the wording.
//
// Each case is run twice — plainly, and with a guarded signal in flight — because the signal is
// what used to route it into "cancelled: nothing was minted", the sentence that sends an
// operator away from a live key.
func TestSPMintKeyTreatsAConsumedChallengeAsAKeyThatMayExist(t *testing.T) {
	const said = "THE MINT PLANE SAYS THAT CHALLENGE WAS ALREADY REDEEMED"
	for _, tc := range []struct {
		name    string
		status  int
		body    map[string]any
		noBody  bool
		want    []string
		unwant  []string
		exiting string
	}{
		{
			name: "409 already_consumed", status: http.StatusConflict,
			body:    map[string]any{"error": "already_consumed"},
			want:    []string{said},
			exiting: "already redeemed and this CLI captured no credential",
		},
		{
			name: "a 409 whose code this client does not know", status: http.StatusConflict,
			body:    map[string]any{"error": "wat"},
			want:    []string{"THE MINT PLANE ANSWERED 409 WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE"},
			unwant:  []string{said},
			exiting: "the mint plane answered 409 for challenge chal_1 without saying what it did with it",
		},
		{
			name: "a bare 409 with no body at all", status: http.StatusConflict, noBody: true,
			want:    []string{"THE MINT PLANE ANSWERED 409 WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE"},
			unwant:  []string{said},
			exiting: "the mint plane answered 409 for challenge chal_1 without saying what it did with it",
		},
		{
			name: "a bare 410 with no body at all", status: http.StatusGone, noBody: true,
			want:    []string{"THE MINT PLANE ANSWERED 410 WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE"},
			unwant:  []string{said},
			exiting: "the mint plane answered 410 for challenge chal_1 without saying what it did with it",
		},
		{
			name: "410 gone", status: http.StatusGone, body: map[string]any{},
			want:    []string{"THE MINT PLANE ANSWERED 410 WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE"},
			unwant:  []string{said},
			exiting: "the mint plane answered 410 for challenge chal_1 without saying what it did with it",
		},
		{
			name: "410 with a code this client does not know", status: http.StatusGone,
			body:    map[string]any{"error": "teapot"},
			want:    []string{"THE MINT PLANE ANSWERED 410 WITHOUT SAYING WHAT IT DID WITH THAT CHALLENGE"},
			unwant:  []string{said},
			exiting: "the mint plane answered 410 for challenge chal_1 without saying what it did with it",
		},
	} {
		for _, interrupted := range []bool{false, true} {
			name := tc.name
			if interrupted {
				name += ", with a signal in flight"
			}
			t.Run(name, func(t *testing.T) {
				srv, _ := mintSeed(t)
				virtualClock(t)
				mintedDir := filepath.Join(t.TempDir(), "minted-keys")
				t.Setenv(store.MintedKeyDirEnv, mintedDir)
				out := filepath.Join(t.TempDir(), "sp.env")
				raise := raiseGuardedSignal(t)
				srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
					if interrupted {
						// The operator hits Ctrl-C while the redeem is on the wire; the guard is
						// up, so the signal is deferred until the answer has been dealt with.
						raise()
						time.Sleep(100 * time.Millisecond)
					}
					if tc.noBody {
						w.WriteHeader(tc.status)
						return
					}
					writeJSON(w, tc.status, tc.body)
				}

				stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
				t.Logf("exit=%d\n%s", code, strings.TrimSpace(stderr))
				if code == 0 {
					t.Fatal("exit 0 for a redeem whose outcome may be a live key")
				}
				if strings.Contains(stdout, "Minted a service-principal key") {
					t.Fatalf("the success banner was printed:\n%s", stdout)
				}
				if strings.Contains(stderr, "nothing was minted") {
					t.Fatalf("THE CLI CLAIMED NOTHING WAS MINTED over an answer that leaves a live "+
						"key possible:\n%s", stderr)
				}
				want := append([]string{
					"A CREDENTIAL MAY HAVE BEEN ISSUED",
					"challenge:  chal_1",
					"Reconcile challenge chal_1",
					tc.exiting,
				}, tc.want...)
				for _, w := range want {
					if !strings.Contains(stderr, w) {
						t.Errorf("the report is missing %q:\n%s", w, stderr)
					}
				}
				for _, w := range tc.unwant {
					if strings.Contains(stderr, w) {
						t.Errorf("the report puts %q in the server's mouth for a %d it did not say "+
							"it with:\n%s", w, tc.status, stderr)
					}
				}
			})
		}
	}
}
