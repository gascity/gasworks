package climint

import (
	"context"
	"net/http"
	"testing"

	"github.com/gascity/gasworks/internal/config"
)

// Two things about leg C's answer that the caller cannot work out for itself, and that decide
// whether it may tell an operator nothing was minted: whether the request left this machine, and
// whether a refusal is really a refusal.

// A redeem that never reached a socket minted nothing, and one that did may have minted
// everything. From the error alone the two are the same sentence.
func TestRedemptionReportsWhetherTheRequestWasSent(t *testing.T) {
	cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
	})
	got, err := client.CompleteChallenge(context.Background(), cfg, testToken, newKey(t), "chal_01", nil)
	if err == nil {
		t.Fatal("CompleteChallenge = nil error for a 503")
	}
	if !got.Sent {
		t.Error("a redeem the server answered is reported as never sent")
	}
	if got.ChallengeID != "chal_01" {
		t.Errorf("ChallengeID = %q, want the challenge the redeem was for", got.ChallengeID)
	}

	// The same call against an origin nothing is listening on. The connection is never made, so
	// no request bytes exist and the challenge is untouched.
	dead := config.Config{ClimintBase: "https://127.0.0.1:1"}
	got, err = client.CompleteChallenge(context.Background(), dead, testToken, newKey(t), "chal_01", nil)
	if err == nil {
		t.Fatal("CompleteChallenge = nil error against a closed port")
	}
	if got.Sent {
		t.Errorf("a redeem that could not be dialled is reported as sent: %v", err)
	}
	if got.ChallengeID != "chal_01" {
		t.Errorf("ChallengeID = %q on the un-sent redeem", got.ChallengeID)
	}
}

// `already_consumed` is the server saying the challenge WAS redeemed, which for a challenge this
// client redeems once means a key exists. Every other 4xx is a refusal, and a 409 or 410 whose
// code this client does not recognise is read the careful way round.
func TestTerminalErrorSeparatesARefusalFromAConsumedChallenge(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		want   bool
	}{
		{http.StatusConflict, "already_consumed", true},
		{http.StatusConflict, "ALREADY_CONSUMED", true},
		{http.StatusConflict, "already_redeemed", true},
		{http.StatusConflict, "", true},
		{http.StatusConflict, "surprise", true},
		{http.StatusGone, "", true},
		{http.StatusBadRequest, "already_consumed", true},
		{http.StatusConflict, "expired", false},
		{http.StatusConflict, "denied", false},
		{http.StatusGone, "expired", false},
		{http.StatusForbidden, "denied", false},
		{http.StatusUnauthorized, "invalid_session", false},
		{http.StatusBadRequest, "invalid_request", false},
	} {
		err := &TerminalError{Status: tc.status, Code: tc.code}
		if got := err.MayHaveMinted(); got != tc.want {
			t.Errorf("%d %q: MayHaveMinted() = %v, want %v", tc.status, tc.code, got, tc.want)
		}
	}
}
