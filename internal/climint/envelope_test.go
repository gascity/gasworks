package climint

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Leg C's 201 carries a secret the server will never reveal again, and by the time it arrives
// the challenge is already consumed. So NO other field may be able to fail the decode: an
// expires_at that arrives as an epoch number, a scopes that arrives as one space-delimited
// string, a key_id that arrives as a number are all read for what they are worth, and the
// secret comes back either way.
func TestCompleteChallengeKeepsTheSecretWhateverTheOtherFieldsAre(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       map[string]any
		wantKeyID  string
		wantExpiry string
		wantScopes []string
	}{
		{
			name: "the shapes the server documents",
			body: map[string]any{
				"key_id": "spk_1", "secret": "gck_sp_shhh", "prefix": "gck_sp", "org_id": "org_1",
				"scopes": []string{"forge:city.create"}, "expires_at": "2026-09-10T00:00:00Z",
			},
			wantKeyID: "spk_1", wantExpiry: "2026-09-10T00:00:00Z",
			wantScopes: []string{"forge:city.create"},
		},
		{
			name: "expires_at as an epoch number",
			body: map[string]any{
				"key_id": "spk_1", "secret": "gck_sp_shhh", "scopes": []string{"forge:city.create"},
				"expires_at": 1789000000,
			},
			wantKeyID: "spk_1", wantExpiry: "1789000000",
			wantScopes: []string{"forge:city.create"},
		},
		{
			name: "scopes as a space-delimited string",
			body: map[string]any{
				"key_id": "spk_1", "secret": "gck_sp_shhh",
				"scopes": "forge:city.create forge:city.delete", "expires_at": "2026-09-10T00:00:00Z",
			},
			wantKeyID: "spk_1", wantExpiry: "2026-09-10T00:00:00Z",
			wantScopes: []string{"forge:city.create", "forge:city.delete"},
		},
		{
			name: "key_id as a number",
			body: map[string]any{
				"key_id": 1, "secret": "gck_sp_shhh", "scopes": []string{"forge:city.create"},
			},
			wantKeyID: "1", wantScopes: []string{"forge:city.create"},
		},
		{
			name: "key_id as an object and scopes as a number",
			body: map[string]any{
				"key_id": map[string]any{"id": "spk_1"}, "secret": "gck_sp_shhh", "scopes": 7,
			},
		},
		{
			name: "nothing but the secret",
			body: map[string]any{"secret": "gck_sp_shhh"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
				writeJSON(t, w, http.StatusCreated, tc.body)
			})

			got, err := redeem(client, cfg, testToken, newKey(t), "chal_01")
			if err != nil {
				t.Fatalf("CompleteChallenge: %v — the secret was in this process's memory and a "+
					"field that is not the secret threw it away", err)
			}
			if got.Secret != "gck_sp_shhh" {
				t.Fatalf("secret = %q, want the revealed one", got.Secret)
			}
			t.Logf("credential = %+v", got)
			if got.KeyID != tc.wantKeyID {
				t.Errorf("key id = %q, want %q", got.KeyID, tc.wantKeyID)
			}
			if got.ExpiresAt != tc.wantExpiry {
				t.Errorf("expires_at = %q, want %q", got.ExpiresAt, tc.wantExpiry)
			}
			if strings.Join(got.Scopes, " ") != strings.Join(tc.wantScopes, " ") {
				t.Errorf("scopes = %v, want %v", got.Scopes, tc.wantScopes)
			}
		})
	}
}

// The one thing that IS a failure: a 201 with no secret in it. There is nothing to protect, so
// the caller has to be able to tell that apart from a credential.
func TestCompleteChallengeReportsAnAbsentSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"no secret field", map[string]any{"key_id": "spk_1"}},
		{"an empty secret", map[string]any{"key_id": "spk_1", "secret": ""}},
		{"a null secret", map[string]any{"key_id": "spk_1", "secret": nil}},
		{"an object where the secret should be", map[string]any{"secret": map[string]any{"value": "x"}}},
		{"a body that is not an object", []any{map[string]any{"secret": "gck_sp_shhh"}}},
		{"an empty body", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
				writeJSON(t, w, http.StatusCreated, tc.body)
			})

			got, err := redeem(client, cfg, testToken, newKey(t), "chal_01")
			if err != nil {
				t.Fatalf("CompleteChallenge: %v", err)
			}
			if got.Secret != "" {
				t.Fatalf("secret = %q, want empty so the caller can say the mint plane sent none", got.Secret)
			}
		})
	}
}

// The approval window is turned into an int64 deadline by the caller, so it is clamped where it
// is read: an unclamped 1e19 seconds converts to the most negative int there is.
func TestCreateChallengeClampsTheApprovalWindow(t *testing.T) {
	for _, tc := range []struct {
		raw  any
		want int
	}{
		{180, 180},
		{"180", 180},
		{0, 0},
		{-5, 0},
		{0.5, 0},
		{"not a number", 0},
		{nil, 0},
		{map[string]any{}, 0},
		{MaxChallengeTTLSecs, MaxChallengeTTLSecs},
		{MaxChallengeTTLSecs + 1, MaxChallengeTTLSecs},
		{100000, MaxChallengeTTLSecs},
		{9223372036854774784.0, MaxChallengeTTLSecs},
		{1e19, MaxChallengeTTLSecs},
		{1e300, MaxChallengeTTLSecs},
	} {
		cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
			writeJSON(t, w, http.StatusCreated, map[string]any{
				"challenge_id": "chal_01", "confirm_code": "WXYZ-4242",
				"approve_url": "https://auth.gascity.com/cli/approve?c=chal_01",
				"expires_in":  tc.raw,
			})
		})
		got, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1"})
		if err != nil {
			t.Fatalf("expires_in %#v: CreateChallenge: %v", tc.raw, err)
		}
		t.Logf("server expires_in %#v  ->  window %ds", tc.raw, got.ExpiresIn)
		if got.ExpiresIn != tc.want {
			t.Errorf("expires_in %#v decoded to %d, want %d", tc.raw, got.ExpiresIn, tc.want)
		}
		if got.ChallengeID != "chal_01" || got.ConfirmCode != "WXYZ-4242" {
			t.Errorf("expires_in %#v also cost the challenge: %+v", tc.raw, got)
		}
	}
}

// The deadline the CLI computes from that window must stay in the future, which is what
// clamping before the conversion buys.
func TestClampedWindowCannotWrapAnInt64Deadline(t *testing.T) {
	now := time.Now().Unix()
	for _, raw := range []any{1e19, 9223372036854774784.0, 1e300, float64(MaxChallengeTTLSecs + 1)} {
		window := seconds(raw)
		if deadline := now + int64(window); deadline < now {
			t.Fatalf("expires_in %#v -> window %d -> deadline %d, which is BEFORE now (%d)",
				raw, window, deadline, now)
		}
	}
}
