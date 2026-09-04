package climint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
)

const testToken = "gcs_user_abc123"

// capture is what the stub server saw on one request.
type capture struct {
	URL    string
	Method string
	Auth   string
	Body   string
	Header map[string]any // the DPoP proof's JWS header
	Claims map[string]any // the DPoP proof's claims
}

// mintStub starts a TLS httptest server whose origin is canonical enough for config to accept
// (https, lowercase host, non-443 port, bare origin), points the package's mint client at its
// CA, and records every request. handler writes the response for call n (0-based).
func mintStub(t *testing.T, handler func(w http.ResponseWriter, n int)) (config.Config, *Client, *[]capture) {
	t.Helper()
	var seen []capture
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		hdr, claims := decodeProof(t, r.Header.Get("DPoP"))
		seen = append(seen, capture{
			// Reconstruct the absolute URL the client asked for; httptest strips it to a path.
			URL:    "https://" + r.Host + r.URL.Path,
			Method: r.Method,
			Auth:   r.Header.Get("Authorization"),
			Body:   string(body),
			Header: hdr,
			Claims: claims,
		})
		handler(w, len(seen)-1)
	}))
	t.Cleanup(srv.Close)

	// The stub's cert is self-signed, so the ceremony client must trust its CA. Keepalives and
	// transport decompression stay off as they are in production, and the redirect refusal and
	// timeout are the ones production runs with.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	tr.DisableCompression = true
	production := New().HTTP
	client := &Client{HTTP: &http.Client{
		Transport:     tr,
		CheckRedirect: production.CheckRedirect,
		Timeout:       production.Timeout,
	}}

	return config.Config{ClimintBase: srv.URL}, client, &seen
}

func decodeProof(t *testing.T, proof string) (header, claims map[string]any) {
	t.Helper()
	if proof == "" {
		t.Fatal("request carried no DPoP proof")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("DPoP proof is not a 3-part JWS: %q", proof)
	}
	return decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode proof segment: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal proof segment: %v", err)
	}
	return m
}

// redeem drives leg C the way the ceremony does, minus the BodySink, and hands back the part of
// the answer most of these tests are about: what the client made of the response. Where the
// bytes are PUT is cmd/gasworks's half, and the tests that care about it call CompleteChallenge
// directly for the whole Redemption.
func redeem(client *Client, cfg config.Config, token string, key *dpop.Key, challengeID string) (Credential, error) {
	got, err := client.CompleteChallenge(context.Background(), cfg, token, key, challengeID, nil)
	return got.Credential, err
}

func newKey(t *testing.T) *dpop.Key {
	t.Helper()
	k, err := dpop.NewKey()
	if err != nil {
		t.Fatalf("dpop.NewKey: %v", err)
	}
	return k
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("write stub response: %v", err)
	}
}

func TestCreateChallengeDecodes201(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusCreated, map[string]any{
			"challenge_id": "chal_01",
			"confirm_code": "WXYZ-4242",
			"approve_url":  "https://auth.gascity.com/cli/approve?c=chal_01",
			"expires_in":   180,
		})
	})

	got, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{
		OrgID: "org_1", SPID: "sp_1", Product: "forge",
		Scopes: []string{"forge:city.create", "forge:city.delete"}, ExpiresInDays: 1,
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	want := Challenge{ChallengeID: "chal_01", ConfirmCode: "WXYZ-4242", ApproveURL: "https://auth.gascity.com/cli/approve?c=chal_01", ExpiresIn: 180}
	if got != want {
		t.Errorf("challenge = %+v, want %+v", got, want)
	}
	if n := len(*seen); n != 1 {
		t.Fatalf("server saw %d requests, want 1", n)
	}
	if body := (*seen)[0].Body; !strings.Contains(body, `"org_id":"org_1"`) || strings.Contains(body, "resource_refs") {
		t.Errorf("leg A body = %s, want org_id present and resource_refs absent", body)
	}
}

func TestCompleteChallengeDecodes201(t *testing.T) {
	cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusCreated, map[string]any{
			"key_id":     "key_9",
			"secret":     "gck_live_shhh",
			"prefix":     "gck_live",
			"org_id":     "org_1",
			"scopes":     []string{"forge:city.create", "forge:city.delete"},
			"expires_at": "2026-09-10T00:00:00Z",
		})
	})

	got, err := redeem(client, cfg, testToken, newKey(t), "chal_01")
	if err != nil {
		t.Fatalf("CompleteChallenge: %v", err)
	}
	if got.KeyID != "key_9" || got.Secret != "gck_live_shhh" || got.Prefix != "gck_live" ||
		got.OrgID != "org_1" || got.ExpiresAt != "2026-09-10T00:00:00Z" {
		t.Errorf("credential = %+v, want the stub's fields", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "forge:city.create" {
		t.Errorf("credential scopes = %v", got.Scopes)
	}
}

// The server compares htu byte for byte. Leg C's URL carries the challenge id, so a proof
// minted for leg A's URL cannot be reused: assert each leg signed the URL it actually called.
func TestProofHTUMatchesTheRequestURLIncludingTheChallengeID(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, n int) {
		if n == 0 {
			writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
			return
		}
		writeJSON(t, w, http.StatusCreated, map[string]any{"key_id": "key_9"})
	})
	key := newKey(t)

	if _, err := client.CreateChallenge(cfg, testToken, key, ChallengeRequest{OrgID: "org_1"}); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if _, err := redeem(client, cfg, testToken, key, "chal_01"); err != nil {
		t.Fatalf("CompleteChallenge: %v", err)
	}

	if n := len(*seen); n != 2 {
		t.Fatalf("server saw %d requests, want 2", n)
	}
	for i, c := range *seen {
		if htu, _ := c.Claims["htu"].(string); htu != c.URL {
			t.Errorf("call %d: htu = %q, want the request URL %q", i, htu, c.URL)
		}
	}
	legC := (*seen)[1]
	if !strings.HasSuffix(legC.URL, "/v0/cli/mint/challenges/chal_01/complete") {
		t.Fatalf("leg C URL = %q, want the challenge id in the path", legC.URL)
	}
	if (*seen)[0].Claims["htu"] == legC.Claims["htu"] {
		t.Error("leg C reused leg A's htu; the proof must be minted over leg C's own URL")
	}
}

func TestProofBindsTheSessionTokenAndMethod(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
	})

	if _, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1"}); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	c := (*seen)[0]

	sum := sha256.Sum256([]byte(testToken))
	wantATH := base64.RawURLEncoding.EncodeToString(sum[:])
	ath, _ := c.Claims["ath"].(string)
	if ath != wantATH {
		t.Errorf("ath = %q, want base64url(SHA-256(token)) = %q", ath, wantATH)
	}
	// Asserted on the ath the proof actually carried, not on the value this test computed:
	// padding or a standard-base64 character is exactly what a `+`/`/`/`=` alphabet slip
	// would produce, and the server decodes ath as unpadded base64url.
	if strings.ContainsAny(ath, "=+/") {
		t.Errorf("ath = %q, want unpadded base64url (no '=', '+' or '/')", ath)
	}
	if htm, _ := c.Claims["htm"].(string); htm != http.MethodPost {
		t.Errorf("htm = %q, want %q", htm, http.MethodPost)
	}
	if c.Auth != "Bearer "+testToken {
		t.Errorf("Authorization = %q, want the session token as a Bearer", c.Auth)
	}
	if typ, _ := c.Header["typ"].(string); typ != "dpop+jwt" {
		t.Errorf("proof typ = %q, want dpop+jwt", typ)
	}
	if alg, _ := c.Header["alg"].(string); alg != "ES256" {
		t.Errorf("proof alg = %q, want ES256", alg)
	}
	if _, ok := c.Header["jwk"]; !ok {
		t.Error("proof header carries no jwk")
	}
	for _, forbidden := range []string{"jku", "x5u"} {
		if _, ok := c.Header[forbidden]; ok {
			t.Errorf("proof header carries %s, which the server forbids", forbidden)
		}
	}
	if iat, _ := c.Claims["iat"].(float64); iat == 0 {
		t.Error("proof carries no iat")
	}
}

// The jti ledger is single-use and fails closed, so no two calls may present the same one.
func TestEachCallMintsAFreshJTI(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
	})
	key := newKey(t)

	for i := range 2 {
		if _, err := client.CreateChallenge(cfg, testToken, key, ChallengeRequest{OrgID: "org_1"}); err != nil {
			t.Fatalf("CreateChallenge %d: %v", i, err)
		}
	}
	if _, err := redeem(client, cfg, testToken, key, "chal_01"); err != nil {
		t.Fatalf("CompleteChallenge: %v", err)
	}

	ids := map[string]bool{}
	for i, c := range *seen {
		jti, _ := c.Claims["jti"].(string)
		if jti == "" {
			t.Fatalf("call %d carried no jti", i)
		}
		if ids[jti] {
			t.Fatalf("call %d reused jti %q", i, jti)
		}
		ids[jti] = true
	}
	if len(ids) != 3 {
		t.Fatalf("saw %d distinct jtis across 3 calls", len(ids))
	}
}

// 425 is climint's pending answer. It is NOT RFC 8628 (no 400 with a bare `error`), so a
// device-flow poller would read it as a hard failure.
func TestCompleteChallengeMapsPending(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     map[string]any
		wantStat string
		wantSecs int
	}{
		{"authorization_pending", map[string]any{"status": "authorization_pending", "interval": 5}, "authorization_pending", 5},
		{"slow_down", map[string]any{"status": "slow_down", "interval": 10}, "slow_down", 10},
		{"interval omitted", map[string]any{"status": "authorization_pending"}, "authorization_pending", defaultPendingInterval},
		{"interval zero", map[string]any{"status": "authorization_pending", "interval": 0}, "authorization_pending", defaultPendingInterval},
		{"interval absurd", map[string]any{"status": "slow_down", "interval": 86400}, "slow_down", maxPendingInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
				writeJSON(t, w, http.StatusTooEarly, tc.body)
			})

			_, err := redeem(client, cfg, testToken, newKey(t), "chal_01")
			var pending *PendingError
			if !errors.As(err, &pending) {
				t.Fatalf("err = %v (%T), want *PendingError", err, err)
			}
			if pending.Status != tc.wantStat {
				t.Errorf("pending status = %q, want %q", pending.Status, tc.wantStat)
			}
			if pending.Interval != tc.wantSecs {
				t.Errorf("pending interval = %d, want %d", pending.Interval, tc.wantSecs)
			}
			var terminal *TerminalError
			if errors.As(err, &terminal) {
				t.Error("a pending poll must not classify as terminal")
			}
		})
	}
}

func TestCompleteChallengeMapsTerminal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   map[string]any
		code   string
	}{
		{"denied", http.StatusConflict, map[string]any{"error": "denied"}, "denied"},
		{"expired", http.StatusConflict, map[string]any{"error": "expired"}, "expired"},
		{"forbidden", http.StatusForbidden, map[string]any{"error": "forbidden"}, "forbidden"},
		{"unavailable", http.StatusServiceUnavailable, map[string]any{"error": "mint_unavailable"}, "mint_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
				writeJSON(t, w, tc.status, tc.body)
			})

			_, err := redeem(client, cfg, testToken, newKey(t), "chal_01")
			var terminal *TerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("err = %v (%T), want *TerminalError", err, err)
			}
			if terminal.Status != tc.status {
				t.Errorf("terminal status = %d, want %d", terminal.Status, tc.status)
			}
			if terminal.Code != tc.code {
				t.Errorf("terminal code = %q, want %q", terminal.Code, tc.code)
			}
			if !strings.Contains(err.Error(), tc.code) {
				t.Errorf("error text %q does not carry the server's message", err)
			}
			var pending *PendingError
			if errors.As(err, &pending) {
				t.Error("a terminal failure must not classify as pending")
			}
		})
	}
}

func TestCreateChallengeMapsTerminal(t *testing.T) {
	cfg, client, _ := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusBadRequest, map[string]any{"error": "ttl_exceeds_max"})
	})

	_, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1", ExpiresInDays: 999})
	var terminal *TerminalError
	if !errors.As(err, &terminal) {
		t.Fatalf("err = %v (%T), want *TerminalError", err, err)
	}
	if terminal.Status != http.StatusBadRequest || terminal.Code != "ttl_exceeds_max" {
		t.Errorf("terminal = %+v, want 400 ttl_exceeds_max", terminal)
	}
	if !strings.Contains(err.Error(), "ttl_exceeds_max") {
		t.Errorf("error text %q must surface the server's cap message verbatim", err)
	}
}

// resource_refs OMITTED tells the server to auto-fold the SP's workspace grant; a null does
// not. Neither an unset field nor an explicit JSON null may reach the wire as null.
func TestResourceRefsOmissionIsPreserved(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs json.RawMessage
		want string
	}{
		{"unset", nil, ""},
		{"explicit null", json.RawMessage(`null`), ""},
		{"padded null", json.RawMessage(" null\n"), ""},
		{"present", json.RawMessage(`[{"kind":"workspace","id":"ws_1"}]`), `"resource_refs":[{"kind":"workspace","id":"ws_1"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
				writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
			})

			if _, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1", ResourceRefs: tc.refs}); err != nil {
				t.Fatalf("CreateChallenge: %v", err)
			}
			body := (*seen)[0].Body
			if strings.Contains(body, `"resource_refs":null`) {
				t.Fatalf("body sent an explicit null: %s", body)
			}
			if tc.want == "" {
				if strings.Contains(body, "resource_refs") {
					t.Errorf("body = %s, want resource_refs absent", body)
				}
				return
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("body = %s, want it to contain %s", body, tc.want)
			}
		})
	}
}

// A token the edge is certain to reject must not cost a jti.
func TestNonUserSessionTokenIsRejectedBeforeTheRequest(t *testing.T) {
	for _, tok := range []string{"", "gcs_svc_abc", "gcs_delegated_abc"} {
		cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
			t.Error("a rejected session token still reached the server")
			writeJSON(t, w, http.StatusCreated, map[string]any{})
		})

		if _, err := client.CreateChallenge(cfg, tok, newKey(t), ChallengeRequest{OrgID: "org_1"}); err == nil {
			t.Errorf("CreateChallenge with token %q = nil error, want a refusal", tok)
		}
		if _, err := redeem(client, cfg, tok, newKey(t), "chal_01"); err == nil {
			t.Errorf("CompleteChallenge with token %q = nil error, want a refusal", tok)
		}
		if n := len(*seen); n != 0 {
			t.Errorf("token %q: server saw %d requests, want 0", tok, n)
		}
	}
}

func TestNonCanonicalBaseFailsBeforeAProofIsSigned(t *testing.T) {
	cfg := config.Config{ClimintBase: "http://auth.gascity.com"}
	client := New()

	if _, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1"}); err == nil {
		t.Error("CreateChallenge accepted a non-https climint base")
	} else if !strings.Contains(err.Error(), config.ClimintBaseEnv) {
		t.Errorf("error %q does not name the override that fixes it", err)
	}
	if _, err := redeem(client, cfg, testToken, newKey(t), "chal_01"); err == nil {
		t.Error("CompleteChallenge accepted a non-https climint base")
	}
}

func TestCompleteChallengeRejectsAnUnsafeChallengeID(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		t.Error("an unsafe challenge id reached the server")
		writeJSON(t, w, http.StatusCreated, map[string]any{})
	})

	for _, id := range []string{"", "chal/../other", "chal 01", "chal%2f01", "chal?a=b"} {
		if _, err := redeem(client, cfg, testToken, newKey(t), id); err == nil {
			t.Errorf("CompleteChallenge(%q) = nil error, want a refusal", id)
		}
	}
	if n := len(*seen); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

func TestMissingKeyIsRefused(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		t.Error("a keyless request reached the server")
		writeJSON(t, w, http.StatusCreated, map[string]any{})
	})

	if _, err := client.CreateChallenge(cfg, testToken, nil, ChallengeRequest{OrgID: "org_1"}); err == nil {
		t.Error("CreateChallenge accepted a nil key")
	}
	if n := len(*seen); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

// The two legs are JKT-pinned to one session key, so the same key must sign both.
func TestBothLegsSignWithTheKeyTheyAreGiven(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, n int) {
		if n == 0 {
			writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
			return
		}
		writeJSON(t, w, http.StatusCreated, map[string]any{"key_id": "key_9"})
	})
	key := newKey(t)

	if _, err := client.CreateChallenge(cfg, testToken, key, ChallengeRequest{OrgID: "org_1"}); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if _, err := redeem(client, cfg, testToken, key, "chal_01"); err != nil {
		t.Fatalf("CompleteChallenge: %v", err)
	}

	want := key.PublicJWK()
	for i, c := range *seen {
		jwk, ok := c.Header["jwk"].(map[string]any)
		if !ok {
			t.Fatalf("call %d: proof header jwk is not an object", i)
		}
		for k, v := range want {
			if got, _ := jwk[k].(string); got != v {
				t.Errorf("call %d: jwk[%q] = %q, want %q (both legs must present one key)", i, k, got, v)
			}
		}
		if _, leaked := jwk["d"]; leaked {
			t.Fatalf("call %d: proof header leaked the private key", i)
		}
	}
}

func TestErrorTextsAreReadable(t *testing.T) {
	pending := &PendingError{Status: "slow_down", Interval: 10}
	if got, want := pending.Error(), "climint: slow_down (retry in 10s)"; got != want {
		t.Errorf("PendingError.Error() = %q, want %q", got, want)
	}
	terminal := &TerminalError{Status: http.StatusConflict, Code: "denied"}
	if got, want := terminal.Error(), "climint: 409 denied"; got != want {
		t.Errorf("TerminalError.Error() = %q, want %q", got, want)
	}
	bare := &TerminalError{Status: http.StatusBadGateway}
	if got := bare.Error(); !strings.Contains(got, "502") {
		t.Errorf("TerminalError.Error() without a body = %q, want the status", got)
	}
}

// Sanity check on the fixture itself: the URL the stub reconstructs is the one the client
// asked for, so the htu assertions above compare against something real.
func TestStubReconstructsTheRequestedURL(t *testing.T) {
	cfg, client, seen := mintStub(t, func(w http.ResponseWriter, _ int) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"challenge_id": "chal_01"})
	})

	if _, err := client.CreateChallenge(cfg, testToken, newKey(t), ChallengeRequest{OrgID: "org_1"}); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	want, err := cfg.MintChallengesURL()
	if err != nil {
		t.Fatalf("MintChallengesURL: %v", err)
	}
	if got := (*seen)[0].URL; got != want {
		t.Fatalf("stub saw %q, client asked for %q", got, want)
	}
	if !strings.HasPrefix(want, "https://127.0.0.1:") {
		t.Fatalf("fixture origin %q is not the https origin config validates", want)
	}
}
