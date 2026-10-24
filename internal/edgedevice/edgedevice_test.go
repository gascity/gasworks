package edgedevice

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
)

const testRoot = "gcs_cli_aaaabbbbccccddddeeeeffffgggghhhh"

type edgeRequest struct {
	method string
	path   string
	body   string
	auth   string
	dpop   string
	ctype  string
}

// stubEdge is a cli-edge device plane on its own https origin. tokenAnswers is consumed one
// per poll; the last answer repeats.
type stubEdge struct {
	t            *testing.T
	srv          *httptest.Server
	mu           sync.Mutex
	requests     []edgeRequest
	issueStatus  int
	issueBody    map[string]any
	tokenAnswers []func(w http.ResponseWriter)
}

func newStubEdge(t *testing.T) *stubEdge {
	t.Helper()
	s := &stubEdge{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/gc/v0/auth/device/code", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if s.issueStatus != 0 {
			writeJSON(w, s.issueStatus, map[string]any{"error": map[string]any{"code": "nope", "message": "no"}})
			return
		}
		body := s.issueBody
		if body == nil {
			body = map[string]any{
				"device_code": "gcd_" + strings.Repeat("A", 43), "user_code": "BDWK-JQPX",
				"verification_uri":          s.srv.URL + "/gc/v0/device",
				"verification_uri_complete": s.srv.URL + "/gc/v0/device?code=BDWK-JQPX",
				"expires_in":                600, "interval": 5,
			}
		}
		writeJSON(w, http.StatusOK, body)
	})
	mux.HandleFunc("/gc/v0/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		s.mu.Lock()
		polls := 0
		for _, req := range s.requests {
			if req.path == "/gc/v0/auth/device/token" {
				polls++
			}
		}
		answers := s.tokenAnswers
		s.mu.Unlock()
		if len(answers) == 0 {
			ok(w)
			return
		}
		index := polls - 1
		if index >= len(answers) {
			index = len(answers) - 1
		}
		answers[index](w)
	})
	mux.HandleFunc("/gc/v0/session", func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.WriteHeader(http.StatusNoContent)
	})
	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubEdge) record(r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, edgeRequest{
		method: r.Method, path: r.URL.Path, body: string(raw),
		auth: r.Header.Get("Authorization"), dpop: r.Header.Get("DPoP"), ctype: r.Header.Get("Content-Type"),
	})
}

func (s *stubEdge) reqs(path string) []edgeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []edgeRequest
	for _, r := range s.requests {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func (s *stubEdge) cfg() config.Config { return config.Config{CLIEdgeBase: s.srv.URL} }

// clock is a fake Now/Sleep pair: sleeping advances time and is recorded.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
}

func (s *stubEdge) client() (*Client, *clock) {
	clk := &clock{now: time.Unix(1_800_000_000, 0)}
	return &Client{HTTP: s.srv.Client(), Sleep: clk.Sleep, Now: clk.Now}, clk
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func ok(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"access_token": testRoot, "token_type": "DPoP"})
}

func deviceError(code string, interval int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		body := map[string]any{"error": code}
		if interval > 0 {
			body["interval"] = interval
		}
		writeJSON(w, http.StatusBadRequest, body)
	}
}

func proofParts(t *testing.T, proof string) (map[string]any, map[string]any) {
	t.Helper()
	segments := strings.Split(proof, ".")
	if len(segments) != 3 {
		t.Fatalf("proof %q is not a compact JWS", proof)
	}
	decode := func(segment string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}
	return decode(segments[0]), decode(segments[1])
}

func newKey(t *testing.T) *dpop.Key {
	t.Helper()
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDeviceFlowRedeemsADPoPBoundRootWithAFreshProofPerPoll(t *testing.T) {
	edge := newStubEdge(t)
	edge.tokenAnswers = []func(http.ResponseWriter){
		deviceError("authorization_pending", 5), deviceError("authorization_pending", 5), ok,
	}
	client, clk := edge.client()
	key := newKey(t)

	auth, err := client.Issue(edge.cfg(), "dev@laptop")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if auth.UserCode != "BDWK-JQPX" || auth.VerificationURIComplete != edge.srv.URL+"/gc/v0/device?code=BDWK-JQPX" ||
		auth.Interval != 5*time.Second || auth.ExpiresIn != 600*time.Second {
		t.Fatalf("authorization = %+v", auth)
	}
	issue := edge.reqs("/gc/v0/auth/device/code")
	if len(issue) != 1 || issue[0].dpop != "" || issue[0].body != `{"label":"dev@laptop"}` ||
		!strings.HasPrefix(issue[0].ctype, "application/json") {
		t.Fatalf("issue request = %+v", issue)
	}

	root, err := client.Await(edge.cfg(), auth, key)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if root.Token != testRoot || root.TokenType != TokenTypeDPoP {
		t.Fatalf("root = %+v", root)
	}
	polls := edge.reqs("/gc/v0/auth/device/token")
	if len(polls) != 3 {
		t.Fatalf("polls = %d, want 3", len(polls))
	}
	seen := map[string]bool{}
	for i, poll := range polls {
		if poll.body != `{"device_code":"gcd_`+strings.Repeat("A", 43)+`"}` || poll.auth != "" {
			t.Fatalf("poll %d = %+v", i, poll)
		}
		header, claims := proofParts(t, poll.dpop)
		if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" {
			t.Fatalf("poll %d header = %v", i, header)
		}
		jwk, _ := header["jwk"].(map[string]any)
		if jwk["x"] != key.PublicJWK()["x"] || jwk["y"] != key.PublicJWK()["y"] || jwk["d"] != nil {
			t.Fatalf("poll %d is not signed by the flow's one key: %v", i, jwk)
		}
		if claims["htm"] != "POST" || claims["htu"] != edge.srv.URL+"/gc/v0/auth/device/token" {
			t.Fatalf("poll %d htm/htu = %v %v", i, claims["htm"], claims["htu"])
		}
		if _, present := claims["ath"]; present {
			t.Fatalf("poll %d carries ath: %v", i, claims)
		}
		if _, present := claims["nonce"]; present {
			t.Fatalf("poll %d carries a nonce: %v", i, claims)
		}
		jti, _ := claims["jti"].(string)
		if jti == "" || seen[jti] {
			t.Fatalf("poll %d jti %q is empty or reused", i, jti)
		}
		seen[jti] = true
		if iat, _ := claims["iat"].(float64); iat == 0 || time.Since(time.Unix(int64(iat), 0)).Abs() > time.Minute {
			t.Fatalf("poll %d iat = %v", i, claims["iat"])
		}
	}
	if len(clk.sleeps) != 3 || clk.sleeps[0] != 5*time.Second || clk.sleeps[2] != 5*time.Second {
		t.Fatalf("sleeps = %v, want the server interval before every poll", clk.sleeps)
	}
	if len(edge.reqs("/gc/v0/session")) != 0 {
		t.Fatal("a successful flow revoked its root")
	}
}

// slow_down adds the RFC 8628 step and honours a larger server interval; pending never shrinks
// the interval; nothing exceeds the 60s cap.
func TestPollIntervalFollowsPendingAndSlowDown(t *testing.T) {
	edge := newStubEdge(t)
	edge.tokenAnswers = []func(http.ResponseWriter){
		deviceError("slow_down", 0),             // 5 -> 10
		deviceError("authorization_pending", 2), // stays 10
		deviceError("slow_down", 30),            // max(15, 30) = 30
		deviceError("slow_down", 0),             // 35
		deviceError("authorization_pending", 600),
		ok,
	}
	client, clk := edge.client()
	auth, err := client.Issue(edge.cfg(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Await(edge.cfg(), auth, newKey(t)); err != nil {
		t.Fatalf("Await: %v", err)
	}
	want := []time.Duration{5, 10, 10, 30, 35, 60}
	if len(clk.sleeps) != len(want) {
		t.Fatalf("sleeps = %v", clk.sleeps)
	}
	for i := range want {
		if clk.sleeps[i] != want[i]*time.Second {
			t.Fatalf("sleeps = %v, want %v seconds", clk.sleeps, want)
		}
	}
}

func TestTerminalPollRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(http.ResponseWriter)
		kind   ErrorKind
	}{
		{"denied", deviceError("access_denied", 0), Denied},
		{"expired", deviceError("expired_token", 0), Expired},
		{"invalid proof", deviceError("invalid_dpop_proof", 0), InvalidProof},
		{"invalid request", deviceError("invalid_request", 0), InvalidRequest},
		{"dark", func(w http.ResponseWriter) { http.NotFound(w, nil) }, NotEnabled},
		{"unexpected status", func(w http.ResponseWriter) { writeJSON(w, http.StatusUnauthorized, map[string]any{}) }, Protocol},
		{"unusable token", func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "has space", "token_type": "DPoP"})
		}, Protocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edge := newStubEdge(t)
			edge.tokenAnswers = []func(http.ResponseWriter){tc.answer}
			client, _ := edge.client()
			auth, err := client.Issue(edge.cfg(), "x")
			if err != nil {
				t.Fatal(err)
			}
			root, err := client.Await(edge.cfg(), auth, newKey(t))
			if KindOf(err) != tc.kind || root.Token != "" {
				t.Fatalf("Await = %+v, %v; want kind %s", root, err, tc.kind)
			}
			if polls := len(edge.reqs("/gc/v0/auth/device/token")); polls != 1 {
				t.Fatalf("a terminal refusal was polled %d times", polls)
			}
		})
	}
}

// A redeem whose token_type is not DPoP is an unbound bearer root. It is refused, revoked at
// the cli-edge with a plain Bearer, and never handed back — not even inside the error.
func TestUnboundRootIsRefusedAndRevoked(t *testing.T) {
	for _, tokenType := range []string{"bearer", "Bearer", "", "N_A"} {
		t.Run(tokenType, func(t *testing.T) {
			edge := newStubEdge(t)
			edge.tokenAnswers = []func(http.ResponseWriter){func(w http.ResponseWriter) {
				writeJSON(w, http.StatusOK, map[string]any{"access_token": testRoot, "token_type": tokenType})
			}}
			client, _ := edge.client()
			auth, err := client.Issue(edge.cfg(), "x")
			if err != nil {
				t.Fatal(err)
			}
			root, err := client.Await(edge.cfg(), auth, newKey(t))
			if KindOf(err) != NotKeyBound || root.Token != "" {
				t.Fatalf("Await = %+v, %v", root, err)
			}
			if strings.Contains(err.Error(), testRoot) {
				t.Fatalf("the error carries the root: %v", err)
			}
			revokes := edge.reqs("/gc/v0/session")
			if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+testRoot || revokes[0].dpop != "" {
				t.Fatalf("revocations = %+v", revokes)
			}
		})
	}
}

// A poll that gets no answer is retried with the same key and a fresh proof: that is how a
// redeem whose response was lost is recovered. Three in a row end the flow.
func TestTransientPollFailuresRetryThenGiveUp(t *testing.T) {
	unavailable := func(w http.ResponseWriter) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": "temporarily_unavailable"}})
	}
	edge := newStubEdge(t)
	edge.tokenAnswers = []func(http.ResponseWriter){unavailable, unavailable, ok}
	client, _ := edge.client()
	auth, err := client.Issue(edge.cfg(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if root, err := client.Await(edge.cfg(), auth, newKey(t)); err != nil || root.Token != testRoot {
		t.Fatalf("Await after two transient failures = %+v, %v", root, err)
	}

	edge = newStubEdge(t)
	edge.tokenAnswers = []func(http.ResponseWriter){unavailable}
	client, _ = edge.client()
	auth, err = client.Issue(edge.cfg(), "x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Await(edge.cfg(), auth, newKey(t))
	var e *Error
	if !errors.As(err, &e) || e.Kind != Unavailable || e.Status != http.StatusServiceUnavailable || e.Code != "temporarily_unavailable" {
		t.Fatalf("Await = %v", err)
	}
	if polls := len(edge.reqs("/gc/v0/auth/device/token")); polls != maxConsecutiveTransient {
		t.Fatalf("polls = %d, want %d", polls, maxConsecutiveTransient)
	}
}

// The loop stops at the server's window (plus the replay grace) without polling past it.
func TestAwaitStopsAtTheExpiry(t *testing.T) {
	edge := newStubEdge(t)
	edge.issueBody = map[string]any{
		"device_code": "gcd_x", "user_code": "ABCD", "verification_uri_complete": "",
		"verification_uri": "", "expires_in": 60, "interval": 20,
	}
	edge.issueBody["verification_uri"] = edge.srv.URL + "/gc/v0/device"
	edge.tokenAnswers = []func(http.ResponseWriter){deviceError("authorization_pending", 0)}
	client, _ := edge.client()
	auth, err := client.Issue(edge.cfg(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if auth.VerificationURIComplete != "" || auth.VerificationURI == "" {
		t.Fatalf("authorization = %+v", auth)
	}
	_, err = client.Await(edge.cfg(), auth, newKey(t))
	if KindOf(err) != Expired {
		t.Fatalf("Await = %v, want expired", err)
	}
	// 60s window + 30s grace at 20s a poll: polls at 20, 40, 60, 80; the sleep to 100 ends it.
	if polls := len(edge.reqs("/gc/v0/auth/device/token")); polls != 4 {
		t.Fatalf("polls = %d, want 4", polls)
	}
}

func TestIssueRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   ErrorKind
	}{
		{http.StatusNotFound, NotEnabled}, {http.StatusMethodNotAllowed, NotEnabled},
		{http.StatusTooManyRequests, RateLimited}, {http.StatusBadRequest, InvalidRequest},
		{http.StatusServiceUnavailable, Unavailable}, {http.StatusUnauthorized, Protocol},
	} {
		edge := newStubEdge(t)
		edge.issueStatus = tc.status
		client, _ := edge.client()
		if _, err := client.Issue(edge.cfg(), "x"); KindOf(err) != tc.kind {
			t.Fatalf("issue %d = %v, want %s", tc.status, err, tc.kind)
		}
	}
}

// Every server-authored value the terminal will show is validated, and the verification URI
// must be on the cli-edge origin: a server cannot send the approver to another host.
func TestIssueValidatesWhatTheTerminalWillShow(t *testing.T) {
	edge := newStubEdge(t)
	good := func() map[string]any {
		return map[string]any{
			"device_code": "gcd_x", "user_code": "BDWK-JQPX",
			"verification_uri":          edge.srv.URL + "/gc/v0/device",
			"verification_uri_complete": edge.srv.URL + "/gc/v0/device?code=BDWK-JQPX",
			"expires_in":                600, "interval": 5,
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"foreign host": func(m map[string]any) { m["verification_uri_complete"] = "https://evil.example/gc/v0/device?code=X" },
		"plain http": func(m map[string]any) {
			m["verification_uri"] = strings.Replace(edge.srv.URL, "https", "http", 1) + "/gc/v0/device"
		},
		"userinfo": func(m map[string]any) {
			m["verification_uri"] = strings.Replace(edge.srv.URL, "https://", "https://u@", 1) + "/x"
		},
		"terminal escape":     func(m map[string]any) { m["user_code"] = "AB\x1b[2JCD" },
		"no user code":        func(m map[string]any) { delete(m, "user_code") },
		"no device code":      func(m map[string]any) { m["device_code"] = "" },
		"spaced device code":  func(m map[string]any) { m["device_code"] = "a b" },
		"no verification uri": func(m map[string]any) { delete(m, "verification_uri"); delete(m, "verification_uri_complete") },
	} {
		t.Run(name, func(t *testing.T) {
			body := good()
			mutate(body)
			edge.issueBody = body
			client, _ := edge.client()
			if _, err := client.Issue(edge.cfg(), "x"); KindOf(err) != Protocol {
				t.Fatalf("Issue = %v, want a protocol refusal", err)
			}
		})
	}
	edge.issueBody = good()
	client, _ := edge.client()
	if _, err := client.Issue(edge.cfg(), "x"); err != nil {
		t.Fatalf("Issue(good) = %v", err)
	}
	if _, err := client.Issue(config.Config{CLIEdgeBase: "http://127.0.0.1:1"}, "x"); err == nil ||
		!strings.Contains(err.Error(), config.CLIEdgeBaseEnv) {
		t.Fatalf("Issue on a plain-http edge = %v", err)
	}
}

func TestRevokeProvesPossessionOfTheRootsKey(t *testing.T) {
	edge := newStubEdge(t)
	client, _ := edge.client()
	key := newKey(t)
	if err := client.Revoke(edge.srv.URL, testRoot, key); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revokes := edge.reqs("/gc/v0/session")
	if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+testRoot {
		t.Fatalf("revocation = %+v", revokes)
	}
	_, claims := proofParts(t, revokes[0].dpop)
	sum := sha256.Sum256([]byte(testRoot))
	if claims["htm"] != "DELETE" || claims["htu"] != edge.srv.URL+"/gc/v0/session" ||
		claims["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("revocation proof = %v", claims)
	}
	if err := client.Revoke("http://works.gascity.com", testRoot, key); KindOf(err) != Protocol {
		t.Fatalf("Revoke at a non-canonical origin = %v", err)
	}
}

func TestCleanLabel(t *testing.T) {
	for raw, want := range map[string]string{
		"dev@laptop":                "dev@laptop",
		"  dev@laptop  ":            "dev@laptop",
		"dev\x00@lap\x1btop":        "dev@laptop",
		"dev\u2028@laptop\u200b":    "dev@laptop",
		strings.Repeat("é", 200):    strings.Repeat("é", maxLabelRunes),
		"gasworks (dev@host) é\xff": "gasworks (dev@host) é",
	} {
		if got := CleanLabel(raw); got != want {
			t.Errorf("CleanLabel(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A redeem whose access_token is unusable but could still be a live session (header-safe, just
// longer than any root) is refused AND revoked — with proof of possession when it claimed to be
// DPoP-bound. One that could not travel in a header is not presented anywhere. The token is
// never in the error.
func TestUnusableRootIsRevokedWhenItCanBe(t *testing.T) {
	long := "gcs_cli_" + strings.Repeat("x", maxRootLength)
	for _, tc := range []struct {
		name      string
		token     string
		tokenType string
		revoked   bool
		withProof bool
	}{
		{"oversized DPoP", long, "DPoP", true, true},
		{"oversized bearer", long, "bearer", true, false},
		{"space", "has space", "DPoP", false, false},
		{"control byte", "gcs_cli_\x1bx", "DPoP", false, false},
		{"absurdly long", strings.Repeat("x", maxRevocableLength+1), "DPoP", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edge := newStubEdge(t)
			edge.tokenAnswers = []func(http.ResponseWriter){func(w http.ResponseWriter) {
				writeJSON(w, http.StatusOK, map[string]any{"access_token": tc.token, "token_type": tc.tokenType})
			}}
			client, _ := edge.client()
			auth, err := client.Issue(edge.cfg(), "x")
			if err != nil {
				t.Fatal(err)
			}
			key := newKey(t)
			root, err := client.Await(edge.cfg(), auth, key)
			if KindOf(err) != Protocol || root.Token != "" || strings.Contains(err.Error(), tc.token) {
				t.Fatalf("Await = %+v, %v", root, err)
			}
			revokes := edge.reqs("/gc/v0/session")
			if !tc.revoked {
				if len(revokes) != 0 {
					t.Fatalf("revocations = %+v", revokes)
				}
				return
			}
			if len(revokes) != 1 || revokes[0].method != http.MethodDelete || revokes[0].auth != "Bearer "+tc.token {
				t.Fatalf("revocations = %+v", revokes)
			}
			if !tc.withProof {
				if revokes[0].dpop != "" {
					t.Fatal("an unbound token was revoked with a proof")
				}
				return
			}
			_, claims := proofParts(t, revokes[0].dpop)
			if claims["htm"] != http.MethodDelete || claims["ath"] == nil {
				t.Fatalf("revocation proof = %v", claims)
			}
		})
	}
}
