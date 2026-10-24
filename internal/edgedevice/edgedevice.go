// Package edgedevice is the client for the cli-edge device plane behind the opt-in
// `gasworks login --edge-device` (V1-L-01 option (b)):
//
//	POST   {edge}/gc/v0/auth/device/code   {"label": ...}        -> device_code, user_code, verification URIs
//	       (the human opens verification_uri_complete, signs in again, and approves)
//	POST   {edge}/gc/v0/auth/device/token  {"device_code": ...}  -> the CLI root session
//	       DPoP: a fresh proof per poll, ONE key for the whole flow, no ath
//	DELETE {edge}/gc/v0/session            Authorization: Bearer <root>, DPoP: proof with ath
//
// The poll's proof is what makes the root useful only to this device: the cli-edge verifies it
// before Accounts redeems the approval and binds the new root to the proof key's thumbprint.
// The root is then DPoP-bound like a /sts/v0/login session, and the STS exchanges it the same
// way. A server that answers with anything but a DPoP-bound root is refused and the root it
// issued is revoked: an unbound root is a plain bearer, and keeping one would be a step back
// from the Keycloak device grant this flow replaces.
//
// Nothing here prints. The package validates every server-authored value a terminal will show
// (the user code and the verification URI) and leaves the wording to the caller.
package edgedevice

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
)

const (
	requestTimeout = 30 * time.Second

	defaultInterval = 5 * time.Second
	minInterval     = 1 * time.Second
	// maxInterval matches the cli-edge's own bound on a poll interval.
	maxInterval  = 60 * time.Second
	slowDownStep = 5 * time.Second

	// defaultLifetime applies when the issue response has no usable expires_in; maxLifetime is
	// the longest device authorization the cli-edge issues (15 minutes).
	defaultLifetime = 10 * time.Minute
	maxLifetime     = 15 * time.Minute
	// expiryGrace keeps polling briefly past the window: Accounts replays an already-committed
	// result for 30s after expiry, which is what recovers a redeem whose answer was lost.
	expiryGrace = 30 * time.Second

	// maxConsecutiveTransient bounds how many polls in a row may fail without an answer
	// (transport error, 5xx) before the flow gives up. Retrying is not optional: if a redeem's
	// answer is lost in transit, the next poll with the same key is how the root is recovered.
	maxConsecutiveTransient = 3

	maxDeviceCodeLength      = 256
	maxUserCodeLength        = 128
	maxVerificationURILength = 2048
	maxRootLength            = 512
	maxTokenTypeLength       = 32
	maxLabelRunes            = 128
)

// TokenTypeDPoP is the only token_type this client accepts from a redeem.
const TokenTypeDPoP = "DPoP"

// Client drives one device flow. Its HTTP client never reuses a connection: a pooled
// connection that went stale between polls is silently retried by net/http, and a cli-edge
// whose proof ledger is single-use cannot tell that retry from a replayed proof.
type Client struct {
	// HTTP issues every request. A zero value falls back to the production client, so a test
	// can point one Client at a stub with its own CA without touching anything global.
	HTTP *http.Client
	// Sleep and Now pace the poll loop. Zero values fall back to time.Sleep and time.Now.
	Sleep func(time.Duration)
	Now   func() time.Time
}

// New returns the production client.
func New() *Client { return &Client{HTTP: defaultHTTPClient} }

var defaultHTTPClient = httpc.NewNoKeepAliveClient(requestTimeout)

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTPClient
}

func (c *Client) sleep(d time.Duration) {
	if c != nil && c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (c *Client) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Authorization is a validated device-code issue response.
type Authorization struct {
	DeviceCode string
	// UserCode is the code the approval page asks the human to confirm. Printable ASCII.
	UserCode string
	// VerificationURI and VerificationURIComplete are https URLs on the cli-edge origin. At
	// least one is set; VerificationURIComplete carries the user code.
	VerificationURI         string
	VerificationURIComplete string
	// ExpiresIn and Interval are the server's numbers, clamped to what the loop will honour.
	ExpiresIn time.Duration
	Interval  time.Duration

	issuedAt time.Time
}

// Root is a redeemed, DPoP-bound CLI root session.
type Root struct {
	Token     string
	TokenType string
	// ExpiresIn is the root's lifetime if the cli-edge reported one, else 0.
	ExpiresIn time.Duration
}

// ErrorKind classifies a refusal so the caller can say what to do about it.
type ErrorKind string

const (
	// NotEnabled: the device routes answered 404/405 — the plane is dark on this server.
	NotEnabled ErrorKind = "not_enabled"
	// RateLimited: too many device-code requests from this address.
	RateLimited ErrorKind = "rate_limited"
	// Unavailable: no usable answer (transport failure, 5xx), after any retries.
	Unavailable ErrorKind = "unavailable"
	// Denied: the approver denied the request.
	Denied ErrorKind = "denied"
	// Expired: the device code expired before it was approved.
	Expired ErrorKind = "expired"
	// InvalidProof: the cli-edge rejected the poll's DPoP proof.
	InvalidProof ErrorKind = "invalid_proof"
	// InvalidRequest: the cli-edge rejected the request as malformed.
	InvalidRequest ErrorKind = "invalid_request"
	// NotKeyBound: the cli-edge redeemed the approval but issued an unbound root.
	NotKeyBound ErrorKind = "not_key_bound"
	// Protocol: an answer this client cannot use (a malformed body, an unexpected status).
	Protocol ErrorKind = "protocol"
)

// Error is a device-plane refusal. Its message never carries a credential or a raw response
// body: only the operation, the HTTP status, and an error code from the protocol's closed set.
type Error struct {
	Kind ErrorKind
	// Op is "issue", "poll" or "revoke".
	Op string
	// Status is the HTTP status, or 0 when no response arrived.
	Status int
	// Code is the server's error code when it is one the protocol defines, else "".
	Code string
	// TokenType is, for NotKeyBound, the token_type the server reported (printable, bounded).
	TokenType string
	// Err is the underlying transport or decode failure, if any.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cli-edge device %s: %s", e.Op, e.Kind)
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.Status)
		if e.Code != "" {
			fmt.Fprintf(&b, " %s", e.Code)
		}
		b.WriteString(")")
	}
	if e.Kind == NotKeyBound && e.TokenType != "" {
		fmt.Fprintf(&b, ": token_type %q", e.TokenType)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf reports the ErrorKind of err, or "" when err is not a device-plane Error.
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// Issue opens a device authorization. It carries no DPoP proof: nothing is bound until the
// redeem.
func (c *Client) Issue(cfg config.Config, label string) (Authorization, error) {
	origin, err := cfg.CLIEdgeOrigin()
	if err != nil {
		return Authorization{}, err
	}
	codeURL, err := cfg.CLIDeviceCodeURL()
	if err != nil {
		return Authorization{}, err
	}
	issuedAt := c.now()
	_, body, err := httpc.PostJSONWith(c.httpClient(), codeURL, map[string]string{"label": CleanLabel(label)}, nil)
	if err != nil {
		return Authorization{}, classifyIssue(err)
	}
	auth, err := parseAuthorization(origin, body)
	if err != nil {
		return Authorization{}, &Error{Kind: Protocol, Op: "issue", Err: err}
	}
	auth.issuedAt = issuedAt
	return auth, nil
}

func classifyIssue(err error) error {
	var he *httpc.HTTPError
	if !errors.As(err, &he) {
		return &Error{Kind: Unavailable, Op: "issue", Err: err}
	}
	code := errorCode(he.Body)
	switch {
	case he.Status == http.StatusNotFound || he.Status == http.StatusMethodNotAllowed:
		return &Error{Kind: NotEnabled, Op: "issue", Status: he.Status}
	case he.Status == http.StatusTooManyRequests:
		return &Error{Kind: RateLimited, Op: "issue", Status: he.Status, Code: code}
	case he.Status == http.StatusBadRequest:
		return &Error{Kind: InvalidRequest, Op: "issue", Status: he.Status, Code: code}
	case he.Status >= 500:
		return &Error{Kind: Unavailable, Op: "issue", Status: he.Status, Code: code}
	default:
		return &Error{Kind: Protocol, Op: "issue", Status: he.Status, Code: code}
	}
}

func parseAuthorization(origin string, body any) (Authorization, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return Authorization{}, errors.New("the issue response is not a JSON object")
	}
	deviceCode := asString(m["device_code"])
	if deviceCode == "" || len(deviceCode) > maxDeviceCodeLength || !printable(deviceCode, false) {
		return Authorization{}, errors.New("the issue response has no usable device_code")
	}
	userCode := asString(m["user_code"])
	if userCode == "" || len(userCode) > maxUserCodeLength || !printable(userCode, true) {
		return Authorization{}, errors.New("the issue response has no usable user_code")
	}
	auth := Authorization{DeviceCode: deviceCode, UserCode: userCode}
	var err error
	if raw := asString(m["verification_uri_complete"]); raw != "" {
		if auth.VerificationURIComplete, err = verificationURI(origin, raw); err != nil {
			return Authorization{}, fmt.Errorf("verification_uri_complete: %w", err)
		}
	}
	if raw := asString(m["verification_uri"]); raw != "" {
		if auth.VerificationURI, err = verificationURI(origin, raw); err != nil {
			return Authorization{}, fmt.Errorf("verification_uri: %w", err)
		}
	}
	if auth.VerificationURI == "" && auth.VerificationURIComplete == "" {
		return Authorization{}, errors.New("the issue response has no verification URI")
	}
	auth.ExpiresIn = lifetime(m["expires_in"])
	auth.Interval = clampInterval(seconds(m["interval"], defaultInterval))
	return auth, nil
}

// verificationURI accepts a server-authored URL for a terminal and a human: bounded printable
// ASCII, https, no userinfo, and on the cli-edge origin itself. The cli-edge builds it from the
// same service origin it checks every poll's htu against, so a URL on another host is a
// misconfigured — or hostile — server sending the approver somewhere else.
func verificationURI(origin, raw string) (string, error) {
	if len(raw) > maxVerificationURILength || !printable(raw, false) {
		return "", errors.New("is not a printable URL")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("is not an https URL")
	}
	if got := u.Scheme + "://" + u.Host; got != origin {
		return "", fmt.Errorf("is on %s, not the cli-edge origin %s", got, origin)
	}
	return raw, nil
}

// Await polls until the approval is redeemed, refused, or expires. Every poll carries a fresh
// proof (new jti, new iat) from key, the one key the root will be bound to; the interval
// follows the server's pending/slow_down answers and never shrinks.
func (c *Client) Await(cfg config.Config, auth Authorization, key *dpop.Key) (Root, error) {
	if key == nil {
		return Root{}, errors.New("edgedevice: the poll needs the DPoP key the root will be bound to")
	}
	origin, err := cfg.CLIEdgeOrigin()
	if err != nil {
		return Root{}, err
	}
	tokenURL, err := cfg.CLIDeviceTokenURL()
	if err != nil {
		return Root{}, err
	}
	issuedAt := auth.issuedAt
	if issuedAt.IsZero() {
		issuedAt = c.now()
	}
	expiresIn := auth.ExpiresIn
	if expiresIn <= 0 || expiresIn > maxLifetime {
		expiresIn = defaultLifetime
	}
	deadline := issuedAt.Add(expiresIn + expiryGrace)
	interval := clampInterval(auth.Interval)
	failures := 0
	for {
		c.sleep(interval)
		if c.now().After(deadline) {
			return Root{}, &Error{Kind: Expired, Op: "poll"}
		}
		result := c.poll(tokenURL, auth.DeviceCode, key)
		switch result.state {
		case pollRedeemed:
			return result.root, nil
		case pollNotKeyBound:
			// The server minted a root it did not bind. Nothing can use it safely, so it is
			// revoked here, before the error leaves this package; the token never does.
			_ = c.Revoke(origin, result.root.Token, nil)
			return Root{}, result.err
		case pollPending:
			failures = 0
			interval = nextInterval(interval, result.interval, false)
		case pollSlowDown:
			failures = 0
			interval = nextInterval(interval, result.interval, true)
		case pollTransient:
			failures++
			if failures >= maxConsecutiveTransient {
				return Root{}, result.err
			}
		default:
			return Root{}, result.err
		}
	}
}

type pollState int

const (
	pollTerminal pollState = iota
	pollRedeemed
	pollNotKeyBound
	pollPending
	pollSlowDown
	pollTransient
)

type pollResult struct {
	state    pollState
	root     Root
	interval time.Duration
	err      error
}

func (c *Client) poll(tokenURL, deviceCode string, key *dpop.Key) pollResult {
	proof, err := key.ProofWithoutATH(http.MethodPost, tokenURL)
	if err != nil {
		return pollResult{state: pollTerminal, err: &Error{Kind: Protocol, Op: "poll", Err: err}}
	}
	_, body, err := httpc.PostJSONWith(c.httpClient(), tokenURL,
		map[string]string{"device_code": deviceCode}, map[string]string{"DPoP": proof})
	if err == nil {
		return redeemed(body)
	}
	var he *httpc.HTTPError
	if !errors.As(err, &he) {
		return pollResult{state: pollTransient, err: &Error{Kind: Unavailable, Op: "poll", Err: err}}
	}
	code := errorCode(he.Body)
	refusal := func(kind ErrorKind) pollResult {
		return pollResult{state: pollTerminal, err: &Error{Kind: kind, Op: "poll", Status: he.Status, Code: code}}
	}
	switch {
	case he.Status == http.StatusBadRequest && code == "authorization_pending":
		return pollResult{state: pollPending, interval: seconds(intervalField(he.Body), 0)}
	case he.Status == http.StatusBadRequest && code == "slow_down",
		he.Status == http.StatusTooManyRequests:
		return pollResult{state: pollSlowDown, interval: seconds(intervalField(he.Body), 0)}
	case he.Status == http.StatusBadRequest && code == "access_denied":
		return refusal(Denied)
	case he.Status == http.StatusBadRequest && code == "expired_token":
		return refusal(Expired)
	case he.Status == http.StatusBadRequest && code == "invalid_dpop_proof":
		return refusal(InvalidProof)
	case he.Status == http.StatusBadRequest:
		return refusal(InvalidRequest)
	case he.Status == http.StatusNotFound || he.Status == http.StatusMethodNotAllowed:
		return refusal(NotEnabled)
	case he.Status >= 500:
		return pollResult{state: pollTransient, err: &Error{Kind: Unavailable, Op: "poll", Status: he.Status, Code: code}}
	default:
		return refusal(Protocol)
	}
}

// redeemed reads a 2xx poll answer. The only acceptable one is a DPoP-bound root.
func redeemed(body any) pollResult {
	m, ok := body.(map[string]any)
	if !ok {
		return pollResult{state: pollTerminal, err: &Error{Kind: Protocol, Op: "poll", Status: http.StatusOK,
			Err: errors.New("the token response is not a JSON object")}}
	}
	token := asString(m["access_token"])
	if token == "" || len(token) > maxRootLength || !printable(token, false) {
		return pollResult{state: pollTerminal, err: &Error{Kind: Protocol, Op: "poll", Status: http.StatusOK,
			Err: errors.New("the token response has no usable access_token")}}
	}
	tokenType := asString(m["token_type"])
	if !strings.EqualFold(tokenType, TokenTypeDPoP) {
		shown := tokenType
		if len(shown) > maxTokenTypeLength || !printable(shown, false) {
			shown = "(unprintable)"
		}
		return pollResult{
			state: pollNotKeyBound,
			root:  Root{Token: token},
			err:   &Error{Kind: NotKeyBound, Op: "poll", Status: http.StatusOK, TokenType: shown},
		}
	}
	return pollResult{state: pollRedeemed, root: Root{
		Token:     token,
		TokenType: TokenTypeDPoP,
		ExpiresIn: rootLifetime(m["expires_in"]),
	}}
}

// maxRootLifetime bounds a root expires_in the cli-edge may report (it is optional, and today
// absent): far above any CLI session TTL, and far below where a duration overflows.
const maxRootLifetime = 400 * 24 * time.Hour

// rootLifetime reads an optional root expires_in, or 0 when absent or unusable.
func rootLifetime(v any) time.Duration {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || f < 1 || f > maxRootLifetime.Seconds() || f != math.Trunc(f) {
		return 0
	}
	return time.Duration(f) * time.Second
}

// Revoke best-effort revokes a root at the cli-edge origin that issued it. The root is
// presented as a Bearer — the scheme DELETE /gc/v0/session takes — and, when key is given,
// with a DPoP proof of possession (htm DELETE, htu the session URL, ath the root) for a server
// that checks one on a bound root. Callers ignore the error; it never carries the root.
func (c *Client) Revoke(origin, root string, key *dpop.Key) error {
	sessionURL, err := config.CLISessionURL(origin)
	if err != nil {
		return &Error{Kind: Protocol, Op: "revoke", Err: err}
	}
	headers := map[string]string{"Authorization": "Bearer " + root}
	if key != nil {
		proof, err := key.Proof(http.MethodDelete, sessionURL, root)
		if err != nil {
			return &Error{Kind: Protocol, Op: "revoke", Err: err}
		}
		headers["DPoP"] = proof
	}
	if _, _, err := httpc.DeleteWith(c.httpClient(), sessionURL, headers); err != nil {
		var he *httpc.HTTPError
		if errors.As(err, &he) {
			return &Error{Kind: Protocol, Op: "revoke", Status: he.Status, Code: errorCode(he.Body)}
		}
		return &Error{Kind: Unavailable, Op: "revoke", Err: err}
	}
	return nil
}

// CleanLabel returns label in the form the cli-edge accepts — at most 128 runes, no
// surrounding space, no control, format or line/paragraph separator characters — so a
// hostname with an odd byte does not turn the whole issue request into a 400.
func CleanLabel(label string) string {
	var b strings.Builder
	runes := 0
	for _, r := range label {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			continue
		}
		if runes == maxLabelRunes {
			break
		}
		b.WriteRune(r)
		runes++
	}
	return strings.TrimSpace(b.String())
}

// nextInterval honours a larger server interval on every answer and never shortens polling;
// slow_down additionally adds the RFC 8628 step to the current interval.
func nextInterval(current, server time.Duration, slowDown bool) time.Duration {
	next := current
	if slowDown {
		next = current + slowDownStep
	}
	if server > next {
		next = server
	}
	return clampInterval(next)
}

func clampInterval(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return defaultInterval
	case d < minInterval:
		return minInterval
	case d > maxInterval:
		return maxInterval
	default:
		return d
	}
}

func lifetime(v any) time.Duration {
	d := seconds(v, 0)
	if d <= 0 || d > maxLifetime {
		return defaultLifetime
	}
	return d
}

// seconds reads a JSON number of seconds. Anything that is not a positive whole number below
// an hour yields def — the value turns into a sleep or a deadline, and JSON carries no bound.
func seconds(v any, def time.Duration) time.Duration {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || f < 1 || f > 3600 || f != math.Trunc(f) {
		return def
	}
	return time.Duration(f) * time.Second
}

// errorCode reads an error code from either error shape the cli-edge sends: the RFC 8628
// device-token form {"error": "<code>"} and the service-protocol envelope
// {"error": {"code": "<code>", "message": ...}}. Only printable, bounded codes are returned.
func errorCode(body any) string {
	m, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	var code string
	switch v := m["error"].(type) {
	case string:
		code = v
	case map[string]any:
		code, _ = v["code"].(string)
	}
	if len(code) > 64 || !printable(code, false) {
		return ""
	}
	return code
}

func intervalField(body any) any {
	if m, ok := body.(map[string]any); ok {
		return m["interval"]
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// printable reports whether s is printable ASCII (space allowed only when withSpace), the
// boundary for anything a terminal will show or a header will carry.
func printable(s string, withSpace bool) bool {
	low := byte(0x21)
	if withSpace {
		low = 0x20
	}
	for i := 0; i < len(s); i++ {
		if s[i] < low || s[i] > 0x7e {
			return false
		}
	}
	return true
}
