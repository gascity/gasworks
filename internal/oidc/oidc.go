// Package oidc implements the Keycloak OIDC grants: device-code and browser auth-code (both
// PKCE S256), refresh, and revoke.
//
// Every grant requests scope='openid profile email offline_access' — `openid` is NOT a
// default client scope, and without it Keycloak returns only an access_token and no id_token
// (the STS subject_token). `offline_access` asks for a durable refresh token. Keycloak
// rotates refresh tokens on use, so the caller MUST persist the newly-returned one.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/jwtutil"
)

// OIDCScope is the scope on EVERY grant. It MUST be byte-identical across device, browser,
// and refresh — dropping `openid` makes Keycloak omit the id_token.
const OIDCScope = "openid profile email offline_access"

const (
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantAuthCode   = "authorization_code"
	grantRefresh    = "refresh_token"

	deviceLoginCap   = 600 * time.Second
	browserTimeout   = 300 * time.Second
	slowDownIncrease = 5 * time.Second
)

// b64url is base64url WITHOUT padding.
var b64url = base64.RawURLEncoding

// Tokens is the subset of a Keycloak token response the CLI consumes.
type Tokens struct {
	IDToken      string
	RefreshToken string
	AccessToken  string
}

func tokensFrom(body map[string]any) Tokens {
	str := func(k string) string {
		if s, ok := body[k].(string); ok {
			return s
		}
		return ""
	}
	return Tokens{
		IDToken:      str("id_token"),
		RefreshToken: str("refresh_token"),
		AccessToken:  str("access_token"),
	}
}

// pkce returns a PKCE verifier and its S256 challenge. The verifier is base64url-nopad of 32
// random bytes; the challenge is base64url-nopad(SHA256(verifier-ascii-bytes)).
func pkce() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = b64url.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = b64url.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// randToken returns base64url-nopad of n random bytes (state / nonce).
func randToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64url.EncodeToString(buf), nil
}

// asString coerces a parsed JSON value to a string.
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// asInt coerces a parsed JSON number (float64) to an int, falling back to def.
func asInt(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return def
	}
}

// DeviceLogin runs the device-authorization grant (headless). It prints the verification URL
// (and user code, if no complete URL) to stderr via logf, polls the token endpoint at the
// server-supplied interval, and returns the tokens on success. It stops polling at the
// server's expires_in lifetime, capped at deviceLoginCap (600s).
func DeviceLogin(cfg config.Config, logf func(string)) (Tokens, error) {
	if logf == nil {
		logf = func(string) {}
	}
	verifier, challenge, err := pkce()
	if err != nil {
		return Tokens{}, err
	}

	_, body, err := httpc.PostForm(cfg.DeviceAuthURL(), url.Values{
		"client_id":             {cfg.ClientID},
		"scope":                 {OIDCScope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}, nil)
	if err != nil {
		return Tokens{}, err
	}
	m, ok := body.(map[string]any)
	if !ok {
		return Tokens{}, fmt.Errorf("device login: unexpected response %T", body)
	}

	deviceCode := asString(m["device_code"])
	if deviceCode == "" {
		return Tokens{}, errors.New("device login: no device_code in response")
	}
	interval := time.Duration(asInt(m["interval"], 5)) * time.Second
	uri := asString(m["verification_uri_complete"])
	if uri == "" {
		uri = asString(m["verification_uri"])
	}
	logf(fmt.Sprintf("\nTo sign in, open:\n\n    %s\n", uri))
	if uc := asString(m["user_code"]); uc != "" && asString(m["verification_uri_complete"]) == "" {
		logf(fmt.Sprintf("and enter the code:  %s\n", uc))
	}
	logf("Waiting for you to authorize...")

	// Honor the server-supplied lifetime (the Python uses now + expires_in, default 600s),
	// but never poll past our local cap. deadline = min(now+expires_in, now+cap).
	now := time.Now()
	deadline := now.Add(deviceLoginCap)
	if exp := asInt(m["expires_in"], 0); exp > 0 {
		if serverDeadline := now.Add(time.Duration(exp) * time.Second); serverDeadline.Before(deadline) {
			deadline = serverDeadline
		}
	}
	for time.Now().Before(deadline) {
		sleep := interval
		if sleep < time.Second {
			sleep = time.Second
		}
		time.Sleep(sleep)

		_, tokBody, err := httpc.PostForm(cfg.OIDCTokenURL(), url.Values{
			"grant_type":    {grantDeviceCode},
			"device_code":   {deviceCode},
			"client_id":     {cfg.ClientID},
			"code_verifier": {verifier},
		}, nil)
		if err == nil {
			tm, ok := tokBody.(map[string]any)
			if !ok {
				return Tokens{}, fmt.Errorf("device login: unexpected token response %T", tokBody)
			}
			return tokensFrom(tm), nil
		}

		var he *httpc.HTTPError
		if !errors.As(err, &he) {
			return Tokens{}, err
		}
		switch he.OAuthError() {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += slowDownIncrease
			continue
		case "expired_token", "access_denied":
			return Tokens{}, fmt.Errorf("device login failed: %s", he.OAuthError())
		default:
			return Tokens{}, err
		}
	}
	return Tokens{}, errors.New("device login timed out")
}

// BrowserLogin runs the authorization-code + PKCE grant on a 127.0.0.1 loopback. The fixed
// port must be a registered redirect URI on the gasworks-cli client (Keycloak's `*` does not
// span the port). It binds 127.0.0.1 ONLY, serves exactly one /callback, fails closed on any
// error/CSRF/nonce mismatch, and exchanges the code for tokens.
func BrowserLogin(cfg config.Config, logf func(string)) (Tokens, error) {
	if logf == nil {
		logf = func(string) {}
	}
	verifier, challenge, err := pkce()
	if err != nil {
		return Tokens{}, err
	}
	state, err := randToken(24)
	if err != nil {
		return Tokens{}, err
	}
	nonce, err := randToken(24)
	if err != nil {
		return Tokens{}, err
	}

	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", cfg.LoopbackPort)
	authURL := cfg.AuthorizeURL() + "?" + url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {OIDCScope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// Bind 127.0.0.1 ONLY (never 0.0.0.0) so the callback is not reachable off-host.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.LoopbackPort))
	if err != nil {
		return Tokens{}, fmt.Errorf("loopback port %d is busy (%v); free it or use --device", cfg.LoopbackPort, err)
	}

	type result struct {
		code     string
		gotState string
		oauthErr string
	}
	resultCh := make(chan result, 1)
	var deliver sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h3>gasworks: signed in. You can close this tab.</h3></body></html>"))
		// Deliver exactly once: net/http serves each request in its own goroutine, so a
		// concurrent second /callback must not race the bool or block on the full channel.
		deliver.Do(func() {
			resultCh <- result{code: q.Get("code"), gotState: q.Get("state"), oauthErr: q.Get("error")}
		})
	})
	// Any other path 404s (only /callback is served).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	logf(fmt.Sprintf("\nOpening your browser to sign in...\nIf it doesn't open, visit:\n\n    %s\n", authURL))
	openBrowser(authURL) // best-effort; overridable in tests to drive the callback

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(browserTimeout):
		return Tokens{}, errors.New("login timed out waiting for the browser callback")
	}

	if res.oauthErr != "" {
		return Tokens{}, fmt.Errorf("login failed: %s", res.oauthErr)
	}
	if res.code == "" {
		return Tokens{}, errors.New("login timed out waiting for the browser callback")
	}
	// (L5) Defense-in-depth: state is locally generated non-empty, but reject an empty
	// expected/returned state outright (never let "" == "" pass as a match) and compare in
	// constant time so the check can't be timing-probed.
	if state == "" || res.gotState == "" || subtle.ConstantTimeCompare([]byte(res.gotState), []byte(state)) != 1 {
		return Tokens{}, errors.New("state mismatch (possible CSRF) — aborting")
	}

	_, tokBody, err := httpc.PostForm(cfg.OIDCTokenURL(), url.Values{
		"grant_type":    {grantAuthCode},
		"code":          {res.code},
		"redirect_uri":  {redirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}, nil)
	if err != nil {
		return Tokens{}, err
	}
	tm, ok := tokBody.(map[string]any)
	if !ok {
		return Tokens{}, fmt.Errorf("browser login: unexpected token response %T", tokBody)
	}
	tokens := tokensFrom(tm)

	// (L4) An empty id_token means the nonce check below is skipped — treat it as an error
	// rather than silently accepting an unverifiable response. We asked for scope=openid, so
	// a missing id_token is a misconfigured client, not a normal outcome.
	if tokens.IDToken == "" {
		return Tokens{}, errors.New("token response had no id_token (is the 'openid' scope enabled on the client?)")
	}
	claims, err := jwtutil.DecodeClaims(tokens.IDToken)
	if err != nil {
		return Tokens{}, fmt.Errorf("id_token decode failed: %w", err)
	}
	// (L5) Defense-in-depth: nonce is locally generated non-empty; reject an empty
	// expected/returned nonce and compare in constant time.
	gotNonce := asString(claims["nonce"])
	if nonce == "" || gotNonce == "" || subtle.ConstantTimeCompare([]byte(gotNonce), []byte(nonce)) != 1 {
		return Tokens{}, errors.New("id_token nonce mismatch — aborting")
	}
	return tokens, nil
}

// Refresh runs the refresh grant. Keycloak ROTATES the refresh token, so the returned
// Tokens.RefreshToken is the new one the caller must persist.
func Refresh(cfg config.Config, refreshToken string) (Tokens, error) {
	_, body, err := httpc.PostForm(cfg.OIDCTokenURL(), url.Values{
		"grant_type":    {grantRefresh},
		"refresh_token": {refreshToken},
		"client_id":     {cfg.ClientID},
		"scope":         {OIDCScope},
	}, nil)
	if err != nil {
		return Tokens{}, err
	}
	m, ok := body.(map[string]any)
	if !ok {
		return Tokens{}, fmt.Errorf("refresh: unexpected response %T", body)
	}
	return tokensFrom(m), nil
}

// Revoke best-effort revokes a refresh token at Keycloak (called on logout). Errors are
// swallowed.
func Revoke(cfg config.Config, refreshToken string) {
	_, _, _ = httpc.PostForm(cfg.RevokeURL(), url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {cfg.ClientID},
	}, nil)
}

// openBrowser best-effort opens url in the user's browser. It is a package var so tests can
// drive the loopback callback in place of a real browser. Failure is ignored — the URL was
// already printed.
var openBrowser = func(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}
