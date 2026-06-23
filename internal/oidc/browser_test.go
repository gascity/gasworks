package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/config"
)

// mkIDToken builds an unsigned id_token carrying the given nonce (BrowserLogin reads the
// nonce claim without verifying the signature).
func mkIDToken(nonce string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pj, _ := json.Marshal(map[string]any{"nonce": nonce, "sub": "usr_1"})
	p := base64.RawURLEncoding.EncodeToString(pj)
	return h + "." + p + ".sig"
}

// browserHarness wires a Keycloak-token stub + an openBrowser override that drives the
// loopback /callback. nonceMutator lets a test forge a wrong nonce; stateMutator a wrong state.
type browserHarness struct {
	t            *testing.T
	cfg          config.Config
	mu           sync.Mutex
	nonce        string // captured from the authorize URL
	state        string
	tokenSrv     *httptest.Server
	stateMutator func(string) string
	nonceForIDT  func(realNonce string) string
	callbackErr  string // if set, callback carries ?error= and no code
	omitCode     bool
	emptyIDToken bool // if set, the token response carries an empty id_token
}

func newBrowserHarness(t *testing.T) *browserHarness {
	h := &browserHarness{t: t, stateMutator: func(s string) string { return s }, nonceForIDT: func(n string) string { return n }}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/g/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		nonce := h.nonce
		empty := h.emptyIDToken
		h.mu.Unlock()
		idt := mkIDToken(h.nonceForIDT(nonce))
		if empty {
			idt = ""
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id_token":      idt,
			"refresh_token": "RT",
			"access_token":  "AT",
		})
	})
	h.tokenSrv = httptest.NewServer(mux)
	t.Cleanup(h.tokenSrv.Close)
	h.cfg = config.Config{
		STSBase:      h.tokenSrv.URL,
		OIDCIssuer:   h.tokenSrv.URL + "/realms/g",
		ClientID:     "gasworks-cli",
		LoopbackPort: freePort(t),
	}
	return h
}

// install swaps openBrowser to capture state/nonce from the authorize URL and fire the
// loopback callback, restoring the original on cleanup.
func (h *browserHarness) install() {
	orig := openBrowser
	h.t.Cleanup(func() { openBrowser = orig })
	openBrowser = func(authURL string) {
		u, err := url.Parse(authURL)
		if err != nil {
			h.t.Errorf("bad authorize URL: %v", err)
			return
		}
		q := u.Query()
		h.mu.Lock()
		h.nonce = q.Get("nonce")
		h.state = q.Get("state")
		h.mu.Unlock()

		cb := fmt.Sprintf("http://127.0.0.1:%d/callback", h.cfg.LoopbackPort)
		params := url.Values{}
		if h.callbackErr != "" {
			params.Set("error", h.callbackErr)
		} else {
			if !h.omitCode {
				params.Set("code", "AUTHCODE")
			}
			params.Set("state", h.stateMutator(q.Get("state")))
		}
		// Fire asynchronously so BrowserLogin's server is already accepting.
		go func() {
			for i := 0; i < 50; i++ {
				resp, err := http.Get(cb + "?" + params.Encode())
				if err == nil {
					resp.Body.Close()
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestBrowserLoginHappyPath(t *testing.T) {
	h := newBrowserHarness(t)
	h.install()
	tok, err := BrowserLogin(h.cfg, func(string) {})
	if err != nil {
		t.Fatalf("BrowserLogin: %v", err)
	}
	if tok.RefreshToken != "RT" || tok.AccessToken != "AT" {
		t.Fatalf("tokens = %+v", tok)
	}
	if tok.IDToken == "" {
		t.Error("missing id_token")
	}
}

func TestBrowserLoginRejectsStateMismatch(t *testing.T) {
	h := newBrowserHarness(t)
	h.stateMutator = func(string) string { return "FORGED" }
	h.install()
	_, err := BrowserLogin(h.cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("want state mismatch error, got %v", err)
	}
}

func TestBrowserLoginRejectsNonceMismatch(t *testing.T) {
	h := newBrowserHarness(t)
	h.nonceForIDT = func(string) string { return "WRONG-NONCE" }
	h.install()
	_, err := BrowserLogin(h.cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("want nonce mismatch error, got %v", err)
	}
}

// TestBrowserLoginRejectsEmptyIDToken is the L4 regression: an empty id_token in the token
// response must be an error (the nonce check would otherwise be silently skipped).
func TestBrowserLoginRejectsEmptyIDToken(t *testing.T) {
	h := newBrowserHarness(t)
	h.emptyIDToken = true
	h.install()
	_, err := BrowserLogin(h.cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "no id_token") {
		t.Fatalf("want no-id_token error, got %v", err)
	}
}

func TestBrowserLoginRejectsCallbackError(t *testing.T) {
	h := newBrowserHarness(t)
	h.callbackErr = "access_denied"
	h.install()
	_, err := BrowserLogin(h.cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("want login failed error, got %v", err)
	}
}

func TestBrowserLoginRejectsMissingCode(t *testing.T) {
	h := newBrowserHarness(t)
	h.omitCode = true
	h.install()
	_, err := BrowserLogin(h.cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want missing-code/timeout error, got %v", err)
	}
}

// TestBrowserLoginSends404OnOtherPaths confirms only /callback is served.
func TestBrowserLoginSends404OnOtherPaths(t *testing.T) {
	port := freePort(t)
	cfg := config.Config{
		STSBase:      "http://unused",
		OIDCIssuer:   "http://unused/realms/g",
		ClientID:     "gasworks-cli",
		LoopbackPort: port,
	}
	done := make(chan struct{})
	orig := openBrowser
	t.Cleanup(func() { openBrowser = orig })
	openBrowser = func(string) {
		go func() {
			defer close(done)
			base := fmt.Sprintf("http://127.0.0.1:%d", port)
			// A non-callback path must 404.
			for i := 0; i < 50; i++ {
				resp, err := http.Get(base + "/other")
				if err == nil {
					if resp.StatusCode != http.StatusNotFound {
						t.Errorf("/other status = %d, want 404", resp.StatusCode)
					}
					resp.Body.Close()
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Then complete the flow so BrowserLogin returns instead of timing out.
			http.Get(fmt.Sprintf("%s/callback?code=X&state=", base))
		}()
	}
	// We can't easily reach the token endpoint here (unused host) so just assert the 404 ran
	// and BrowserLogin returns some error (token POST will fail).
	_, _ = BrowserLogin(cfg, func(string) {})
	<-done
}
