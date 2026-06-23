// Package httpc is a thin net/http wrapper: a custom User-Agent on every request
// (Keycloak/Cloudflare returns 1010 to a default UA), TLS verification always on, form/GET
// JSON helpers, and a typed HTTPError carrying the parsed body for OAuth/STS error mapping.
//
// Redirects are refused (CheckRedirect returns http.ErrUseLastResponse) so a 30x never
// replays the Authorization/DPoP header to another host.
package httpc

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/version"
)

// UserAgent is sent on every request. It folds in the build-stamped version so the
// server logs the exact CLI build; the value tracks internal/version (stamped via
// -ldflags at release, "gasworks-cli/dev" for an unstamped build/test).
func UserAgent() string { return "gasworks-cli/" + version.Version }

const defaultTimeout = 30 * time.Second

// HTTPError is a non-2xx response with the parsed body (a decoded JSON value, else the raw
// string) preserved for OAuth/STS error mapping.
type HTTPError struct {
	Status int
	Body   any
	URL    string
}

func (e *HTTPError) Error() string {
	var errStr, detail string
	if m, ok := e.Body.(map[string]any); ok {
		if v, ok := m["error"].(string); ok {
			errStr = v
		}
		if v, ok := m["error_description"].(string); ok {
			detail = v
		}
	}
	if detail == "" {
		if s, ok := e.Body.(string); ok {
			detail = s
		}
	}
	return strings.TrimSpace(fmt.Sprintf("%d %s %s", e.Status, errStr, detail))
}

// OAuthError extracts the OAuth `error` field from a JSON body, or "" if absent.
func (e *HTTPError) OAuthError() string {
	if m, ok := e.Body.(map[string]any); ok {
		if v, ok := m["error"].(string); ok {
			return v
		}
	}
	return ""
}

// newClient builds an http.Client that refuses redirects and pins a TLS 1.2 floor. TLS
// verification stays on (InsecureSkipVerify is never set); the explicit MinVersion just
// refuses a downgrade to the deprecated TLS 1.0/1.1 a MITM might try to negotiate.
func newClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// parse mirrors the Python _parse: empty body -> {}, valid JSON -> the decoded value,
// otherwise the trimmed raw string.
func parse(raw []byte) any {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	return v
}

func do(method, rawURL string, body io.Reader, headers map[string]string, timeout time.Duration) (int, any, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", UserAgent())
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := newClient(timeout).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	parsed := parse(raw)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, parsed, &HTTPError{Status: resp.StatusCode, Body: parsed, URL: rawURL}
	}
	return resp.StatusCode, parsed, nil
}

// GetJSON issues a GET and returns (status, parsedBody). On a non-2xx it returns an
// *HTTPError carrying the parsed body.
func GetJSON(url string, headers map[string]string) (int, any, error) {
	return do(http.MethodGet, url, nil, headers, defaultTimeout)
}

// PostForm issues a urlencoded POST and returns (status, parsedBody). On a non-2xx it
// returns an *HTTPError carrying the parsed body.
func PostForm(rawURL string, values url.Values, headers map[string]string) (int, any, error) {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range headers {
		h[k] = v
	}
	return do(http.MethodPost, rawURL, strings.NewReader(values.Encode()), h, defaultTimeout)
}
