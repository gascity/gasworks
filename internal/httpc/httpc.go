// Package httpc is a thin net/http wrapper: a custom User-Agent on every request
// (Keycloak/Cloudflare returns 1010 to a default UA), TLS verification always on, GET/form/
// JSON helpers, and a typed HTTPError carrying the parsed body for OAuth/STS error mapping.
//
// Redirects are refused (CheckRedirect returns http.ErrUseLastResponse) so a 30x never
// replays the Authorization/DPoP header to another host.
package httpc

import (
	"bytes"
	"compress/gzip"
	"context"
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

// newTransport clones the default transport and pins a TLS 1.2 floor. TLS verification stays
// on (InsecureSkipVerify is never set); the explicit MinVersion just refuses a downgrade to
// the deprecated TLS 1.0/1.1 a MITM might try to negotiate.
func newTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return tr
}

// clientWith wraps a transport in the client policy every request in this package shares:
// one timeout, and redirects refused so a 30x never replays the Authorization/DPoP header to
// another host.
func clientWith(tr *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newClient builds the default http.Client: connection reuse on, redirects refused.
func newClient(timeout time.Duration) *http.Client { return clientWith(newTransport(), timeout) }

// NewNoKeepAliveClient builds a client that opens a fresh connection per request and closes
// it after the response, with the same redirect refusal and TLS floor as the default client.
//
// Use it for a request carrying a single-use proof. A pooled connection can go stale between
// requests, and net/http answers that by silently REPLAYING the request on a fresh
// connection — indistinguishable, at a server whose replay ledger fails closed, from an
// attacker resending the proof. Whichever copy lands second is rejected, and the proof's jti
// is spent either way. No pooled connection, no silent replay.
//
// Transport-level decompression is off for the same class of reason. When net/http negotiates
// gzip itself it hands back a body that is the OUTPUT of an inflater, so a response whose
// Content-Encoding does not match its bytes yields an error and NOTHING — the wire bytes are
// consumed inside the transport and never reach the caller. A single-use response has to be
// recoverable byte for byte, so this client asks for no encoding and Response.Payload undoes
// one the server applied anyway.
func NewNoKeepAliveClient(timeout time.Duration) *http.Client {
	tr := newTransport()
	tr.DisableKeepAlives = true
	tr.DisableCompression = true
	return clientWith(tr, timeout)
}

// Response is one HTTP response whose body has been read but NOT parsed.
//
// Body holds every byte that was read, INCLUDING when ReadErr is set: io.ReadAll returns what
// it managed to read alongside its error, and for a response that reveals a one-shot secret
// those bytes are the whole point. A 201 whose body is cut short by a truncation, a timeout, a
// reset or a GOAWAY has still revealed a credential that cannot be re-issued, and discarding
// the partial read is how that credential gets destroyed. Callers with nothing to lose use the
// parsed helpers below, which keep the old "a read error is just an error" behaviour; callers
// holding the only copy of something use PostJSONRaw and deal with the bytes themselves.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	ReadErr error
}

// Payload is Body with a declared content encoding undone, for parsing.
func (r *Response) Payload() []byte { return Payload(r.Header, r.Body) }

// Payload undoes a content encoding the response declared, so a caller holding the wire bytes
// can still read what is in them.
//
// A body that really is gzip is inflated as far as it goes — a truncated stream still yields
// the bytes before the truncation — and one that only CLAIMS to be gzip is handed back exactly
// as it came. A Content-Encoding header that disagrees with the bytes under it is a proxy bug,
// and it must not be what stops a credential being read.
func Payload(header http.Header, body []byte) []byte {
	if !strings.EqualFold(header.Get("Content-Encoding"), "gzip") {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer zr.Close()
	inflated, _ := io.ReadAll(zr)
	if len(inflated) == 0 {
		return body
	}
	return inflated
}

// Parse mirrors the Python _parse: empty body -> {}, valid JSON -> the decoded value,
// otherwise the trimmed raw string.
func Parse(raw []byte) any {
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
	return doWith(newClient(timeout), method, rawURL, body, headers)
}

// send issues one request and reads its body without parsing it. The error it returns is for a
// request that produced NO response at all (a marshal, dial, TLS or header-read failure); once
// a response exists, everything about it — including a body read that did not finish — is
// reported through the Response.
func send(ctx context.Context, client *http.Client, method, rawURL string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent())
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(resp.Body)
	return &Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: raw, ReadErr: readErr}, nil
}

func doWith(client *http.Client, method, rawURL string, body io.Reader, headers map[string]string) (int, any, error) {
	resp, err := send(context.Background(), client, method, rawURL, body, headers)
	if err != nil {
		return 0, nil, err
	}
	if resp.ReadErr != nil {
		return 0, nil, resp.ReadErr
	}
	parsed := Parse(resp.Payload())

	if resp.Status < 200 || resp.Status >= 300 {
		return resp.Status, parsed, &HTTPError{Status: resp.Status, Body: parsed, URL: rawURL}
	}
	return resp.Status, parsed, nil
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

// PostJSON marshals body and issues a JSON POST, returning (status, parsedBody). On a
// non-2xx it returns an *HTTPError whose Body is the parsed response, so a caller can read
// the fields of an error the API expresses in JSON rather than in the status alone.
func PostJSON(rawURL string, body any, headers map[string]string) (int, any, error) {
	return PostJSONWith(newClient(defaultTimeout), rawURL, body, headers)
}

// PostJSONWith is PostJSON on a caller-supplied client — NewNoKeepAliveClient for a request
// carrying a single-use proof, which must not be replayed on a fresh connection.
func PostJSONWith(client *http.Client, rawURL string, body any, headers map[string]string) (int, any, error) {
	buf, h, err := jsonRequest(body, headers)
	if err != nil {
		return 0, nil, err
	}
	return doWith(client, http.MethodPost, rawURL, buf, h)
}

// PostJSONRaw is PostJSONWith for a caller that must not lose the response body: it hands the
// bytes back unparsed, and hands them back even when the read that produced them failed.
//
// ctx cancels the request. Cancelling a read that is already under way is safe here for the
// same reason the partial body is returned at all — whatever arrived before the cancel is in
// Response.Body.
func PostJSONRaw(ctx context.Context, client *http.Client, rawURL string, body any, headers map[string]string) (*Response, error) {
	buf, h, err := jsonRequest(body, headers)
	if err != nil {
		return nil, err
	}
	return send(ctx, client, http.MethodPost, rawURL, buf, h)
}

// jsonRequest marshals a JSON body and folds the caller's headers over the content type.
//
// body is marshalled as given: a field the API treats as absent must be OMITTED from the value
// (an omitempty field, or a key left out of a map), because a JSON null is a value the server
// can see.
func jsonRequest(body any, headers map[string]string) (io.Reader, map[string]string, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return bytes.NewReader(buf), h, nil
}
