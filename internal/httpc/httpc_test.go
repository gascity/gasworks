package httpc

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUserAgentOnEveryRequest(t *testing.T) {
	var gotUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	if _, _, err := GetJSON(srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if gotUA != UserAgent() {
		t.Errorf("User-Agent = %q, want %q", gotUA, UserAgent())
	}
	if !strings.HasPrefix(gotUA, "gasworks-cli/") {
		t.Errorf("User-Agent = %q, want gasworks-cli/ prefix", gotUA)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
}

func TestUserAgentOnPostForm(t *testing.T) {
	var gotUA, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if _, _, err := PostForm(srv.URL, url.Values{"a": {"b"}}, nil); err != nil {
		t.Fatal(err)
	}
	if gotUA != UserAgent() {
		t.Errorf("User-Agent = %q, want %q", gotUA, UserAgent())
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want urlencoded", gotCT)
	}
}

func TestPostJSONSendsJSON(t *testing.T) {
	var gotUA, gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"challenge_id":"chal_1","confirm_code":"ABCD-1234"}`))
	}))
	defer srv.Close()

	// resource_refs is OMITTED, not null: the server folds in a default only when the field
	// is absent, so an omitempty field must survive the round trip as absent.
	body := struct {
		OrgID        string   `json:"org_id"`
		Scopes       []string `json:"scopes"`
		ResourceRefs []string `json:"resource_refs,omitempty"`
	}{OrgID: "org_a", Scopes: []string{"forge:city.create"}}

	status, parsed, err := PostJSON(srv.URL, body, map[string]string{"Authorization": "Bearer gcs_user_x"})
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want 201", status)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotUA != UserAgent() {
		t.Errorf("User-Agent = %q, want %q", gotUA, UserAgent())
	}
	if want := `{"org_id":"org_a","scopes":["forge:city.create"]}`; gotBody != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
	m, ok := parsed.(map[string]any)
	if !ok || m["confirm_code"] != "ABCD-1234" {
		t.Errorf("parsed body = %#v, want the decoded response", parsed)
	}
}

// Pending on the mint-complete leg is a 425 whose JSON body carries the poll interval — not
// an RFC 8628 400. The caller has to be able to read that body off the error.
func TestPostJSONSurfacesBodyOn425(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooEarly)
		_, _ = w.Write([]byte(`{"status":"authorization_pending","interval":5}`))
	}))
	defer srv.Close()

	status, parsed, err := PostJSON(srv.URL, map[string]any{}, nil)
	if status != http.StatusTooEarly {
		t.Errorf("status = %d, want 425", status)
	}
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("err is %T, want *HTTPError", err)
	}
	for _, body := range []any{parsed, httpErr.Body} {
		m, ok := body.(map[string]any)
		if !ok {
			t.Fatalf("body = %#v, want a decoded object", body)
		}
		if m["status"] != "authorization_pending" {
			t.Errorf("status field = %#v", m["status"])
		}
		if interval, ok := m["interval"].(float64); !ok || interval != 5 {
			t.Errorf("interval field = %#v, want 5", m["interval"])
		}
	}
	// A 425 is not an OAuth error shape; the mapping must not invent one.
	if got := httpErr.OAuthError(); got != "" {
		t.Errorf("OAuthError() = %q, want empty", got)
	}
}

// A request carrying a single-use DPoP proof must never ride a pooled connection: net/http
// silently replays a request whose reused connection died before anything was written, and
// the second copy meets a replay ledger that fails closed.
func TestNoKeepAliveClientDoesNotReuseConnections(t *testing.T) {
	var conns int
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	// ConnState has to be installed before the accept loop starts reading it.
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns++
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()

	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return conns
	}
	post := func(client *http.Client) {
		t.Helper()
		if _, _, err := PostJSONWith(client, srv.URL, map[string]any{"a": "b"}, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Control: one pooling client, two requests, one connection.
	pooling := newClient(defaultTimeout)
	post(pooling)
	post(pooling)
	if got := count(); got != 1 {
		t.Fatalf("the default client opened %d connections for 2 requests, want 1 (reuse)", got)
	}

	mu.Lock()
	conns = 0
	mu.Unlock()

	fresh := NewNoKeepAliveClient(defaultTimeout)
	post(fresh)
	post(fresh)
	if got := count(); got != 2 {
		t.Errorf("the no-keepalive client opened %d connections for 2 requests, want 2", got)
	}
	if tr := fresh.Transport.(*http.Transport); !tr.DisableKeepAlives {
		t.Error("DisableKeepAlives is not set on the no-keepalive client")
	}
	// The default client is untouched by the new constructor.
	if tr := newClient(time.Second).Transport.(*http.Transport); tr.DisableKeepAlives {
		t.Error("the default client's keepalives were disabled")
	}
}

// A response body that stops early is not an empty response body. io.ReadAll returns what it
// managed to read alongside its error, and for a caller holding the only copy of a one-shot
// secret those bytes are the whole point — so PostJSONRaw hands them back rather than dropping
// them on the way out of the package.
func TestPartialBodyReachesTheCaller(t *testing.T) {
	const partial = `{"key_id":"spk_1","secret":"gck_sp_wire_marker"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		// A Content-Length that promises far more than is delivered, then a close: the read
		// fails with an unexpected EOF over bytes that already carry the secret.
		_, _ = buf.WriteString("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n" +
			"Content-Length: 400\r\n\r\n" + partial)
		_ = buf.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()

	resp, err := PostJSONRaw(context.Background(), NewNoKeepAliveClient(5*time.Second), srv.URL,
		map[string]any{}, nil)
	if err != nil {
		t.Fatalf("PostJSONRaw = %v, want the response that DID arrive", err)
	}
	if resp.ReadErr == nil {
		t.Fatal("ReadErr = nil for a body that never finished")
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("Status = %d, want 201", resp.Status)
	}
	if string(resp.Body) != partial {
		t.Fatalf("Body = %q, want the %d bytes that arrived before %v", resp.Body, len(partial), resp.ReadErr)
	}
	// The parsed helpers keep their old contract: a caller with nothing to lose still sees a
	// read failure as an error and nothing else.
	if _, _, err := PostJSONWith(NewNoKeepAliveClient(5*time.Second), srv.URL, map[string]any{}, nil); err == nil {
		t.Error("PostJSONWith swallowed the read failure")
	}
}

// The ceremony client asks for no content encoding, so what it reads is what is on the wire and
// a partial read can reach it. A server that gzips anyway is undone by Payload — and one that
// only CLAIMS to have gzipped is not allowed to cost the caller the bytes.
func TestProductionMintClientKeepsTheWireBytes(t *testing.T) {
	const body = `{"key_id":"spk_1","secret":"gck_sp_wire_marker"}`
	var acceptEncoding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip") // and then does not gzip
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := PostJSONRaw(context.Background(), NewNoKeepAliveClient(5*time.Second), srv.URL,
		map[string]any{}, nil)
	if err != nil {
		t.Fatalf("PostJSONRaw: %v", err)
	}
	if acceptEncoding != "" {
		t.Errorf("the client asked for %q; a transport that negotiates an encoding consumes the "+
			"wire bytes inside itself, where a partial read cannot reach them", acceptEncoding)
	}
	if resp.ReadErr != nil {
		t.Fatalf("ReadErr = %v", resp.ReadErr)
	}
	if string(resp.Body) != body {
		t.Fatalf("Body = %q, want the wire bytes %q", resp.Body, body)
	}
	if got := string(resp.Payload()); got != body {
		t.Fatalf("Payload() = %q, want the body a mislabelled Content-Encoding did not change", got)
	}
}

func TestHTTPErrorParsesOAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad refresh"}`))
	}))
	defer srv.Close()

	status, _, err := GetJSON(srv.URL, nil)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("err is %T, want *HTTPError", err)
	}
	if got := httpErr.OAuthError(); got != "invalid_grant" {
		t.Errorf("OAuthError() = %q, want invalid_grant", got)
	}
	if httpErr.Status != 400 {
		t.Errorf("HTTPError.Status = %d, want 400", httpErr.Status)
	}
	// The error message folds in the error + description.
	if msg := httpErr.Error(); msg == "" {
		t.Error("HTTPError.Error() is empty")
	}
}

func TestOAuthErrorEmptyForNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("plain text boom"))
	}))
	defer srv.Close()

	_, _, err := GetJSON(srv.URL, nil)
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("err is %T, want *HTTPError", err)
	}
	if got := httpErr.OAuthError(); got != "" {
		t.Errorf("OAuthError() = %q, want empty for non-JSON body", got)
	}
	if s, ok := httpErr.Body.(string); !ok || s != "plain text boom" {
		t.Errorf("Body = %#v, want raw string", httpErr.Body)
	}
}

func TestCheckRedirectRefuses302(t *testing.T) {
	var secondHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHit = true
		_, _ = w.Write([]byte(`{"reached":"other host"}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// A 302 must be surfaced as a non-2xx HTTPError, NOT followed (no header replay to the
	// other host).
	status, _, err := GetJSON(redirector.URL, map[string]string{"Authorization": "Bearer secret"})
	if status != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect not followed)", status)
	}
	if _, ok := err.(*HTTPError); !ok {
		t.Errorf("err = %v (%T), want *HTTPError for the 302", err, err)
	}
	if secondHit {
		t.Error("redirect WAS followed — the target host was hit, replaying the Authorization header")
	}
}
