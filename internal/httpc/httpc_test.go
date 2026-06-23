package httpc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
