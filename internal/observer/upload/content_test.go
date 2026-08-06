package upload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// contentServer records the last content POST it saw and returns a scripted response.
type contentServer struct {
	method      string
	path        string
	authz       string
	nativeID    string
	gcSessionID string
	provider    string
	sourcePath  string
	ctype       string
	body        []byte

	status     int
	respBody   []byte
	retryAfter string
}

func (s *contentServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.method = r.Method
		s.path = r.URL.Path
		s.authz = r.Header.Get("Authorization")
		s.nativeID = r.Header.Get(headerNativeSessionID)
		s.gcSessionID = r.Header.Get(headerGCSessionID)
		s.provider = r.Header.Get(headerProvider)
		s.sourcePath = r.Header.Get(headerSourcePath)
		s.ctype = r.Header.Get("Content-Type")
		s.body = b
		if s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		status := s.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(s.respBody)
	}
}

func TestPostContentSendsWholeBodyWithHeaders(t *testing.T) {
	ack, _ := json.Marshal(contentAck{GCSessionID: "gcs_123", ReceiptID: "rcpt_9", Status: "accepted"})
	srv := &contentServer{status: http.StatusOK, respBody: ack}
	base := newHTTPServer(t, srv.handler())
	client := loopbackClient(t, base, staticToken("secret-bearer-abc"))

	body := []byte("line1\nline2\nline3\n")
	res, err := client.PostContent(context.Background(), ContentRequest{
		NativeSessionID: "sess-abc",
		GCSessionID:     "gc_exact_123",
		Provider:        "Claude", // exercises lowercasing
		SourcePath:      "/home/u/.claude/projects/p/sess.jsonl",
		Body:            body,
	})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if res.GCSessionID != "gcs_123" || res.ReceiptID != "rcpt_9" || res.Status != "accepted" {
		t.Fatalf("decoded receipt = %+v", res)
	}
	if srv.method != http.MethodPost {
		t.Fatalf("method = %q, want POST", srv.method)
	}
	if srv.path != contentPath {
		t.Fatalf("path = %q, want %q", srv.path, contentPath)
	}
	if srv.authz != "Bearer secret-bearer-abc" {
		t.Fatalf("authz = %q, want bearer", srv.authz)
	}
	if srv.nativeID != "sess-abc" {
		t.Fatalf("native id header = %q", srv.nativeID)
	}
	if srv.gcSessionID != "gc_exact_123" {
		t.Fatalf("GC session id header = %q", srv.gcSessionID)
	}
	if srv.provider != "claude" {
		t.Fatalf("provider header = %q, want lowercased claude", srv.provider)
	}
	if srv.sourcePath != "/home/u/.claude/projects/p/sess.jsonl" {
		t.Fatalf("source-path header = %q", srv.sourcePath)
	}
	if srv.ctype != "application/octet-stream" {
		t.Fatalf("content-type = %q", srv.ctype)
	}
	if string(srv.body) != string(body) {
		t.Fatalf("body = %q, want whole file %q", srv.body, body)
	}
}

func TestPostContentOmitsGCSessionIDWhenUnknown(t *testing.T) {
	srv := &contentServer{}
	base := newHTTPServer(t, srv.handler())
	client := loopbackClient(t, base, staticToken("t"))

	if _, err := client.PostContent(context.Background(), ContentRequest{NativeSessionID: "s", Provider: "codex", Body: []byte("x")}); err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if srv.gcSessionID != "" {
		t.Fatalf("GC session id header = %q, want omitted", srv.gcSessionID)
	}
}

func TestPostContentShedReturnsRetryAfter(t *testing.T) {
	srv := &contentServer{status: http.StatusTooManyRequests, retryAfter: "42"}
	base := newHTTPServer(t, srv.handler())
	client := loopbackClient(t, base, staticToken("t"))

	res, err := client.PostContent(context.Background(), ContentRequest{NativeSessionID: "s", Provider: "codex", Body: []byte("x")})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", res.StatusCode)
	}
	if res.RetryAfter != 42*time.Second {
		t.Fatalf("retry-after = %v, want 42s", res.RetryAfter)
	}
}

func TestPostContentNotProvisioned(t *testing.T) {
	srv := &contentServer{status: http.StatusNotImplemented}
	base := newHTTPServer(t, srv.handler())
	client := loopbackClient(t, base, staticToken("t"))

	res, err := client.PostContent(context.Background(), ContentRequest{NativeSessionID: "s", Provider: "codex", Body: []byte("x")})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", res.StatusCode)
	}
}
