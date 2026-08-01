package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/artifactapi"
)

type artifactRequest struct {
	method         string
	path           string
	rawQuery       string
	authorization  string
	idempotencyKey string
	contentType    string
	legacyNative   string
	legacyProvider string
	legacyPath     string
	body           []byte
}

type artifactLifecycleServer struct {
	t      *testing.T
	mu     sync.Mutex
	fault  string
	key    string
	digest string
	length int
	reqs   []artifactRequest
	failed bool
}

func (s *artifactLifecycleServer) handler(w http.ResponseWriter, r *http.Request) {
	s.t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.t.Errorf("read request: %v", err)
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, artifactRequest{
		method:         r.Method,
		path:           r.URL.Path,
		rawQuery:       r.URL.RawQuery,
		authorization:  r.Header.Get("Authorization"),
		idempotencyKey: r.Header.Get("Idempotency-Key"),
		contentType:    r.Header.Get("Content-Type"),
		legacyNative:   r.Header.Get("X-Observer-Native-Session-Id"),
		legacyProvider: r.Header.Get("X-Observer-Provider"),
		legacyPath:     r.Header.Get("X-Observer-Source-Path"),
		body:           append([]byte(nil), body...),
	})
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/observer/api/v1/artifacts":
		if s.fault == "problem" || s.fault == "create-problem" {
			s.writeProblem(w, http.StatusTooManyRequests, "42")
			return
		}
		if s.fault == "not-provisioned" {
			s.writeProblem(w, http.StatusNotImplemented, "")
			return
		}
		var create artifactapi.CreateArtifactRequest
		if err := json.Unmarshal(body, &create); err != nil {
			s.t.Errorf("decode create: %v", err)
		}
		s.key = create.ArtifactKey
		if create.DeclaredDigest != nil {
			s.digest = *create.DeclaredDigest
		}
		if create.DeclaredByteLength != nil {
			s.length = *create.DeclaredByteLength
		}
		if s.failTransportOnce("create-transport-once") {
			panic(http.ErrAbortHandler)
		}
		response := s.artifact("open")
		s.applyArtifactFault(response, "create")
		if s.fault == "create-unknown-field" {
			response["private-response-canary"] = true
		}
		if s.fault == "create-time-canary" {
			response["created_at"] = "private-time-canary"
		}
		if s.fault == "create-compressed" {
			w.Header().Set("Content-Encoding", "gzip")
		}
		if s.fault == "create-oversized" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, strings.Repeat("x", int(maxResponseBytes)+1))
			return
		}
		contentType := "application/json"
		if s.fault == "create-media-type" {
			contentType = "text/json"
		}
		if s.fault == "upload-transport-once" {
			w.Header().Set("Connection", "close")
		}
		s.writeJSONAs(w, http.StatusCreated, contentType, response)

	case r.Method == http.MethodPost && r.URL.Path == "/observer/api/v1/artifacts/art_1/content":
		if s.failTransportOnce("upload-transport-once") {
			panic(http.ErrAbortHandler)
		}
		if s.fault == "upload-problem" {
			s.writeProblem(w, http.StatusConflict, "")
			return
		}
		part := map[string]any{
			"artifact_id":          "art_1",
			"part_number":          0,
			"received_byte_length": len(body),
		}
		switch s.fault {
		case "upload-artifact":
			part["artifact_id"] = "art_foreign"
		case "upload-part":
			part["part_number"] = 1
		case "upload-length":
			part["received_byte_length"] = len(body) + 1
		case "upload-unknown-field":
			part["private-response-canary"] = true
		}
		contentType := "application/json"
		if s.fault == "upload-media-type" {
			contentType = "text/json"
		}
		if s.fault == "finalize-transport-once" {
			w.Header().Set("Connection", "close")
		}
		s.writeJSONAs(w, http.StatusAccepted, contentType, part)

	case r.Method == http.MethodPost && r.URL.Path == "/observer/api/v1/artifacts/art_1/finalize":
		if s.failTransportOnce("finalize-transport-once") {
			panic(http.ErrAbortHandler)
		}
		if s.fault == "finalize-problem" {
			s.writeProblem(w, http.StatusConflict, "")
			return
		}
		response := s.artifact("finalized")
		s.applyArtifactFault(response, "finalize")
		if s.fault == "finalize-unknown-field" {
			response["private-response-canary"] = true
		}
		contentType := "application/json"
		if s.fault == "finalize-media-type" {
			contentType = "text/json"
		}
		s.writeJSONAs(w, http.StatusOK, contentType, response)

	default:
		http.Error(w, "unexpected route", http.StatusNotFound)
	}
}

func (s *artifactLifecycleServer) artifact(state string) map[string]any {
	var length any
	var digest any
	if state == "finalized" {
		length = s.length
		digest = s.digest
	}
	artifact := map[string]any{
		"artifact_id":  "art_1",
		"artifact_key": s.key,
		"byte_length":  length,
		"created_at":   "2026-08-01T00:00:00Z",
		"digest":       digest,
		"kind":         "transcript",
		"links":        map[string]any{"self": map[string]any{"href": "/api/v1/artifacts/art_1"}},
		"media_type":   "application/x-ndjson",
		"provenance": map[string]any{
			"ingested_at":    "2026-08-01T00:00:00Z",
			"org_id":         "org_test",
			"policy_digest":  "sha256:policy",
			"principal_id":   "sp_test",
			"principal_type": "machine",
			"schema_version": "1",
			"source_id":      testSourceID,
			"source_kind":    "custom_orchestrator",
			"workspace_id":   "ws_test",
		},
		"state": state,
	}
	provenance := artifact["provenance"].(map[string]any)
	switch s.fault {
	case "provenance-principal-type":
		provenance["principal_type"] = "unknown"
	case "provenance-source-kind":
		provenance["source_kind"] = "unknown"
	case "provenance-schema-version":
		provenance["schema_version"] = ""
	}
	return artifact
}

func (s *artifactLifecycleServer) applyArtifactFault(response map[string]any, phase string) {
	switch s.fault {
	case phase + "-artifact":
		response["artifact_id"] = "art_foreign"
	case phase + "-artifact-long":
		response["artifact_id"] = strings.Repeat("a", 129)
	case phase + "-source":
		response["provenance"].(map[string]any)["source_id"] = "src_foreign"
	case phase + "-workspace":
		response["provenance"].(map[string]any)["workspace_id"] = "ws_foreign"
	case phase + "-state":
		if phase == "create" {
			response["state"] = "finalized"
		} else {
			response["state"] = "open"
		}
	case phase + "-digest":
		response["digest"] = "sha256:wrong"
	case phase + "-length":
		response["byte_length"] = s.length + 1
	}
}

func (s *artifactLifecycleServer) writeJSON(w http.ResponseWriter, status int, value any) {
	s.writeJSONAs(w, status, "application/json", value)
}

func (s *artifactLifecycleServer) writeJSONAs(w http.ResponseWriter, status int, contentType string, value any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.t.Errorf("encode response: %v", err)
	}
}

func (s *artifactLifecycleServer) writeProblem(w http.ResponseWriter, status int, retryAfter string) {
	w.Header().Set("Content-Type", "application/problem+json")
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":       "https://errors.example/artifact",
		"title":      "artifact rejected",
		"status":     status,
		"request_id": "req_test",
		"code":       "artifact_rejected",
	})
}

func (s *artifactLifecycleServer) requests() []artifactRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]artifactRequest, len(s.reqs))
	copy(out, s.reqs)
	return out
}

func (s *artifactLifecycleServer) failTransportOnce(fault string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != fault || s.failed {
		return false
	}
	s.failed = true
	return true
}

type rotatingContentToken struct {
	mu sync.Mutex
	n  int
}

func (s *rotatingContentToken) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return fmt.Sprintf("token-%d", s.n), nil
}

type failingContentToken struct {
	mu     sync.Mutex
	n      int
	failAt int
	err    error
}

func (s *failingContentToken) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.n == s.failAt {
		return "", s.err
	}
	return fmt.Sprintf("token-%d", s.n), nil
}

func TestPostContentArtifactLifecycle(t *testing.T) {
	script := &artifactLifecycleServer{t: t}
	base := newHTTPServer(t, http.HandlerFunc(script.handler))
	tokens := &rotatingContentToken{}
	client := loopbackClient(t, base+"/observer", tokens)

	body := []byte("line1\nline2\x00\n")
	res, err := client.PostContent(context.Background(), ContentRequest{
		NativeSessionID: "sess-abc",
		Provider:        "Claude",
		SourcePath:      "/must/not/reach\nthe/wire.jsonl",
		Body:            body,
	})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusOK || res.ArtifactID != "art_1" {
		t.Fatalf("result = %+v, want finalized art_1", res)
	}

	requests := script.requests()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want create/upload/finalize", len(requests))
	}
	wantPaths := []string{
		"/observer/api/v1/artifacts",
		"/observer/api/v1/artifacts/art_1/content",
		"/observer/api/v1/artifacts/art_1/finalize",
	}
	for i, req := range requests {
		if req.method != http.MethodPost || req.path != wantPaths[i] {
			t.Errorf("request %d = %s %s, want POST %s", i, req.method, req.path, wantPaths[i])
		}
		if req.authorization != fmt.Sprintf("Bearer token-%d", i+1) {
			t.Errorf("request %d auth = %q; credential was not read fresh", i, req.authorization)
		}
		if req.idempotencyKey == "" || len(req.idempotencyKey) > 255 {
			t.Errorf("request %d idempotency key length = %d", i, len(req.idempotencyKey))
		}
		if req.legacyNative != "" || req.legacyProvider != "" || req.legacyPath != "" {
			t.Errorf("request %d retained legacy provenance headers: %+v", i, req)
		}
	}
	if requests[0].idempotencyKey == requests[1].idempotencyKey ||
		requests[1].idempotencyKey == requests[2].idempotencyKey ||
		requests[0].idempotencyKey == requests[2].idempotencyKey {
		t.Fatalf("phase idempotency keys are not distinct: %q %q %q",
			requests[0].idempotencyKey, requests[1].idempotencyKey, requests[2].idempotencyKey)
	}

	var create artifactapi.CreateArtifactRequest
	if err := json.Unmarshal(requests[0].body, &create); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	sum := sha256.Sum256(body)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	wantKey := "observer-transcript-v1:claude:sess-abc:" + wantDigest + ":source-" + tupleHash(testSourceID)
	if create.ArtifactKey != wantKey || len(create.ArtifactKey) > 256 {
		t.Fatalf("artifact_key = %q, want %q", create.ArtifactKey, wantKey)
	}
	if create.Kind != "transcript" || create.MediaType != "application/x-ndjson" {
		t.Fatalf("create kind/media = %q %q", create.Kind, create.MediaType)
	}
	if create.DeclaredByteLength == nil || *create.DeclaredByteLength != len(body) ||
		create.DeclaredDigest == nil || *create.DeclaredDigest != wantDigest {
		t.Fatalf("create declaration = length %v digest %v", create.DeclaredByteLength, create.DeclaredDigest)
	}
	if bytes.Contains(requests[0].body, []byte("/must/not/reach")) ||
		requests[0].contentType != "application/json" {
		t.Fatalf("create leaked source path or wrong content type: %s", requests[0].body)
	}
	if requests[1].rawQuery != "part_number=0" || requests[1].contentType != "application/octet-stream" ||
		!bytes.Equal(requests[1].body, body) {
		t.Fatalf("upload = query %q type %q body %q", requests[1].rawQuery, requests[1].contentType, requests[1].body)
	}
	var finalize artifactapi.FinalizeArtifactRequest
	if err := json.Unmarshal(requests[2].body, &finalize); err != nil {
		t.Fatalf("decode finalize body: %v", err)
	}
	if finalize.ByteLength != len(body) || finalize.Digest != wantDigest {
		t.Fatalf("finalize declaration = %+v", finalize)
	}
}

func TestPostContentArtifactRetryUsesIdenticalIdentitiesAndBodies(t *testing.T) {
	script := &artifactLifecycleServer{t: t}
	base := newHTTPServer(t, http.HandlerFunc(script.handler))
	client := loopbackClient(t, base+"/observer", staticToken("token"))
	request := ContentRequest{NativeSessionID: "session", Provider: "codex", SourcePath: "/first", Body: []byte("same")}
	if _, err := client.PostContent(context.Background(), request); err != nil {
		t.Fatalf("first PostContent: %v", err)
	}
	request.SourcePath = "/moved/path"
	if _, err := client.PostContent(context.Background(), request); err != nil {
		t.Fatalf("retry PostContent: %v", err)
	}
	requests := script.requests()
	if len(requests) != 6 {
		t.Fatalf("requests = %d, want two three-phase attempts", len(requests))
	}
	for i := 0; i < 3; i++ {
		first, retry := requests[i], requests[i+3]
		if first.path != retry.path || first.rawQuery != retry.rawQuery ||
			first.idempotencyKey != retry.idempotencyKey || !bytes.Equal(first.body, retry.body) {
			t.Errorf("phase %d retry drifted\nfirst: %+v\nretry: %+v", i, first, retry)
		}
	}
}

func TestPostContentArtifactRetryAfterUncertainPhaseCommitReplaysIdentically(t *testing.T) {
	tests := []struct {
		fault             string
		firstRequestCount int
	}{
		{fault: "create-transport-once", firstRequestCount: 1},
		{fault: "upload-transport-once", firstRequestCount: 2},
		{fault: "finalize-transport-once", firstRequestCount: 3},
	}
	for _, tt := range tests {
		t.Run(tt.fault, func(t *testing.T) {
			script := &artifactLifecycleServer{t: t, fault: tt.fault}
			base := newHTTPServer(t, http.HandlerFunc(script.handler))
			client := loopbackClient(t, base+"/observer", staticToken("token"))
			request := ContentRequest{NativeSessionID: "session", Provider: "codex", Body: []byte("same snapshot")}

			if result, err := client.PostContent(context.Background(), request); err == nil || result != nil {
				t.Fatalf("first PostContent = result %+v error %v, want uncertain transport failure", result, err)
			}
			if result, err := client.PostContent(context.Background(), request); err != nil || result == nil || result.StatusCode != http.StatusOK {
				t.Fatalf("retry PostContent = result %+v error %v, want finalized success", result, err)
			}

			requests := script.requests()
			if len(requests) != tt.firstRequestCount+3 {
				t.Fatalf("requests = %d, want %d", len(requests), tt.firstRequestCount+3)
			}
			for i := 0; i < tt.firstRequestCount; i++ {
				first, replay := requests[i], requests[tt.firstRequestCount+i]
				if first.path != replay.path || first.rawQuery != replay.rawQuery ||
					first.idempotencyKey != replay.idempotencyKey || first.contentType != replay.contentType ||
					!bytes.Equal(first.body, replay.body) {
					t.Errorf("phase %d replay drifted\nfirst: %+v\nreplay: %+v", i, first, replay)
				}
			}
		})
	}
}

func TestPostContentArtifactLongIdentityUsesStableBoundedFallback(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	native := strings.Repeat("n", 256)
	first := artifactKey(testSourceID, "codex", native, digest)
	second := artifactKey(testSourceID, "codex", native, digest)
	if first != second || len(first) > 256 || !strings.HasPrefix(first, "observer-transcript-v1:sha256:") {
		t.Fatalf("fallback key = %q (%d bytes)", first, len(first))
	}
	if other := artifactKey(testSourceID, "codex", native, "sha256:"+strings.Repeat("b", 64)); other == first {
		t.Fatal("fallback key did not bind the content digest")
	}
}

func TestPostContentArtifactRejectsInvalidIdentityBeforeNetwork(t *testing.T) {
	tests := []ContentRequest{
		{NativeSessionID: "", Provider: "codex", Body: []byte("body")},
		{NativeSessionID: "bad/session", Provider: "codex", Body: []byte("body")},
		{NativeSessionID: "session", Provider: "unknown", Body: []byte("body")},
	}
	for _, request := range tests {
		t.Run(request.NativeSessionID+"_"+request.Provider, func(t *testing.T) {
			script := &artifactLifecycleServer{t: t}
			base := newHTTPServer(t, http.HandlerFunc(script.handler))
			client := loopbackClient(t, base+"/observer", staticToken("token"))
			result, err := client.PostContent(context.Background(), request)
			if !errors.Is(err, ErrInvalidContentIdentity) || result != nil {
				t.Fatalf("PostContent = result %+v error %v, want invalid identity", result, err)
			}
			if got := len(script.requests()); got != 0 {
				t.Fatalf("invalid identity sent %d requests", got)
			}
		})
	}
}

func TestPostContentArtifactRejectsMismatchedOrHostileSuccess(t *testing.T) {
	faults := []string{
		"create-artifact-long", "create-source", "create-state", "create-digest", "create-length", "create-unknown-field", "create-time-canary",
		"upload-artifact", "upload-part", "upload-length", "upload-unknown-field",
		"finalize-artifact", "finalize-source", "finalize-workspace", "finalize-state", "finalize-digest", "finalize-length",
		"finalize-unknown-field", "create-compressed", "create-oversized",
		"create-media-type", "upload-media-type", "finalize-media-type",
		"provenance-principal-type", "provenance-source-kind", "provenance-schema-version",
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			script := &artifactLifecycleServer{t: t, fault: fault}
			base := newHTTPServer(t, http.HandlerFunc(script.handler))
			client := loopbackClient(t, base+"/observer", staticToken("token"))
			res, err := client.PostContent(context.Background(), ContentRequest{
				NativeSessionID: "session", Provider: "codex", Body: []byte("body"),
			})
			if err == nil || res != nil {
				t.Fatalf("PostContent = result %+v error %v, want fail-closed error", res, err)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatalf("PostContent error leaked untrusted response data: %v", err)
			}
		})
	}
}

func TestPostContentArtifactStopsAtProblemPhase(t *testing.T) {
	tests := []struct {
		fault        string
		wantRequests int
		wantStatus   int
	}{
		{fault: "create-problem", wantRequests: 1, wantStatus: http.StatusTooManyRequests},
		{fault: "upload-problem", wantRequests: 2, wantStatus: http.StatusConflict},
		{fault: "finalize-problem", wantRequests: 3, wantStatus: http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.fault, func(t *testing.T) {
			script := &artifactLifecycleServer{t: t, fault: tt.fault}
			base := newHTTPServer(t, http.HandlerFunc(script.handler))
			client := loopbackClient(t, base+"/observer", staticToken("token"))
			result, err := client.PostContent(context.Background(), ContentRequest{
				NativeSessionID: "session", Provider: "codex", Body: []byte("body"),
			})
			if err != nil {
				t.Fatalf("PostContent: %v", err)
			}
			if result == nil || result.StatusCode != tt.wantStatus {
				t.Fatalf("result = %+v, want status %d", result, tt.wantStatus)
			}
			if got := len(script.requests()); got != tt.wantRequests {
				t.Fatalf("requests = %d, want %d", got, tt.wantRequests)
			}
		})
	}
}

func TestPostContentArtifactCredentialFailureStopsAtPhase(t *testing.T) {
	credentialErr := errors.New("credential temporarily unavailable")
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(fmt.Sprintf("phase-%d", failAt), func(t *testing.T) {
			script := &artifactLifecycleServer{t: t}
			base := newHTTPServer(t, http.HandlerFunc(script.handler))
			client := loopbackClient(t, base+"/observer", &failingContentToken{failAt: failAt, err: credentialErr})
			result, err := client.PostContent(context.Background(), ContentRequest{
				NativeSessionID: "session", Provider: "codex", SourcePath: "/private/path", Body: []byte("private body"),
			})
			if result != nil || !errors.Is(err, credentialErr) {
				t.Fatalf("PostContent = result %+v error %v, want credential error", result, err)
			}
			if got := len(script.requests()); got != failAt-1 {
				t.Fatalf("requests = %d, want %d before credential failure", got, failAt-1)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "token-") {
				t.Fatalf("credential error leaked request data: %v", err)
			}
		})
	}
}

func TestPostContentArtifactProblemReturnsStatusAndRetryAfter(t *testing.T) {
	script := &artifactLifecycleServer{t: t, fault: "problem"}
	base := newHTTPServer(t, http.HandlerFunc(script.handler))
	client := loopbackClient(t, base+"/observer", staticToken("token"))
	res, err := client.PostContent(context.Background(), ContentRequest{NativeSessionID: "s", Provider: "codex", Body: []byte("x")})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests || res.RetryAfter != 42*time.Second || res.Code != "artifact_rejected" {
		t.Fatalf("problem result = %+v", res)
	}
	if got := len(script.requests()); got != 1 {
		t.Fatalf("requests after create Problem = %d, want 1", got)
	}
}

func TestPostContentArtifactNotProvisionedStopsAfterCreate(t *testing.T) {
	script := &artifactLifecycleServer{t: t, fault: "not-provisioned"}
	base := newHTTPServer(t, http.HandlerFunc(script.handler))
	client := loopbackClient(t, base+"/observer", staticToken("token"))
	res, err := client.PostContent(context.Background(), ContentRequest{NativeSessionID: "s", Provider: "codex", Body: []byte("x")})
	if err != nil {
		t.Fatalf("PostContent: %v", err)
	}
	if res.StatusCode != http.StatusNotImplemented || len(script.requests()) != 1 {
		t.Fatalf("not-provisioned result = %+v requests=%d", res, len(script.requests()))
	}
}
