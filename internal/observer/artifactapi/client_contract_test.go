package artifactapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	wantBundleSHA256   = "e08b2b5b244a57bb3a5f4e742cb0f4d07887a579038e46099a34be05cf61cc46"
	wantDigestSHA256   = "919879c70605dc79ff12e82146cfc0fa67f6a4aae50e7f7cda8956396adf7f0d"
	wantPolicySHA256   = "da05687a27e25e1e1fb9857729fca97940b5258a59bca55564c7bc1dd18da283"
	wantContractDigest = "sha256:a9728ca23ec0f0b471d58ded2f52787819d0e54c7bd71c48b2242c1cbab36366"
)

type policyMatrix struct {
	Rows []struct {
		OperationID string `json:"operationId"`
	} `json:"rows"`
}

func contractBytes(t *testing.T, name string) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "contracts", "beadsapi", "v1", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vendored %s: %v", name, err)
	}
	return b
}

func TestVendoredArtifactContractIsFrozen(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "openapi.bundled.json", want: wantBundleSHA256},
		{name: "CONTRACT_DIGESTS.json", want: wantDigestSHA256},
		{name: "policy_matrix.json", want: wantPolicySHA256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := sha256.Sum256(contractBytes(t, tt.name))
			if got := hex.EncodeToString(sum[:]); got != tt.want {
				t.Fatalf("sha256 = %s, want frozen %s", got, tt.want)
			}
		})
	}

	var digests struct {
		ContractDigest string `json:"contract_digest"`
	}
	if err := json.Unmarshal(contractBytes(t, "CONTRACT_DIGESTS.json"), &digests); err != nil {
		t.Fatalf("decode contract digests: %v", err)
	}
	if digests.ContractDigest != wantContractDigest {
		t.Fatalf("contract_digest = %q, want %q", digests.ContractDigest, wantContractDigest)
	}
}

func TestGeneratedClientCoversFrozenOperationMatrix(t *testing.T) {
	var matrix policyMatrix
	if err := json.Unmarshal(contractBytes(t, "policy_matrix.json"), &matrix); err != nil {
		t.Fatalf("decode policy matrix: %v", err)
	}
	if got := len(matrix.Rows); got != 39 {
		t.Fatalf("policy rows = %d, want 39", got)
	}

	clientType := reflect.TypeOf((*ClientWithResponses)(nil))
	generatedOperations := make(map[string]bool, len(matrix.Rows))
	for i := 0; i < clientType.NumMethod(); i++ {
		name := clientType.Method(i).Name
		switch {
		case strings.HasSuffix(name, "WithBodyWithResponse"):
			generatedOperations[strings.TrimSuffix(name, "WithBodyWithResponse")] = true
		case strings.HasSuffix(name, "WithResponse"):
			generatedOperations[strings.TrimSuffix(name, "WithResponse")] = true
		}
	}
	gotOperations := make([]string, 0, len(generatedOperations))
	for operation := range generatedOperations {
		gotOperations = append(gotOperations, operation)
	}
	sort.Strings(gotOperations)

	wantOperations := make([]string, 0, len(matrix.Rows))
	for _, row := range matrix.Rows {
		if row.OperationID == "" {
			t.Fatal("policy matrix row has empty operationId")
		}
		wantOperations = append(wantOperations, strings.ToUpper(row.OperationID[:1])+row.OperationID[1:])
	}
	sort.Strings(wantOperations)
	if !reflect.DeepEqual(gotOperations, wantOperations) {
		t.Fatalf("generated typed operations do not match the 39-row matrix\n got: %v\nwant: %v", gotOperations, wantOperations)
	}
}

func TestGeneratedArtifactParameterShapes(t *testing.T) {
	uploadParams := reflect.TypeOf(UploadArtifactContentParams{})
	part, ok := uploadParams.FieldByName("PartNumber")
	if !ok || part.Type.Kind() != reflect.Int {
		t.Fatalf("UploadArtifactContentParams.PartNumber = %v, want required int", part.Type)
	}
	if key, ok := uploadParams.FieldByName("IdempotencyKey"); !ok || key.Type.Kind() != reflect.String {
		t.Fatalf("UploadArtifactContentParams.IdempotencyKey = %v, want required string", key.Type)
	}

	readParams := reflect.TypeOf(GetArtifactContentParams{})
	rangeField, ok := readParams.FieldByName("Range")
	if !ok || rangeField.Type != reflect.TypeOf((*string)(nil)) {
		t.Fatalf("GetArtifactContentParams.Range = %v, want optional *string", rangeField.Type)
	}

	readResponse := reflect.TypeOf(GetArtifactContentResponse{})
	body, ok := readResponse.FieldByName("Body")
	if !ok || body.Type != reflect.TypeOf([]byte(nil)) {
		t.Fatalf("GetArtifactContentResponse.Body = %v, want []byte", body.Type)
	}
	problem, ok := readResponse.FieldByName("ApplicationproblemJSONDefault")
	if !ok || problem.Type != reflect.TypeOf((*Problem)(nil)) {
		t.Fatalf("GetArtifactContentResponse.ApplicationproblemJSONDefault = %v, want *Problem", problem.Type)
	}
}

func TestGeneratedArtifactClientPreservesBinaryUploadAndRangeRead(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/artifacts/art_1/content" {
				t.Errorf("upload request = %s %s", r.Method, r.URL.Path)
			}
			if got := r.URL.Query().Get("part_number"); got != "7" {
				t.Errorf("part_number = %q, want 7", got)
			}
			if got := r.Header.Get("Idempotency-Key"); got != "idem-upload" {
				t.Errorf("Idempotency-Key = %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
				t.Errorf("Content-Type = %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "raw\x00bytes" {
				t.Errorf("upload body = %q", body)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"artifact_id":"art_1","part_number":7,"received_byte_length":9}`)
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/artifacts/art_1/content" {
				t.Errorf("read request = %s %s", r.Method, r.URL.Path)
			}
			if got := r.Header.Get("Range"); got != "bytes=1-3" {
				t.Errorf("Range = %q", got)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{1, 2, 3})
		case 3:
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/artifacts/art_1/content" {
				t.Errorf("whole read request = %s %s", r.Method, r.URL.Path)
			}
			if got := r.Header.Get("Range"); got != "" {
				t.Errorf("whole read Range = %q, want empty", got)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{4, 5})
		default:
			t.Errorf("unexpected request %d", calls)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	upload, err := client.UploadArtifactContentWithBodyWithResponse(
		context.Background(),
		"art_1",
		&UploadArtifactContentParams{IdempotencyKey: "idem-upload", PartNumber: 7},
		"application/octet-stream",
		strings.NewReader("raw\x00bytes"),
	)
	if err != nil {
		t.Fatalf("UploadArtifactContentWithBodyWithResponse: %v", err)
	}
	if upload.StatusCode() != http.StatusAccepted || upload.JSON202 == nil {
		t.Fatalf("upload response = status %d JSON202 %#v", upload.StatusCode(), upload.JSON202)
	}

	rangeHeader := "bytes=1-3"
	read, err := client.GetArtifactContentWithResponse(
		context.Background(),
		"art_1",
		&GetArtifactContentParams{Range: &rangeHeader},
	)
	if err != nil {
		t.Fatalf("GetArtifactContentWithResponse: %v", err)
	}
	if read.StatusCode() != http.StatusPartialContent || !reflect.DeepEqual(read.Body, []byte{1, 2, 3}) {
		t.Fatalf("read response = status %d body %v", read.StatusCode(), read.Body)
	}
	whole, err := client.GetArtifactContentWithResponse(context.Background(), "art_1", nil)
	if err != nil {
		t.Fatalf("whole GetArtifactContentWithResponse: %v", err)
	}
	if whole.StatusCode() != http.StatusOK || !reflect.DeepEqual(whole.Body, []byte{4, 5}) {
		t.Fatalf("whole read response = status %d body %v", whole.StatusCode(), whole.Body)
	}
	if calls != 3 {
		t.Fatalf("requests = %d, want 3", calls)
	}
}

func TestGeneratedArtifactClientDecodesDefaultProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"type":"https://errors.example/conflict","title":"conflict","status":409,"request_id":"req_1","code":"artifact_conflict"}`)
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	resp, err := client.GetArtifactWithResponse(context.Background(), "art_1")
	if err != nil {
		t.Fatalf("GetArtifactWithResponse: %v", err)
	}
	if resp.StatusCode() != http.StatusConflict || resp.ApplicationproblemJSONDefault == nil {
		t.Fatalf("default response = status %d problem %#v", resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}
	if resp.ApplicationproblemJSONDefault.Code != "artifact_conflict" || resp.ApplicationproblemJSONDefault.RequestId != "req_1" {
		t.Fatalf("decoded problem = %#v", resp.ApplicationproblemJSONDefault)
	}
}
