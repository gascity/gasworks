package executionadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPUploaderUsesArtifactSequenceAndHandlerAcksOnlyAfterObserverAck(t *testing.T) {
	var got uploadRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != executionEventsPath {
			t.Errorf("path=%q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"acknowledged_through":2}`))
	}))
	defer server.Close()
	uploader, err := NewHTTPUploader(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Endpoint: server.URL, TenantID: testKey.TenantID, WorkspaceID: testKey.WorkspaceID, SourceID: testKey.SourceID, Ledger: newMemoryLedger(), Uploader: uploader, Owner: "http"})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, a, 0)
	if err := a.ProcessRaw(context.Background(), rawRecords(41, 44)); err != nil {
		t.Fatal(err)
	}
	if got.SourceID != testSource || len(got.Records) != 2 || got.Records[0].Seq != 1 || got.Records[1].Seq != 2 {
		t.Fatalf("request=%+v", got)
	}
	var record rawRecord
	if err := json.Unmarshal(got.Records[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.ProducerSeq != 41 || record.Event.Seq != 41 {
		t.Fatalf("record=%+v", record)
	}
}
