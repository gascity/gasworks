package executionadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const executionEventsPath = "/v1/artifacts/execution-events"

// HTTPUploader posts the established raw-artifact request. A caller supplies the workspace-bound
// authenticated client; this type never writes the Observer database directly.
type HTTPUploader struct {
	endpoint string
	client   *http.Client
}

// NewHTTPUploader constructs the downstream Observer transport.
func NewHTTPUploader(endpoint string, client *http.Client) (*HTTPUploader, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("execution-event adapter: Observer endpoint required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPUploader{endpoint: endpoint, client: client}, nil
}

type uploadRequest struct {
	SourceID string         `json:"source_id"`
	Records  []uploadRecord `json:"records"`
}
type uploadRecord struct {
	Seq     uint64          `json:"seq"`
	Payload json.RawMessage `json:"payload"`
}
type uploadResponse struct {
	AcknowledgedThrough uint64 `json:"acknowledged_through"`
}

// Upload sends rows in their adapter-owned order and returns only a strict durable acknowledgement.
func (u *HTTPUploader) Upload(ctx context.Context, key SourceKey, rows []MappedRecord) (uint64, error) {
	reqBody := uploadRequest{SourceID: key.SourceID, Records: make([]uploadRecord, 0, len(rows))}
	for _, row := range rows {
		reqBody.Records = append(reqBody.Records, uploadRecord{Seq: row.ArtifactSeq, Payload: json.RawMessage(row.Record.Payload)})
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("execution-event adapter: encode upload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint+executionEventsPath, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("execution-event adapter: build upload: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("execution-event adapter: upload: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("execution-event adapter: read acknowledgement: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("execution-event adapter: Observer status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ack uploadResponse
	if err := dec.Decode(&ack); err != nil {
		return 0, fmt.Errorf("execution-event adapter: decode acknowledgement: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return 0, fmt.Errorf("execution-event adapter: trailing acknowledgement: %w", err)
	}
	return ack.AcknowledgedThrough, nil
}

// Handler receives the frozen eventexport batch. It returns 200 only once Observer and the durable
// mapping both acknowledge the complete batch; any error leaves the producer cursor held.
func (a *Adapter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err == nil {
			err = a.ProcessRaw(r.Context(), body)
		}
		if err != nil {
			http.Error(w, "execution-event adapter: batch held", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	})
}

var _ Uploader = (*HTTPUploader)(nil)
