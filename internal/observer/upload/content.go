package upload

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// contentPath is the Phase 1a raw-transcript content route on the observer collector. It is
// appended to the same observer-rooted base URL the observation-batch and capabilities routes use,
// so a collector base of https://host/observer targets https://host/observer/v1/artifacts/content.
const contentPath = "/v1/artifacts/content"

// Content request headers (Phase 1a contract). The server keys the snapshot by the native session
// id, records the provider, and retains the source path for operator provenance.
const (
	headerNativeSessionID = "X-Observer-Native-Session-Id"
	headerGCSessionID     = "X-Observer-Gc-Session-Id"
	headerProvider        = "X-Observer-Provider"
	headerSourcePath      = "X-Observer-Source-Path"
)

// ContentRequest is one whole-transcript snapshot upload. Body is the raw transcript file bytes;
// the client sends them verbatim under the source-bound bearer credential, adding only the
// provenance headers the Phase 1a endpoint requires.
type ContentRequest struct {
	// NativeSessionID is the transcript's native (provider) session id — the dedup + CASS key.
	NativeSessionID string
	// GCSessionID is the optional authoritative Gas City binding read from a transcript sidecar.
	// Empty means unknown and is deliberately omitted from the request.
	GCSessionID string
	// Provider is the lowercase provider label ("claude" or "codex").
	Provider string
	// SourcePath is the transcript file path, retained by the server for provenance only.
	SourcePath string
	// Body is the raw transcript bytes (the whole current file).
	Body []byte
}

// ContentResult is the typed outcome of one content POST: the HTTP status plus the server's decoded
// receipt (on 2xx) and any Retry-After the server asked for (on a shed). A transport-level failure
// is reported as an error from PostContent instead, with no result. The caller classifies by
// StatusCode: 200/201 accepted, 409 idempotency-content-mismatch, 429 shed (honor RetryAfter), 501
// tenant not provisioned (content disabled), other 5xx/4xx retryable/hold per the caller's policy.
type ContentResult struct {
	StatusCode  int
	GCSessionID string
	ReceiptID   string
	Status      string
	RetryAfter  time.Duration
	// Message is the server's content-free error message when a typed error body decoded.
	Message string
}

// contentAck is the decoded 2xx body of a content upload.
type contentAck struct {
	GCSessionID  string `json:"gc_session_id"`
	TranscriptID string `json:"transcript_id"`
	ReceiptID    string `json:"receipt_id"`
	Status       string `json:"status"`
}

// PostContent uploads one whole-transcript snapshot to the collector's content route. It reads the
// bearer credential fresh (like Send), sends the raw body under application/octet-stream with the
// three provenance headers, refuses redirects and enforces the HTTPS floor through the shared
// transport, and decodes the typed receipt on 2xx. Any HTTP status returns a non-nil result; only a
// transport, redirect, TLS, timeout, or content-encoding failure returns an error (no result).
func (c *Client) PostContent(ctx context.Context, r ContentRequest) (*ContentResult, error) {
	req, err := c.newRequest(ctx, http.MethodPost, contentPath, r.Body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(headerNativeSessionID, r.NativeSessionID)
	if r.GCSessionID != "" {
		req.Header.Set(headerGCSessionID, r.GCSessionID)
	}
	req.Header.Set(headerProvider, strings.ToLower(r.Provider))
	req.Header.Set(headerSourcePath, r.SourcePath)

	resp, err := c.content.Do(req)
	if err != nil {
		return nil, classifyDo(err)
	}
	defer drainClose(resp)

	body, err := readBounded(resp)
	if err != nil {
		return nil, err
	}

	res := &ContentResult{
		StatusCode: resp.StatusCode,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var ack contentAck
		if err := strictDecodeResponse(body, &ack); err == nil {
			res.GCSessionID = ack.GCSessionID
			res.ReceiptID = ack.ReceiptID
			res.Status = ack.Status
		}
		return res, nil
	}
	if eb, ok := decodeError(body); ok {
		res.Message = messageOf(eb)
	}
	return res, nil
}
