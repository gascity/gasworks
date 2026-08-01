package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/artifactapi"
)

const (
	artifactKeyPrefix = "observer-transcript-v1:"
	artifactKind      = "transcript"
	artifactMediaType = "application/x-ndjson"
	artifactPartType  = "application/octet-stream"
	maxArtifactKeyLen = 256
	maxNativeIDLen    = 256
)

var artifactNativeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

var (
	// ErrArtifactResponseTooLarge is returned before a generated response parser
	// can buffer more than the Observer response ceiling.
	ErrArtifactResponseTooLarge = errors.New("observer upload: artifact response exceeds byte limit")
	// ErrInvalidArtifactResponse means a nominal success did not satisfy the
	// source, identity, phase, or closed-DTO contract. No content marker advances.
	ErrInvalidArtifactResponse = errors.New("observer upload: invalid artifact response")
	// ErrInvalidContentIdentity prevents a malformed native session or unknown
	// provider from becoming a stable server-side artifact identity.
	ErrInvalidContentIdentity = errors.New("observer upload: invalid artifact content identity")
)

// ContentRequest is one immutable whole-transcript snapshot. SourcePath remains
// local watcher context: the frozen artifact body has no caller-controlled
// provenance or filesystem-path member, so it is never sent.
type ContentRequest struct {
	NativeSessionID string
	Provider        string
	SourcePath      string
	Body            []byte
}

// ContentResult is the terminal result of create -> part 0 -> finalize, or the
// first non-success HTTP response. A 200 result always means finalization was
// decoded and validated; intermediate 201/202 responses are never success here.
type ContentResult struct {
	StatusCode  int
	ArtifactID  string
	ArtifactKey string
	Digest      string
	RetryAfter  time.Duration
	// Code is the bounded machine code from a default Problem response, when one
	// was decoded. Problem detail/body bytes are never retained or logged.
	Code string
}

// artifactResponseDoer preserves the existing transport policy around the
// generated client. Metadata calls keep the short attempt timeout; only the
// binary part upload receives the whole-content timeout.
type artifactResponseDoer struct {
	metadata *http.Client
	content  *http.Client
}

func (d artifactResponseDoer) Do(req *http.Request) (*http.Response, error) {
	client := d.metadata
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/content") {
		client = d.content
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		drainClose(resp)
		return nil, ErrUnsupportedContentEncoding
	}
	resp.Body = &artifactResponseBody{body: resp.Body, remaining: maxResponseBytes}
	return resp, nil
}

// artifactResponseBody returns an error rather than a truncated body when the
// generated parser attempts to read beyond maxResponseBytes. A valid prefix can
// therefore never hide trailing attacker-controlled bytes beyond the ceiling.
type artifactResponseBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *artifactResponseBody) Read(p []byte) (int, error) {
	if b.remaining > 0 {
		if int64(len(p)) > b.remaining {
			p = p[:b.remaining]
		}
		n, err := b.body.Read(p)
		b.remaining -= int64(n)
		return n, err
	}
	var probe [1]byte
	n, err := b.body.Read(probe[:])
	if n > 0 {
		return 0, ErrArtifactResponseTooLarge
	}
	return 0, err
}

func (b *artifactResponseBody) Close() error { return b.body.Close() }

// authorizeArtifactRequest reads the rotating credential fresh for every phase.
// The generated client never stores the bearer value.
func (c *Client) authorizeArtifactRequest(ctx context.Context, req *http.Request) error {
	token, err := c.cred.Token(ctx)
	if err != nil {
		return err
	}
	if token == "" {
		return ErrEmptyCredential
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return nil
}

// PostContent publishes one immutable transcript snapshot through the generated
// artifact lifecycle. Each phase has a deterministic idempotency key, so a retry
// after any uncertain commit replays the same operation and converges.
func (c *Client) PostContent(ctx context.Context, request ContentRequest) (*ContentResult, error) {
	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	if !ValidContentIdentity(request.NativeSessionID, provider) {
		return nil, ErrInvalidContentIdentity
	}
	digest := artifactDigest(request.Body)
	key := artifactKey(c.sourceID, provider, request.NativeSessionID, digest)
	length := len(request.Body)

	create, err := c.artifacts.CreateArtifactWithResponse(ctx,
		&artifactapi.CreateArtifactParams{IdempotencyKey: artifactIdempotencyKey(key, "create")},
		artifactapi.CreateArtifactRequest{
			ArtifactKey:        key,
			DeclaredByteLength: &length,
			DeclaredDigest:     &digest,
			Kind:               artifactKind,
			MediaType:          artifactMediaType,
		},
	)
	if err != nil {
		return nil, classifyArtifactCall(err)
	}
	if create.StatusCode() != http.StatusCreated {
		return artifactFailure(create.HTTPResponse, create.ApplicationproblemJSONDefault)
	}
	if err := validateArtifactSuccessMediaType(create.HTTPResponse); err != nil {
		return nil, err
	}
	if create.JSON201 == nil {
		return nil, fmt.Errorf("%w: create body", ErrInvalidArtifactResponse)
	}
	var opened artifactapi.Artifact
	if err := strictDecodeResponse(create.Body, &opened); err != nil {
		return nil, fmt.Errorf("%w: create body", ErrInvalidArtifactResponse)
	}
	if err := validateArtifact(opened, c.sourceID, key, artifactapi.ArtifactStateOpen, length, digest, false); err != nil {
		return nil, err
	}

	uploaded, err := c.artifacts.UploadArtifactContentWithBodyWithResponse(ctx,
		opened.ArtifactId,
		&artifactapi.UploadArtifactContentParams{
			PartNumber:     0,
			IdempotencyKey: artifactIdempotencyKey(key, "part-0"),
		},
		artifactPartType,
		bytes.NewReader(request.Body),
	)
	if err != nil {
		return nil, classifyArtifactCall(err)
	}
	if uploaded.StatusCode() != http.StatusAccepted {
		return artifactFailure(uploaded.HTTPResponse, uploaded.ApplicationproblemJSONDefault)
	}
	if err := validateArtifactSuccessMediaType(uploaded.HTTPResponse); err != nil {
		return nil, err
	}
	if uploaded.JSON202 == nil {
		return nil, fmt.Errorf("%w: upload body", ErrInvalidArtifactResponse)
	}
	var part artifactapi.ArtifactContentPart
	if err := strictDecodeResponse(uploaded.Body, &part); err != nil {
		return nil, fmt.Errorf("%w: upload body", ErrInvalidArtifactResponse)
	}
	if part.ArtifactId != opened.ArtifactId || part.PartNumber != 0 || part.ReceivedByteLength != length {
		return nil, fmt.Errorf("%w: upload identity or length", ErrInvalidArtifactResponse)
	}

	finalized, err := c.artifacts.FinalizeArtifactWithResponse(ctx,
		opened.ArtifactId,
		&artifactapi.FinalizeArtifactParams{IdempotencyKey: artifactIdempotencyKey(key, "finalize")},
		artifactapi.FinalizeArtifactRequest{ByteLength: length, Digest: digest},
	)
	if err != nil {
		return nil, classifyArtifactCall(err)
	}
	if finalized.StatusCode() != http.StatusOK {
		return artifactFailure(finalized.HTTPResponse, finalized.ApplicationproblemJSONDefault)
	}
	if err := validateArtifactSuccessMediaType(finalized.HTTPResponse); err != nil {
		return nil, err
	}
	if finalized.JSON200 == nil {
		return nil, fmt.Errorf("%w: finalize body", ErrInvalidArtifactResponse)
	}
	var sealed artifactapi.Artifact
	if err := strictDecodeResponse(finalized.Body, &sealed); err != nil {
		return nil, fmt.Errorf("%w: finalize body", ErrInvalidArtifactResponse)
	}
	if sealed.ArtifactId != opened.ArtifactId {
		return nil, fmt.Errorf("%w: finalize artifact identity", ErrInvalidArtifactResponse)
	}
	if err := validateArtifact(sealed, c.sourceID, key, artifactapi.ArtifactStateFinalized, length, digest, true); err != nil {
		return nil, err
	}
	if err := validateArtifactContinuity(opened, sealed); err != nil {
		return nil, err
	}
	return &ContentResult{
		StatusCode:  http.StatusOK,
		ArtifactID:  sealed.ArtifactId,
		ArtifactKey: key,
		Digest:      digest,
	}, nil
}

// classifyArtifactCall preserves transport and credential error identity while
// replacing JSON/time decoder details that may echo untrusted response values.
func classifyArtifactCall(err error) error {
	var syntaxError *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	var timeError *time.ParseError
	if errors.As(err, &syntaxError) || errors.As(err, &typeError) || errors.As(err, &timeError) {
		return fmt.Errorf("%w: response body", ErrInvalidArtifactResponse)
	}
	return classifyDo(err)
}

// ValidContentIdentity is shared by the daemon preflight and the network
// boundary. It accepts only the two transcript providers and the established
// bounded native-session grammar.
func ValidContentIdentity(nativeSessionID, provider string) bool {
	return nativeSessionID != "" && len(nativeSessionID) <= maxNativeIDLen &&
		artifactNativeIDPattern.MatchString(nativeSessionID) &&
		(provider == "claude" || provider == "codex")
}

func artifactFailure(response *http.Response, problem *artifactapi.Problem) (*ContentResult, error) {
	if response == nil {
		return nil, fmt.Errorf("%w: missing HTTP response", ErrInvalidArtifactResponse)
	}
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return nil, fmt.Errorf("%w: unexpected success status %d", ErrInvalidArtifactResponse, response.StatusCode)
	}
	result := &ContentResult{
		StatusCode: response.StatusCode,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")),
	}
	if problem != nil && len(problem.Code) <= 128 {
		result.Code = problem.Code
	}
	return result, nil
}

func validateArtifactSuccessMediaType(response *http.Response) error {
	if response == nil {
		return fmt.Errorf("%w: missing HTTP response", ErrInvalidArtifactResponse)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: success media type", ErrInvalidArtifactResponse)
	}
	return nil
}

func validateArtifact(artifact artifactapi.Artifact, sourceID, key string, state artifactapi.ArtifactState, length int, digest string, finalized bool) error {
	if !nonEmptyBounded(artifact.ArtifactId, 128) || artifact.ArtifactKey != key || artifact.Provenance.SourceId != sourceID ||
		artifact.Kind != artifactKind || artifact.MediaType != artifactMediaType || artifact.State != state {
		return fmt.Errorf("%w: artifact identity, source, or state", ErrInvalidArtifactResponse)
	}
	provenance := artifact.Provenance
	if !nonEmptyBounded(provenance.OrgId, 128) || !nonEmptyBounded(provenance.WorkspaceId, 128) ||
		!nonEmptyBounded(provenance.PrincipalId, 128) || !provenance.PrincipalType.Valid() ||
		!nonEmptyBounded(provenance.SourceId, 128) || !provenance.SourceKind.Valid() ||
		!nonEmptyBounded(provenance.SchemaVersion, 64) || !nonEmptyBounded(provenance.PolicyDigest, 128) ||
		!nonEmptyBounded(artifact.Links.Self.Href, 2048) || artifact.CreatedAt.IsZero() || provenance.IngestedAt.IsZero() {
		return fmt.Errorf("%w: required provenance or link", ErrInvalidArtifactResponse)
	}
	if artifact.Labels != nil {
		if len(*artifact.Labels) > 64 {
			return fmt.Errorf("%w: artifact labels", ErrInvalidArtifactResponse)
		}
		for _, label := range *artifact.Labels {
			if len(label) > 128 {
				return fmt.Errorf("%w: artifact labels", ErrInvalidArtifactResponse)
			}
		}
	}
	if artifact.ByteLength != nil && *artifact.ByteLength != length {
		return fmt.Errorf("%w: artifact byte length", ErrInvalidArtifactResponse)
	}
	if artifact.Digest != nil && *artifact.Digest != digest {
		return fmt.Errorf("%w: artifact digest", ErrInvalidArtifactResponse)
	}
	if finalized && (artifact.ByteLength == nil || artifact.Digest == nil) {
		return fmt.Errorf("%w: finalized digest or length", ErrInvalidArtifactResponse)
	}
	return nil
}

func nonEmptyBounded(value string, max int) bool {
	return value != "" && len(value) <= max
}

func validateArtifactContinuity(opened, sealed artifactapi.Artifact) error {
	before, after := opened.Provenance, sealed.Provenance
	if before.OrgId != after.OrgId || before.WorkspaceId != after.WorkspaceId ||
		before.PrincipalId != after.PrincipalId || before.PrincipalType != after.PrincipalType ||
		before.SourceId != after.SourceId || before.SourceKind != after.SourceKind ||
		before.SchemaVersion != after.SchemaVersion || before.PolicyDigest != after.PolicyDigest ||
		!before.IngestedAt.Equal(after.IngestedAt) || !opened.CreatedAt.Equal(sealed.CreatedAt) ||
		opened.Links.Self.Href != sealed.Links.Self.Href {
		return fmt.Errorf("%w: artifact provenance continuity", ErrInvalidArtifactResponse)
	}
	return nil
}

func artifactDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func artifactKey(sourceID, provider, nativeSessionID, digest string) string {
	// Keep the provider/native lineage readable for server-side transcript
	// association, but bind uniqueness to the credential-derived source without
	// restating that authority field verbatim in caller-controlled metadata.
	direct := artifactKeyPrefix + provider + ":" + nativeSessionID + ":" + digest + ":source-" + tupleHash(sourceID)
	if len(direct) <= maxArtifactKeyLen {
		return direct
	}
	return artifactKeyPrefix + "sha256:" + tupleHash(sourceID, provider, nativeSessionID, digest)
}

func artifactIdempotencyKey(artifactKey, phase string) string {
	return "gw-observer-artifact-v1:" + tupleHash(artifactKey) + ":" + phase
}

// tupleHash length-prefixes every member so boundaries are unambiguous even if
// an upstream identifier later admits a delimiter used by artifactKey.
func tupleHash(fields ...string) string {
	h := sha256.New()
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, field)
	}
	return hex.EncodeToString(h.Sum(nil))
}
