package upload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gascity/gasworks/internal/observer/artifactapi"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// Wire routes (docs/design/gasworks-observer-mvp.md "Ingest wire contract").
const (
	ingestPath       = "/v1/observation-batches"
	capabilitiesPath = "/v1/observer-capabilities"
)

// DefaultAttemptTimeout bounds a single delivery attempt (connect + TLS + write + read)
// when the caller supplies no context deadline. Timeouts are always bounded.
const DefaultAttemptTimeout = 30 * time.Second

// DefaultContentTimeout bounds a single whole-transcript content upload. It is far larger
// than DefaultAttemptTimeout because a content POST streams the entire transcript (up to
// hundreds of MiB) rather than a small observation batch, and the 30 s attempt timeout would
// otherwise cut a large upload over a slow link and force a wasteful re-read/re-hash/re-send
// loop. It is still bounded so a hung server cannot stall the content loop forever.
const DefaultContentTimeout = 10 * time.Minute

// maxResponseBytes bounds a decoded response body so a hostile or misconfigured server
// cannot exhaust memory. Ack and capabilities responses are small typed JSON.
const maxResponseBytes int64 = 1 << 20

// Transport-level failure sentinels. These never carry a credential and never advance the
// acknowledgement; the retry layer classifies them (redirect/transport → retry with
// backoff; unsupported content-encoding → hold).
var (
	// ErrRedirectRefused is returned when the server answers with a redirect. Credentials
	// and content must never move to another host, so the client refuses to follow it. The
	// error names only the target host, never the credential.
	ErrRedirectRefused = errors.New("observer upload: redirect refused (credentials never move host)")
	// ErrInsecureScheme is returned when the endpoint is not HTTPS and loopback-HTTP dev
	// mode was not explicitly enabled.
	ErrInsecureScheme = errors.New("observer upload: endpoint must be https (loopback http requires explicit dev mode)")
	// ErrUnsupportedContentEncoding is returned when a response carries a Content-Encoding
	// the client did not request and cannot verify. V1 rejects it rather than risk
	// mis-decoding a compressed body against the decompressed limits.
	ErrUnsupportedContentEncoding = errors.New("observer upload: unsupported response Content-Encoding")
	// ErrEmptyCredential is returned when a credential source yields an empty token.
	ErrEmptyCredential = errors.New("observer upload: credential source returned an empty token")
	// ErrSourceMismatch is returned when a formed batch's source id does not match the
	// client's configured, credential-bound source. A body field can never claim a
	// different binding, so the client refuses to send it.
	ErrSourceMismatch = errors.New("observer upload: batch source_id does not match the configured source binding")
	// ErrEmptySourceID is returned when a Client or Deliverer is built with an empty source
	// id. The credential is source-bound by contract, so an unbound client is never valid:
	// an empty binding would silently disable both local source-binding controls (outbound
	// body-source verification and inbound ack-source verification). We fail closed instead.
	ErrEmptySourceID = errors.New("observer upload: source id must not be empty (credential is source-bound)")
	// ErrSystemCertPoolUnavailable is returned when an additive customer CA is configured but
	// the system trust store cannot be loaded. Falling back to the customer CAs alone would
	// silently narrow trust below the additive contract, so construction fails instead.
	ErrSystemCertPoolUnavailable = errors.New("observer upload: system cert pool unavailable; refusing to narrow trust to customer CAs only")
)

// systemCertPool is the seam for loading the system trust store; tests override it to
// exercise the additive-CA failure path.
var systemCertPool = x509.SystemCertPool

// CredentialSource yields the current bearer token. It is read fresh on EACH attempt so a
// rotated token is picked up without restart, and the returned value is never logged or
// stored in the spool. Implementations must not cache across calls.
type CredentialSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenFileSource reads a bearer token from a rotating file on each call. The token is
// never cached, so rotating the file (atomic replace) is observed on the next attempt.
type TokenFileSource struct {
	// Path is the token file, expected owner-only.
	Path string
}

// Token reads and returns the current token, trimming trailing whitespace/newline. An
// empty file is ErrEmptyCredential; the raw file bytes never enter an error string.
func (s TokenFileSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		// The path itself is not secret, but the file contents must never leak; ReadFile's
		// error names only the path, so it is safe to wrap.
		return "", fmt.Errorf("observer upload: read token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", ErrEmptyCredential
	}
	return tok, nil
}

// HelperError is a sanitized workload-identity helper failure. It intentionally retains no
// helper output: a failing helper may print a partial or full token to stdout/stderr, so
// only a generic reason and the exit signal survive. errors.Is(err, ErrHelperFailed)
// matches it.
type HelperError struct {
	// Reason is a bounded, output-free description (e.g. "exit status 1", "timed out",
	// "output exceeded bound", "empty token").
	Reason string
}

// Error renders the sanitized reason without any captured helper output.
func (e *HelperError) Error() string {
	return "observer upload: workload-identity helper failed: " + e.Reason
}

// Is lets errors.Is(err, ErrHelperFailed) match a *HelperError.
func (e *HelperError) Is(target error) bool { return target == ErrHelperFailed }

// ErrHelperFailed is the sentinel matched by errors.Is for any helper failure.
var ErrHelperFailed = errors.New("observer upload: workload-identity helper failed")

// HelperSource obtains a bearer token from a customer workload-identity helper. The helper
// is a FIXED argv (never shell text), runs with a bounded time and output cap and a
// minimal environment, and its output is treated as opaque token material — a failure
// surfaces a sanitized reason with no captured output, so a token cannot leak through an
// error path or a log line.
type HelperSource struct {
	// Argv is the fixed argument vector; Argv[0] is the executable (use an absolute path)
	// and is executed directly, never through a shell.
	Argv []string
	// Timeout bounds one helper invocation (0 selects DefaultHelperTimeout).
	Timeout time.Duration
	// MaxOutput bounds captured stdout bytes (0 selects DefaultHelperMaxOutput). Output
	// past the bound is a failure, not a truncated token.
	MaxOutput int64
	// Env is the minimal environment passed to the helper; nil runs it with an empty
	// environment. It never inherits the daemon's environment implicitly.
	Env []string
}

// Helper bounds.
const (
	// DefaultHelperTimeout bounds one helper invocation.
	DefaultHelperTimeout = 5 * time.Second
	// DefaultHelperMaxOutput bounds captured helper stdout.
	DefaultHelperMaxOutput int64 = 64 << 10
)

// Token runs the helper and returns its stdout as the token. On any failure it returns a
// *HelperError whose message contains no captured output. The success path returns the
// trimmed token and retains nothing.
//
// Output is bounded by reading at most MaxOutput+1 bytes from a pipe and killing the child
// on overflow, so a flooding helper cannot fill the pipe and wedge the wait; stderr is
// drained to io.Discard so it can never block and is never captured into an error.
func (h HelperSource) Token(ctx context.Context) (string, error) {
	if len(h.Argv) == 0 {
		return "", &HelperError{Reason: "no argv configured"}
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}
	maxOut := h.MaxOutput
	if maxOut <= 0 {
		maxOut = DefaultHelperMaxOutput
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, h.Argv[0], h.Argv[1:]...)
	// Minimal environment: nil Env means the helper would inherit the parent's, so force
	// an explicit (possibly empty) environment.
	if h.Env != nil {
		cmd.Env = h.Env
	} else {
		cmd.Env = []string{}
	}
	cmd.Stderr = io.Discard // may echo a token; drained and never captured

	// Bounded stdout: the buffer always accepts bytes (so the helper never blocks on a full
	// pipe) but retains only the first maxOut and, on overflow, kills the helper. WaitDelay
	// bounds a grandchild that inherits and holds the pipe after the helper is killed, so a
	// pathological helper can never wedge Wait.
	out := &boundedBuffer{limit: int(maxOut), onOverflow: cancel}
	cmd.Stdout = out
	cmd.WaitDelay = time.Second

	err := cmd.Run()

	switch {
	case out.overflowed():
		return "", &HelperError{Reason: "output exceeded bound"}
	case runCtx.Err() == context.DeadlineExceeded:
		return "", &HelperError{Reason: "timed out"}
	case runCtx.Err() == context.Canceled:
		return "", &HelperError{Reason: "canceled"}
	case errors.Is(err, exec.ErrWaitDelay):
		// The helper exited but a grandchild it spawned still holds the stdout pipe;
		// WaitDelay closed it. Distinct from a non-executable helper so an operator is not
		// misdirected. No output is retained in the reason.
		return "", &HelperError{Reason: "helper i/o not closed"}
	case err != nil:
		return "", &HelperError{Reason: sanitizedExitReason(err)}
	}
	tok := strings.TrimSpace(out.string())
	if tok == "" {
		return "", &HelperError{Reason: "empty token"}
	}
	return tok, nil
}

// boundedBuffer captures at most limit bytes of a helper's stdout. It always accepts the
// full write (so the helper never blocks on a full pipe) but discards past the cap, and on
// the first byte over the cap it invokes onOverflow (which kills the helper). It is written
// only by exec's copy goroutine and read only after cmd.Run has returned, which synchronizes
// with that goroutine's completion — so no lock is needed.
type boundedBuffer struct {
	buf        []byte
	seen       int
	limit      int
	overflow   bool
	onOverflow func()
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.seen += len(p)
	if room := b.limit - len(b.buf); room > 0 {
		take := len(p)
		if take > room {
			take = room
		}
		b.buf = append(b.buf, p[:take]...)
	}
	if b.seen > b.limit && !b.overflow {
		b.overflow = true
		if b.onOverflow != nil {
			b.onOverflow()
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) overflowed() bool { return b.overflow }
func (b *boundedBuffer) string() string   { return string(b.buf) }

// sanitizedExitReason returns an output-free description of a helper exit error.
func sanitizedExitReason(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return "exit " + strconv.Itoa(ee.ExitCode())
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "helper not found"
	}
	return "not executable"
}

// Config configures the authenticated HTTPS Collector client.
type Config struct {
	// Endpoint is the Collector base URL (scheme + host[:port]); paths are appended. It
	// must be https unless AllowLoopbackHTTP is set and the host is loopback.
	Endpoint *url.URL
	// SourceID is the credential-bound Observer source; a batch whose body claims a
	// different source is refused before it is sent.
	SourceID string
	// Credential yields the bearer token, read fresh per attempt.
	Credential CredentialSource
	// CustomCAs are additive trust anchors merged on top of the system roots (a customer
	// CA bundle, or an intercepting egress proxy's CA). TLS verification stays on; these
	// only widen trust, never disable it.
	CustomCAs []*x509.Certificate
	// Proxy is an explicit corporate egress proxy (http/https). nil disables proxying;
	// the environment is never consulted implicitly.
	Proxy *url.URL
	// AttemptTimeout bounds a single attempt (0 selects DefaultAttemptTimeout).
	AttemptTimeout time.Duration
	// ContentTimeout bounds a single whole-transcript content upload (0 selects
	// DefaultContentTimeout). It is separate from AttemptTimeout because content bodies are
	// orders of magnitude larger than observation batches.
	ContentTimeout time.Duration
	// AllowLoopbackHTTP permits a plain-HTTP endpoint only when the host is loopback — an
	// explicit development mode, never a production path.
	AllowLoopbackHTTP bool
	// TLSMinVersion is the TLS floor (0 selects tls.VersionTLS12).
	TLSMinVersion uint16
}

// Client is the authenticated HTTPS Collector client. It refuses redirects, enforces the
// HTTPS floor, verifies TLS against the system roots plus any additive customer CA, reads
// the credential fresh on each request, and decodes typed responses against the wire
// contract.
type Client struct {
	http      *http.Client
	content   *http.Client
	artifacts *artifactapi.ClientWithResponses
	base      *url.URL
	sourceID  string
	cred      CredentialSource
}

// NewClient validates the configuration and builds the client. It fails closed on an
// insecure scheme or a missing credential source.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == nil {
		return nil, errors.New("observer upload: nil endpoint")
	}
	if err := checkScheme(cfg.Endpoint, cfg.AllowLoopbackHTTP); err != nil {
		return nil, err
	}
	if cfg.Credential == nil {
		return nil, errors.New("observer upload: nil credential source")
	}
	if cfg.SourceID == "" {
		return nil, ErrEmptySourceID
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	rt := &http.Transport{
		// DisableCompression stops the transport from adding Accept-Encoding: gzip and
		// transparently inflating responses, so the client sees and can reject any
		// unexpected Content-Encoding rather than silently decoding it.
		DisableCompression:  true,
		TLSClientConfig:     tlsCfg,
		Proxy:               proxyFunc(cfg.Proxy),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	// The observation-batch client and the content client share one transport (connection pool,
	// TLS config, redirect refusal) but carry different whole-request timeouts: batches are small
	// and bounded at the attempt timeout, whereas a whole-transcript content upload needs a much
	// larger ceiling so a large body over a slow link is not cut and re-sent in a loop.
	transport := &http.Client{
		Timeout:       attemptTimeoutOrDefault(cfg.AttemptTimeout),
		CheckRedirect: refuseRedirect,
		Transport:     rt,
	}
	contentClient := &http.Client{
		Timeout:       contentTimeoutOrDefault(cfg.ContentTimeout),
		CheckRedirect: refuseRedirect,
		Transport:     rt,
	}
	base := *cfg.Endpoint
	base.Path = strings.TrimRight(base.Path, "/")
	client := &Client{
		http:     transport,
		content:  contentClient,
		base:     &base,
		sourceID: cfg.SourceID,
		cred:     cfg.Credential,
	}
	artifacts, err := artifactapi.NewClientWithResponses(
		base.String(),
		artifactapi.WithHTTPClient(artifactResponseDoer{metadata: transport, content: contentClient}),
		artifactapi.WithRequestEditorFn(client.authorizeArtifactRequest),
	)
	if err != nil {
		return nil, fmt.Errorf("observer upload: build artifact client: %w", err)
	}
	client.artifacts = artifacts
	return client, nil
}

// checkScheme enforces the HTTPS floor. Plain HTTP is permitted only for a loopback host
// under an explicit dev flag.
func checkScheme(u *url.URL, allowLoopbackHTTP bool) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowLoopbackHTTP && isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %q", ErrInsecureScheme, u.Redacted())
	default:
		return fmt.Errorf("%w: scheme %q", ErrInsecureScheme, u.Scheme)
	}
}

// isLoopbackHost reports whether host is a loopback address or localhost.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// buildTLSConfig builds the TLS floor with additive customer trust anchors. The floor is
// clamped to at least TLS 1.2 (a configured value may raise it but never lower it), it
// starts from the system roots (so customer CAs are additive, never a replacement), and it
// never disables verification. If the system trust store cannot be loaded while a customer
// CA is configured, construction fails rather than silently narrowing trust.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	min := cfg.TLSMinVersion
	if min < tls.VersionTLS12 {
		// Covers both the unset (0) case and any explicit sub-1.2 value: the floor can be
		// raised but never lowered below TLS 1.2.
		min = tls.VersionTLS12
	}
	tlsCfg := &tls.Config{MinVersion: min}
	if len(cfg.CustomCAs) > 0 {
		pool, err := systemCertPool()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSystemCertPoolUnavailable, err)
		}
		if pool == nil {
			return nil, ErrSystemCertPoolUnavailable
		}
		for _, c := range cfg.CustomCAs {
			if c == nil {
				continue
			}
			pool.AddCert(c)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// proxyFunc returns a fixed-proxy selector, or nil when no proxy is configured. The
// environment is never consulted implicitly — the egress proxy is always explicit.
func proxyFunc(p *url.URL) func(*http.Request) (*url.URL, error) {
	if p == nil {
		return nil
	}
	fixed := *p
	return func(*http.Request) (*url.URL, error) { return &fixed, nil }
}

// refuseRedirect makes the client never follow a redirect: credentials and content must
// not move to another host. Returning an error here stops the transport before it copies
// any header to the redirect target.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("%w: %s", ErrRedirectRefused, req.URL.Host)
}

// contentTimeoutOrDefault selects the whole-transcript content-upload timeout.
func contentTimeoutOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultContentTimeout
	}
	return d
}

func attemptTimeoutOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultAttemptTimeout
	}
	return d
}

// Attempt is the typed outcome of one HTTP round trip: the status code, a decoded ack (on
// 2xx), a decoded error body (on a typed error status), and any Retry-After the server
// asked for. A transport-level failure is reported as an error from Send/Capabilities
// instead, with no Attempt.
type Attempt struct {
	StatusCode int
	Ack        *wire.IngestAck
	ErrorBody  *wire.ObserverErrorBody
	RetryAfter time.Duration
}

// Capabilities probes GET /v1/observer-capabilities with the source-bound credential and
// returns the clamped delivery ceiling. It is the non-mutating call setup/doctor also use.
func (c *Client) Capabilities(ctx context.Context) (Caps, wire.CapabilitiesResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, capabilitiesPath, nil)
	if err != nil {
		return Caps{}, wire.CapabilitiesResponse{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Caps{}, wire.CapabilitiesResponse{}, classifyDo(err)
	}
	defer drainClose(resp)

	body, err := readBounded(resp)
	if err != nil {
		return Caps{}, wire.CapabilitiesResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		errBody, _ := decodeError(body)
		return Caps{}, wire.CapabilitiesResponse{}, &OperatorError{
			Reason:  "capabilities probe rejected",
			Status:  resp.StatusCode,
			Code:    codeOf(errBody),
			Message: messageOf(errBody),
		}
	}
	var caps wire.CapabilitiesResponse
	if err := strictDecodeResponse(body, &caps); err != nil {
		return Caps{}, wire.CapabilitiesResponse{}, fmt.Errorf("observer upload: decode capabilities: %w", err)
	}
	return CapsFromCapabilities(caps), caps, nil
}

// Send performs one POST /v1/observation-batches attempt with plan.Body. It reads the
// credential fresh, verifies the body's source binding, and decodes the typed response.
// A transport, redirect, TLS, timeout, or content-encoding failure is returned as an
// error (no Attempt); an HTTP status with a decoded typed body is returned as an Attempt.
func (c *Client) Send(ctx context.Context, plan Plan) (*Attempt, error) {
	// c.sourceID is guaranteed non-empty by NewClient, so this check is unconditional: a
	// body claiming a different binding is always refused before it is sent.
	if err := verifyBatchSource(plan.Body, c.sourceID); err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, ingestPath, plan.Body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, classifyDo(err)
	}
	defer drainClose(resp)

	body, err := readBounded(resp)
	if err != nil {
		return nil, err
	}

	att := &Attempt{StatusCode: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	if resp.StatusCode == http.StatusOK {
		var ack wire.IngestAck
		if err := strictDecodeResponse(body, &ack); err != nil {
			// A 2xx with an undecodable ack is a corrupt acknowledgement: the retry layer
			// holds on it rather than advancing.
			att.Ack = nil
			return att, nil
		}
		att.Ack = &ack
		return att, nil
	}
	if eb, ok := decodeError(body); ok {
		att.ErrorBody = eb
	}
	return att, nil
}

// newRequest builds a request with the freshly-read bearer credential. The token is set on
// the Authorization header and never stored on the client or logged.
func (c *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	tok, err := c.cred.Token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return nil, ErrEmptyCredential
	}
	u := *c.base
	u.Path = c.base.Path + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, fmt.Errorf("observer upload: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// verifyBatchSource confirms the batch body's source_id equals the client's configured,
// credential-bound source. The body can never claim a different binding.
func verifyBatchSource(body []byte, sourceID string) error {
	var env struct {
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("observer upload: read batch source_id: %w", err)
	}
	if env.SourceID != sourceID {
		return fmt.Errorf("%w: body %q, bound %q", ErrSourceMismatch, env.SourceID, sourceID)
	}
	return nil
}

// readBounded reads at most maxResponseBytes of the body and rejects any unsupported
// Content-Encoding before decoding.
func readBounded(resp *http.Response) ([]byte, error) {
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedContentEncoding, enc)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("observer upload: read response body: %w", err)
	}
	return b, nil
}

// strictDecodeResponse decodes a typed response with unknown-field rejection and no
// trailing data, mirroring the closed-schema decode the wire contract requires.
func strictDecodeResponse(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing data")
		}
		return fmt.Errorf("unexpected trailing data: %w", err)
	}
	return nil
}

// decodeError decodes a typed ObserverError body, returning ok=false when the body is not
// the expected shape (the caller still holds/retries on the status alone).
func decodeError(data []byte) (*wire.ObserverErrorBody, bool) {
	var oe wire.ObserverError
	if err := strictDecodeResponse(data, &oe); err != nil {
		return nil, false
	}
	return &oe.Error, true
}

func codeOf(b *wire.ObserverErrorBody) wire.ObserverErrorBodyCode {
	if b == nil {
		return ""
	}
	return b.Code
}

func messageOf(b *wire.ObserverErrorBody) string {
	if b == nil {
		return ""
	}
	return b.Message
}

// parseRetryAfter parses a Retry-After header as either delta-seconds or an HTTP date,
// returning 0 when absent or unparseable.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// classifyDo maps a client.Do error to a typed transport failure. A refused redirect and
// an unsupported content-encoding keep their sentinels so the retry layer can distinguish
// hold-worthy protocol failures from retryable transport failures.
func classifyDo(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRedirectRefused) {
		return err
	}
	if errors.Is(err, ErrUnsupportedContentEncoding) {
		return err
	}
	if errors.Is(err, ErrArtifactResponseTooLarge) {
		return err
	}
	// A url.Error wrapping our CheckRedirect error still matches via errors.Is above; any
	// other Do error is a transport failure the retry layer backs off on.
	return &TransportError{err: err}
}

// TransportError is a retryable transport-level failure (dial, TLS, timeout, reset). It
// carries no credential.
type TransportError struct{ err error }

func (e *TransportError) Error() string {
	return "observer upload: transport failure: " + e.err.Error()
}
func (e *TransportError) Unwrap() error { return e.err }

// drainClose drains and closes a response body so the connection can be reused.
func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
}
