//go:build linux || darwin

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// DefaultClientTimeout bounds a single client round trip (dial + write + durable reply) when
// the caller supplies no context deadline.
const DefaultClientTimeout = 10 * time.Second

// ErrCaptureUnacknowledged reports that the daemon did not durably acknowledge a capture. The
// hook (E1.7) matches this to emit its bounded SessionStart capture-failure systemMessage.
var ErrCaptureUnacknowledged = errors.New("observer local: daemon did not durably acknowledge capture")

// ErrServerError wraps a typed error response returned by the daemon.
var ErrServerError = errors.New("observer local: daemon returned an error")

// ErrDaemonUnreachable is a path-free classification of a failed connect to the daemon socket.
// The raw dial error names the absolute socket path, which the spec forbids from any surfaced
// error/log, so the client classifies it rather than wrapping the net error verbatim.
var ErrDaemonUnreachable = errors.New("observer local: daemon unreachable")

// ErrNoDurableAck is a path-free classification of a request/response transport failure after
// connecting (write or read error), where the client never obtained a durable acknowledgement.
var ErrNoDurableAck = errors.New("observer local: no durable acknowledgement from daemon")

// Client is the typed client the producers (E1.6 wrapper, E1.7 hook, E1.8 parser) use to reach
// the daemon socket. It is stateless: every call opens a fresh connection with bounded timeouts.
type Client struct {
	socketPath string
	timeout    time.Duration
	maxBytes   int
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithTimeout overrides the default per-call timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxMessageBytes overrides the client's per-message size cap.
func WithMaxMessageBytes(n int) ClientOption {
	return func(c *Client) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// NewClient returns a client for the daemon socket at socketPath.
func NewClient(socketPath string, opts ...ClientOption) *Client {
	c := &Client{
		socketPath: socketPath,
		timeout:    DefaultClientTimeout,
		maxBytes:   DefaultMaxMessageBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AppendObservation seals a pending observation with a placeholder sequence/id for transport,
// sends it to the daemon, and returns the durable ack carrying the daemon-assigned sequence.
// The daemon replies only after the WAL fsync, so a returned ack proves durability.
func (c *Client) AppendObservation(ctx context.Context, p evidence.PendingObservation) (AppendAck, error) {
	obs, err := p.Seal(wire.SequenceMin, placeholderObservationID)
	if err != nil {
		return AppendAck{}, fmt.Errorf("observer local: seal pending observation: %w", err)
	}
	resp, err := c.roundTrip(ctx, Request{
		Kind:   KindAppendObservation,
		Append: &AppendObservationRequest{Observation: obs},
	})
	if err != nil {
		return AppendAck{}, err
	}
	if resp.Status != StatusOK {
		return AppendAck{}, responseError(resp)
	}
	if resp.Append == nil {
		return AppendAck{}, ErrMalformedResponse
	}
	return *resp.Append, nil
}

// CaptureObservation is the hook's durable-capture-ack path: it appends the observation and
// returns a clear ErrCaptureUnacknowledged on any failure to obtain a durable ack, so the
// caller can emit its capture-failure systemMessage instead of stalling session startup.
func (c *Client) CaptureObservation(ctx context.Context, p evidence.PendingObservation) (AppendAck, error) {
	ack, err := c.AppendObservation(ctx, p)
	if err != nil {
		return AppendAck{}, fmt.Errorf("%w: %w", ErrCaptureUnacknowledged, err)
	}
	return ack, nil
}

// ReserveRun preallocates a run's terminal reserve.
func (c *Client) ReserveRun(ctx context.Context, runID string) (RunReserveAck, error) {
	return c.runReserve(ctx, KindReserveRun, runID)
}

// ReleaseRun releases a run's terminal reserve.
func (c *Client) ReleaseRun(ctx context.Context, runID string) (RunReserveAck, error) {
	return c.runReserve(ctx, KindReleaseRun, runID)
}

func (c *Client) runReserve(ctx context.Context, kind RequestKind, runID string) (RunReserveAck, error) {
	req := Request{Kind: kind}
	body := &RunReserveRequest{RunID: runID}
	if kind == KindReserveRun {
		req.ReserveRun = body
	} else {
		req.ReleaseRun = body
	}
	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return RunReserveAck{}, err
	}
	if resp.Status != StatusOK {
		return RunReserveAck{}, responseError(resp)
	}
	if resp.Reserve == nil {
		return RunReserveAck{}, ErrMalformedResponse
	}
	return *resp.Reserve, nil
}

// Status reads a content-free health/capacity snapshot from the daemon.
func (c *Client) Status(ctx context.Context) (HealthSnapshot, error) {
	resp, err := c.roundTrip(ctx, Request{Kind: KindStatus})
	if err != nil {
		return HealthSnapshot{}, err
	}
	if resp.Status != StatusOK {
		return HealthSnapshot{}, responseError(resp)
	}
	if resp.Health == nil {
		return HealthSnapshot{}, ErrMalformedResponse
	}
	return *resp.Health, nil
}

// LookupRegisteredProcess asks the daemon registry whether id was registered by a wrapper (E1.6
// PROCESS_LIFECYCLE{REGISTERED}) and, if so, the run it opened. A miss returns found=false with a
// nil error — a queried process that is not a registered wrapper is the ordinary case; a non-nil
// error is reserved for a transport/query failure and is always path-free.
func (c *Client) LookupRegisteredProcess(ctx context.Context, id wire.ProcessIdentity) (runID string, found bool, err error) {
	resp, err := c.roundTrip(ctx, Request{
		Kind:             KindLookupRegisteredProcess,
		LookupRegistered: &LookupRegisteredProcessRequest{Identity: id},
	})
	if err != nil {
		return "", false, err
	}
	if resp.Status != StatusOK {
		return "", false, responseError(resp)
	}
	if resp.LookupRegistered == nil {
		return "", false, ErrMalformedResponse
	}
	return resp.LookupRegistered.RunID, resp.LookupRegistered.Found, nil
}

// ResolveInheritedRun classifies how runID resolves against this source's boundary index, passing
// workspace for the daemon's same-workspace comparison. A definite classification returns a valid
// status and a nil error; a transport/query failure returns a path-free error. An unrecognized
// status token from the daemon is rejected fail-closed rather than surfaced as trustworthy.
func (c *Client) ResolveInheritedRun(ctx context.Context, runID, workspace string) (InheritedRunStatus, error) {
	resp, err := c.roundTrip(ctx, Request{
		Kind:             KindResolveInheritedRun,
		ResolveInherited: &ResolveInheritedRunRequest{RunID: runID, Workspace: workspace},
	})
	if err != nil {
		return "", err
	}
	if resp.Status != StatusOK {
		return "", responseError(resp)
	}
	if resp.ResolveInherited == nil {
		return "", ErrMalformedResponse
	}
	if !resp.ResolveInherited.Status.Valid() {
		return "", ErrMalformedResponse
	}
	return resp.ResolveInherited.Status, nil
}

// BindSession records that a child's native session id belongs to runID, so the daemon's candidate
// sink stamps run_context onto that session's watcher-captured observations. It is best-effort from
// the caller's perspective — a transport/query failure returns a path-free error the wrapper logs
// and moves past — but a nil error means the binding is recorded.
func (c *Client) BindSession(ctx context.Context, nativeSessionID, runID string) error {
	resp, err := c.roundTrip(ctx, Request{
		Kind:        KindBindSession,
		BindSession: &BindSessionRequest{NativeSessionID: nativeSessionID, RunID: runID},
	})
	if err != nil {
		return err
	}
	if resp.Status != StatusOK {
		return responseError(resp)
	}
	if resp.BindSession == nil || !resp.BindSession.Bound {
		return ErrMalformedResponse
	}
	return nil
}

// roundTrip dials the socket, writes the request, and reads the typed response under a bounded
// deadline. It opens and closes a fresh connection per call.
func (c *Client) roundTrip(ctx context.Context, req Request) (Response, error) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var d net.Dialer
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "unix", c.socketPath)
	if err != nil {
		// The raw dial error names the absolute socket path; classify it path-free.
		return Response{}, ErrDaemonUnreachable
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, ErrNoDurableAck
	}
	payload, err := EncodeRequest(req)
	if err != nil {
		return Response{}, err
	}
	if err := writeMessage(conn, payload, c.maxBytes); err != nil {
		if errors.Is(err, ErrMessageTooLarge) {
			return Response{}, err // client-side, path-free
		}
		return Response{}, ErrNoDurableAck
	}
	respBytes, err := readMessage(conn, c.maxBytes)
	if err != nil {
		if errors.Is(err, ErrMessageTooLarge) || errors.Is(err, ErrEmptyMessage) {
			return Response{}, err // client-side, path-free
		}
		return Response{}, ErrNoDurableAck
	}
	return DecodeResponse(respBytes)
}

// responseError turns a typed error response into a Go error preserving the content-free code.
func responseError(resp Response) error {
	if resp.Error == nil {
		return ErrServerError
	}
	return fmt.Errorf("%w: %s: %s", ErrServerError, resp.Error.Code, resp.Error.Message)
}
