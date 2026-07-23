//go:build linux

// Package local implements the endpoint's owner-only daemon socket (E1.5): a bounded,
// typed, length-prefixed request/response protocol over a user-local Unix-domain socket,
// the single-writer producer path into the durable WAL spool, and the typed client the
// wrapper (E1.6), hook (E1.7), and parser (E1.8) use.
//
// The daemon exposes no inbound network port. Every request is serviced by the serialized
// single-writer spool and a producer receives success only after the spool has made the
// write durable (fsync-before-reply). Peer identity is verified with Linux SO_PEERCRED and
// rejected fail-closed when it does not match the daemon's own effective UID.
//
// This file owns the wire protocol: the closed set of request kinds, the typed
// request/response structs (no map[string]any on any wire type), and the length-prefixed,
// size-bounded codec.
package local

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// lengthPrefixBytes is the fixed big-endian uint32 frame-length prefix every message carries.
const lengthPrefixBytes = 4

// DefaultMaxMessageBytes bounds a single request or response. It sits just above the WAL's
// 4 MiB canonical-payload ceiling (spool.MaxFramePayload) so a maximal observation plus its
// protocol envelope fits, while still capping allocation against a hostile length prefix.
const DefaultMaxMessageBytes = 5 << 20

// placeholderObservationID is the non-empty, bounded observation id the client stamps when it
// seals a pending observation for transport. The daemon is the single writer and overwrites it
// (and the sequence) with the authoritative assigned values, so the client-side value never
// reaches the WAL.
const placeholderObservationID = "obs_pending"

// RequestKind is the closed discriminator selecting a typed request body. An unknown kind is
// rejected fail-closed by DecodeRequest.
type RequestKind string

const (
	// KindAppendObservation appends a sealed observation to the WAL and returns a durable ack
	// carrying the daemon-assigned sequence. It is the durable-capture-ack primitive the hook
	// (E1.7) relies on: the client's CaptureObservation is a thin wrapper over this kind that
	// surfaces a clear capture-failure error when the daemon cannot acknowledge.
	KindAppendObservation RequestKind = "APPEND_OBSERVATION"
	// KindReserveRun preallocates a run's terminal reserve (drives E1.3 capacity).
	KindReserveRun RequestKind = "RESERVE_RUN"
	// KindReleaseRun releases a run's terminal reserve (drives E1.3 capacity).
	KindReleaseRun RequestKind = "RELEASE_RUN"
	// KindStatus reads a content-free health/capacity snapshot.
	KindStatus RequestKind = "STATUS"
	// KindLookupRegisteredProcess asks the daemon's registry whether an OS process identity was
	// registered by a wrapper (E1.6 PROCESS_LIFECYCLE{REGISTERED}) and, if so, the run it opened.
	// A miss is an ordinary found=false answer, not an error — the ancestry-query seam the hook
	// (E1.7) relies on to prove exact process lineage.
	KindLookupRegisteredProcess RequestKind = "LOOKUP_REGISTERED_PROCESS"
	// KindResolveInheritedRun classifies how an inherited run id resolves against this source's
	// durable boundary index, comparing the caller's workspace against the run's recorded scope —
	// the boundary-resolve seam the hook (E1.7) uses to validate an inherited GASWORKS_RUN_ID.
	KindResolveInheritedRun RequestKind = "RESOLVE_INHERITED_RUN"
	// KindBindSession associates a child's native session id with the run a wrapper opened, so the
	// daemon's candidate sink stamps run_context onto that session's watcher-captured observations.
	// It is the explicit-run usage-binding seam (E1.6 wrapper -> daemon): the wrapper learns its
	// child's native session id and binds it to GASWORKS_RUN_ID so the session's real cost lands on
	// the run's own bead without a manual attach step.
	KindBindSession RequestKind = "BIND_SESSION"
)

// InheritedRunStatus is the closed classification KindResolveInheritedRun returns for an
// inherited run id, mirroring the endpoint's boundary-and-membership rules. Only
// InheritedRunOpenSameScope is a trustworthy attachment proof; every other value is a quarantine
// input at the hook. The daemon owns the source/workspace scoping and returns the classified
// status; the wire carries only the closed token, never a path or run detail.
type InheritedRunStatus string

const (
	// InheritedRunUnknown means the run id is not present in this source's boundary index. A run id
	// authored by another Observer source/installation is simply absent here, so this also covers
	// the cross-source case.
	InheritedRunUnknown InheritedRunStatus = "UNKNOWN"
	// InheritedRunOpenSameScope means the run id resolves to a durable OPEN boundary in the same
	// source AND the same workspace as the caller — the only trustworthy inherited-id status.
	InheritedRunOpenSameScope InheritedRunStatus = "OPEN_SAME_SCOPE"
	// InheritedRunClosed means the run id is known but its boundary was already closed by RUN_ENDED.
	InheritedRunClosed InheritedRunStatus = "CLOSED"
	// InheritedRunCrossWorkspace means the run id resolves to an OPEN boundary in this source but a
	// different workspace than the caller's.
	InheritedRunCrossWorkspace InheritedRunStatus = "CROSS_WORKSPACE"
)

// Valid reports whether s is a member of the closed InheritedRunStatus set.
func (s InheritedRunStatus) Valid() bool {
	switch s {
	case InheritedRunUnknown, InheritedRunOpenSameScope, InheritedRunClosed, InheritedRunCrossWorkspace:
		return true
	default:
		return false
	}
}

// ResponseStatus is the closed outcome discriminator on every response.
type ResponseStatus string

const (
	// StatusOK means the request succeeded and the matching typed body is present.
	StatusOK ResponseStatus = "OK"
	// StatusError means the request failed; Error carries a content-free code and message.
	StatusError ResponseStatus = "ERROR"
)

// Error codes are closed, machine-readable, and content-free: they never carry paths,
// secrets, or unbounded identifiers (spec: status/diagnostics/errors reveal no content).
const (
	CodeBadRequest         = "BAD_REQUEST"
	CodeInvalidObservation = "INVALID_OBSERVATION"
	CodeAppendFailed       = "APPEND_FAILED"
	CodeReserveFailed      = "RESERVE_FAILED"
	CodeReleaseFailed      = "RELEASE_FAILED"
	CodeHealthFailed       = "HEALTH_FAILED"
	CodeLookupFailed       = "LOOKUP_FAILED"
	CodeResolveFailed      = "RESOLVE_FAILED"
	CodeBindFailed         = "BIND_FAILED"
)

// Protocol errors. All are matchable with errors.Is.
var (
	// ErrMessageTooLarge is a request/response whose declared or actual length exceeds the cap.
	ErrMessageTooLarge = errors.New("observer local: message exceeds maximum size")
	// ErrEmptyMessage is a zero-length framed message.
	ErrEmptyMessage = errors.New("observer local: empty message")
	// ErrUnknownRequestKind is a request whose discriminator is not a member of the closed set.
	ErrUnknownRequestKind = errors.New("observer local: unknown request kind")
	// ErrMalformedRequest is a request whose body is missing or does not match its kind.
	ErrMalformedRequest = errors.New("observer local: malformed request body")
	// ErrMalformedResponse is a success response missing its typed body.
	ErrMalformedResponse = errors.New("observer local: malformed response body")
)

// AppendObservationRequest carries the sealed observation to append. The producer seals an
// evidence.PendingObservation with a placeholder sequence/id (which the daemon reassigns), so
// the payload is a fully-typed wire.Observation union, not an untyped map.
type AppendObservationRequest struct {
	Observation wire.Observation `json:"observation"`
}

// RunReserveRequest names the run whose terminal reserve is being reserved or released.
type RunReserveRequest struct {
	RunID string `json:"run_id"`
}

// LookupRegisteredProcessRequest carries the OS process identity to look up in the daemon's
// registered-ancestor index. It is a closed typed body — an identity in, a found+run out.
type LookupRegisteredProcessRequest struct {
	Identity wire.ProcessIdentity `json:"identity"`
}

// ResolveInheritedRunRequest carries the inherited run id and the caller's workspace token. The
// daemon compares the workspace against the run's recorded scope; an empty workspace is a valid
// (unset) scope, not a malformed request.
type ResolveInheritedRunRequest struct {
	RunID     string `json:"run_id"`
	Workspace string `json:"workspace"`
}

// BindSessionRequest associates a child's native session id with the run the wrapper opened. Both
// are required and bounded; the daemon records the mapping so the sink can stamp run_context onto
// the session's observations.
type BindSessionRequest struct {
	NativeSessionID string `json:"native_session_id"`
	RunID           string `json:"run_id"`
}

// Request is the single typed envelope for every local request. Exactly one body pointer is
// set, selected by Kind; Status carries no body.
type Request struct {
	Kind             RequestKind                     `json:"kind"`
	Append           *AppendObservationRequest       `json:"append,omitempty"`
	ReserveRun       *RunReserveRequest              `json:"reserve_run,omitempty"`
	ReleaseRun       *RunReserveRequest              `json:"release_run,omitempty"`
	LookupRegistered *LookupRegisteredProcessRequest `json:"lookup_registered,omitempty"`
	ResolveInherited *ResolveInheritedRunRequest     `json:"resolve_inherited,omitempty"`
	BindSession      *BindSessionRequest             `json:"bind_session,omitempty"`
}

// AppendAck is the durable acknowledgement for an appended observation: the daemon-assigned
// sequence and observation id, returned only after the WAL fsync.
type AppendAck struct {
	Sequence       int64  `json:"sequence"`
	ObservationID  string `json:"observation_id"`
	DurableThrough int64  `json:"durable_through"`
}

// RunReserveAck reports the terminal-reserve outcome and the resulting capacity view.
type RunReserveAck struct {
	RunID            string `json:"run_id"`
	Open             bool   `json:"open"`
	OpenReserveBytes int64  `json:"open_reserve_bytes"`
	Pressure         string `json:"pressure"`
	AdmitNewRun      bool   `json:"admit_new_explicit_run"`
}

// HealthSnapshot is a content-free health/capacity read: byte counts, watermarks, pressure,
// and open-run counts only — never content, secrets, or paths.
type HealthSnapshot struct {
	Healthy             bool   `json:"healthy"`
	UsedBytes           int64  `json:"used_bytes"`
	OpenReserveBytes    int64  `json:"open_reserve_bytes"`
	OpenRuns            int    `json:"open_runs"`
	AcknowledgedThrough int64  `json:"acknowledged_through"`
	HighestDurable      int64  `json:"highest_durable"`
	Pressure            string `json:"pressure"`
	CeilingBytes        int64  `json:"ceiling_bytes"`
}

// LookupRegisteredProcessAck reports whether the queried identity was registered and, when it
// was, the run it opened. Found=false with an empty RunID is the ordinary "not a wrapper" answer.
type LookupRegisteredProcessAck struct {
	Found bool   `json:"found"`
	RunID string `json:"run_id"`
}

// ResolveInheritedRunAck carries the closed inherited-run classification.
type ResolveInheritedRunAck struct {
	Status InheritedRunStatus `json:"status"`
}

// BindSessionAck confirms the session→run association was recorded. Bound is always true on OK; it
// keeps the response envelope's "one typed body per OK kind" invariant.
type BindSessionAck struct {
	Bound bool `json:"bound"`
}

// ErrorBody is the content-free typed error a failed request returns.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is the single typed envelope for every reply. On StatusOK exactly one body pointer
// matching the request kind is set; on StatusError only Error is set.
type Response struct {
	Status           ResponseStatus              `json:"status"`
	Error            *ErrorBody                  `json:"error,omitempty"`
	Append           *AppendAck                  `json:"append,omitempty"`
	Reserve          *RunReserveAck              `json:"reserve,omitempty"`
	Health           *HealthSnapshot             `json:"health,omitempty"`
	LookupRegistered *LookupRegisteredProcessAck `json:"lookup_registered,omitempty"`
	ResolveInherited *ResolveInheritedRunAck     `json:"resolve_inherited,omitempty"`
	BindSession      *BindSessionAck             `json:"bind_session,omitempty"`
}

// validate rejects an unknown discriminator and a body that does not match its kind, so a
// malformed request fails closed before it can reach the spool.
func (r Request) validate() error {
	switch r.Kind {
	case KindAppendObservation:
		if r.Append == nil {
			return fmt.Errorf("%w: append body missing", ErrMalformedRequest)
		}
	case KindReserveRun:
		if r.ReserveRun == nil || r.ReserveRun.RunID == "" {
			return fmt.Errorf("%w: reserve_run body missing or empty run_id", ErrMalformedRequest)
		}
	case KindReleaseRun:
		if r.ReleaseRun == nil || r.ReleaseRun.RunID == "" {
			return fmt.Errorf("%w: release_run body missing or empty run_id", ErrMalformedRequest)
		}
	case KindStatus:
		// no body
	case KindLookupRegisteredProcess:
		if r.LookupRegistered == nil {
			return fmt.Errorf("%w: lookup_registered body missing", ErrMalformedRequest)
		}
		if r.LookupRegistered.Identity.BootId == "" {
			return fmt.Errorf("%w: lookup_registered body missing boot_id", ErrMalformedRequest)
		}
	case KindResolveInheritedRun:
		if r.ResolveInherited == nil || r.ResolveInherited.RunID == "" {
			return fmt.Errorf("%w: resolve_inherited body missing or empty run_id", ErrMalformedRequest)
		}
	case KindBindSession:
		if r.BindSession == nil || r.BindSession.NativeSessionID == "" || r.BindSession.RunID == "" {
			return fmt.Errorf("%w: bind_session body missing or empty native_session_id/run_id", ErrMalformedRequest)
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnknownRequestKind, r.Kind)
	}
	return nil
}

// EncodeRequest marshals a request to its wire JSON payload.
func EncodeRequest(req Request) ([]byte, error) {
	return json.Marshal(req)
}

// DecodeRequest strictly decodes a request payload (unknown envelope fields are rejected) and
// validates its discriminator/body. A malformed request is an error, never a silently-accepted
// partial value.
func DecodeRequest(data []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}
	if dec.More() {
		return Request{}, fmt.Errorf("%w: trailing bytes after request", ErrMalformedRequest)
	}
	if err := req.validate(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// EncodeResponse marshals a response to its wire JSON payload.
func EncodeResponse(resp Response) ([]byte, error) {
	return json.Marshal(resp)
}

// DecodeResponse strictly decodes a response payload.
func DecodeResponse(data []byte) (Response, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	return resp, nil
}

// writeMessage frames one payload as a big-endian length prefix followed by the bytes. A
// payload over max is rejected before anything is written.
func writeMessage(w io.Writer, payload []byte, max int) error {
	if len(payload) > max {
		return fmt.Errorf("%w: %d > %d", ErrMessageTooLarge, len(payload), max)
	}
	var hdr [lengthPrefixBytes]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

// readMessage reads one length-prefixed message, rejecting a declared length over max BEFORE
// allocating the buffer (fail closed against a hostile prefix). The caller sets a read deadline
// on the connection so a slow or partial write cannot block the reader indefinitely.
func readMessage(r io.Reader, max int) ([]byte, error) {
	var hdr [lengthPrefixBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyMessage
	}
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("%w: declared %d > %d", ErrMessageTooLarge, n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
