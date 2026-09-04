// Package climint is the client for the climint external-mint ceremony: the two machine legs
// that bracket a human approval in the browser.
//
//	leg A  POST /v0/cli/mint/challenges                      -> challenge id + confirm code
//	       (the human opens approve_url and types the confirm code)
//	leg C  POST /v0/cli/mint/challenges/{id}/complete        -> the minted credential
//
// climint is served at its own origin (auth.gascity.com), NOT the STS origin, and it is
// deliberately not routed through internal/sts: that client re-issues a failed request at the
// next configured origin, and a re-issue would present a DPoP proof whose jti the server's
// single-use ledger has already spent.
//
// Both legs authenticate with a `gcs_user_` session Bearer plus a DPoP proof bound to the
// exact request URL. Leg C's URL carries the challenge id, so its proof cannot be leg A's:
// every call here mints a fresh proof (fresh jti, fresh iat, htu = the URL about to be
// called). The server compares htu byte for byte and consumes each jti exactly once, so this
// package never retries — a retry would need a new proof, and deciding to make one is the
// caller's call, not a transport detail. The two legs must be driven with the SAME key and the
// SAME session: the server pins leg C to leg A's subject and JKT.
package climint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
)

// UserSessionPrefix is the only session-token prefix the mint legs accept. A service, machine,
// or delegated session is rejected at the edge, so callers should select the session by this
// prefix rather than discover the mismatch through a spent proof.
const UserSessionPrefix = "gcs_user_"

// mintTimeout bounds one leg. Leg C is a poll, not a long-poll: the server answers 425
// immediately while the human is still deciding.
const mintTimeout = 30 * time.Second

// The server's 425 paces its own mint plane, so the interval it sends is authoritative — but
// only within a range this client can act on. A value below minPendingInterval (including a
// missing, zero or negative one) is replaced by defaultPendingInterval rather than spinning
// the poll loop, and maxPendingInterval caps a value that would otherwise park the CLI past
// the challenge's own expiry.
const (
	defaultPendingInterval = 5
	minPendingInterval     = 1
	maxPendingInterval     = 60
)

// MaxChallengeTTLSecs caps the approval window leg A reports, and is the bound Challenge's
// ExpiresIn is decoded within. The server's default window is 180s, so a day is far past any
// value it can mean — but the caller turns this number into a poll deadline, and JSON carries
// no integer limit: 1e19 seconds converted straight to an int64 is a NEGATIVE deadline, which
// is a poll loop with no end. Clamping happens where the number enters the program, before any
// arithmetic sees it.
const MaxChallengeTTLSecs = 24 * 60 * 60

// Client drives both legs of one ceremony. Hold ONE for the whole ceremony: the server pins
// leg C to leg A's subject and thumbprint, and both legs must leave by the same door.
//
// New builds the client production uses. Its keepalives are DISABLED: on a pooled connection
// that went stale between requests net/http silently replays the request on a fresh one,
// which a server whose replay ledger fails closed cannot tell from an attacker resending the
// proof. The climint server disables them on its own mint proxy for exactly this reason.
type Client struct {
	// HTTP issues both legs. It is a field, not a package global with a setter, so a test
	// in another package can point one ceremony at a stub mint plane with its own CA
	// without mutating anything a concurrent test can see. A zero value falls back to the
	// production client, so a Client is usable however it was built.
	HTTP *http.Client
}

// New returns the ceremony client: no connection reuse, one 30s timeout per leg.
func New() *Client { return &Client{HTTP: defaultHTTPClient} }

var defaultHTTPClient = httpc.NewNoKeepAliveClient(mintTimeout)

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTPClient
}

// ChallengeRequest is the leg A body — what the caller wants minted.
//
// ResourceRefs is opaque passthrough JSON and its ABSENCE is meaningful: omitted, the server
// auto-folds the service principal's own workspace grant; present, it is taken as the
// caller's ref set. So the field is omitempty and a JSON `null` is normalised back to absent —
// a null is a value the server can see, and not the one the caller meant.
type ChallengeRequest struct {
	OrgID         string          `json:"org_id"`
	SPID          string          `json:"sp_id"`
	Product       string          `json:"product"`
	Scopes        []string        `json:"scopes"`
	ExpiresInDays int             `json:"expires_in_days"`
	ResourceRefs  json.RawMessage `json:"resource_refs,omitempty"`
}

// Challenge is the leg A 201 response. ConfirmCode is returned HERE and nowhere else — the
// approval page never renders it, so the human reads it from the terminal and types it in.
// Print it; never log it. ExpiresIn is the approval window in seconds, clamped to
// [0, MaxChallengeTTLSecs].
type Challenge struct {
	ChallengeID string
	ConfirmCode string
	ApproveURL  string
	ExpiresIn   int
}

// Credential is the leg C 201 response: the minted service-principal key, relayed from
// accounts. Secret is revealed exactly once, in this response, and it is the only field that
// decides anything — see decodeCredential. ExpiresAt is kept as the server's own string so the
// CLI prints what the server said; it is empty for a key the server minted without an expiry,
// and for one whose expiry arrived in a shape this client did not expect.
type Credential struct {
	KeyID     string
	Secret    string
	Prefix    string
	OrgID     string
	Scopes    []string
	ExpiresAt string
}

// BodySink is handed leg C's response body the instant it has been read — before this package
// parses one byte of it, and so before anything downstream can decide it does not like the
// shape. Its job is to make those bytes DURABLE. Every other loss this ceremony has ever had
// lived between the read and the write; there is no longer anything in between.
//
// What it returns is the bytes to parse: the ones it stored, read back out of wherever it
// stored them, so everything reported afterwards is a statement about what the operator will
// open rather than about a copy in memory.
//
// Its error does not stop the redemption. It is carried on the Redemption so the caller can
// fall back to its own recovery with the bytes still in hand.
type BodySink func(raw []byte) (stored []byte, err error)

// Redemption is leg C's answer: the raw response body, and whatever could be made of it.
//
// Body and Credential are deliberately independent. Body is the ground truth — the bytes the
// server sent, which the sink has already put on the disk — and Credential is this client's
// reading of them, which a drifted, truncated or unrecognised envelope can defeat without any
// of it being lost. When ParseErr is set, Credential.Secret is empty and Body is where the
// secret is.
type Redemption struct {
	// ChallengeID is the challenge this answer belongs to. It travels on the answer because it
	// is the only identifier tying a key that may exist server-side back to the command that
	// asked for it, and every message about an answer this client could not turn into a
	// credential has to carry it.
	ChallengeID string
	// Sent reports that the redeem's bytes reached the network. It is the difference between
	// "the server may have minted and the answer did not get back" and "nothing left this
	// machine, so nothing was minted" — two failures that look identical from the error alone
	// and that must never be reported as each other.
	Sent bool
	// Status is the HTTP status, or 0 when there was no response at all.
	Status int
	// Body is the response body exactly as it was read, partial reads included.
	Body []byte
	// ReadErr is the body read that did not finish, if it did not. Body is what arrived first.
	ReadErr error
	// Truncated reports that bytes are PROVABLY missing: the read did not finish AND what
	// arrived is not a whole JSON document.
	//
	// A read error on its own does not establish that. A chunked response whose terminating
	// chunk never came, a connection closed on a body that had already landed, a GOAWAY after
	// the last byte — all set ReadErr over an envelope with nothing missing from it, and JSON
	// proves it: a document cut anywhere inside an object does not parse, so one that parses
	// arrived whole. The distinction is the difference between "read the secret out of that
	// file" and "that file may hold half of one", and only one of them is true at a time.
	Truncated bool
	// SinkErr is what the BodySink reported, if it reported anything.
	SinkErr error
	// Credential is what parsing Body produced. Metadata is best-effort and is filled in even
	// when the secret could not be.
	Credential Credential
	// ParseErr says why Body could not be read as a credential envelope, in the words the
	// operator needs to find the secret in the saved file by hand.
	ParseErr error
}

// Revealed reports whether leg C came back with bytes that may carry a credential. A 2xx means
// the server acted on the challenge, which is spent either way; bytes mean there is something
// to save. Both together are the moment the reservation stops being disposable.
func (r Redemption) Revealed() bool {
	return r.Status >= 200 && r.Status < 300 && len(r.Body) > 0
}

// PendingError is the 425 answer to leg C: the human has not approved yet. It is not a
// failure and not RFC 8628 — there is no OAuth `error` field to match on, only this status and
// an interval. Interval is in seconds and is always usable: the server's own value when it
// sends a usable one, else defaultPendingInterval, capped at maxPendingInterval.
//
// A caller that waits and polls again MUST call CompleteChallenge afresh; the proof from the
// attempt that returned this error is spent.
type PendingError struct {
	Status   string // authorization_pending | slow_down
	Interval int    // seconds
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("climint: %s (retry in %ds)", e.Status, e.Interval)
}

// TerminalError is a non-2xx that ends the ceremony: the challenge was denied, expired, or
// already consumed (409), the caller does not own it (403), auth failed (401), the request was
// rejected (400), or the mint plane is unavailable (503/502). Retrying the same challenge
// cannot succeed — a new ceremony must be started.
type TerminalError struct {
	Status  int    // HTTP status
	Code    string // the server's `error` code: denied, expired, already_consumed, ...
	Message string // human-readable detail, when the server sent one
	err     error
}

func (e *TerminalError) Error() string {
	msg := strings.TrimSpace(strings.Join([]string{e.Code, e.Message}, " "))
	if msg == "" {
		msg = "mint request failed"
	}
	return fmt.Sprintf("climint: %d %s", e.Status, msg)
}

// consumedCodes are the server's words for a challenge that has already been redeemed. A
// redeem answered with one of these is not a refusal: it is the mint plane saying the credential
// came out somewhere the caller is not holding.
var consumedCodes = map[string]bool{
	"already_consumed":  true,
	"already_redeemed":  true,
	"already_completed": true,
	"consumed":          true,
	"redeemed":          true,
}

// refusalCodes are the server's words for a challenge that was never redeemed: the window shut,
// the human said no, or there was no such challenge to begin with. On a status that would
// otherwise be read as ambiguous these settle the question the safe way round.
var refusalCodes = map[string]bool{
	"expired":           true,
	"challenge_expired": true,
	"denied":            true,
	"rejected":          true,
	"not_found":         true,
	"unknown_challenge": true,
	"invalid_challenge": true,
}

// MayHaveMinted reports whether this refusal leaves open the possibility that leg C redeemed the
// challenge and a credential exists that the caller is not holding.
//
// Most 4xx answers are the mint plane refusing before it minted anything, and repeating that is
// repeating the server. `already_consumed` is the opposite: it is the server stating that the
// challenge WAS redeemed, which — for a challenge this client only ever redeems once — means a
// key came out of an attempt whose answer never landed. A 409 or a 410 with a code this client
// does not recognise is read the same way, because Conflict and Gone are the statuses that
// carry that meaning and guessing the comfortable half of them is how a live key ends up with
// nobody looking for it.
func (e *TerminalError) MayHaveMinted() bool {
	if e.SaysConsumed() {
		return true
	}
	if e.Status != http.StatusConflict && e.Status != http.StatusGone {
		return false
	}
	return !refusalCodes[strings.ToLower(strings.TrimSpace(e.Code))]
}

// SaysConsumed reports whether the mint plane STATED that the challenge was already redeemed,
// as opposed to answering with a status that can carry that meaning.
//
// MayHaveMinted is the classification the control flow needs and it is deliberately wide: a bare
// 409, or a 410 whose code this client does not know, leaves the question open and is treated as
// open. But a REPORT must not put words in the server's mouth. "The mint plane says that
// challenge was already redeemed" is true only of an answer that named one of the consumed
// codes; everything else is a status this client read the safe way round, and reporting it as a
// statement is inventing a quote. Both halves are needed, and they are not the same question.
func (e *TerminalError) SaysConsumed() bool {
	return consumedCodes[strings.ToLower(strings.TrimSpace(e.Code))]
}

// Unwrap exposes the underlying *httpc.HTTPError, whose Body carries any fields beyond the
// ones lifted above.
func (e *TerminalError) Unwrap() error { return e.err }

// CreateChallenge is leg A: it opens a mint challenge and returns the confirm code the human
// types into the approval page. sessionToken must be a live `gcs_user_` session and key must
// be the key that session is JKT-bound to; hold BOTH for leg C, which the server pins to this
// leg's subject and thumbprint. The challenge's own TTL (ExpiresIn) starts now.
func (c *Client) CreateChallenge(cfg config.Config, sessionToken string, key *dpop.Key, req ChallengeRequest) (Challenge, error) {
	u, err := cfg.MintChallengesURL()
	if err != nil {
		return Challenge{}, err
	}
	resp, err := c.send(context.Background(), u, sessionToken, key, req.body())
	if err != nil {
		return Challenge{}, fmt.Errorf("climint: create challenge: %w", err)
	}
	if resp.ReadErr != nil {
		return Challenge{}, fmt.Errorf("climint: create challenge: %w", resp.ReadErr)
	}
	parsed := httpc.Parse(resp.Payload())
	if err := statusError(resp.Status, parsed, u); err != nil {
		return Challenge{}, fmt.Errorf("climint: create challenge: %w", err)
	}
	return decodeChallenge(parsed), nil
}

// CompleteChallenge is leg C: it redeems an approved challenge for the credential. Before the
// human approves it returns a *PendingError carrying the interval to wait — this call does not
// wait or retry, so the caller sleeps and calls again, which mints the fresh proof each
// attempt needs. Anything else non-2xx is a *TerminalError.
//
// The ORDER inside it is the point of this package. A 2xx body is handed to onBody — which
// makes it durable — before it is parsed, before its fields are judged, before its status is
// even turned into an error. Everything after that line is reporting: a body this client
// cannot read comes back as a Redemption whose ParseErr says so, never as a lost credential.
//
// A 2xx therefore returns a nil error even when its body was cut short or is unreadable. The
// caller looks at Revealed and at the Redemption's fields, not at err, to decide what it holds.
func (c *Client) CompleteChallenge(ctx context.Context, cfg config.Config, sessionToken string, key *dpop.Key, challengeID string, onBody BodySink) (Redemption, error) {
	u, err := cfg.MintCompleteURL(challengeID)
	if err != nil {
		return Redemption{ChallengeID: challengeID}, err
	}
	// Whether the request bytes actually left this machine is not something the transport's error
	// can be read for: a dial that never connected and a connection that died with the answer on
	// it both surface as one error. httptrace answers it directly, and the answer decides whether
	// the caller may say nothing was minted.
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				sent.Store(true)
			}
		},
	})
	resp, err := c.send(ctx, u, sessionToken, key, struct{}{})
	if err != nil {
		return Redemption{ChallengeID: challengeID, Sent: sent.Load()},
			fmt.Errorf("climint: complete challenge: %w", err)
	}
	got := Redemption{
		ChallengeID: challengeID,
		Sent:        true,
		Status:      resp.Status,
		Body:        resp.Body,
		ReadErr:     resp.ReadErr,
	}
	if got.Revealed() && onBody != nil {
		stored, err := onBody(resp.Body)
		if got.SinkErr = err; err == nil {
			got.Body = stored
		}
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return got, fmt.Errorf("climint: complete challenge: %w",
			statusError(resp.Status, httpc.Parse(resp.Payload()), u))
	}
	if !got.Revealed() {
		// A 2xx with no body at all. Nothing was revealed and nothing was saved, so this is an
		// ordinary contract break rather than a credential in an unreadable envelope.
		got.ParseErr = emptyBodyError(resp.Status, resp.ReadErr)
		return got, nil
	}
	payload := httpc.Payload(resp.Header, got.Body)
	got.Truncated = resp.ReadErr != nil && !json.Valid(bytes.TrimSpace(payload))
	got.Credential, got.ParseErr = decodeCredential(payload, got.Truncated)
	return got, nil
}

// send signs one fresh proof over rawURL and issues the request, returning the response with
// its body READ but not parsed. rawURL is passed to Proof and to the transport as the SAME
// string, which is what makes the server's byte-for-byte htu comparison hold; config
// canonicalises it before either sees it.
//
// The body is never decoded into a struct anywhere in this package. Leg C's 201 carries a
// secret this process is the only holder of, and a strict decode makes EVERY field of that
// response a veto: a drifted expires_at or scopes type would fail the unmarshal and discard the
// secret one line after it was in hand.
func (c *Client) send(ctx context.Context, rawURL, sessionToken string, key *dpop.Key, body any) (*httpc.Response, error) {
	if key == nil {
		return nil, errors.New("no DPoP key (leg A and leg C must be signed by the session's key)")
	}
	if err := checkSessionToken(sessionToken); err != nil {
		return nil, err
	}
	// ath binds the proof to this exact token; Proof hashes the credential it is given.
	proof, err := key.Proof(http.MethodPost, rawURL, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("building DPoP proof: %w", err)
	}
	return httpc.PostJSONRaw(ctx, c.httpClient(), rawURL, body, map[string]string{
		"Authorization": "Bearer " + sessionToken,
		"DPoP":          proof,
	})
}

// secretField is the key the leg C contract names. It is the ONLY key whose value is taken as
// the credential: everything else the walk below can find is turned into a sentence, never into
// a credential file.
const secretField = "secret"

// decodeCredential lifts the minted credential out of leg C's body, which by the time this runs
// is already on the disk.
//
// The secret is read on its own and nothing can veto it. Every other field is best-effort: a
// key id that arrives as a number, an expires_at that arrives as an epoch, a scopes that
// arrives as one space-delimited string are all read for what they are worth, and not one of
// them can fail this function. That asymmetry is the whole point. The server reveals the secret
// exactly once, this client cannot revoke what it was given, and by the time this runs the
// challenge is already consumed — so a field whose type drifted is a DISPLAY problem, and
// treating it as a decode failure would throw away a live key to protect the formatting of the
// line that announces it.
//
// The error it returns is NOT a failure to propagate as one. It is the sentence the operator
// reads to find the secret in the saved response by hand, so it says what the body was and
// where in it the secret looks like it is.
func decodeCredential(body []byte, truncated bool) (Credential, error) {
	parsed := httpc.Parse(body)
	m := object(parsed)
	credential := Credential{
		KeyID:     text(m["key_id"]),
		Prefix:    text(m["prefix"]),
		OrgID:     text(m["org_id"]),
		Scopes:    textList(m["scopes"]),
		ExpiresAt: text(m["expires_at"]),
	}
	secret, err := findSecret(parsed, len(body), truncated)
	credential.Secret = secret
	return credential, err
}

// findSecret reads the contract's secret out of a decoded body, or explains what is there
// instead.
//
// One string (or number) under a top-level "secret" is the contract, and it is taken as-is.
// Anything else is refused for the credential FILE and described for the operator: an envelope
// this client does not recognise must degrade to "saved raw, could not interpret", never to a
// guess written into something a shell will source. The one concession is naming the guess —
// when exactly one field in the body could be the secret, the message says which, so the
// operator can pull it out of the saved response without reverse-engineering the shape.
func findSecret(parsed any, size int, truncated bool) (string, error) {
	m, isObject := parsed.(map[string]any)
	if !isObject {
		return "", fmt.Errorf("the %d-byte response body is not a JSON object%s", size, truncationNote(truncated))
	}
	// rawText, not text: this value is written to a file byte for byte, and the display filter
	// every other field goes through would corrupt the one thing the server reveals once.
	if secret := rawText(m[secretField]); secret != "" {
		return secret, nil
	}
	return "", fmt.Errorf("the response body carries no usable %q%s%s",
		secretField, truncationNote(truncated), secretHint(parsed))
}

// emptyBodyError is the 2xx that carried nothing: a 204, a 201 with a zero-length body, or a
// read that failed before one byte arrived. There is no envelope to describe and nothing was
// saved, because there was nothing to save.
func emptyBodyError(status int, readErr error) error {
	if readErr != nil {
		return fmt.Errorf("the mint plane answered %d and its body could not be read at all: %s",
			status, Display(readErr.Error()))
	}
	return fmt.Errorf("the mint plane answered %d with an empty body", status)
}

// truncationNote is the clause that says bytes are missing. It is driven by Redemption.Truncated
// and not by the read error on its own: a read that stopped after the last byte of a complete
// JSON document has lost nothing, and a report that calls such a credential partial sends the
// operator to reconcile a key that is in their hand.
func truncationNote(truncated bool) string {
	if !truncated {
		return ""
	}
	return " (it was cut short before the body was complete)"
}

// secretHint names the one field that could be the secret, when there is exactly one.
//
// Every string in the body whose path names a secret is a candidate: `client_secret`, `SECRET`,
// `credential.secret`, `secret.value`, `secret[0]`. Two candidates are not chosen between and
// none is not worth a sentence, so both come back empty — the saved bytes are the answer in
// either case.
func secretHint(parsed any) string {
	found := secretCandidates(parsed, "")
	if len(found) != 1 {
		return ""
	}
	return fmt.Sprintf("; the only field that could be it is %q", found[0])
}

// secretCandidates returns the path of every non-empty string in the body that sits under a
// secret-named key, at any depth. Object keys are walked in sorted order so the same body
// always produces the same sentence.
func secretCandidates(v any, path string) []string {
	switch t := v.(type) {
	case string:
		if t != "" && pathNamesASecret(path) {
			return []string{path}
		}
	case []any:
		var found []string
		for i, item := range t {
			found = append(found, secretCandidates(item, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return found
	case map[string]any:
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var found []string
		for _, key := range keys {
			child := key
			if path != "" {
				child = path + "." + key
			}
			found = append(found, secretCandidates(t[key], child)...)
		}
		return found
	}
	return nil
}

// pathNamesASecret reports whether any segment of a JSON path is a key naming a secret:
// "secret" itself, or a qualified one like client_secret / API-SECRET. A segment that merely
// contains the word (secret_hint, has_secret_id) is not one.
func pathNamesASecret(path string) bool {
	for _, segment := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	}) {
		key := strings.ToLower(segment)
		if key == secretField || strings.HasSuffix(key, "_"+secretField) || strings.HasSuffix(key, "-"+secretField) {
			return true
		}
	}
	return false
}

// decodeChallenge lifts leg A's 201 the same way, for the same reason one leg earlier: leg A
// spends a jti and opens a challenge on the server, so a field this client could not parse must
// not be what ends the ceremony. The caller checks the three fields it cannot proceed without.
func decodeChallenge(body any) Challenge {
	m := object(body)
	return Challenge{
		ChallengeID: text(m["challenge_id"]),
		ConfirmCode: text(m["confirm_code"]),
		ApproveURL:  text(m["approve_url"]),
		ExpiresIn:   seconds(m["expires_in"]),
	}
}

// object is the response body as a JSON object; a body that is not one (an array, a bare
// string, a number) yields an empty map, so every field reads as absent rather than panicking.
func object(body any) map[string]any {
	m, _ := body.(map[string]any)
	return m
}

// text renders one JSON value as the string this client will PRINT — which is why it is
// filtered through Display on the way out. Every display field on both legs goes through here,
// so a control character the server put in one cannot reach a terminal from any of them.
//
// The secret does not come through here. See rawText.
func text(v any) string { return Display(rawText(v)) }

// rawText renders one JSON value verbatim. httpc decodes numbers as float64, so a number is
// formatted without an exponent — a key id of 1 is "1", not "1e+00". An object, an array, a null
// or an absent key is "": there is no honest text for them, and an empty field the caller can
// fall back on beats an error it cannot act on.
func rawText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// textList reads a field that should be an array of strings. A single string is split on
// whitespace: a space-delimited scope list is how the same value is written in a token claim,
// so it is the one alternative shape worth understanding rather than dropping.
func textList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := text(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Fields(t)
	}
	return nil
}

// seconds reads a duration field and clamps it to [0, MaxChallengeTTLSecs]. The clamp is
// applied to the FLOAT, before the conversion: converting a float64 that does not fit in an int
// is undefined behaviour in Go, and on amd64 int(1e19) is the most negative int there is.
func seconds(v any) int {
	f, ok := number(v)
	if !ok || math.IsNaN(f) || f < 1 {
		return 0
	}
	if f > MaxChallengeTTLSecs {
		return MaxChallengeTTLSecs
	}
	return int(f)
}

// number reads a JSON number, or one the server wrote as a string.
func number(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
}

// checkSessionToken rejects a token the mint legs cannot accept, before a proof is signed over
// it. The jti ledger is single-use, so a request that is certain to 401 is worth not sending.
func checkSessionToken(tok string) error {
	if tok == "" {
		return errors.New("no session token")
	}
	if !strings.HasPrefix(tok, UserSessionPrefix) {
		return fmt.Errorf("session token is not a user session (the mint legs accept only %s...); sign in as yourself", UserSessionPrefix)
	}
	return nil
}

// statusError maps a non-2xx onto this package's typed errors, and returns nil for a 2xx. The
// wrapped *httpc.HTTPError is kept so a caller that wants a field beyond the two lifted here
// can reach the whole parsed body through Unwrap.
func statusError(status int, parsed any, rawURL string) error {
	if status >= 200 && status < 300 {
		return nil
	}
	if status == http.StatusTooEarly {
		return &PendingError{Status: pendingStatus(parsed), Interval: pendingInterval(parsed)}
	}
	code, message := errorFields(parsed)
	return &TerminalError{
		Status:  status,
		Code:    code,
		Message: message,
		err:     &httpc.HTTPError{Status: status, Body: parsed, URL: rawURL},
	}
}

// pendingStatus reads the 425 discriminator (authorization_pending or slow_down). The status
// only labels the wait; the interval is what the caller acts on, so an unrecognised or absent
// value degrades to the pending label rather than to an error.
func pendingStatus(body any) string {
	if m, ok := body.(map[string]any); ok {
		if s, ok := m["status"].(string); ok && s != "" {
			return Display(s)
		}
	}
	return "authorization_pending"
}

// pendingInterval reads the server's poll interval in seconds. httpc decodes JSON numbers as
// float64. The result is clamped so the caller can use it unchecked: a missing, zero, negative
// or absurd interval becomes a usable one.
//
// Both comparisons are made on the FLOAT. int(f) for an f that does not fit in an int is
// undefined behaviour, and on amd64 int(1e19) is the most negative int there is — which the
// caller would then add to a deadline it can no longer reach.
func pendingInterval(body any) int {
	secs := float64(defaultPendingInterval)
	if f, ok := number(object(body)["interval"]); ok && f >= minPendingInterval {
		secs = f
	}
	if secs > maxPendingInterval {
		secs = maxPendingInterval
	}
	return int(secs)
}

// errorFields lifts the server's error code and any human detail out of a JSON error body.
// Both climint and the accounts responses it relays answer {"error": "<code>"}; a body that is
// not that shape is surfaced as the message so nothing the server said is dropped.
//
// Both come back display-filtered. An error message is the most obviously attacker-shaped field
// on either leg — it is free text, it is relayed, and it is printed the moment something goes
// wrong — and it must not be able to add a line to the report that carries it.
func errorFields(body any) (code, message string) {
	switch b := body.(type) {
	case map[string]any:
		code, _ = b["error"].(string)
		message, _ = b["error_description"].(string)
	case string:
		message = b
	}
	return Display(code), Display(message)
}

// body returns the wire form of the request. The receiver is a value, so normalising away a
// JSON null resource_refs edits a copy: an explicit null must reach the server as an ABSENT
// field, which is what makes it auto-fold the service principal's workspace grant.
func (r ChallengeRequest) body() any {
	if bytes.Equal(bytes.TrimSpace(r.ResourceRefs), []byte("null")) {
		r.ResourceRefs = nil
	}
	return r
}
