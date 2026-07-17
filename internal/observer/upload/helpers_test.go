package upload

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// testSourceID is the credential-bound source used across the upload tests. It matches the
// vendored corpus source id so the encoder-vs-corpus test lines up.
const testSourceID = "src_019f7a1000observerpilot0001"

// canonPayload returns a canonical observation payload of a controllable size. The content
// is opaque to batch formation (which concatenates payloads verbatim); pad grows the
// payload so byte-budget behavior can be exercised deterministically.
func canonPayload(t *testing.T, seq int64, pad int) []byte {
	t.Helper()
	obj := map[string]any{
		"kind":           "CAPTURE_DIAGNOSTIC",
		"sequence":       seq,
		"observation_id": fmt.Sprintf("obs_%016d", seq),
	}
	if pad > 0 {
		b := make([]byte, pad)
		for i := range b {
			b[i] = 'a'
		}
		obj["pad"] = string(b)
	}
	p, err := wire.CanonicalBytes(obj)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	return p
}

// memStore is an in-memory FrameStore over a fixed set of records.
type memStore struct {
	recs map[int64][]byte
}

func newMemStore(t *testing.T, first, last int64, pad int) *memStore {
	t.Helper()
	m := &memStore{recs: map[int64][]byte{}}
	for s := first; s <= last; s++ {
		m.recs[s] = canonPayload(t, s, pad)
	}
	return m
}

func (m *memStore) ReadRange(first, last int64) ([]Record, error) {
	var out []Record
	for s := first; s <= last; s++ {
		p, ok := m.recs[s]
		if !ok {
			continue
		}
		out = append(out, Record{Sequence: s, Payload: p})
	}
	return out, nil
}

// newAckState builds a fresh durable AckState over a temp dir, seeded with a highest
// durable sequence and nothing acknowledged (fresh install).
func newAckState(t *testing.T, highestDurable int64) *spool.AckState {
	t.Helper()
	a, err := spool.LoadAckState(t.TempDir(), highestDurable, spool.AckOptions{})
	if err != nil {
		t.Fatalf("LoadAckState: %v", err)
	}
	return a
}

// --- HTTP test server helpers -------------------------------------------------

// recordingHandler captures the requests a server saw and returns scripted responses.
type recordingHandler struct {
	mu       sync.Mutex
	requests []recordedRequest
	// respond returns (status, headers, body) for the nth ingest request (0-based).
	respond func(n int, r recordedRequest) (int, http.Header, []byte)
}

type recordedRequest struct {
	method    string
	path      string
	authz     string
	body      []byte
	host      string
	userAgent string
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	rr := recordedRequest{
		method:    r.Method,
		path:      r.URL.Path,
		authz:     r.Header.Get("Authorization"),
		body:      body,
		host:      r.Host,
		userAgent: r.Header.Get("User-Agent"),
	}
	h.mu.Lock()
	n := len(h.requests)
	h.requests = append(h.requests, rr)
	respond := h.respond
	h.mu.Unlock()

	status, hdr, out := http.StatusOK, http.Header{}, []byte("{}")
	if respond != nil {
		status, hdr, out = respond(n, rr)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func (h *recordingHandler) snapshot() []recordedRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]recordedRequest, len(h.requests))
	copy(out, h.requests)
	return out
}

// ackJSON builds a well-formed success ack for a range.
func ackJSON(t *testing.T, sourceID string, first, last int64) []byte {
	t.Helper()
	ack := wire.IngestAck{
		SourceId:                    sourceID,
		AcknowledgedThroughSequence: last,
		Accepted:                    last - first + 1,
		Duplicates:                  0,
	}
	b, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	return b
}

// errorJSON builds a typed ObserverError body.
func errorJSON(t *testing.T, code wire.ObserverErrorBodyCode, retryable bool) []byte {
	t.Helper()
	oe := wire.ObserverError{Error: wire.ObserverErrorBody{Code: code, Message: "content-free message", Retryable: retryable}}
	b, err := json.Marshal(oe)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	return b
}

// newHTTPServer starts a plain-HTTP loopback test server and returns its base URL.
func newHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// loopbackClient builds a Client against a plain-HTTP loopback server using dev mode, with
// a static token source. It is the workhorse for the retry/redirect/timeout tests that do
// not need real TLS.
func loopbackClient(t *testing.T, endpoint string, cred CredentialSource) *Client {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	c, err := NewClient(Config{
		Endpoint:          u,
		SourceID:          testSourceID,
		Credential:        cred,
		AllowLoopbackHTTP: true,
		AttemptTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// staticToken is a CredentialSource returning a fixed token.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// --- TLS / certificate helpers ------------------------------------------------

// caCerts returns the CA certificate as an additive trust-anchor slice for Config.CustomCAs.
func caCerts(ca *testCA) []*x509.Certificate { return []*x509.Certificate{ca.cert} }

// jsonMarshal is a test convenience wrapper.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "observer-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issueLeaf signs a server leaf for the given DNS names and IPs.
func (ca *testCA) issueLeaf(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "observer-test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// startTLSServer starts an HTTPS server on 127.0.0.1 with the given leaf certificate and
// returns its base URL. It is torn down at test end.
func startTLSServer(t *testing.T, leaf tls.Certificate, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{leaf}})
	// Silence the expected "bad certificate" handshake log from the untrusted-CA test.
	srv := &http.Server{Handler: handler, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return "https://" + ln.Addr().String()
}

// --- MITM egress proxy fixture ------------------------------------------------

// singleConnListener yields exactly one connection to http.Serve, then blocks.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	first := false
	l.once.Do(func() { c = l.conn; first = true })
	if first {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// startMITMProxy starts an HTTP CONNECT proxy that terminates TLS for the given target
// host using a leaf signed by the proxy CA (a corporate TLS-terminating egress proxy),
// then serves the inner request with handler. It returns the proxy URL. The client must
// trust the proxy CA additively to verify the re-signed target certificate.
func startMITMProxy(t *testing.T, ca *testCA, targetHost string, handler http.Handler) string {
	t.Helper()
	leaf := ca.issueLeaf(t, []string{targetHost}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMITMConn(conn, leaf, handler)
		}
	}()
	return "http://" + ln.Addr().String()
}

func serveMITMConn(conn net.Conn, leaf tls.Certificate, handler http.Handler) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	// Establish the tunnel, then MITM it with the CA-signed target leaf.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{leaf}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	// Serve exactly one inner HTTP request over the terminated TLS connection.
	_ = http.Serve(newSingleConnListener(tlsConn), handler)
}

// writeWAL writes a real spool WAL under dir with frames for [first,last], rotating a new
// segment every segPerSeg records so multi-segment reads are exercised. It returns the
// per-sequence canonical payloads it wrote for byte-identical comparison.
func writeWAL(t *testing.T, dir string, first, last int64, pad, segPerSeg int) map[int64][]byte {
	t.Helper()
	walDir := filepath.Join(dir, "wal")
	if err := os.MkdirAll(walDir, 0o700); err != nil {
		t.Fatalf("mkdir wal: %v", err)
	}
	payloads := map[int64][]byte{}
	var seg *spool.Segment
	count := 0
	for s := first; s <= last; s++ {
		if seg == nil || count == segPerSeg {
			if seg != nil {
				_ = seg.Close()
			}
			var err error
			seg, err = spool.CreateSegment(walDir, spool.SegmentOptions{
				FormatVersion: 1,
				SourceID:      testSourceID,
				FirstSequence: s,
				CreationTime:  time.Unix(0, 0),
			})
			if err != nil {
				t.Fatalf("create segment at %d: %v", s, err)
			}
			count = 0
		}
		p := canonPayload(t, s, pad)
		payloads[s] = p
		if err := seg.Append(spool.Frame{Sequence: s, Payload: p}); err != nil {
			t.Fatalf("append %d: %v", s, err)
		}
		count++
	}
	if seg != nil {
		_ = seg.Close()
	}
	return payloads
}
