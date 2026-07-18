//go:build linux

package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/adapter/codex"
	"github.com/gascity/gasworks/internal/observer/evidence"
	"github.com/gascity/gasworks/internal/observer/local"
	"github.com/gascity/gasworks/internal/observer/spool"
	"github.com/gascity/gasworks/internal/observer/wire"
)

// compile-time proof the adapter satisfies the committed watcher sink.
var _ codex.CandidateSink = (*CandidateSinkAdapter)(nil)

func metadataOnlyPolicy() evidence.Policy {
	return evidence.Policy{
		Adapter:        "codex-hook",
		AdapterVersion: "1.0.0",
		ContentPolicy:  wire.ProvenanceContentPolicyMETADATAONLY,
		Extraction:     evidence.DefaultExtractionConfig(),
	}
}

func newSink(t *testing.T, client *local.Client) *CandidateSinkAdapter {
	t.Helper()
	sink, err := NewCandidateSinkAdapter(SinkConfig{
		Client:           client,
		Policy:           metadataOnlyPolicy(),
		Provider:         "codex",
		ParserVersion:    codex.ParserVersion,
		TransformVersion: "codex-transform-v1",
		Now:              func() time.Time { return testBase },
	})
	if err != nil {
		t.Fatalf("NewCandidateSinkAdapter: %v", err)
	}
	return sink
}

// messageCandidate carries a forbidden body; the committed METADATA_ONLY transform must strip it.
func messageCandidate(body string) *codex.Candidate {
	return &codex.Candidate{
		Kind:       codex.KindMessage,
		OccurredAt: testBase,
		Message:    &evidence.MessageCandidate{Role: wire.MessagePayloadRoleUSER, Body: body},
	}
}

// TestSinkDeliversTransformedObservationDurably proves the sink runs each candidate through the
// committed Policy transform (stripping content) and durably appends the result through the daemon.
func TestSinkDeliversTransformedObservationDurably(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client)

	const secret = "TOPSECRETMESSAGEBODY"
	ref := codex.TranscriptRef{Locator: "sessions/2026/x.jsonl"}
	if err := sink.DeliverCandidates(context.Background(), ref, []*codex.Candidate{messageCandidate(secret)}); err != nil {
		t.Fatalf("DeliverCandidates: %v", err)
	}

	frames := readWAL(t, dir)
	if len(frames) != 1 {
		t.Fatalf("WAL has %d frames, want 1 durable observation", len(frames))
	}
	var obs wire.Observation
	if err := obs.UnmarshalJSON(frames[0].Payload); err != nil {
		t.Fatalf("decode appended observation: %v", err)
	}
	kind, err := obs.Discriminator()
	if err != nil {
		t.Fatalf("discriminator: %v", err)
	}
	if kind != string(wire.ObservationEnvelopeKindMESSAGE) {
		t.Fatalf("appended kind = %q, want MESSAGE", kind)
	}
	if bytes.Contains(frames[0].Payload, []byte(secret)) {
		t.Fatalf("appended observation leaked the forbidden message body")
	}
}

// TestSinkDeliveryFailureDoesNotAdvance is the at-least-once watcher contract: when the durable
// append cannot be acknowledged, DeliverCandidates returns a non-nil error so the watcher does not
// advance its cursor past the batch and re-reads it on the next poll.
func TestSinkDeliveryFailureDoesNotAdvance(t *testing.T) {
	// A client pointed at a socket that does not exist can never obtain a durable ack.
	badClient := local.NewClient(filepath.Join(t.TempDir(), "absent.sock"), local.WithTimeout(300*time.Millisecond))
	sink := newSink(t, badClient)

	err := sink.DeliverCandidates(context.Background(), codex.TranscriptRef{Locator: "sessions/2026/x.jsonl"}, []*codex.Candidate{messageCandidate("body")})
	if err == nil {
		t.Fatalf("DeliverCandidates returned nil on a non-durable append; the watcher would wrongly advance")
	}
}

// TestSinkOrderedMultiCandidate proves a batch of candidates is delivered in transcript order and
// all become durable observations.
func TestSinkOrderedMultiCandidate(t *testing.T) {
	dir := t.TempDir()
	w := newSpoolWriter(t, dir)
	srv := startDaemonServer(t, dir, w, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client)

	cands := []*codex.Candidate{messageCandidate("a"), messageCandidate("b"), messageCandidate("c")}
	if err := sink.DeliverCandidates(context.Background(), codex.TranscriptRef{Locator: "sessions/x.jsonl"}, cands); err != nil {
		t.Fatalf("DeliverCandidates: %v", err)
	}
	frames := readWAL(t, dir)
	if len(frames) != len(cands) {
		t.Fatalf("WAL has %d frames, want %d", len(frames), len(cands))
	}
	// The single-writer spool assigns strictly increasing sequences in delivery order.
	for i := 1; i < len(frames); i++ {
		if frames[i].Sequence <= frames[i-1].Sequence {
			t.Fatalf("frame sequences not increasing: %d then %d", frames[i-1].Sequence, frames[i].Sequence)
		}
	}
}

// failOnNthSpool wraps a real spool writer and fails the Nth AppendObservation, so a test can drive
// a mid-batch delivery failure. Reserve/Release/Health delegate unchanged.
type failOnNthSpool struct {
	inner *local.SpoolWriter
	mu    sync.Mutex
	n     int
	calls int
}

func (s *failOnNthSpool) AppendObservation(obs wire.Observation) (local.AppendAck, error) {
	s.mu.Lock()
	s.calls++
	fail := s.calls == s.n
	s.mu.Unlock()
	if fail {
		return local.AppendAck{}, errors.New("injected mid-batch append failure")
	}
	return s.inner.AppendObservation(obs)
}

func (s *failOnNthSpool) ReserveRun(runID string) (local.RunReserveAck, error) {
	return s.inner.ReserveRun(runID)
}

func (s *failOnNthSpool) ReleaseRun(runID string) (local.RunReserveAck, error) {
	return s.inner.ReleaseRun(runID)
}

func (s *failOnNthSpool) Health() (local.HealthSnapshot, error) { return s.inner.Health() }

// TestSinkStopsAtMidBatchFailureNoAdvance is the at-least-once ordering contract: with a batch of
// three candidates and the daemon failing the SECOND append, DeliverCandidates returns non-nil (so
// the watcher holds its cursor) and the WAL holds exactly ONE durable frame — candidate 1 committed,
// candidate 3 never appended past the failure. Without stop-on-first-failure ordering this would
// leave 2 frames, which a plausible accumulate-and-continue regression would produce undetected.
func TestSinkStopsAtMidBatchFailureNoAdvance(t *testing.T) {
	dir := t.TempDir()
	spy := &failOnNthSpool{inner: newSpoolWriter(t, dir), n: 2}
	srv := startDaemonServer(t, dir, spy, NewRegistry("src_test", "ws_main"))
	client := local.NewClient(srv.SocketPath())
	sink := newSink(t, client)

	cands := []*codex.Candidate{messageCandidate("one"), messageCandidate("two"), messageCandidate("three")}
	err := sink.DeliverCandidates(context.Background(), codex.TranscriptRef{Locator: "sessions/x.jsonl"}, cands)
	if err == nil {
		t.Fatalf("DeliverCandidates returned nil on a mid-batch failure; the watcher would wrongly advance")
	}
	frames := readWAL(t, dir)
	if len(frames) != 1 {
		t.Fatalf("WAL has %d frames, want exactly 1 (candidate 1 durable, candidate 3 absent)", len(frames))
	}
}

func readWAL(t *testing.T, dir string) []spool.Frame {
	t.Helper()
	walDir := filepath.Join(dir, "wal")
	entries, err := os.ReadDir(walDir)
	if err != nil {
		t.Fatalf("read wal dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".seg" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var frames []spool.Frame
	for _, n := range names {
		seg, err := spool.OpenSegment(filepath.Join(walDir, n), spool.SegmentOptions{})
		if err != nil {
			t.Fatalf("OpenSegment %s: %v", n, err)
		}
		fr, err := seg.ReadAll()
		_ = seg.Close()
		if err != nil {
			t.Fatalf("ReadAll %s: %v", n, err)
		}
		frames = append(frames, fr...)
	}
	return frames
}
