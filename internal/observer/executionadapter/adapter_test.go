package executionadapter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdapterMapsSparseProducerSequencesToContiguousArtifactSequences(t *testing.T) {
	ledger := newMemoryLedger()
	uploader := &memoryUploader{}
	a := newTestAdapter(t, ledger, uploader, "one")
	bootstrap(t, a, 0)
	if err := a.ProcessRaw(context.Background(), rawRecords(41, 44)); err != nil {
		t.Fatalf("ProcessRaw: %v", err)
	}
	if got, want := uploader.sequences(), []uint64{1, 2}; !sameUint64(got, want) {
		t.Fatalf("artifact seqs = %v, want %v", got, want)
	}
	if got := ledger.producerHigh(testKey); got != 44 {
		t.Fatalf("producer high = %d, want 44", got)
	}
	if got := ledger.ack(testKey); got != 2 {
		t.Fatalf("observer ack = %d, want 2", got)
	}
}

func TestAdapterHoldsProducerOnValidationUploadOrBootstrapFailure(t *testing.T) {
	t.Run("invalid complete batch creates no mapping", func(t *testing.T) {
		ledger := newMemoryLedger()
		a := newTestAdapter(t, ledger, &memoryUploader{}, "one")
		bootstrap(t, a, 0)
		bad := rawRecords(8)
		bad = append(bad[:len(bad)-1], []byte(`,"unexpected":true}`)...)
		if err := a.ProcessRaw(context.Background(), bad); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("ProcessRaw = %v, want ErrInvalidRecord", err)
		}
		if ledger.count(testKey) != 0 {
			t.Fatal("invalid batch created a durable mapping")
		}
	})
	t.Run("upload failure leaves assigned row pending for exact retry", func(t *testing.T) {
		ledger := newMemoryLedger()
		uploader := &memoryUploader{fail: errors.New("unavailable")}
		a := newTestAdapter(t, ledger, uploader, "one")
		bootstrap(t, a, 0)
		if err := a.ProcessRaw(context.Background(), rawRecords(8)); err == nil {
			t.Fatal("ProcessRaw succeeded after upload failure")
		}
		if got := ledger.ack(testKey); got != 0 {
			t.Fatalf("ack = %d, want 0", got)
		}
		uploader.fail = nil
		if err := a.ProcessRaw(context.Background(), rawRecords(8)); err != nil {
			t.Fatalf("retry: %v", err)
		}
		if got, want := uploader.sequences(), []uint64{1, 1}; !sameUint64(got, want) {
			t.Fatalf("uploads = %v, want retry of seq 1", got)
		}
	})
	t.Run("nonempty remote head requires complete existing mapping", func(t *testing.T) {
		a := newTestAdapter(t, newMemoryLedger(), &memoryUploader{}, "one")
		if err := a.Bootstrap(context.Background(), 1); !errors.Is(err, ErrBootstrapRequired) {
			t.Fatalf("Bootstrap = %v, want ErrBootstrapRequired", err)
		}
	})
}

func TestAdapterRejectsConflictsPartitionRolloverAndUnseenLowerSequence(t *testing.T) {
	ledger := newMemoryLedger()
	uploader := &memoryUploader{}
	a := newTestAdapter(t, ledger, uploader, "one")
	bootstrap(t, a, 0)
	if err := a.ProcessRaw(context.Background(), rawRecords(10, 20)); err != nil {
		t.Fatal(err)
	}
	conflict, err := DecodeBatch(rawRecords(10))
	if err != nil {
		t.Fatal(err)
	}
	conflict.Records[0].Payload = append(conflict.Records[0].Payload, ' ')
	if err := a.Process(context.Background(), conflict); !errors.Is(err, ErrRetryConflict) {
		t.Fatalf("changed retry = %v, want ErrRetryConflict", err)
	}
	if err := a.ProcessRaw(context.Background(), rawRecords(15)); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("unseen lower seq = %v, want ErrSequenceConflict", err)
	}
	if err := a.ProcessRaw(context.Background(), rawRecordsWithPartition("0123456789abcdef", 30)); !errors.Is(err, ErrSourceRotationRequired) {
		t.Fatalf("partition rollover = %v, want ErrSourceRotationRequired", err)
	}
}

func TestAdapterSupportsOverlapRestartAndConcurrentAllocation(t *testing.T) {
	ledger := newMemoryLedger()
	uploader := &memoryUploader{}
	a := newTestAdapter(t, ledger, uploader, "one")
	bootstrap(t, a, 0)
	if err := a.ProcessRaw(context.Background(), rawRecords(10, 20)); err != nil {
		t.Fatal(err)
	}
	restarted := newTestAdapter(t, ledger, uploader, "two")
	bootstrap(t, restarted, 2)
	if err := restarted.ProcessRaw(context.Background(), rawRecords(20, 30)); err != nil {
		t.Fatalf("overlap: %v", err)
	}
	concurrent := newTestAdapter(t, ledger, uploader, "three")
	bootstrap(t, concurrent, 3)
	var wg sync.WaitGroup
	for _, adapterAndSeq := range []struct {
		a   *Adapter
		seq uint64
	}{{restarted, 40}, {concurrent, 40}} {
		wg.Add(1)
		go func(v struct {
			a   *Adapter
			seq uint64
		}) {
			defer wg.Done()
			_ = v.a.ProcessRaw(context.Background(), rawRecords(v.seq))
		}(adapterAndSeq)
	}
	wg.Wait()
	if got, want := ledger.artifactSequences(testKey), []uint64{1, 2, 3, 4}; !sameUint64(got, want) {
		t.Fatalf("mapped artifact seqs = %v, want %v", got, want)
	}
}

func TestAdapterIsDefaultOffAndEmptyFilteredIntervalIsInert(t *testing.T) {
	ledger := newMemoryLedger()
	disabled, err := New(Config{})
	if err != nil {
		t.Fatalf("New disabled: %v", err)
	}
	if disabled.Enabled() {
		t.Fatal("adapter enabled without endpoint/source")
	}
	if err := disabled.ProcessRaw(context.Background(), rawRecords(1)); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled ProcessRaw = %v, want ErrDisabled", err)
	}
	if ledger.count(testKey) != 0 {
		t.Fatal("disabled adapter touched durable ledger")
	}

	a := newTestAdapter(t, ledger, &memoryUploader{}, "one")
	bootstrap(t, a, 0)
	if err := a.ProcessRaw(context.Background(), rawRecords()); err != nil {
		t.Fatalf("all-filtered interval: %v", err)
	}
	if ledger.count(testKey) != 0 {
		t.Fatal("empty batch created a mapping")
	}
}

func TestAdapterRejectsEveryPartialConfiguration(t *testing.T) {
	ledger := newMemoryLedger()
	uploader := &memoryUploader{}
	partials := map[string]Config{
		"endpoint":  {Endpoint: "https://observer.test"},
		"tenant":    {TenantID: testKey.TenantID},
		"workspace": {WorkspaceID: testKey.WorkspaceID},
		"source":    {SourceID: testKey.SourceID},
		"ledger":    {Ledger: ledger},
		"uploader":  {Uploader: uploader},
		"owner":     {Owner: "adapter-one"},
		"lease ttl": {LeaseTTL: time.Minute},
		"clock":     {Now: time.Now},
	}
	for name, cfg := range partials {
		t.Run(name, func(t *testing.T) {
			if adapter, err := New(cfg); err == nil {
				t.Fatalf("New(%+v) = %#v, nil; partial configuration must fail closed", cfg, adapter)
			}
		})
	}
}

const testSource = "src_execution_test"

var testKey = SourceKey{TenantID: "ten_test", WorkspaceID: "ws_test", SourceID: testSource}

func newTestAdapter(t *testing.T, ledger *memoryLedger, uploader *memoryUploader, owner string) *Adapter {
	t.Helper()
	a, err := New(Config{Endpoint: "https://observer.test", TenantID: testKey.TenantID, WorkspaceID: testKey.WorkspaceID, SourceID: testKey.SourceID, Ledger: ledger, Uploader: uploader, Owner: owner, LeaseTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func bootstrap(t *testing.T, a *Adapter, ack uint64) {
	t.Helper()
	if err := a.Bootstrap(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
}

func rawRecords(seqs ...uint64) []byte { return rawRecordsWithPartition("7f3a9c1e5b2d4068", seqs...) }
func rawRecordsWithPartition(partition string, seqs ...uint64) []byte {
	events := make([]string, 0, len(seqs))
	for _, seq := range seqs {
		events = append(events, fmt.Sprintf(`{"seq":%d,"type":"bead.closed","ts":"2026-08-02T08:00:00Z","run_id":"run-opaque","session_id":"session-opaque","step_id":"step-opaque"}`, seq))
	}
	return []byte(fmt.Sprintf(`{"city_hash":"%s","schema_version":2,"events":[%s]}`, partition, strings.Join(events, ",")))
}

type memorySource struct {
	partition       string
	high, ack, next uint64
	owner           string
	leaseUntil      time.Time
	rows            map[uint64]MappedRecord
}
type memoryLedger struct {
	mu      sync.Mutex
	sources map[SourceKey]*memorySource
}

func newMemoryLedger() *memoryLedger { return &memoryLedger{sources: map[SourceKey]*memorySource{}} }
func (m *memoryLedger) Bootstrap(_ context.Context, key SourceKey, remoteAck uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil {
		if remoteAck != 0 {
			return ErrBootstrapRequired
		}
		m.sources[key] = &memorySource{next: 1, rows: map[uint64]MappedRecord{}}
		return nil
	}
	if s.ack != remoteAck {
		return ErrBootstrapConflict
	}
	return nil
}
func (m *memoryLedger) Map(_ context.Context, key SourceKey, batch Batch) ([]MappedRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil {
		return nil, ErrBootstrapRequired
	}
	if s.partition == "" {
		s.partition = batch.PartitionID
	} else if s.partition != batch.PartitionID {
		return nil, ErrSourceRotationRequired
	}
	out := make([]MappedRecord, 0, len(batch.Records))
	for _, r := range batch.Records {
		if old, ok := s.rows[r.ProducerSeq]; ok {
			if string(old.Record.Payload) != string(r.Payload) {
				return nil, ErrRetryConflict
			}
			out = append(out, old)
			continue
		}
		if r.ProducerSeq <= s.high {
			return nil, ErrSequenceConflict
		}
		mapped := MappedRecord{ArtifactSeq: s.next, Record: r}
		s.next++
		s.high = r.ProducerSeq
		s.rows[r.ProducerSeq] = mapped
		out = append(out, mapped)
	}
	return out, nil
}
func (m *memoryLedger) AcquireLease(_ context.Context, key SourceKey, owner string, now time.Time, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil {
		return false, ErrBootstrapRequired
	}
	if s.owner != "" && s.owner != owner && s.leaseUntil.After(now) {
		return false, nil
	}
	s.owner = owner
	s.leaseUntil = now.Add(ttl)
	return true, nil
}
func (m *memoryLedger) RenewLease(_ context.Context, key SourceKey, owner string, now time.Time, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil || s.owner != owner || !s.leaseUntil.After(now) {
		return ErrLeaseLost
	}
	s.leaseUntil = now.Add(ttl)
	return nil
}
func (m *memoryLedger) Pending(_ context.Context, key SourceKey, owner string) ([]MappedRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil || s.owner != owner {
		return nil, ErrLeaseLost
	}
	out := []MappedRecord{}
	for _, r := range s.rows {
		if r.ArtifactSeq > s.ack {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ArtifactSeq < out[j].ArtifactSeq })
	return out, nil
}
func (m *memoryLedger) Acknowledge(_ context.Context, key SourceKey, owner string, through uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s == nil || s.owner != owner {
		return ErrLeaseLost
	}
	if through < s.ack {
		return ErrAckConflict
	}
	s.ack = through
	return nil
}
func (m *memoryLedger) ReleaseLease(_ context.Context, key SourceKey, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sources[key]
	if s != nil && s.owner == owner {
		s.owner = ""
		s.leaseUntil = time.Time{}
	}
	return nil
}
func (m *memoryLedger) count(k SourceKey) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sources[k] == nil {
		return 0
	}
	return len(m.sources[k].rows)
}
func (m *memoryLedger) ack(k SourceKey) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sources[k].ack
}
func (m *memoryLedger) producerHigh(k SourceKey) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sources[k].high
}
func (m *memoryLedger) artifactSequences(k SourceKey) []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []uint64{}
	for _, r := range m.sources[k].rows {
		out = append(out, r.ArtifactSeq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type memoryUploader struct {
	mu       sync.Mutex
	fail     error
	uploaded []uint64
}

func (m *memoryUploader) Upload(_ context.Context, _ SourceKey, rows []MappedRecord) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.uploaded = append(m.uploaded, r.ArtifactSeq)
	}
	if m.fail != nil {
		return 0, m.fail
	}
	return rows[len(rows)-1].ArtifactSeq, nil
}
func (m *memoryUploader) sequences() []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]uint64(nil), m.uploaded...)
}
func sameUint64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
