package executionadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresLedgerRealStore(t *testing.T) {
	db := openPostgresTestDB(t)
	ledger, err := NewPostgresLedger(db)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fresh source requires authoritative zero", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		if err := ledger.Bootstrap(context.Background(), testKey, 1); !errors.Is(err, ErrBootstrapRequired) {
			t.Fatalf("Bootstrap fresh remote 1 = %v, want ErrBootstrapRequired", err)
		}
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM observer_execution_adapter_sources`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("fresh nonzero bootstrap persisted %d source rows, want 0", count)
		}
		if err := ledger.Bootstrap(context.Background(), testKey, 0); err != nil {
			t.Fatalf("Bootstrap fresh zero: %v", err)
		}
	})

	t.Run("remote ack ahead of local ack reconciles only mapped prefix", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		seedPostgresAdapterState(t, db, testKey, ptr("7f3a9c1e5b2d4068"), 30, 0, 4, []postgresSeedRow{
			{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1},
			{partition: "7f3a9c1e5b2d4068", producer: 20, artifact: 2},
			{partition: "7f3a9c1e5b2d4068", producer: 30, artifact: 3},
		})
		if err := ledger.Bootstrap(context.Background(), testKey, 2); err != nil {
			t.Fatalf("Bootstrap safe crash window: %v", err)
		}
		if got := postgresSourceAck(t, db, testKey); got != 2 {
			t.Fatalf("reconciled ack = %d, want 2", got)
		}
		if err := ledger.Bootstrap(context.Background(), testKey, 1); !errors.Is(err, ErrBootstrapConflict) {
			t.Fatalf("Bootstrap remote regression = %v, want ErrBootstrapConflict", err)
		}
		if err := ledger.Bootstrap(context.Background(), testKey, 4); !errors.Is(err, ErrBootstrapConflict) {
			t.Fatalf("Bootstrap remote beyond mapped prefix = %v, want ErrBootstrapConflict", err)
		}
	})

	t.Run("sparse overlap retry and concurrent allocation are durable", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		if err := ledger.Bootstrap(context.Background(), testKey, 0); err != nil {
			t.Fatal(err)
		}
		initial, err := DecodeBatch(rawRecords(10, 20))
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := ledger.Map(context.Background(), testKey, initial)
		if err != nil {
			t.Fatal(err)
		}
		if got := []uint64{mapped[0].ArtifactSeq, mapped[1].ArtifactSeq}; !sameUint64(got, []uint64{1, 2}) {
			t.Fatalf("initial artifact sequences = %v", got)
		}
		overlap, err := DecodeBatch(rawRecords(20, 30))
		if err != nil {
			t.Fatal(err)
		}
		mapped, err = ledger.Map(context.Background(), testKey, overlap)
		if err != nil {
			t.Fatal(err)
		}
		if got := []uint64{mapped[0].ArtifactSeq, mapped[1].ArtifactSeq}; !sameUint64(got, []uint64{2, 3}) {
			t.Fatalf("overlap artifact sequences = %v", got)
		}

		concurrentBatch, err := DecodeBatch(rawRecords(40))
		if err != nil {
			t.Fatal(err)
		}
		otherLedger, err := NewPostgresLedger(db)
		if err != nil {
			t.Fatal(err)
		}
		type mapResult struct {
			rows []MappedRecord
			err  error
		}
		results := make(chan mapResult, 2)
		for _, candidate := range []*PostgresLedger{ledger, otherLedger} {
			go func(candidate *PostgresLedger) {
				rows, err := candidate.Map(context.Background(), testKey, concurrentBatch)
				results <- mapResult{rows: rows, err: err}
			}(candidate)
		}
		for range 2 {
			result := <-results
			if result.err != nil {
				t.Fatalf("concurrent Map: %v", result.err)
			}
			if len(result.rows) != 1 || result.rows[0].ArtifactSeq != 4 {
				t.Fatalf("concurrent mapping = %+v, want artifact 4", result.rows)
			}
		}
		var count int
		var high, next uint64
		if err := db.QueryRow(`SELECT count(*) FROM observer_execution_adapter_records`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT producer_high_seq,next_artifact_seq FROM observer_execution_adapter_sources
			WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, testKey.TenantID, testKey.WorkspaceID, testKey.SourceID).Scan(&high, &next); err != nil {
			t.Fatal(err)
		}
		if count != 4 || high != 40 || next != 5 {
			t.Fatalf("durable mapping count=%d high=%d next=%d, want 4/40/5", count, high, next)
		}

		changed, err := DecodeBatch(rawRecords(10))
		if err != nil {
			t.Fatal(err)
		}
		changed.Records[0].Payload = append(changed.Records[0].Payload, ' ')
		if _, err := ledger.Map(context.Background(), testKey, changed); !errors.Is(err, ErrRetryConflict) {
			t.Fatalf("changed retry = %v, want ErrRetryConflict", err)
		}
		lower, err := DecodeBatch(rawRecords(15))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Map(context.Background(), testKey, lower); !errors.Is(err, ErrSequenceConflict) {
			t.Fatalf("unseen lower sequence = %v, want ErrSequenceConflict", err)
		}
		rotated, err := DecodeBatch(rawRecordsWithPartition("0123456789abcdef", 50))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Map(context.Background(), testKey, rotated); !errors.Is(err, ErrSourceRotationRequired) {
			t.Fatalf("partition rotation = %v, want ErrSourceRotationRequired", err)
		}
	})

	corruptions := map[string]struct {
		partition *string
		high      uint64
		ack       uint64
		next      uint64
		remote    uint64
		rows      []postgresSeedRow
	}{
		"artifact sequence hole": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 30, next: 4,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}, {partition: "7f3a9c1e5b2d4068", producer: 30, artifact: 3}},
		},
		"mixed row partitions": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 20, next: 3,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}, {partition: "0123456789abcdef", producer: 20, artifact: 2}},
		},
		"source partition without rows": {
			partition: ptr("7f3a9c1e5b2d4068"), next: 1,
		},
		"rows without source partition": {
			partition: nil, high: 10, next: 2,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}},
		},
		"producer high water": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 99, next: 3,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}, {partition: "7f3a9c1e5b2d4068", producer: 20, artifact: 2}},
		},
		"producer order": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 10, next: 3,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 20, artifact: 1}, {partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 2}},
		},
		"next artifact sequence": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 20, next: 4,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}, {partition: "7f3a9c1e5b2d4068", producer: 20, artifact: 2}},
		},
		"local ack beyond mapping": {
			partition: ptr("7f3a9c1e5b2d4068"), high: 20, ack: 3, next: 3, remote: 3,
			rows: []postgresSeedRow{{partition: "7f3a9c1e5b2d4068", producer: 10, artifact: 1}, {partition: "7f3a9c1e5b2d4068", producer: 20, artifact: 2}},
		},
	}
	for name, tc := range corruptions {
		t.Run(name, func(t *testing.T) {
			resetPostgresAdapterSchema(t, db)
			seedPostgresAdapterState(t, db, testKey, tc.partition, tc.high, tc.ack, tc.next, tc.rows)
			if err := ledger.Bootstrap(context.Background(), testKey, tc.remote); !errors.Is(err, ErrBootstrapConflict) {
				t.Fatalf("Bootstrap corrupt state = %v, want ErrBootstrapConflict", err)
			}
		})
	}

	t.Run("database time fences pending and acknowledge", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		if err := ledger.Bootstrap(context.Background(), testKey, 0); err != nil {
			t.Fatal(err)
		}
		batch, err := DecodeBatch(rawRecords(10))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Map(context.Background(), testKey, batch); err != nil {
			t.Fatal(err)
		}
		const ttl = 200 * time.Millisecond
		ok, err := ledger.AcquireLease(context.Background(), testKey, "skewed-owner", time.Now().Add(-24*time.Hour), ttl)
		if err != nil || !ok {
			t.Fatalf("AcquireLease = %v, %v", ok, err)
		}
		var leaseUntil time.Time
		var remaining float64
		if err := db.QueryRow(`SELECT lease_until, extract(epoch FROM lease_until-clock_timestamp())
			FROM observer_execution_adapter_sources WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`,
			testKey.TenantID, testKey.WorkspaceID, testKey.SourceID).Scan(&leaseUntil, &remaining); err != nil {
			t.Fatal(err)
		}
		if remaining <= 0 || remaining > ttl.Seconds() {
			t.Fatalf("database lease remaining = %.3fs, want (0,%s]; process clock affected authority", remaining, ttl)
		}
		waitForPostgresClockAfter(t, db, leaseUntil)
		if _, err := ledger.Pending(context.Background(), testKey, "skewed-owner"); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("Pending after expiry = %v, want ErrLeaseLost", err)
		}
		if err := ledger.Acknowledge(context.Background(), testKey, "skewed-owner", 1); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("Acknowledge after expiry = %v, want ErrLeaseLost", err)
		}
		if got := postgresSourceAck(t, db, testKey); got != 0 {
			t.Fatalf("expired owner advanced ack to %d", got)
		}
		ok, err = ledger.AcquireLease(context.Background(), testKey, "current-owner", time.Now().Add(24*time.Hour), time.Second)
		if err != nil || !ok {
			t.Fatalf("AcquireLease current owner = %v, %v", ok, err)
		}
		if _, err := ledger.Pending(context.Background(), testKey, "wrong-owner"); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("Pending wrong owner = %v, want ErrLeaseLost", err)
		}
		if err := ledger.Acknowledge(context.Background(), testKey, "current-owner", 2); !errors.Is(err, ErrAckConflict) {
			t.Fatalf("Acknowledge beyond mapping = %v, want ErrAckConflict", err)
		}
		if err := ledger.Acknowledge(context.Background(), testKey, "current-owner", 1); err != nil {
			t.Fatalf("Acknowledge mapped row: %v", err)
		}
		if got := postgresSourceAck(t, db, testKey); got != 1 {
			t.Fatalf("valid owner ack = %d, want 1", got)
		}
	})

	t.Run("released owner cannot acknowledge", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		if err := ledger.Bootstrap(context.Background(), testKey, 0); err != nil {
			t.Fatal(err)
		}
		batch, err := DecodeBatch(rawRecords(10))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Map(context.Background(), testKey, batch); err != nil {
			t.Fatal(err)
		}
		ok, err := ledger.AcquireLease(context.Background(), testKey, "released-owner", time.Now(), time.Second)
		if err != nil || !ok {
			t.Fatalf("AcquireLease = %v, %v", ok, err)
		}
		if err := ledger.ReleaseLease(context.Background(), testKey, "released-owner"); err != nil {
			t.Fatalf("ReleaseLease: %v", err)
		}
		if err := ledger.Acknowledge(context.Background(), testKey, "released-owner", 1); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("Acknowledge after release = %v, want ErrLeaseLost", err)
		}
		if got := postgresSourceAck(t, db, testKey); got != 0 {
			t.Fatalf("released owner advanced ack to %d", got)
		}
	})

	t.Run("blocked upload renews lease and prevents overlap despite process clock skew", func(t *testing.T) {
		resetPostgresAdapterSchema(t, db)
		uploader := newBlockingUploader()
		const ttl = 300 * time.Millisecond
		first, err := New(Config{
			Endpoint: "https://observer.test", TenantID: testKey.TenantID, WorkspaceID: testKey.WorkspaceID,
			SourceID: testKey.SourceID, Ledger: ledger, Uploader: uploader, Owner: "first", LeaseTTL: ttl,
			Now: func() time.Time { return time.Now().Add(-24 * time.Hour) },
		})
		if err != nil {
			t.Fatal(err)
		}
		secondLedger, err := NewPostgresLedger(db)
		if err != nil {
			t.Fatal(err)
		}
		second, err := New(Config{
			Endpoint: "https://observer.test", TenantID: testKey.TenantID, WorkspaceID: testKey.WorkspaceID,
			SourceID: testKey.SourceID, Ledger: secondLedger, Uploader: uploader, Owner: "second", LeaseTTL: ttl,
			Now: func() time.Time { return time.Now().Add(24 * time.Hour) },
		})
		if err != nil {
			t.Fatal(err)
		}
		bootstrap(t, first, 0)
		bootstrap(t, second, 0)

		firstDone := make(chan error, 1)
		go func() { firstDone <- first.ProcessRaw(context.Background(), rawRecords(10)) }()
		select {
		case <-uploader.started:
		case <-time.After(5 * time.Second):
			t.Fatal("first upload did not start")
		}
		var initialLeaseUntil time.Time
		if err := db.QueryRow(`SELECT lease_until FROM observer_execution_adapter_sources
			WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, testKey.TenantID, testKey.WorkspaceID, testKey.SourceID).Scan(&initialLeaseUntil); err != nil {
			t.Fatal(err)
		}
		waitForPostgresClockAfter(t, db, initialLeaseUntil)

		secondDone := make(chan error, 1)
		go func() { secondDone <- second.ProcessRaw(context.Background(), rawRecords(10)) }()
		var secondErr error
		secondReturned := false
		overlapped := false
		select {
		case secondErr = <-secondDone:
			secondReturned = true
		case <-uploader.overlap:
			overlapped = true
		case <-time.After(5 * time.Second):
			t.Fatal("second adapter neither returned nor began upload")
		}
		uploader.unblock()
		firstErr := waitAdapterResult(t, firstDone, "first adapter")
		if !secondReturned {
			secondErr = waitAdapterResult(t, secondDone, "second adapter")
		}
		if overlapped {
			t.Fatal("two adapter instances uploaded concurrently after the first lease TTL")
		}
		if !errors.Is(secondErr, ErrLeaseHeld) {
			t.Fatalf("second ProcessRaw = %v, want ErrLeaseHeld", secondErr)
		}
		if firstErr != nil {
			t.Fatalf("first ProcessRaw: %v", firstErr)
		}
		if got := uploader.maxConcurrency(); got != 1 {
			t.Fatalf("max upload concurrency = %d, want 1", got)
		}
	})
}

type blockingUploader struct {
	started     chan struct{}
	overlap     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	overlapOnce sync.Once
	releaseOnce sync.Once
	mu          sync.Mutex
	active      int
	maxActive   int
}

func newBlockingUploader() *blockingUploader {
	return &blockingUploader{started: make(chan struct{}), overlap: make(chan struct{}), release: make(chan struct{})}
}

func (u *blockingUploader) Upload(ctx context.Context, _ SourceKey, rows []MappedRecord) (uint64, error) {
	u.mu.Lock()
	u.active++
	if u.active > u.maxActive {
		u.maxActive = u.active
	}
	active := u.active
	u.mu.Unlock()
	u.startedOnce.Do(func() { close(u.started) })
	if active > 1 {
		u.overlapOnce.Do(func() { close(u.overlap) })
	}
	defer func() {
		u.mu.Lock()
		u.active--
		u.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-u.release:
		return rows[len(rows)-1].ArtifactSeq, nil
	}
}

func (u *blockingUploader) unblock() { u.releaseOnce.Do(func() { close(u.release) }) }

func (u *blockingUploader) maxConcurrency() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.maxActive
}

func waitAdapterResult(t *testing.T, result <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish", label)
		return nil
	}
}

func waitForPostgresClockAfter(t *testing.T, db *sql.DB, deadline time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var after bool
		if err := db.QueryRowContext(ctx, `SELECT clock_timestamp() > $1`, deadline).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("database clock did not pass %s: %v", deadline, ctx.Err())
		case <-ticker.C:
		}
	}
}

type postgresSeedRow struct {
	partition string
	producer  uint64
	artifact  uint64
}

func seedPostgresAdapterState(t *testing.T, db *sql.DB, key SourceKey, partition *string, high, ack, next uint64, rows []postgresSeedRow) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO observer_execution_adapter_sources
		(tenant_id,workspace_id,source_id,partition_id,producer_high_seq,observer_ack,next_artifact_seq)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, key.TenantID, key.WorkspaceID, key.SourceID, partition, high, ack, next); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	for _, row := range rows {
		payload := []byte(fmt.Sprintf(`{"producer_seq":%d}`, row.producer))
		digest := sha256.Sum256(payload)
		if _, err := db.Exec(`INSERT INTO observer_execution_adapter_records
			(tenant_id,workspace_id,source_id,partition_id,producer_seq,artifact_seq,payload,payload_sha256)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, key.TenantID, key.WorkspaceID, key.SourceID, row.partition, row.producer, row.artifact, payload, digest[:]); err != nil {
			t.Fatalf("seed record: %v", err)
		}
	}
}

func postgresSourceAck(t *testing.T, db *sql.DB, key SourceKey) uint64 {
	t.Helper()
	var ack uint64
	if err := db.QueryRow(`SELECT observer_ack FROM observer_execution_adapter_sources
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, key.TenantID, key.WorkspaceID, key.SourceID).Scan(&ack); err != nil {
		t.Fatal(err)
	}
	return ack
}

func resetPostgresAdapterSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DROP TABLE IF EXISTS observer_execution_adapter_records, observer_execution_adapter_sources`); err != nil {
		t.Fatalf("drop adapter schema: %v", err)
	}
	if _, err := db.Exec(PostgresSchema); err != nil {
		t.Fatalf("create adapter schema: %v", err)
	}
}

func openPostgresTestDB(t *testing.T) *sql.DB {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("gasworks-exec-adapter-%d-%s", os.Getpid(), hex.EncodeToString(suffix[:]))
	cmd := exec.Command("docker", "run", "--rm", "-d", "--name", name,
		"-e", "POSTGRES_PASSWORD=adapter-test", "-e", "POSTGRES_DB=adapter",
		"-p", "127.0.0.1::5432", "postgres:16-alpine")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start PostgreSQL container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if out, err := exec.Command("docker", "logs", name).CombinedOutput(); err == nil {
				t.Logf("PostgreSQL container logs:\n%s", out)
			}
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	out, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("resolve PostgreSQL port: %v\n%s", err, out)
	}
	hostPort := strings.TrimSpace(string(out))
	colon := strings.LastIndexByte(hostPort, ':')
	if colon < 0 || colon == len(hostPort)-1 {
		t.Fatalf("unexpected docker port output %q", hostPort)
	}
	dsn := "postgres://postgres:adapter-test@127.0.0.1:" + hostPort[colon+1:] + "/adapter?sslmode=disable&application_name=executionadapter_test"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(12)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := db.PingContext(ctx); err == nil {
			return db
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for PostgreSQL: %v (last ping: %v)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func ptr(value string) *string { return &value }
