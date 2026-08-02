package executionadapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PostgresSchema creates the source-scoped durable map. The two stated unique identities keep
// sparse producer sequence separate from contiguous artifact sequence.
const PostgresSchema = `
CREATE TABLE IF NOT EXISTS observer_execution_adapter_sources (
 tenant_id text NOT NULL, workspace_id text NOT NULL, source_id text NOT NULL,
 partition_id text, producer_high_seq bigint NOT NULL DEFAULT 0, observer_ack bigint NOT NULL DEFAULT 0,
 next_artifact_seq bigint NOT NULL, lease_owner text, lease_until timestamptz,
 PRIMARY KEY (tenant_id, workspace_id, source_id)
);
CREATE TABLE IF NOT EXISTS observer_execution_adapter_records (
 tenant_id text NOT NULL, workspace_id text NOT NULL, source_id text NOT NULL, partition_id text NOT NULL,
 producer_seq bigint NOT NULL, artifact_seq bigint NOT NULL, payload bytea NOT NULL, payload_sha256 bytea NOT NULL,
 PRIMARY KEY (tenant_id, workspace_id, source_id, partition_id, producer_seq),
 UNIQUE (tenant_id, workspace_id, source_id, artifact_seq)
);`

// PostgresLedger is the production Ledger. Callers own database opening and migrations; all state
// mutations lock the source row FOR UPDATE and never hold a transaction across an HTTP upload.
type PostgresLedger struct{ db *sql.DB }

// NewPostgresLedger binds the durable ledger to an opened PostgreSQL database.
func NewPostgresLedger(db *sql.DB) (*PostgresLedger, error) {
	if db == nil {
		return nil, errors.New("execution-event adapter: nil postgres database")
	}
	return &PostgresLedger{db: db}, nil
}

// Bootstrap validates durable source and record state against the authoritative Observer cursor.
func (p *PostgresLedger) Bootstrap(ctx context.Context, k SourceKey, remote uint64) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO observer_execution_adapter_sources (tenant_id,workspace_id,source_id,next_artifact_seq) VALUES ($1,$2,$3,1) ON CONFLICT DO NOTHING`, k.TenantID, k.WorkspaceID, k.SourceID)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	var partition sql.NullString
	var high, ack, next uint64
	err = tx.QueryRowContext(ctx, `SELECT partition_id,producer_high_seq,observer_ack,next_artifact_seq FROM observer_execution_adapter_sources WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 FOR UPDATE`, k.TenantID, k.WorkspaceID, k.SourceID).Scan(&partition, &high, &ack, &next)
	if err != nil {
		return err
	}
	if inserted == 1 && remote != 0 {
		return fmt.Errorf("%w: fresh source has authoritative acknowledgement %d", ErrBootstrapRequired, remote)
	}

	rows, err := tx.QueryContext(ctx, `SELECT partition_id,producer_seq,artifact_seq FROM observer_execution_adapter_records WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY artifact_seq FOR UPDATE`, k.TenantID, k.WorkspaceID, k.SourceID)
	if err != nil {
		return err
	}
	var mapped, previousProducer uint64
	var mappedPartition string
	for rows.Next() {
		var rowPartition string
		var producer, artifact uint64
		if err := rows.Scan(&rowPartition, &producer, &artifact); err != nil {
			_ = rows.Close()
			return err
		}
		mapped++
		if artifact != mapped {
			_ = rows.Close()
			return fmt.Errorf("%w: artifact sequence %d at mapped position %d", ErrBootstrapConflict, artifact, mapped)
		}
		if mapped == 1 {
			mappedPartition = rowPartition
		} else if rowPartition != mappedPartition {
			_ = rows.Close()
			return fmt.Errorf("%w: mixed record partitions", ErrBootstrapConflict)
		}
		if producer == 0 || (mapped > 1 && producer <= previousProducer) {
			_ = rows.Close()
			return fmt.Errorf("%w: producer sequence %d is not strictly increasing", ErrBootstrapConflict, producer)
		}
		previousProducer = producer
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	if mapped == 0 {
		if partition.Valid || high != 0 || ack != 0 || next != 1 {
			return fmt.Errorf("%w: empty mapping has non-empty source state", ErrBootstrapConflict)
		}
	} else {
		if !partition.Valid || partition.String != mappedPartition {
			return fmt.Errorf("%w: source partition does not match mapped partition", ErrBootstrapConflict)
		}
		if high != previousProducer {
			return fmt.Errorf("%w: producer high-water %d does not match mapped high %d", ErrBootstrapConflict, high, previousProducer)
		}
		if next != mapped+1 {
			return fmt.Errorf("%w: next artifact sequence %d does not follow mapped high %d", ErrBootstrapConflict, next, mapped)
		}
		if ack > mapped {
			return fmt.Errorf("%w: local acknowledgement %d exceeds mapped high %d", ErrBootstrapConflict, ack, mapped)
		}
	}
	if remote < ack {
		return fmt.Errorf("%w: authoritative acknowledgement regressed from %d to %d", ErrBootstrapConflict, ack, remote)
	}
	if remote > mapped {
		return fmt.Errorf("%w: authoritative acknowledgement %d exceeds mapped high %d", ErrBootstrapConflict, remote, mapped)
	}
	if remote > ack {
		if _, err := tx.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET observer_ack=$4 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, k.TenantID, k.WorkspaceID, k.SourceID, remote); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Map idempotently assigns contiguous artifact sequences while holding the source-row lock.
func (p *PostgresLedger) Map(ctx context.Context, k SourceKey, b Batch) ([]MappedRecord, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var part sql.NullString
	var high, next uint64
	err = tx.QueryRowContext(ctx, `SELECT partition_id,producer_high_seq,next_artifact_seq FROM observer_execution_adapter_sources WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 FOR UPDATE`, k.TenantID, k.WorkspaceID, k.SourceID).Scan(&part, &high, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBootstrapRequired
	}
	if err != nil {
		return nil, err
	}
	if part.Valid && part.String != b.PartitionID {
		return nil, ErrSourceRotationRequired
	}
	if !part.Valid {
		if _, err = tx.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET partition_id=$4 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, k.TenantID, k.WorkspaceID, k.SourceID, b.PartitionID); err != nil {
			return nil, err
		}
	}
	out := make([]MappedRecord, 0, len(b.Records))
	for _, r := range b.Records {
		var seq uint64
		var payload []byte
		err = tx.QueryRowContext(ctx, `SELECT artifact_seq,payload FROM observer_execution_adapter_records WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND partition_id=$4 AND producer_seq=$5`, k.TenantID, k.WorkspaceID, k.SourceID, b.PartitionID, r.ProducerSeq).Scan(&seq, &payload)
		if err == nil {
			if string(payload) != string(r.Payload) {
				return nil, ErrRetryConflict
			}
			out = append(out, MappedRecord{ArtifactSeq: seq, Record: r})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if r.ProducerSeq <= high {
			return nil, ErrSequenceConflict
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO observer_execution_adapter_records (tenant_id,workspace_id,source_id,partition_id,producer_seq,artifact_seq,payload,payload_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, k.TenantID, k.WorkspaceID, k.SourceID, b.PartitionID, r.ProducerSeq, next, r.Payload, r.PayloadHash[:]); err != nil {
			return nil, err
		}
		out = append(out, MappedRecord{ArtifactSeq: next, Record: r})
		high = r.ProducerSeq
		next++
	}
	_, err = tx.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET producer_high_seq=$4,next_artifact_seq=$5 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`, k.TenantID, k.WorkspaceID, k.SourceID, high, next)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// AcquireLease claims or extends the source lease using PostgreSQL's authoritative clock.
func (p *PostgresLedger) AcquireLease(ctx context.Context, k SourceKey, owner string, _ time.Time, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, errors.New("execution-event adapter: lease TTL must be positive")
	}
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources
		SET lease_owner=$4,lease_until=clock_timestamp()+($5::bigint * interval '1 microsecond')
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3
		AND (lease_owner IS NULL OR lease_owner=$4 OR lease_until <= clock_timestamp())`,
		k.TenantID, k.WorkspaceID, k.SourceID, owner, leaseMicroseconds(ttl))
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// RenewLease extends a live lease owned by owner using PostgreSQL's authoritative clock.
func (p *PostgresLedger) RenewLease(ctx context.Context, k SourceKey, owner string, _ time.Time, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("execution-event adapter: lease TTL must be positive")
	}
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources
		SET lease_until=clock_timestamp()+($5::bigint * interval '1 microsecond')
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3
		AND lease_owner=$4 AND lease_until>clock_timestamp()`,
		k.TenantID, k.WorkspaceID, k.SourceID, owner, leaseMicroseconds(ttl))
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return nil
}

// Pending returns the next bounded artifact-sequence suffix only to the current live lease owner.
func (p *PostgresLedger) Pending(ctx context.Context, k SourceKey, owner string) ([]MappedRecord, error) {
	rows, err := p.db.QueryContext(ctx, `WITH lease AS MATERIALIZED (
		SELECT observer_ack, lease_until>clock_timestamp() AS valid
		FROM observer_execution_adapter_sources
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4
	)
	SELECT lease.valid,r.artifact_seq,r.partition_id,r.producer_seq,r.payload,r.payload_sha256
	FROM lease
	LEFT JOIN LATERAL (
		SELECT artifact_seq,partition_id,producer_seq,payload,payload_sha256
		FROM observer_execution_adapter_records
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3
		AND artifact_seq>lease.observer_ack AND lease.valid
		ORDER BY artifact_seq
		LIMIT 1000
	) r ON true
	ORDER BY r.artifact_seq`, k.TenantID, k.WorkspaceID, k.SourceID, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MappedRecord
	sawLease := false
	for rows.Next() {
		sawLease = true
		var valid bool
		var artifact, producer sql.NullInt64
		var partition sql.NullString
		var payload, digest []byte
		if err = rows.Scan(&valid, &artifact, &partition, &producer, &payload, &digest); err != nil {
			return nil, err
		}
		if !valid {
			return nil, ErrLeaseLost
		}
		if !artifact.Valid {
			continue
		}
		if artifact.Int64 <= 0 || !producer.Valid || producer.Int64 <= 0 || !partition.Valid || len(digest) != sha256.Size {
			return nil, fmt.Errorf("%w: malformed pending mapping", ErrBootstrapConflict)
		}
		record := Record{PartitionID: partition.String, ProducerSeq: uint64(producer.Int64), Payload: payload}
		copy(record.PayloadHash[:], digest)
		out = append(out, MappedRecord{ArtifactSeq: uint64(artifact.Int64), Record: record})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !sawLease {
		return nil, ErrLeaseLost
	}
	return out, nil
}

// Acknowledge advances the durable Observer cursor only for a mapped prefix and live lease owner.
func (p *PostgresLedger) Acknowledge(ctx context.Context, k SourceKey, owner string, through uint64) error {
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET observer_ack=$5
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4
		AND lease_until>clock_timestamp() AND observer_ack <= $5 AND $5 < next_artifact_seq`,
		k.TenantID, k.WorkspaceID, k.SourceID, owner, through)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var valid bool
	err = p.db.QueryRowContext(ctx, `SELECT COALESCE(lease_owner=$4 AND lease_until>clock_timestamp(), false)
		FROM observer_execution_adapter_sources WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3`,
		k.TenantID, k.WorkspaceID, k.SourceID, owner).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !valid) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	return ErrAckConflict
}

// ReleaseLease clears a source lease only when owner still owns it.
func (p *PostgresLedger) ReleaseLease(ctx context.Context, k SourceKey, owner string) error {
	_, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4`, k.TenantID, k.WorkspaceID, k.SourceID, owner)
	return err
}

func leaseMicroseconds(ttl time.Duration) int64 {
	microseconds := ttl.Microseconds()
	if microseconds < 1 {
		return 1
	}
	return microseconds
}

var _ Ledger = (*PostgresLedger)(nil)
