package executionadapter

import (
	"context"
	"database/sql"
	"errors"
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

func NewPostgresLedger(db *sql.DB) (*PostgresLedger, error) {
	if db == nil {
		return nil, errors.New("execution-event adapter: nil postgres database")
	}
	return &PostgresLedger{db: db}, nil
}
func (p *PostgresLedger) Bootstrap(ctx context.Context, k SourceKey, remote uint64) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO observer_execution_adapter_sources (tenant_id,workspace_id,source_id,next_artifact_seq) VALUES ($1,$2,$3,1) ON CONFLICT DO NOTHING`, k.TenantID, k.WorkspaceID, k.SourceID)
	if err != nil {
		return err
	}
	var ack uint64
	err = tx.QueryRowContext(ctx, `SELECT observer_ack FROM observer_execution_adapter_sources WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 FOR UPDATE`, k.TenantID, k.WorkspaceID, k.SourceID).Scan(&ack)
	if err != nil {
		return err
	}
	if remote != ack {
		return ErrBootstrapConflict
	}
	if remote != 0 && ack == 0 {
		return ErrBootstrapRequired
	}
	return tx.Commit()
}
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
func (p *PostgresLedger) AcquireLease(ctx context.Context, k SourceKey, owner string, now time.Time, ttl time.Duration) (bool, error) {
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET lease_owner=$4,lease_until=$5 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND (lease_owner IS NULL OR lease_owner=$4 OR lease_until <= $6)`, k.TenantID, k.WorkspaceID, k.SourceID, owner, now.Add(ttl), now)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n == 1, nil
}
func (p *PostgresLedger) RenewLease(ctx context.Context, k SourceKey, owner string, now time.Time, ttl time.Duration) error {
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET lease_until=$5 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4 AND lease_until>$6`, k.TenantID, k.WorkspaceID, k.SourceID, owner, now.Add(ttl), now)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (p *PostgresLedger) Pending(ctx context.Context, k SourceKey, owner string) ([]MappedRecord, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT r.artifact_seq,r.producer_seq,r.payload FROM observer_execution_adapter_records r JOIN observer_execution_adapter_sources s USING (tenant_id,workspace_id,source_id) WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND r.source_id=$3 AND s.lease_owner=$4 AND r.artifact_seq>s.observer_ack ORDER BY r.artifact_seq`, k.TenantID, k.WorkspaceID, k.SourceID, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MappedRecord
	for rows.Next() {
		var a, q uint64
		var payload []byte
		if err = rows.Scan(&a, &q, &payload); err != nil {
			return nil, err
		}
		out = append(out, MappedRecord{ArtifactSeq: a, Record: Record{ProducerSeq: q, Payload: payload}})
	}
	return out, rows.Err()
}
func (p *PostgresLedger) Acknowledge(ctx context.Context, k SourceKey, owner string, through uint64) error {
	r, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET observer_ack=$5 WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4 AND observer_ack <= $5`, k.TenantID, k.WorkspaceID, k.SourceID, owner, through)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrAckConflict
	}
	return nil
}
func (p *PostgresLedger) ReleaseLease(ctx context.Context, k SourceKey, owner string) error {
	_, err := p.db.ExecContext(ctx, `UPDATE observer_execution_adapter_sources SET lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND lease_owner=$4`, k.TenantID, k.WorkspaceID, k.SourceID, owner)
	return err
}

var _ Ledger = (*PostgresLedger)(nil)
