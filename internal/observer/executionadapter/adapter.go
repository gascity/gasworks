package executionadapter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrDisabled reports an adapter that was intentionally left unconfigured. Process methods are
	// no-ops while disabled, preserving the producer's existing default-off behavior.
	ErrDisabled = errors.New("execution-event adapter: disabled")
	// ErrBootstrapRequired reports a source whose Observer cursor cannot be safely derived.
	ErrBootstrapRequired = errors.New("execution-event adapter: bootstrap evidence required")
	// ErrBootstrapConflict reports a durable map that disagrees with the authoritative source head.
	ErrBootstrapConflict = errors.New("execution-event adapter: bootstrap acknowledgement conflict")
	// ErrSourceRotationRequired reports a different producer partition under an already-bound source.
	ErrSourceRotationRequired = errors.New("SOURCE_ROTATION_REQUIRED")
	// ErrRetryConflict reports a producer retry whose original bytes changed.
	ErrRetryConflict = errors.New("execution-event adapter: retry payload conflict")
	// ErrSequenceConflict reports an unseen producer sequence at or below the durable high-water mark.
	ErrSequenceConflict = errors.New("execution-event adapter: unseen lower producer sequence")
	// ErrLeaseLost reports a lease whose owner is no longer permitted to upload.
	ErrLeaseLost = errors.New("execution-event adapter: upload lease lost")
	// ErrLeaseHeld reports an active lease held by another adapter instance.
	ErrLeaseHeld = errors.New("execution-event adapter: upload lease held")
	// ErrAckConflict reports an Observer acknowledgement that cannot safely advance the durable map.
	ErrAckConflict = errors.New("execution-event adapter: acknowledgement conflict")
)

// SourceKey is the authority scope for a durable mapping and upload lease.
type SourceKey struct{ TenantID, WorkspaceID, SourceID string }

// MappedRecord joins immutable producer bytes to the independent contiguous Observer artifact sequence.
type MappedRecord struct {
	ArtifactSeq uint64
	Record      Record
}

// Ledger is the durable source-row-locked mapping surface. Every implementation must make Map,
// lease state, and acknowledgement durable before returning success.
type Ledger interface {
	Bootstrap(context.Context, SourceKey, uint64) error
	Map(context.Context, SourceKey, Batch) ([]MappedRecord, error)
	AcquireLease(context.Context, SourceKey, string, time.Time, time.Duration) (bool, error)
	RenewLease(context.Context, SourceKey, string, time.Time, time.Duration) error
	Pending(context.Context, SourceKey, string) ([]MappedRecord, error)
	Acknowledge(context.Context, SourceKey, string, uint64) error
	ReleaseLease(context.Context, SourceKey, string) error
}

// Uploader sends exactly the durable records supplied, in artifact-sequence order, and returns the
// Observer durable acknowledgement. It must never acknowledge a record it did not durably receive.
type Uploader interface {
	Upload(context.Context, SourceKey, []MappedRecord) (uint64, error)
}

// Config supplies the explicit opt-in and durable dependencies for an Adapter.
type Config struct {
	Endpoint    string
	TenantID    string
	WorkspaceID string
	SourceID    string
	Ledger      Ledger
	Uploader    Uploader
	Owner       string
	LeaseTTL    time.Duration
	Now         func() time.Time
}

// Adapter maps and uploads producer records. It cannot process a configured source until Bootstrap
// has checked the authoritative Observer acknowledgement against the durable map.
type Adapter struct {
	cfg          Config
	bootstrapped bool
}

// New constructs an Adapter. Missing endpoint or source intentionally produces a disabled no-op;
// partial configured state is rejected rather than accidentally permitting egress without durability.
func New(cfg Config) (*Adapter, error) {
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	cfg.WorkspaceID = strings.TrimSpace(cfg.WorkspaceID)
	cfg.SourceID = strings.TrimSpace(cfg.SourceID)
	if cfg.Endpoint == "" || cfg.SourceID == "" {
		return &Adapter{cfg: cfg}, nil
	}
	if cfg.TenantID == "" || cfg.WorkspaceID == "" || cfg.Ledger == nil || cfg.Uploader == nil {
		return nil, fmt.Errorf("execution-event adapter: configured endpoint/source requires tenant, workspace, ledger, and uploader")
	}
	if cfg.Owner == "" {
		return nil, fmt.Errorf("execution-event adapter: configured source requires lease owner")
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Adapter{cfg: cfg}, nil
}

// Enabled reports whether endpoint and source configuration explicitly enabled the adapter.
func (a *Adapter) Enabled() bool { return a != nil && a.cfg.Endpoint != "" && a.cfg.SourceID != "" }

func (a *Adapter) key() SourceKey {
	return SourceKey{TenantID: a.cfg.TenantID, WorkspaceID: a.cfg.WorkspaceID, SourceID: a.cfg.SourceID}
}

// Bootstrap records the authoritative source acknowledgement. A fresh map can start only at zero;
// a restart succeeds only when the supplied remote acknowledgement matches durable state.
func (a *Adapter) Bootstrap(ctx context.Context, observerAcknowledgedThrough uint64) error {
	if !a.Enabled() {
		return nil
	}
	if err := a.cfg.Ledger.Bootstrap(ctx, a.key(), observerAcknowledgedThrough); err != nil {
		return err
	}
	a.bootstrapped = true
	return nil
}

// ProcessRaw validates the complete producer batch before assigning any durable artifact sequence.
func (a *Adapter) ProcessRaw(ctx context.Context, payload []byte) error {
	if !a.Enabled() {
		return nil
	}
	batch, err := DecodeBatch(payload)
	if err != nil {
		return err
	}
	return a.Process(ctx, batch)
}

// Process assigns any new records then drains all durable pending rows in order. It returns an error
// until every mapped row is durably acknowledged, so callers retain their producer cursor on failure.
func (a *Adapter) Process(ctx context.Context, batch Batch) error {
	if !a.Enabled() || len(batch.Records) == 0 {
		return nil
	}
	if !a.bootstrapped {
		return ErrBootstrapRequired
	}
	if _, err := a.cfg.Ledger.Map(ctx, a.key(), batch); err != nil {
		return err
	}
	return a.drain(ctx)
}

func (a *Adapter) drain(ctx context.Context) error {
	now := a.cfg.Now()
	ok, err := a.cfg.Ledger.AcquireLease(ctx, a.key(), a.cfg.Owner, now, a.cfg.LeaseTTL)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLeaseHeld
	}
	defer func() { _ = a.cfg.Ledger.ReleaseLease(context.Background(), a.key(), a.cfg.Owner) }()
	for {
		if err := a.cfg.Ledger.RenewLease(ctx, a.key(), a.cfg.Owner, a.cfg.Now(), a.cfg.LeaseTTL); err != nil {
			return err
		}
		pending, err := a.cfg.Ledger.Pending(ctx, a.key(), a.cfg.Owner)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return nil
		}
		ack, err := a.cfg.Uploader.Upload(ctx, a.key(), pending)
		if err != nil {
			return err
		}
		last := pending[len(pending)-1].ArtifactSeq
		if ack != last {
			return fmt.Errorf("%w: observer acknowledged %d, sent through %d", ErrAckConflict, ack, last)
		}
		if err := a.cfg.Ledger.Acknowledge(ctx, a.key(), a.cfg.Owner, ack); err != nil {
			return err
		}
	}
}
