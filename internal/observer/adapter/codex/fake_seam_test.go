//go:build unix

package codex

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// fakeSeam is the in-memory DaemonSeam test double. It records every durably-captured
// observation (sealed to canonical bytes for sentinel scans), answers process-ancestry and
// inherited-boundary queries from configured tables, and can inject transport failures or a
// blocking append for the timeout proof.
type fakeSeam struct {
	mu          sync.Mutex
	appends     []capturedObs
	registered  map[string]RegisteredAncestor
	resolutions map[string]InheritedResolution

	appendErr  error
	lookupErr  error
	resolveErr error

	// blockAppend makes CaptureSessionLifecycle wait for the context deadline (never resolving
	// on its own), proving the hook's own timeout bounds a stalled daemon.
	blockAppend bool
}

type capturedObs struct {
	sealed wire.Observation
	canon  []byte
}

func newFakeSeam() *fakeSeam {
	return &fakeSeam{
		registered:  map[string]RegisteredAncestor{},
		resolutions: map[string]InheritedResolution{},
	}
}

func procKey(id wire.ProcessIdentity) string {
	return fmt.Sprintf("%s|%d|%d", id.BootId, id.Pid, id.ProcessStartTime)
}

func (f *fakeSeam) register(id wire.ProcessIdentity, runID string) {
	f.registered[procKey(id)] = RegisteredAncestor{Identity: id, RunID: runID}
}

func (f *fakeSeam) resolve(runID string, status InheritedStatus) {
	f.resolutions[runID] = InheritedResolution{Status: status}
}

func (f *fakeSeam) CaptureSessionLifecycle(ctx context.Context, obs PendingObservation) (CaptureAck, error) {
	if f.blockAppend {
		select {
		case <-ctx.Done():
			return CaptureAck{}, ctx.Err()
		case <-time.After(time.Hour):
			return CaptureAck{}, nil
		}
	}
	if f.appendErr != nil {
		return CaptureAck{}, f.appendErr
	}
	sealed, err := obs.Seal(wire.SequenceMin, "obs_fake")
	if err != nil {
		return CaptureAck{}, err
	}
	canon, err := wire.CanonicalBytes(sealed)
	if err != nil {
		return CaptureAck{}, err
	}
	f.mu.Lock()
	f.appends = append(f.appends, capturedObs{sealed: sealed, canon: canon})
	f.mu.Unlock()
	return CaptureAck{Sequence: wire.SequenceMin}, nil
}

func (f *fakeSeam) LookupRegisteredProcess(ctx context.Context, id wire.ProcessIdentity) (RegisteredAncestor, bool, error) {
	if f.lookupErr != nil {
		return RegisteredAncestor{}, false, f.lookupErr
	}
	r, ok := f.registered[procKey(id)]
	return r, ok, nil
}

func (f *fakeSeam) ResolveInheritedRun(ctx context.Context, runID, workspace string) (InheritedResolution, error) {
	if f.resolveErr != nil {
		return InheritedResolution{}, f.resolveErr
	}
	res, ok := f.resolutions[runID]
	if !ok {
		return InheritedResolution{Status: InheritedUnknown}, nil
	}
	return res, nil
}

func (f *fakeSeam) lastAppend(t *testing.T) capturedObs {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.appends) == 0 {
		t.Fatal("expected at least one durable append, got none")
	}
	return f.appends[len(f.appends)-1]
}

func (f *fakeSeam) appendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.appends)
}

// identityForPID builds the process identity for pid using the SAME /proc parsers the
// production lineage walk uses, so a registered identity and a walked ancestor identity are
// byte-identical.
func identityForPID(t *testing.T, pid int) wire.ProcessIdentity {
	t.Helper()
	_, start, err := readProcStat(pid)
	if err != nil {
		t.Fatalf("readProcStat(%d): %v", pid, err)
	}
	boot, err := hostBootID()
	if err != nil {
		t.Fatalf("hostBootID: %v", err)
	}
	return wire.ProcessIdentity{BootId: boot, Pid: int64(pid), ProcessStartTime: start}
}
