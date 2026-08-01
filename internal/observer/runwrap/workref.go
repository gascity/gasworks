package runwrap

import (
	"time"

	"github.com/gascity/gasworks/internal/observer/evidence"
)

// NewDeclaredWorkReference builds a typed claim-time work reference under the same explicit-run
// provenance as the wrapper boundary. The caller remains responsible for durably appending it.
func NewDeclaredWorkReference(runID, projectID, beadID string, capturedAt time.Time) (evidence.PendingObservation, error) {
	return evidence.NewDeclaredWorkReference(
		commonForRun(runID, capturedAt),
		evidence.DeclaredWorkRefInput{TeamServerProjectID: projectID, BeadID: beadID},
	)
}
