package evidence

import (
	"errors"
	"testing"
	"time"

	"github.com/gascity/gasworks/internal/observer/wire"
)

// TestCheckedOperator (S10 M3): the operator's contract couplings hold at construction: STARTED and
// RESUMED only, a principal id or "", principal_class with a principal only and matching its prefix.
func TestCheckedOperator(t *testing.T) {
	user := wire.SessionOperatorPrincipalClassUSER
	service := wire.SessionOperatorPrincipalClassSERVICE
	since := time.Date(2026, 11, 12, 9, 0, 0, 0, time.FixedZone("x", 3600))
	op := func(id string, class *wire.SessionOperatorPrincipalClass) *wire.SessionOperator {
		return &wire.SessionOperator{PrincipalId: id, PrincipalClass: class, ReportedBy: wire.SessionOperatorReportedByBDLOGINFILE, PrincipalSince: &since}
	}
	started, resumed := wire.SessionLifecyclePayloadTransitionSTARTED, wire.SessionLifecyclePayloadTransitionRESUMED
	for name, tc := range map[string]struct {
		transition wire.SessionLifecyclePayloadTransition
		op         *wire.SessionOperator
		ok         bool
	}{
		"absent":              {started, nil, true},
		"user":                {started, op("usr_01a19b2a-9bbb-79e6-b877-0f48ad23f928", &user), true},
		"service resumed":     {resumed, op("sp_bot-1", &service), true},
		"logged out":          {started, op("", nil), true},
		"cleared":             {wire.SessionLifecyclePayloadTransitionCLEARED, op("usr_a", &user), false},
		"class without id":    {started, op("", &user), false},
		"id without class":    {started, op("usr_a", nil), false},
		"class mismatch":      {started, op("sp_bot", &user), false},
		"email":               {started, op("ada@example.com", &user), false},
		"unknown reported_by": {started, &wire.SessionOperator{PrincipalId: "", ReportedBy: "GUESS"}, false},
	} {
		got, err := checkedOperator(tc.transition, tc.op)
		var be *BuildError
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: %v", name, err)
		case !tc.ok && (err == nil || !errors.As(err, &be)):
			t.Errorf("%s: err = %v, want a BuildError", name, err)
		case tc.ok && tc.op != nil && (got == tc.op || (got.PrincipalSince != nil && got.PrincipalSince.Location() != time.UTC)):
			t.Errorf("%s: not a defensive UTC copy: %+v", name, got)
		}
	}
}
