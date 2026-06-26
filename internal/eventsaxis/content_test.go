package eventsaxis

import (
	"encoding/json"
	"testing"
)

func TestLiftContent(t *testing.T) {
	payload := json.RawMessage(`{"bead":{"id":"mc-1","title":"ESCALATION: JSONL spike [HIGH]","metadata":{"gc.step_id":"synthesize","gc.root_bead_id":"mc-m8afp","gc.step_ref":"mol-randy-triage-patrol.apply"}}}`)
	title, stepID, runID, formula := liftContent(payload)
	if title != "ESCALATION: JSONL spike [HIGH]" {
		t.Errorf("title = %q", title)
	}
	// step_id = the work bead's gc.step_id (the run-step), NOT gc.active_work_bead.
	if stepID != "synthesize" {
		t.Errorf("step_id = %q", stepID)
	}
	// run_id = gc.root_bead_id (the run-root) so the events plane has a run key.
	if runID != "mc-m8afp" {
		t.Errorf("run_id = %q, want mc-m8afp", runID)
	}
	if formula != "randy-triage-patrol" {
		t.Errorf("formula (from step_ref) = %q, want randy-triage-patrol", formula)
	}

	// gc.formula_name wins over the step_ref derivation when present.
	withName := json.RawMessage(`{"bead":{"title":"t","metadata":{"gc.formula_name":"explicit-name","gc.step_ref":"mol-other.x"}}}`)
	if _, _, _, f := liftContent(withName); f != "explicit-name" {
		t.Errorf("gc.formula_name should win, got %q", f)
	}

	// Malformed / empty payloads are best-effort: empties, never a panic.
	for _, bad := range []json.RawMessage{nil, json.RawMessage(`{`), json.RawMessage(`{"bead":null}`), json.RawMessage(`[]`)} {
		ti, si, ri, fo := liftContent(bad)
		if ti != "" || si != "" || ri != "" || fo != "" {
			t.Errorf("malformed payload %q should yield empties, got %q/%q/%q/%q", bad, ti, si, ri, fo)
		}
	}
}

func TestFormulaFromStepRef(t *testing.T) {
	cases := map[string]string{
		"mol-randy-triage-patrol.apply":              "randy-triage-patrol",
		"mol-seth-patrol.patrol":                     "seth-patrol",
		"mol-randy-triage-patrol.report-scope-check": "randy-triage-patrol",
		"mol-bare":      "bare", // no step suffix
		"not-a-mol-ref": "",     // wrong prefix
		"":              "",
	}
	for ref, want := range cases {
		if got := formulaFromStepRef(ref); got != want {
			t.Errorf("formulaFromStepRef(%q) = %q, want %q", ref, got, want)
		}
	}
}
