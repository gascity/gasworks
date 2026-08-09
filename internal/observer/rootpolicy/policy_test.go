package rootpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStrictCanonicalizesAndAcceptsActiveAndTombstoneRecords(t *testing.T) {
	root := t.TempDir()
	tombstoneRoot := t.TempDir()
	policyPath := filepath.Join(t.TempDir(), "roots.json")
	data := `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":7,"active":true,"mode":"forward-only"},{"path":"` + filepath.Join(tombstoneRoot, "..", filepath.Base(tombstoneRoot)) + `","generation":8,"active":false,"mode":""}]}`
	if err := os.WriteFile(policyPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 || got[0].Path != root || got[0].Generation != 7 || !got[0].Active || got[0].Mode != ForwardOnly {
		t.Fatalf("first policy = %+v", got[0])
	}
	if got[1].Path != tombstoneRoot || got[1].Active || got[1].Mode != "" {
		t.Fatalf("tombstone policy = %+v", got[1])
	}
}

func TestLoadRejectsAmbiguousOrUnsafePolicy(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"legacy schema field":      `{"schema":"gasworks.companion.root-policy/v1","roots":[]}`,
		"unknown field":            `{"schema_version":"gasworks.companion.root-policy/v1","roots":[],"extra":true}`,
		"relative root":            `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"relative","generation":1,"active":true,"mode":"backfill"}]}`,
		"zero generation":          `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":0,"active":true,"mode":"backfill"}]}`,
		"bad mode":                 `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":true,"mode":"capture-existing"}]}`,
		"tombstone mode":           `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":false,"mode":"backfill"}]}`,
		"duplicate canonical root": `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":true,"mode":"backfill"},{"path":"` + root + `/.","generation":2,"active":true,"mode":"backfill"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			policyPath := filepath.Join(t.TempDir(), "roots.json")
			if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(policyPath)
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}

	policyPath := filepath.Join(t.TempDir(), "world-readable.json")
	if err := os.WriteFile(policyPath, []byte(`{"schema_version":"gasworks.companion.root-policy/v1","roots":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(policyPath)
	if err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("Load(world-readable) error = %v, want owner-only refusal", err)
	}
}

func TestLoadGoldenEnterprisePolicyAcceptsMissingInactiveTombstone(t *testing.T) {
	activeRoot := t.TempDir()
	missingTombstone := filepath.Join(t.TempDir(), "removed-root")
	policyPath := filepath.Join(t.TempDir(), "enterprise-root-policy.json")
	golden := `{
  "schema_version": "gasworks.companion.root-policy/v1",
  "roots": [
    {"path": "` + activeRoot + `", "generation": 41, "active": true, "mode": "forward-only"},
    {"path": "` + missingTombstone + `", "generation": 42, "active": false, "mode": ""}
  ]
}`
	if err := os.WriteFile(policyPath, []byte(golden), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load golden Enterprise policy: %v", err)
	}
	if len(records) != 2 || records[0].Path != activeRoot || records[1].Path != filepath.Clean(missingTombstone) || records[1].Active {
		t.Fatalf("records = %+v, want active root plus clean missing tombstone", records)
	}
}
