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
	symlinkRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(root, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	symlinkParentTarget := t.TempDir()
	symlinkParentChild := filepath.Join(symlinkParentTarget, "child")
	if err := os.Mkdir(symlinkParentChild, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(symlinkParentTarget, symlinkParent); err != nil {
		t.Fatal(err)
	}
	symlinkParentRoot := filepath.Join(symlinkParent, "child")
	for name, body := range map[string]string{
		"legacy schema field":      `{"schema":"gasworks.companion.root-policy/v1","roots":[]}`,
		"unknown field":            `{"schema_version":"gasworks.companion.root-policy/v1","roots":[],"extra":true}`,
		"relative root":            `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"relative","generation":1,"active":true,"mode":"backfill"}]}`,
		"zero generation":          `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":0,"active":true,"mode":"backfill"}]}`,
		"bad mode":                 `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":true,"mode":"capture-existing"}]}`,
		"tombstone mode":           `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":false,"mode":"backfill"}]}`,
		"symlinked active root":    `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + symlinkRoot + `","generation":1,"active":true,"mode":"forward-only"}]}`,
		"symlinked active parent":  `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + symlinkParentRoot + `","generation":1,"active":true,"mode":"forward-only"}]}`,
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

// writePolicy writes body as an owner-only policy file and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roots.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// mkdir creates dir under parent and returns its path.
func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadPolicyV1KeepsV1Semantics pins back-compat: a v1 document parses through the versioned
// decoder exactly as before, with an empty kind (transcripts) on every root and no stores.
func TestLoadPolicyV1KeepsV1Semantics(t *testing.T) {
	root := t.TempDir()
	body := `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":3,"active":true,"mode":"backfill"}]}`
	policy, err := LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	want := Record{Path: root, Generation: 3, Active: true, Mode: Backfill}
	if len(policy.Roots) != 1 || policy.Roots[0] != want {
		t.Fatalf("roots = %+v, want exactly %+v", policy.Roots, want)
	}
	if policy.Roots[0].IsProject() {
		t.Error("a v1 root must never be a project root")
	}
	if policy.Stores != nil {
		t.Errorf("stores = %v, want nil for a v1 document", policy.Stores)
	}
	records, err := Load(writePolicy(t, body))
	if err != nil || len(records) != 1 || records[0] != want {
		t.Fatalf("Load = %+v, %v, want the same single record LoadPolicy returned", records, err)
	}
}

// TestLoadPolicyV2ParsesProjectRootsAndStores covers the v2 happy path: mixed root kinds (explicit
// transcripts, implicit transcripts, project) plus the recorded provider stores.
func TestLoadPolicyV2ParsesProjectRootsAndStores(t *testing.T) {
	transcripts := t.TempDir()
	implicit := t.TempDir()
	project := t.TempDir()
	claudeStore := t.TempDir()
	codexStore := t.TempDir()
	missingTombstone := filepath.Join(t.TempDir(), "removed-project")
	body := `{
  "schema_version": "gasworks.companion.root-policy/v2",
  "roots": [
    {"path": "` + transcripts + `", "generation": 1, "active": true, "mode": "forward-only", "kind": "transcripts"},
    {"path": "` + implicit + `", "generation": 2, "active": true, "mode": "backfill"},
    {"path": "` + project + `", "generation": 3, "active": true, "mode": "forward-only", "kind": "project"},
    {"path": "` + missingTombstone + `", "generation": 4, "active": false, "mode": "", "kind": "project"}
  ],
  "stores": ["` + claudeStore + `", "` + codexStore + `"]
}`
	policy, err := LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	want := []Record{
		{Path: transcripts, Generation: 1, Active: true, Mode: ForwardOnly, Kind: Transcripts},
		{Path: implicit, Generation: 2, Active: true, Mode: Backfill},
		{Path: project, Generation: 3, Active: true, Mode: ForwardOnly, Kind: Project},
		{Path: missingTombstone, Generation: 4, Kind: Project},
	}
	if len(policy.Roots) != len(want) {
		t.Fatalf("roots = %+v, want %+v", policy.Roots, want)
	}
	for i := range want {
		if policy.Roots[i] != want[i] {
			t.Errorf("root %d = %+v, want %+v", i, policy.Roots[i], want[i])
		}
	}
	if policy.Roots[0].IsProject() || policy.Roots[1].IsProject() || !policy.Roots[2].IsProject() {
		t.Error("IsProject must be true only for the kind=project root")
	}
	if len(policy.Stores) != 2 || policy.Stores[0] != claudeStore || policy.Stores[1] != codexStore {
		t.Fatalf("stores = %v, want %v", policy.Stores, []string{claudeStore, codexStore})
	}
}

// TestLoadPolicyV2StoresAreOptionalWithoutAnActiveProjectRoot proves stores stay inert recorded
// state while no project root is active: their directories may already be gone.
func TestLoadPolicyV2StoresAreOptionalWithoutAnActiveProjectRoot(t *testing.T) {
	root := t.TempDir()
	missingStore := filepath.Join(t.TempDir(), "removed-store")
	tombstonedProject := filepath.Join(t.TempDir(), "removed-project")
	body := `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` +
		`{"path":"` + root + `","generation":1,"active":true,"mode":"forward-only"},` +
		`{"path":"` + tombstonedProject + `","generation":2,"active":false,"mode":"","kind":"project"}],` +
		`"stores":["` + missingStore + `"]}`
	policy, err := LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(policy.Stores) != 1 || policy.Stores[0] != missingStore {
		t.Fatalf("stores = %v, want the recorded missing store %q", policy.Stores, missingStore)
	}

	body = `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` +
		`{"path":"` + t.TempDir() + `","generation":1,"active":true,"mode":"forward-only","kind":"project"}],` +
		`"stores":["` + missingStore + `"]}`
	if _, err := LoadPolicy(writePolicy(t, body)); err == nil {
		t.Fatal("LoadPolicy accepted a missing store while a project root is active, want refusal")
	}
}

// TestLoadPolicyV2OverlapChecksArePathBoundaryAware is the /p/proj vs /p/project regression: a
// shared string prefix is not containment, so sibling directories must all be accepted.
func TestLoadPolicyV2OverlapChecksArePathBoundaryAware(t *testing.T) {
	parent := t.TempDir()
	project := mkdir(t, parent, "proj")
	sibling := mkdir(t, parent, "project")
	storeParent := t.TempDir()
	claudeStore := mkdir(t, storeParent, "store")
	codexStore := mkdir(t, storeParent, "store-two")
	body := `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` +
		`{"path":"` + project + `","generation":1,"active":true,"mode":"forward-only","kind":"project"},` +
		`{"path":"` + sibling + `","generation":2,"active":true,"mode":"forward-only","kind":"project"}],` +
		`"stores":["` + claudeStore + `","` + codexStore + `"]}`
	policy, err := LoadPolicy(writePolicy(t, body))
	if err != nil {
		t.Fatalf("LoadPolicy(sibling paths sharing a prefix): %v", err)
	}
	if len(policy.Roots) != 2 || len(policy.Stores) != 2 {
		t.Fatalf("policy = %+v, want both sibling roots and both sibling stores", policy)
	}
}

func TestLoadPolicyV2RejectsInvalidDocuments(t *testing.T) {
	root := t.TempDir()
	project := t.TempDir()
	store := t.TempDir()
	nestedParent := t.TempDir()
	nestedChild := mkdir(t, nestedParent, "child")
	storeWithRoot := t.TempDir()
	rootInStore := mkdir(t, storeWithRoot, "transcripts")
	fileStore := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileStore, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkedStore := filepath.Join(t.TempDir(), "linked-store")
	if err := os.Symlink(store, symlinkedStore); err != nil {
		t.Fatal(err)
	}
	v2 := func(roots, stores string) string {
		return `{"schema_version":"gasworks.companion.root-policy/v2","roots":[` + roots + `],"stores":[` + stores + `]}`
	}
	activeProject := `{"path":"` + project + `","generation":1,"active":true,"mode":"forward-only","kind":"project"}`
	for name, body := range map[string]string{
		"v1 refuses kind":          `{"schema_version":"gasworks.companion.root-policy/v1","roots":[{"path":"` + root + `","generation":1,"active":true,"mode":"forward-only","kind":"project"}]}`,
		"v1 refuses stores":        `{"schema_version":"gasworks.companion.root-policy/v1","roots":[],"stores":["` + store + `"]}`,
		"v2 refuses unknown field": `{"schema_version":"gasworks.companion.root-policy/v2","roots":[],"extra":true}`,
		"v2 refuses trailing value": `{"schema_version":"gasworks.companion.root-policy/v2","roots":[]}` +
			`{"schema_version":"gasworks.companion.root-policy/v2","roots":[]}`,
		"unsupported schema":         `{"schema_version":"gasworks.companion.root-policy/v3","roots":[],"stores":[]}`,
		"unknown kind":               v2(`{"path":"`+root+`","generation":1,"active":true,"mode":"forward-only","kind":"folder"}`, ""),
		"project root without store": v2(activeProject, ""),
		"nested project roots": v2(`{"path":"`+nestedParent+`","generation":1,"active":true,"mode":"forward-only","kind":"project"},`+
			`{"path":"`+nestedChild+`","generation":2,"active":true,"mode":"forward-only","kind":"project"}`, `"`+store+`"`),
		"project root nested in a transcript root": v2(`{"path":"`+nestedParent+`","generation":1,"active":true,"mode":"forward-only"},`+
			`{"path":"`+nestedChild+`","generation":2,"active":true,"mode":"forward-only","kind":"project"}`, `"`+store+`"`),
		"overlapping stores":       v2(activeProject, `"`+nestedParent+`","`+nestedChild+`"`),
		"duplicate stores":         v2(activeProject, `"`+store+`","`+store+`"`),
		"store overlaps a root":    v2(`{"path":"`+rootInStore+`","generation":1,"active":true,"mode":"forward-only"},`+activeProject, `"`+storeWithRoot+`"`),
		"relative store":           v2(activeProject, `"relative/store"`),
		"non-canonical store":      v2(activeProject, `"`+store+`/."`),
		"symlinked store":          v2(activeProject, `"`+symlinkedStore+`"`),
		"store is not a directory": v2(activeProject, `"`+fileStore+`"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy(writePolicy(t, body)); err == nil {
				t.Fatal("LoadPolicy succeeded, want error")
			}
		})
	}
}
