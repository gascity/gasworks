package store

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func setConfigDir(t *testing.T, sub string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), sub)
	t.Setenv("GASWORKS_CONFIG_DIR", dir)
	return dir
}

func TestSaveLoadRoundtrip(t *testing.T) {
	setConfigDir(t, "cfg")
	want := &Data{
		RefreshToken: "rt",
		Sessions: map[string]Session{
			"org_a": {SessionToken: "t", DPoPPEM: "...", ExpiresAt: 42},
		},
		EIACache: map[string]EIACacheEntry{
			"k": {EIA: "eia", ExpiresAt: 99},
		},
		IDToken:    "id",
		DefaultOrg: "org_a",
	}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roundtrip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestCredsFileIs0600(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX-only mode check")
	}
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(CredsPath())
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("creds mode = %o, want 600", mode)
	}
}

func TestConfigDirIs0700(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX-only mode check")
	}
	dir := setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("config dir mode = %o, want 700", mode)
	}
}

func TestUpdateIsReadModifyWrite(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := Update(func(d *Data) error {
		d.RefreshToken = "b"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// The pre-existing field must survive the update (true RMW, not overwrite).
	if got.IDToken != "a" || got.RefreshToken != "b" {
		t.Errorf("got %+v, want IDToken=a RefreshToken=b", got)
	}
}

// TestConcurrentUpdatePreservesFields stresses the cross-process lock: many goroutines each
// add a distinct session under Update; none may clobber another's write.
func TestConcurrentUpdatePreservesFields(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{Sessions: map[string]Session{}}); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := string(rune('a' + i))
			errs <- Update(func(d *Data) error {
				if d.Sessions == nil {
					d.Sessions = map[string]Session{}
				}
				d.Sessions[key] = Session{SessionToken: key}
				return nil
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sessions) != n {
		t.Errorf("got %d sessions, want %d — a concurrent write was lost", len(got.Sessions), n)
	}
}

func TestUpdateErrorAborts(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "keep"}); err != nil {
		t.Fatal(err)
	}
	wantErr := errSentinel
	if err := Update(func(d *Data) error {
		d.IDToken = "changed"
		return wantErr
	}); err != wantErr {
		t.Fatalf("Update err = %v, want sentinel", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.IDToken != "keep" {
		t.Errorf("mutate error still wrote: IDToken = %q, want keep", got.IDToken)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	setConfigDir(t, "nope")
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &Data{}) {
		t.Errorf("missing file gave %+v, want empty Data", got)
	}
}

func TestClearRemoves(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(CredsPath()); !os.IsNotExist(err) {
		t.Errorf("creds file still exists after Clear: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &Data{}) {
		t.Errorf("after Clear, Load gave %+v, want empty", got)
	}
}

func TestClearMissingIsNoError(t *testing.T) {
	setConfigDir(t, "nope")
	if err := Clear(); err != nil {
		t.Errorf("Clear on missing file errored: %v", err)
	}
}

func TestCorruptFileDegradesToEmpty(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CredsPath(), []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &Data{}) {
		t.Errorf("corrupt file gave %+v, want empty Data", got)
	}
}

// TestUnreadableFileDoesNotWipe is the M2 regression: a credentials file that exists but
// cannot be READ (a transient IO/perms error) must make Update return an error and leave the
// file's contents intact — NOT silently degrade Load to empty and then Save that empty Data
// back over good credentials. Run as a non-root user, chmod 000 reproduces the unreadable case.
func TestUnreadableFileDoesNotWipe(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX-only perms check (NTFS ignores 0000)")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permissions; cannot make a file unreadable")
	}
	setConfigDir(t, "cfg")
	// Seed via Save so the config dir exists, then overwrite with known bytes.
	if err := Save(&Data{IDToken: "seed"}); err != nil {
		t.Fatal(err)
	}
	const good = `{"id_token":"keepme","refresh_token":"keep-rt"}`
	if err := os.WriteFile(CredsPath(), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load must surface the read error rather than returning empty Data.
	if err := os.Chmod(CredsPath(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(CredsPath(), 0o600) }) // let TempDir cleanup remove it
	if _, err := Load(); err == nil {
		t.Fatal("Load on an unreadable file returned nil error — it would degrade to empty Data")
	}

	// Update must abort WITHOUT saving (no truncation of the good file).
	mutated := false
	err := Update(func(d *Data) error {
		mutated = true
		d.IDToken = "WIPED"
		return nil
	})
	if err == nil {
		t.Fatal("Update on an unreadable file returned nil error — it would overwrite good credentials")
	}
	if mutated {
		t.Error("mutate ran on empty Data — Update should have aborted at Load before mutating")
	}

	// The on-disk bytes must be untouched (not truncated/overwritten with empty).
	if err := os.Chmod(CredsPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(CredsPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != good {
		t.Errorf("credentials file was modified by a failed Update:\n got %q\nwant %q", string(raw), good)
	}
}

var errSentinel = sentinelError("sentinel")

type sentinelError string

func (e sentinelError) Error() string { return string(e) }
