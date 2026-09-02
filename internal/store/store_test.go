package store

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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
		RefreshToken:         "rt",
		CredentialGeneration: "g1:00000000000000000000000000000001",
		Sessions: map[string]Session{
			"org_a": {SessionToken: "t", Key: KeyRef{Backend: "file", Handle: "dpop-abc"}, ExpiresAt: 42},
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

func TestLoadWaitsForConcurrentUpdate(t *testing.T) {
	setConfigDir(t, "cfg")
	if err := Save(&Data{IDToken: "before"}); err != nil {
		t.Fatal(err)
	}

	updateEntered := make(chan struct{})
	releaseUpdate := make(chan struct{})
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- Update(func(data *Data) error {
			close(updateEntered)
			<-releaseUpdate
			data.IDToken = "after"
			return nil
		})
	}()
	select {
	case <-updateEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("Update did not acquire the store lock")
	}

	loadStarted := make(chan struct{})
	loadDone := make(chan struct{})
	var loaded *Data
	var loadErr error
	go func() {
		close(loadStarted)
		loaded, loadErr = Load()
		close(loadDone)
	}()
	<-loadStarted
	select {
	case <-loadDone:
		t.Fatal("Load completed while Update held the store lock")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseUpdate)
	if err := <-updateDone; err != nil {
		t.Fatalf("Update: %v", err)
	}
	select {
	case <-loadDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Load did not complete after Update released the store lock")
	}
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	if loaded.IDToken != "after" {
		t.Fatalf("Load read ID token %q, want the completed update", loaded.IDToken)
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

// The DPoP key directory must not sit inside the directory a "back up my dotfiles" job
// copies: the session and the key it is bound to may not be stored or backed up together.
func TestKeyDirIsOutsideTheConfigDirByDefault(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", "")
	t.Setenv(KeyDirEnv, "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if runtime.GOOS == "windows" {
		t.Skip("the Windows split is LOCALAPPDATA vs APPDATA, covered by the resolution above")
	}
	if keyDir := KeyDir(); strings.HasPrefix(keyDir, ConfigDir()+string(os.PathSeparator)) || keyDir == ConfigDir() {
		t.Fatalf("KeyDir %q is inside the config dir %q", keyDir, ConfigDir())
	}
}

func TestKeyDirHonoursItsOverrideAndPinnedProfiles(t *testing.T) {
	t.Setenv(KeyDirEnv, "/tmp/explicit-keys")
	t.Setenv("GASWORKS_CONFIG_DIR", "/tmp/profile")
	if got := KeyDir(); got != "/tmp/explicit-keys" {
		t.Fatalf("KeyDir = %q, want the explicit override", got)
	}
	t.Setenv(KeyDirEnv, "")
	// A pinned profile is self-contained: its keys stay inside it so a disposable canary or
	// test profile does not scatter key material into the user's state dir.
	if got, want := KeyDir(), filepath.Join("/tmp/profile", keyDirName); got != want {
		t.Fatalf("KeyDir = %q, want %q for a pinned profile", got, want)
	}
}

// bd-enterprise vendors this store and writes its DPoP key inline in the SAME
// credentials.json. Our Save must not strip its sessions, or every bd command re-logs in at
// the STS (and re-writes a plaintext key) after every gasworks command.
func TestSaveDoesNotStripAForeignInlineKeySession(t *testing.T) {
	t.Setenv("GASWORKS_CONFIG_DIR", t.TempDir())
	raw := `{
	  "refresh_token": "rt",
	  "sessions": {
	    "gasworks.dev/sts-session/v3:{\"credential_kind\":\"human\",\"sts_authority\":\"https://works.gascity.com\"}": {
	      "session_token": "BD-SESSION",
	      "dpop_pem": "-----BEGIN PRIVATE KEY-----\nbd\n-----END PRIVATE KEY-----\n",
	      "expires_at": 42
	    }
	  }
	}`
	if err := os.MkdirAll(ConfigDir(), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(CredsPath(), []byte(raw), 0o600); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}

	// A gasworks write that has nothing to do with that entry.
	if err := Update(func(d *Data) error {
		d.DefaultOrg = "org_a"
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	after, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(after.Sessions) != 1 {
		t.Fatalf("stored %d sessions, want the foreign one preserved", len(after.Sessions))
	}
	for _, session := range after.Sessions {
		if session.SessionToken != "BD-SESSION" {
			t.Errorf("session token = %q, want the foreign session", session.SessionToken)
		}
		if !strings.Contains(session.InlineKeyPEM, "BEGIN PRIVATE KEY") {
			t.Errorf("the foreign inline key did not survive our write: %q", session.InlineKeyPEM)
		}
	}
}
