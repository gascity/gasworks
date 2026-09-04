package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/store"
)

// --- leg C's envelope --------------------------------------------------------------------

// The server reveals the secret exactly once and this CLI cannot revoke what it was given, so
// no field of the leg C response except the secret may be able to end the ceremony. Each of
// these is a real accounts-side type change: the secret still lands in an owner-only file and
// the command still succeeds, with whatever metadata could be read.
func TestSPMintKeySurvivesADriftedLegCResponse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     map[string]any
		wantLine string // what the summary must say about the drifted field
	}{
		{
			name: "expires_at as an epoch number",
			body: map[string]any{
				"key_id": "spk_1", "secret": "gck_sp_secret_value", "prefix": "gck_sp",
				"org_id": "org_a", "scopes": []string{"forge:city.create"},
				"expires_at": 1789000000,
			},
			wantLine: "expires:  1789000000",
		},
		{
			name: "scopes as a space-delimited string",
			body: map[string]any{
				"key_id": "spk_1", "secret": "gck_sp_secret_value", "prefix": "gck_sp",
				"org_id": "org_a", "scopes": "forge:city.create forge:city.delete",
				"expires_at": "2026-09-10T00:00:00Z",
			},
			wantLine: "scopes:   forge:city.create forge:city.delete",
		},
		{
			name: "key_id as a number",
			body: map[string]any{
				"key_id": 1, "secret": "gck_sp_secret_value", "prefix": "gck_sp",
				"org_id": "org_a", "scopes": []string{"forge:city.create"},
				"expires_at": "2026-09-10T00:00:00Z",
			},
			wantLine: "key id:   1",
		},
		{
			name: "key_id as an object, no scopes, no expiry",
			body: map[string]any{
				"key_id": map[string]any{"id": "spk_1"}, "secret": "gck_sp_secret_value",
			},
			wantLine: "key id:   ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			minted := filepath.Join(t.TempDir(), "minted-keys")
			t.Setenv(store.MintedKeyDirEnv, minted)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusCreated, tc.body)
			}

			stdout, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d leg C=%d\nstdout:%s", code, len(srv.reqs("/complete")), stdout)
			if code != 0 {
				t.Fatalf("exit=%d — leg C revealed the secret and the mint IS complete\nstderr:%s", code, stderr)
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatalf("the secret is not at %s: %v", out, err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s is mode %04o, want 0600", out, info.Mode().Perm())
			}
			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("read %s: %v", out, err)
			}
			if !strings.Contains(string(body), "gck_sp_secret_value") {
				t.Fatalf("%s holds %q, not the secret", out, body)
			}
			if strings.Contains(stdout, "gck_sp_secret_value") || strings.Contains(stderr, "gck_sp_secret_value") {
				t.Fatalf("the secret was printed\nstdout:%s\nstderr:%s", stdout, stderr)
			}
			if !strings.Contains(stdout, tc.wantLine) {
				t.Errorf("the summary does not carry %q:\n%s", tc.wantLine, stdout)
			}
		})
	}
}

// The counterpart: a 201 whose body this CLI cannot read as a credential is a PARTIAL SUCCESS,
// not a failure. Leg C returned bytes, which means the server acted and the challenge is spent,
// so the bytes stay on the disk at 0600 exactly as they arrived — the secret may well be in
// them, in a shape this client does not recognise — and the exit is non-zero because the file
// is not the credential the user asked for. What it must never do is unlink the file or say the
// mint did not happen.
//
// What it must ALSO never do is say a credential WAS minted. No secret was read out of any of
// these bodies, so nobody knows whether one exists: the honest report names the status, says the
// outcome is unknown, and names the challenge to reconcile it against. "A credential was minted"
// here is a guess that happens to point the right way, and the next body along — a 200 carrying
// authorization_pending — is the same guess pointing the wrong way.
func TestSPMintKeyKeepsAResponseItCannotReadAsACredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
		want string
	}{
		{"no secret field", map[string]any{"key_id": "spk_1"}, `carries no usable "secret"`},
		{"an empty secret", map[string]any{"key_id": "spk_1", "secret": ""}, `carries no usable "secret"`},
		{"a null secret", map[string]any{"key_id": "spk_1", "secret": nil}, `carries no usable "secret"`},
		{"a body that is not an object", []any{map[string]any{"secret": "gck_sp_secret_value"}},
			"is not a JSON object"},
		{"the secret under a key this client does not know", map[string]any{"key_id": "spk_1",
			"client_secret": "gck_sp_secret_value"}, `the only field that could be it is "client_secret"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			minted := filepath.Join(t.TempDir(), "minted-keys")
			t.Setenv(store.MintedKeyDirEnv, minted)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				writeJSON(w, http.StatusCreated, tc.body)
			}

			_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d stderr=%q", code, strings.TrimSpace(stderr))
			if code == 0 {
				t.Fatal("exit 0 for a response this CLI could not render as a credential")
			}
			body, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("the response leg C returned was not kept at %s: %v", out, err)
			}
			wire, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(body)) != string(wire) {
				t.Fatalf("%s holds %q, want the server's response verbatim (%s)", out, body, wire)
			}
			if info, err := os.Lstat(out); err == nil && runtime.GOOS != "windows" {
				if perm := info.Mode().Perm(); perm&0o077 != 0 {
					t.Fatalf("the saved response is mode %04o, readable beyond its owner", perm)
				}
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr does not say why the response could not be read (%q):\n%s", tc.want, stderr)
			}
			for _, want := range []string{
				"THE MINT PLANE ANSWERED 201 WITH A BODY THIS CLI COULD NOT READ AS A CREDENTIAL",
				"Whether one was issued is NOT known",
				out,
				"do not delete it",
				"reconcile challenge chal_1",
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr is missing %q:\n%s", want, stderr)
				}
			}
			if strings.Contains(stderr, "A CREDENTIAL WAS MINTED") {
				t.Errorf("stderr states a mint as a fact over a body no secret was read out of:\n%s", stderr)
			}
			if strings.Contains(stderr, "the mint was not completed") {
				t.Errorf("stderr says the mint did not happen, and leg C returned bytes:\n%s", stderr)
			}
			if entries, _ := os.ReadDir(minted); len(entries) != 0 {
				t.Errorf("%d files left in the minted-keys dir", len(entries))
			}
		})
	}
}

// The other side of that line. A 2xx with NO body revealed nothing, so there is nothing to keep
// and the reservation goes with the run — the same rollback any pre-reveal failure gets.
func TestSPMintKeyLeavesNothingWhenLegCRevealsNoBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"204 No Content", http.StatusNoContent},
		{"201 with an empty body", http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := mintSeed(t)
			virtualClock(t)
			minted := filepath.Join(t.TempDir(), "minted-keys")
			t.Setenv(store.MintedKeyDirEnv, minted)
			out := filepath.Join(t.TempDir(), "sp.env")
			srv.mintCompleteHandler = func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.WriteHeader(tc.status)
			}

			_, stderr, code := capture(t, func() int { return run(mintArgs(out)) })
			t.Logf("exit=%d stderr=%q", code, strings.TrimSpace(stderr))
			if code == 0 {
				t.Fatal("exit 0 for a redemption that revealed nothing")
			}
			if !strings.Contains(stderr, "revealed no credential") {
				t.Errorf("stderr = %q, want it to say nothing came back", stderr)
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Errorf("the reservation was left behind at %s (%v)", out, err)
			}
			if entries, _ := os.ReadDir(minted); len(entries) != 0 {
				t.Errorf("%d files left in the minted-keys dir", len(entries))
			}
		})
	}
}

// --- the directory the credentials live in ---------------------------------------------------

// The minted-keys directory is this CLI's own, and the rescue file lands in it. A pre-existing
// one with a wide mode lets anyone list which keys exist and unlink them, so it is tightened
// rather than accepted — the same thing the config dir and the DPoP key dir do.
func TestSPMintKeyTightensAWideMintedKeyDir(t *testing.T) {
	mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.Mkdir(minted, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(minted, 0o777); err != nil { // defeat the umask MkdirAll obeys
		t.Fatal(err)
	}
	t.Setenv(store.MintedKeyDirEnv, minted)

	_, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
			"--scope", "forge:city.create", "--no-browser"})
	})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	info, err := os.Stat(minted)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s is mode %04o after the mint", minted, info.Mode().Perm())
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("minted-keys dir is mode %04o — group and other can list and unlink the credential",
			info.Mode().Perm())
	}
}

// --- the name a saved credential ends up with ------------------------------------------------

// The default destination is reserved as minting-*.partial and promoted once the secret is on
// disk. When the promoted name is taken — an earlier mint of the same key id — the file must
// still stop being called a partial: that name is documented as an interrupted mint, which
// invites someone to delete a live key that cannot be revoked.
func TestSPMintKeyNamesACollidingCredentialAsACredential(t *testing.T) {
	srv, _ := mintSeed(t)
	virtualClock(t)
	minted := filepath.Join(t.TempDir(), "minted-keys")
	if err := os.MkdirAll(minted, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.MintedKeyDirEnv, minted)
	squatter := filepath.Join(minted, "spk_1.env")
	if err := os.WriteFile(squatter, []byte("AN EARLIER MINT\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := capture(t, func() int {
		return run([]string{"sp", "mint-key", "--org", "acme", "--sp", "sp_1",
			"--scope", "forge:city.create", "--no-browser"})
	})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	secret, _ := srv.mintCredential["secret"].(string)
	if body, _ := os.ReadFile(squatter); strings.Contains(string(body), secret) {
		t.Fatalf("the promotion overwrote the earlier mint at %s", squatter)
	}

	entries, err := os.ReadDir(minted)
	if err != nil {
		t.Fatal(err)
	}
	var holder string
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(minted, entry.Name()))
		if err != nil || !strings.Contains(string(body), secret) {
			continue
		}
		holder = entry.Name()
		info, _ := entry.Info()
		t.Logf("the new credential is in %s (mode %04o)", holder, info.Mode().Perm())
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", holder, info.Mode().Perm())
		}
	}
	if holder == "" {
		t.Fatalf("the secret is in none of %v; stderr=%s", entries, stderr)
	}
	if strings.HasSuffix(holder, ".partial") || strings.HasPrefix(holder, "minting-") {
		t.Errorf("a live, unrevokable credential is named %q, which this CLI documents as an "+
			"interrupted mint rather than a credential", holder)
	}
	if !strings.Contains(stdout, holder) {
		t.Errorf("the summary does not name the file the secret is in (%s):\n%s", holder, stdout)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr does not explain the unusual name:\n%s", stderr)
	}
}
