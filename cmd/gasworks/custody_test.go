package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/store"
)

// The DPoP private key must never appear in credentials.json — the whole point of split
// credential storage is that a stolen credentials file carries no signing key.
func TestGetTokenKeepsTheDPoPKeyOutOfTheCredentialsFile(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	raw, err := os.ReadFile(store.CredsPath())
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "dpop_pem") {
		t.Fatalf("credentials.json still holds key material:\n%s", raw)
	}

	data := loadStore(t)
	if len(data.Sessions) != 1 {
		t.Fatalf("stored %d sessions, want 1", len(data.Sessions))
	}
	for _, session := range data.Sessions {
		if !session.Key.Enrolled() {
			t.Fatalf("session has no key reference: %+v", session)
		}
		if _, err := loadSessionKey(session.Key); err != nil {
			t.Fatalf("the referenced key is not readable: %v", err)
		}
	}
}

// With no platform keystore and no opt-in, enrolment fails closed with an actionable error
// instead of silently writing the key to a plaintext dotfile.
func TestGetTokenFailsClosedWithoutAnApprovedKeystore(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	t.Setenv(config.AllowFileKeystoreEnv, "0")

	_, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) })
	if code == 0 {
		t.Fatal("getToken succeeded without an approved credential store")
	}
	for _, want := range []string{"no approved credential store", "--allow-file-keystore", config.AllowFileKeystoreEnv} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr %q does not mention %q", errOut, want)
		}
	}
	// Failing closed happens BEFORE the STS round-trip: no session may be minted for a key
	// this host cannot keep.
	if logins := len(srv.reqs("/sts/v0/login")); logins != 0 {
		t.Fatalf("established %d sessions while failing closed, want 0", logins)
	}
}

// The flag is an equivalent opt-in to the environment variable.
func TestGetTokenAcceptsTheKeystoreOptInFlag(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	t.Setenv(config.AllowFileKeystoreEnv, "0")

	out, errOut, code := capture(t, func() int {
		return run([]string{"getToken", "manifold", "--allow-file-keystore"})
	})
	if code != 0 {
		t.Fatalf("getToken --allow-file-keystore exit=%d stderr=%q", code, errOut)
	}
	if strings.TrimSpace(out) != "EIA.JWT" {
		t.Fatalf("stdout = %q, want the minted EIA", out)
	}
}

// A credentials.json written before split storage carries the key inline. It is not reused,
// and the session that replaces it takes that key off disk.
func TestPreSplitStorageSessionIsReplacedAndItsKeyErased(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, nil)
	legacy := map[string]any{
		"refresh_token":         "RT",
		"id_token":              validIDToken(),
		"credential_generation": testCredentialGenerationA,
		"sessions": map[string]any{
			sessionCacheKey(srv.srv.URL, "org_a", testCredentialGenerationA): map[string]any{
				"session_token": "OLD-SESSION",
				"dpop_pem":      "-----BEGIN PRIVATE KEY-----\nlegacy\n-----END PRIVATE KEY-----\n",
				"expires_at":    1 << 40,
			},
		},
	}
	writeCreds(t, legacy)

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}
	raw, err := os.ReadFile(store.CredsPath())
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if strings.Contains(string(raw), "dpop_pem") || strings.Contains(string(raw), "legacy") {
		t.Fatalf("the pre-split-storage key survived the upgrade:\n%s", raw)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("unmarshal credentials: %v", err)
	}
	sessions, _ := persisted["sessions"].(map[string]any)
	if len(sessions) != 1 {
		t.Fatalf("stored %d sessions, want the single re-established one", len(sessions))
	}
	// The inline-key session was not reused: the CLI re-established one at the STS.
	if logins := len(srv.reqs("/sts/v0/login")); logins != 1 {
		t.Fatalf("made %d session establishments, want 1", logins)
	}
}

// Logout must leave no key material behind, not just an empty credentials file.
func TestLogoutPurgesEnrolledKeys(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}
	keyDir := store.KeyDir()
	if entries, err := os.ReadDir(keyDir); err != nil || len(entries) == 0 {
		t.Fatalf("no key was enrolled before logout (%d entries, err %v)", len(entries), err)
	}

	if _, errOut, code := capture(t, func() int { return run([]string{"logout"}) }); code != 0 {
		t.Fatalf("logout exit=%d stderr=%q", code, errOut)
	}
	if _, err := os.Stat(keyDir); !os.IsNotExist(err) {
		t.Fatalf("logout left key material behind (%v)", err)
	}
}

// The SDK owns renewal: a cached EIA inside its skew window is re-minted transparently, with
// no --refresh and nothing for the caller to implement.
func TestSDKReMintsAnExpiringCachedEIAWithoutBeingAsked(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("first getToken exit=%d stderr=%q", code, errOut)
	}
	data := loadStore(t)
	if len(data.EIACache) != 1 {
		t.Fatalf("cached %d EIAs, want 1", len(data.EIACache))
	}
	// Age the cached credential to just inside the re-mint threshold.
	if err := store.Update(func(d *store.Data) error {
		for key, entry := range d.EIACache {
			entry.ExpiresAt = now() + eiaSkewSecs - 1
			d.EIACache[key] = entry
		}
		return nil
	}); err != nil {
		t.Fatalf("age the cache: %v", err)
	}

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("second getToken exit=%d stderr=%q", code, errOut)
	}
	if mints := len(srv.reqs("/sts/v0/token")); mints != 2 {
		t.Fatalf("made %d mints, want the expiring credential re-minted by the SDK", mints)
	}
}

// bd-enterprise vendors this credential store and shares credentials.json with us, writing
// its own sessions (with the key inline) under its own STS authority. Establishing a session
// must replace OUR entry and leave everything else exactly as it was found — dropping every
// key-less session would sign every bd user out on each gasworks command.
func TestEstablishingASessionLeavesForeignSessionsAlone(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, nil)
	foreignKey := sessionCacheKey("https://works.gascity.com", "org_a", testCredentialGenerationA)
	writeCreds(t, map[string]any{
		"refresh_token":         "RT",
		"id_token":              validIDToken(),
		"credential_generation": testCredentialGenerationA,
		"sessions": map[string]any{
			foreignKey: map[string]any{
				"session_token": "BD-SESSION",
				"dpop_pem":      "-----BEGIN PRIVATE KEY-----\nbd\n-----END PRIVATE KEY-----\n",
				"expires_at":    1 << 40,
			},
		},
	})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}

	data := loadStore(t)
	if len(data.Sessions) != 2 {
		t.Fatalf("stored %d sessions, want the foreign one plus ours", len(data.Sessions))
	}
	foreign, ok := data.Sessions[foreignKey]
	if !ok {
		t.Fatal("the foreign session was deleted by our write")
	}
	if foreign.SessionToken != "BD-SESSION" || !strings.Contains(foreign.InlineKeyPEM, "BEGIN PRIVATE KEY") {
		t.Fatalf("the foreign session was rewritten: %+v", foreign)
	}
}

// A fresh login invalidates every session, so the private keys they were pinned to must go
// too — otherwise each login leaves another live key on the host.
func TestInvalidatingSessionsDeletesTheirKeys(t *testing.T) {
	useFileKeystore(t)
	ref := enrollTestKey(t, "dpop-invalidated")
	data := &store.Data{
		Sessions: map[string]store.Session{"k": {SessionToken: "s", Key: ref, ExpiresAt: 1 << 40}},
		EIACache: map[string]store.EIACacheEntry{"e": {EIA: "eia", ExpiresAt: 1 << 40}},
	}

	forgetSessionKeys(dropSessions(data))

	if data.Sessions != nil || data.EIACache != nil {
		t.Fatalf("dropSessions left state behind: %+v", data)
	}
	if _, err := loadSessionKey(ref); err == nil {
		t.Fatal("the key of an invalidated session is still readable")
	}
}
