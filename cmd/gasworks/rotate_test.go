package main

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gascity/gasworks/internal/store"
)

// countingLogin gives each established session a distinct token so a rotation is visible in
// the store.
func countingLogin(counter *atomic.Int64) func(http.ResponseWriter, *http.Request, url.Values) {
	return func(w http.ResponseWriter, _ *http.Request, form url.Values) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"session_token": "SESS-" + string(rune('0'+counter.Add(1))),
			"session_id":    "ses_1", "org_id": form.Get("org"),
			"token_type": "DPoP", "expires_in": 28800,
		})
	}
}

// storedSession returns the single persisted session, failing if there is not exactly one.
func storedSession(t *testing.T) store.Session {
	t.Helper()
	data := loadStore(t)
	if len(data.Sessions) != 1 {
		t.Fatalf("stored %d sessions, want 1", len(data.Sessions))
	}
	for _, session := range data.Sessions {
		return session
	}
	return store.Session{}
}

func TestRotateKeyReEnrollsWithAFreshKey(t *testing.T) {
	srv := newStub(t)
	var sessions atomic.Int64
	srv.loginHandler = countingLogin(&sessions)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}
	before := storedSession(t)
	beforeKey, err := loadSessionKey(before.Key)
	if err != nil {
		t.Fatalf("load the pre-rotation key: %v", err)
	}

	out, errOut, code := capture(t, func() int { return run([]string{"rotate-key"}) })
	if code != 0 {
		t.Fatalf("rotate-key exit=%d stderr=%q", code, errOut)
	}

	after := storedSession(t)
	afterKey, err := loadSessionKey(after.Key)
	if err != nil {
		t.Fatalf("load the rotated key: %v", err)
	}
	if beforeKey.Thumbprint() == afterKey.Thumbprint() {
		t.Fatal("rotate-key reused the previous DPoP key")
	}
	if after.SessionToken == before.SessionToken {
		t.Fatalf("session token %q survived the rotation", after.SessionToken)
	}
	if logins := len(srv.reqs("/sts/v0/login")); logins != 2 {
		t.Fatalf("made %d session establishments, want a re-enrollment after the first", logins)
	}
	if !strings.Contains(out, afterKey.Thumbprint()) {
		t.Errorf("rotate-key did not report the new jkt:\n%s", out)
	}
	if !strings.Contains(errOut, "superseded session stays valid") {
		t.Errorf("rotate-key did not warn that the old session is not revoked: %q", errOut)
	}
	// The rotated key stays out of the credentials file like any other.
	if !after.Key.Enrolled() {
		t.Fatalf("rotated session has no key reference: %+v", after)
	}
}

func TestRotateKeyDropsCachedEIAsMintedFromTheOldSession(t *testing.T) {
	srv := newStub(t)
	var sessions atomic.Int64
	srv.loginHandler = countingLogin(&sessions)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	if _, errOut, code := capture(t, func() int { return run([]string{"getToken", "manifold"}) }); code != 0 {
		t.Fatalf("getToken exit=%d stderr=%q", code, errOut)
	}
	if len(loadStore(t).EIACache) == 0 {
		t.Fatal("no EIA was cached before the rotation")
	}
	if _, errOut, code := capture(t, func() int { return run([]string{"rotate-key"}) }); code != 0 {
		t.Fatalf("rotate-key exit=%d stderr=%q", code, errOut)
	}
	if cached := loadStore(t).EIACache; len(cached) != 0 {
		t.Fatalf("rotate-key kept %d EIAs minted from the superseded session", len(cached))
	}
}

func TestRotateKeyFailsClosedWithoutAnApprovedKeystore(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})
	t.Setenv("GASWORKS_ALLOW_FILE_KEYSTORE", "0")

	_, errOut, code := capture(t, func() int { return run([]string{"rotate-key"}) })
	if code == 0 {
		t.Fatal("rotate-key succeeded without an approved credential store")
	}
	if !strings.Contains(errOut, "no approved credential store") {
		t.Errorf("stderr = %q, want the fail-closed enrolment error", errOut)
	}
	if logins := len(srv.reqs("/sts/v0/login")); logins != 0 {
		t.Fatalf("re-enrolled %d times while failing closed, want 0", logins)
	}
}

func TestRotateKeyRejectsAnOrgYouAreNotIn(t *testing.T) {
	srv := newStub(t)
	seed(t, srv, map[string]any{"refresh_token": "RT", "id_token": validIDToken()})

	_, errOut, code := capture(t, func() int { return run([]string{"rotate-key", "--org", "nope"}) })
	if code == 0 {
		t.Fatal("rotate-key accepted an org the caller is not a member of")
	}
	if !strings.Contains(errOut, "not a member of org 'nope'") {
		t.Errorf("stderr = %q, want a membership error", errOut)
	}
}
