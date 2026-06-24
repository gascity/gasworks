package recallaxis

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const singleTranscriptName = "01234567-89ab-cdef-0123-456789abcdef.jsonl"

// TestUploadStampsGCSessionIDFromSidecar: when a <transcript>.gcmeta sidecar
// exists, the forwarder reads it and stamps X-Cass-Gc-Session-Id — and the
// sidecar itself is NOT uploaded (it is not a transcript shape).
func TestUploadStampsGCSessionIDFromSidecar(t *testing.T) {
	root := setupSingleTranscriptRoot(t)
	transcript := filepath.Join(root, "proj", singleTranscriptName)
	if err := os.WriteFile(transcript+sidecarSuffix, []byte("gc-session-abc\n"), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	var got http.Header
	stats, _, hits := runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(201)
	})
	if *hits != 1 {
		t.Fatalf("server hit %d times, want 1 (the sidecar must not be uploaded)", *hits)
	}
	if stats.Sent != 1 {
		t.Fatalf("stats=%+v, want Sent=1", stats)
	}
	if v := got.Get("X-Cass-Gc-Session-Id"); v != "gc-session-abc" {
		t.Errorf("X-Cass-Gc-Session-Id = %q, want %q", v, "gc-session-abc")
	}
}

// TestUploadOmitsGCSessionIDWithoutSidecar: no sidecar => header absent (not
// empty-string present), so the server can tell "no correlation" cleanly.
func TestUploadOmitsGCSessionIDWithoutSidecar(t *testing.T) {
	root := setupSingleTranscriptRoot(t)

	var got http.Header
	runWithServer(t, root, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(201)
	})
	if _, present := got["X-Cass-Gc-Session-Id"]; present {
		t.Errorf("X-Cass-Gc-Session-Id present without a sidecar: %q", got.Get("X-Cass-Gc-Session-Id"))
	}
}

func TestReadGCSessionID(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "t.jsonl")
	set := func(content string) {
		t.Helper()
		if err := os.WriteFile(transcript+sidecarSuffix, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := readGCSessionID(transcript); got != "" {
		t.Errorf("no sidecar => %q, want \"\"", got)
	}

	set("gc-session-1\n")
	if got := readGCSessionID(transcript); got != "gc-session-1" {
		t.Errorf("got %q, want gc-session-1", got)
	}

	// Header-injection attempt: CR/LF and control bytes must be rejected outright.
	set("gc-1\r\nX-Evil: pwned")
	if got := readGCSessionID(transcript); got != "" {
		t.Errorf("control chars must be rejected, got %q", got)
	}

	// Whitespace-only / empty.
	set("   \n")
	if got := readGCSessionID(transcript); got != "" {
		t.Errorf("blank sidecar => %q, want \"\"", got)
	}

	// Oversized.
	set(strings.Repeat("a", 300))
	if got := readGCSessionID(transcript); got != "" {
		t.Errorf("oversized sidecar must be rejected, got len %d", len(got))
	}
}

func TestIsSafeHeaderValue(t *testing.T) {
	for _, ok := range []string{"gc-session-1", "abc123", "GC_Session.42", "a"} {
		if !isSafeHeaderValue(ok) {
			t.Errorf("%q should be safe", ok)
		}
	}
	for _, bad := range []string{"with space", "tab\tx", "nl\n", "cr\r", "ctrl\x00", "unicodé"} {
		if isSafeHeaderValue(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
