//go:build linux

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func reuploadPolicy(schema, content string, roots ...string) string {
	records := make([]string, 0, len(roots))
	for i, r := range roots {
		active, mode := true, `"backfill"`
		if strings.HasPrefix(r, "-") {
			r, active, mode = r[1:], false, `""`
		}
		records = append(records, fmt.Sprintf(`{"path":%q,"generation":%d,"active":%t,"mode":%s}`, r, i+1, active, mode))
	}
	return fmt.Sprintf(`{"schema_version":"gasworks.companion.root-policy/%s"%s,"roots":[%s]}`, schema, content, strings.Join(records, ","))
}

// The re-upload honors the producer's consent policy: it reads only the active transcript roots, and
// refuses to run at all unless the policy grants content upload.
func TestReuploadRootsFromPolicy(t *testing.T) {
	active, other := t.TempDir(), t.TempDir()
	withdrawn := filepath.Join(t.TempDir(), "withdrawn")

	roots, err := reuploadRootsFromPolicy(writePolicyFile(t, reuploadPolicy("v3", `,"content_upload":true`, active, "-"+withdrawn, other)))
	if err != nil {
		t.Fatalf("granted policy: %v", err)
	}
	if !slices.Equal(roots, []string{active, other}) {
		t.Fatalf("roots = %v, want only the active transcript roots", roots)
	}
	for name, body := range map[string]string{
		"denied":    reuploadPolicy("v3", `,"content_upload":false`, active),
		"unstated":  reuploadPolicy("v2", "", active),
		"no active": reuploadPolicy("v3", `,"content_upload":true`, "-"+withdrawn),
	} {
		if _, err := reuploadRootsFromPolicy(writePolicyFile(t, body)); err == nil {
			t.Errorf("%s policy: re-upload allowed", name)
		}
	}
}

func TestContentReuploadFlagChecks(t *testing.T) {
	cursors, root := t.TempDir(), t.TempDir()
	base := []string{"-cursor-dir", cursors, "-collector", "https://collector.example", "-source-id", "src_x", "-progress-file", filepath.Join(t.TempDir(), "p.jsonl")}
	cases := map[string][]string{
		"no token file":      append([]string{"-approved-root", root}, base...),
		"missing token file": append([]string{"-approved-root", root, "-token-file", filepath.Join(t.TempDir(), "absent")}, base...),
		"token file is dir":  append([]string{"-approved-root", root, "-token-file", t.TempDir()}, base...),
		"policy and root":    append([]string{"-approved-root", root, "-root-policy-file", writePolicyFile(t, reuploadPolicy("v3", `,"content_upload":true`, root))}, base...),
		"denied policy":      append([]string{"-root-policy-file", writePolicyFile(t, reuploadPolicy("v3", `,"content_upload":false`, root))}, base...),
		"zero conflicts":     append([]string{"-approved-root", root, "-max-consecutive-conflicts", "0", "-dry-run"}, base...),
	}
	for name, args := range cases {
		if code := runContentReupload(args, io.Discard); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
