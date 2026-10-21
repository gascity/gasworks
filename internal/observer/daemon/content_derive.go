//go:build linux || darwin

package daemon

import (
	"path/filepath"
	"strings"
)

// Native session ids derived from the transcript's name.
//
// The content uploader keys a snapshot by the native session id the metadata pipeline stamps. That id
// normally comes from the live sink, which threads it while it parses the transcript's records, or,
// after a restart, from the transcript's pending record or last-uploaded marker. A transcript that a
// previous run parsed to EOF but never had accepted (every upload it was offered failed before the
// daemon stopped) has none of them: its cursor sits at EOF, so the sink never threads it again, and
// no marker or pending record names it. Before this derivation such a transcript was skipped on every
// tick of every later daemon: the restart hole that left thousands of finished transcripts never
// uploaded.
//
// The derivation is the LAST fallback, after the sink, the pending record and the marker. It reads
// the identity the providers write into the transcript's name, which is the id the metadata pipeline
// stamps for an ordinary transcript and the id the collector's content store keys it by:
//
//	claude <uuid>.jsonl                      → <uuid>  (Claude Code names the file by its session)
//	codex  rollout-<timestamp>-<uuid>.jsonl  → <uuid>  (the session_meta id Codex names the file by;
//	                                                    the content store's canonical rollout identity)
//
// A Claude subagent transcript (agent-<hex>.jsonl) is deliberately NOT derived: its records carry
// the PARENT session's id, and the content store keys one transcript per native id, so keying a
// subagent's bytes by its parent's id would replace the parent's snapshot. Anything else stays
// unknown and is skipped cheaply, as before.

// deriveSessionFromName derives the native session id and provider from a transcript's basename.
func deriveSessionFromName(path string) (native, provider string, ok bool) {
	stem, isJSONL := strings.CutSuffix(filepath.Base(path), ".jsonl")
	if !isJSONL {
		return "", "", false
	}
	if rest, isRollout := strings.CutPrefix(stem, "rollout-"); isRollout {
		// rollout-YYYY-MM-DDThh-mm-ss-<uuid>: the session uuid is the last 36 bytes, after a dash.
		if len(rest) < uuidLen+2 || rest[len(rest)-uuidLen-1] != '-' {
			return "", "", false
		}
		id := rest[len(rest)-uuidLen:]
		if !isLowerUUID(id) {
			return "", "", false
		}
		return id, "codex", true
	}
	if isLowerUUID(stem) {
		return stem, "claude", true
	}
	return "", "", false
}

// uuidLen is the length of a canonical textual UUID (8-4-4-4-12).
const uuidLen = 36

// isLowerUUID reports whether s is a canonical lowercase UUID, the shape both providers name their
// transcripts with.
func isLowerUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
