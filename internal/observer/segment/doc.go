// Package segment is the K9 bead-cost segmenter, version seg-v1 (attribution design §5).
//
// A session's usage stream is cut into segments, each a maximal stretch during which the
// session's "current bead" is constant (possibly "none"). The current bead changes only on a
// successful bd command from a closed, versioned list:
//
//   - OPEN(id): `bd update <id> --claim`, `bd ready --claim` (id read from the result),
//     `bd update <id> --status in_progress` / `-s in_progress`. The id is pushed onto the
//     session's claim stack, or moved to the top if it is already there.
//   - CLOSE(id): `bd close <ids…>`, `bd unclaim <ids…>` (it clears the assignee and resets the
//     status, so it is a status change), `bd update <id> --status <anything else>`,
//     `bd update <id> --assignee <x>` without --claim. Each id is removed from the stack.
//   - Everything else (queries, failed commands, git/gh, prose, here-document bodies that are not
//     fed to a shell) has no effect.
//
// A lane that holds only a byte-capped prefix of a command (the transcript lane: CASS caps a
// tool_call command at 2 KiB) reads it with ParseCommandPrefix, which keeps only the effects the
// prefix makes certain; a boundary past the cut is lost, never guessed.
//
// The current bead is the top of the stack ("last-claimed wins"). Closing the top reveals the
// previous still-open claim; an empty stack is "none". A boundary applies after the tool result
// of its command, so the assistant message that issued the command (and its usage) stays in the
// previous segment. Each session starts with an empty stack unless the lane supplies an initial
// bead (a wrapper run's DECLARED bead, or a subagent inheriting its parent's current bead).
//
// The package is pure and deterministic: it never reads a transcript, a clock or the network.
// Two lanes run it. The metadata lane (companion) feeds it the session's records in source
// order; the transcript lane (observer-extractor, gasworks-platform) builds a boundary Timeline
// from uploaded transcripts and assigns usage to it by time. gasworks-platform vendors this
// package; the golden corpus in testdata/ runs in both repositories' CI so the two copies cannot
// drift silently. Changing a rule means a new Version, never an edit to seg-v1.
package segment

// Version names the closed boundary list and tie rules this package implements. Every segment
// row a lane stores records it, and lanes on different versions are never mixed.
const Version = "seg-v1"
