# Observer USAGE `message_id` and `native_session_id` (spend-join keys)

The observer daemon stamps two ids on the evidence it captures from native
transcripts. gasworks-platform's run view joins them to Manifold's metered spend
rows to promote a list-price estimate to the real metered cost:

| Observer evidence                          | `manifold.spend` column |
| ------------------------------------------ | ----------------------- |
| SESSION_LIFECYCLE `native_session_id`      | `native_session_id`     |
| USAGE `payload.usage.message_id`           | `message_id`            |

The reader side is `docs/reference/observer-metered-spend-join-v1.md` in
gasworks-platform. Manifold's side is
`docs/architecture/spend-observer-cost-join.md` in gascity/manifold. Both ids
are correlation evidence only. They never affect token totals, pricing inputs,
or run membership. An absent id means that atom can only use the heuristic
(timestamp) lane.

## Codex rollouts (`internal/observer/adapter/codex/rollout.go`)

- `native_session_id` = `session_meta.payload.id`. This is the Codex thread
  id, which Manifold reads from `client_metadata.thread_id` /
  `prompt_cache_key`.
- `message_id` = the Responses API **response** id (`resp_…`). Manifold takes
  it from `response.id` in the response body.
  - Codex 0.153.0 and later writes exactly one `token_usage_record` line per
    completed response that reported usage, turns and compactions alike. Its
    `payload.response_id` is the response id.
  - The assistant `response_item` id is the output **item** id (`msg_…`). It is
    never used as `message_id` because it never equals the metered response id.
    No other consumer reads it.
  - A rollout from before Codex 0.153 has no `token_usage_record`. Its atoms
    carry no `message_id` and use the heuristic lane only.
  - An id is unusable when it is missing, not a string, longer than 128 bytes,
    or contains non-ASCII, whitespace or control characters. The atom then has
    no `message_id`. Its tokens are kept.

## Codex USAGE token source

A rollout's usage comes from one source only, chosen per file:

- **Record mode** (Codex 0.153.0 and later). Each `token_usage_record`
  becomes one USAGE atom. Its tokens come from `payload.usage` and its
  `message_id` is the response id. `token_count` events never become atoms in
  this mode. They only repeat usage a record already reported:
  - After each response, Codex writes a `token_count` with the same usage.
  - On each rate-limit refresh, Codex writes the previous usage again.
  - After a context reset (compaction), Codex writes zero input/output with an
    estimated `total_tokens`. The compaction response's real usage is in its
    record.

  A file enters record mode when its first `session_meta` names
  `cli_version` 0.153.0 or later, or at its first `token_usage_record`. A
  forked rollout copies its parent's `session_meta` after its own, so only the
  first one counts. A legacy rollout resumed by a newer Codex keeps its legacy
  atoms, and only records count after that.
- **Legacy mode** (before 0.153). Each `token_count` becomes an atom from
  `info.last_token_usage`. A `token_count` whose cumulative
  `info.total_token_usage` equals the previous one's is dropped. Only a
  completed response moves the total, so an unchanged total is a rate-limit
  refresh or a reset recount. A `token_count` with no cumulative total is kept.

Both modes map fields the same way:

- `input_tokens` less `cached_input_tokens` (clamped at zero) becomes
  `input_tokens`: fresh input, the same meaning Claude's `input_tokens` has.
  Codex's own `input_tokens` includes the cached input. Before
  `parser_version` `codex-transcript-v2` the observer copied it unchanged, so
  older Codex atoms count cached input twice when `input_tokens` and
  `cache_read_tokens` are both priced (gascity/gasworks#95).
- `cached_input_tokens` becomes `cache_read_tokens`.
- `output_tokens` becomes `output_tokens`. It already includes
  `reasoning_output_tokens`, so reasoning is not added again.

A usage with zero input and output is dropped. `total_tokens` is used only when
both are absent.

Parse state is per poll buffer. The usage mode and the legacy repeat total are
different: the durable cursor carries them with its offset and persists them
(`rollout_record_mode`, `rollout_legacy_total`). If a poll or a restart falls
between a record and its `token_count`, each response is still counted exactly
once, with its id. A cursor that is reset or sealed at a baseline forgets the
mode, and switches back to record mode at the next record.

A cursor state file written before this change holds only an offset. Every
state saved since sets `rollout_carry`, so such a file is recognized on load.
On the first drain after the upgrade, the watcher re-reads the bytes that the
cursor already consumed. It starts at byte zero, or at the forward-only floor,
so no pre-consent byte is read. From those bytes it derives the mode and the
repeat total that a current daemon would hold at that offset. It also derives
one more thing. The old daemon counted each response from the `token_count`
that follows its record. If it stopped between a record and that
`token_count`, the response was never counted. That record is kept as
`rollout_pending` and emitted once, with its response id, when parsing
resumes. So an upgrade neither re-counts a response the old daemon counted
(for example from a rate-limit repeat) nor drops one it had not counted.

## Claude transcripts (`internal/observer/adapter/codex/claude.go`)

- `native_session_id` = the envelope's `sessionId`. This equals the
  `session_id` inside Claude Code's `metadata.user_id` request field, which
  Manifold records.
- `message_id` = the assistant record's `message.id` (`msg_…`). This equals the
  Anthropic `message_start.message.id` that Manifold records.

## Claude USAGE token source

Claude Code writes one transcript record per content block of an API response
(thinking, text, each tool_use). Every record repeats the response's
`message.id` and its `usage`, as Claude Code knew it when it wrote the block.
A block written while the response still streams carries partial counts: the
input and cache counts are final, but `output_tokens` is a handful. The block
written after the response finished carries the final usage and a
`stop_reason`. Records of one response can be interleaved with other
responses' records, because Claude Code can stream several requests into one
transcript at once.

The observer emits **one USAGE atom per `message.id`, with the usage of the
response's last record**. Taking the first record would keep a partial output
count. Taking each field's maximum would be wrong too: a proxied model's last
record can move input into cache reads. The atom is emitted as soon as
nothing can change it:

- At the response's first record with a `stop_reason`. No later record of a
  response reports different usage.
- When the response's branch continues. Each record names the record it
  follows (`uuid`, `parentUuid`; a compaction boundary names it as
  `logicalParentUuid`). A new response or a user turn that follows from the
  response's records (its blocks, its tool results, their attachments) is
  only written after the response finished. About 3% of
  responses never get a `stop_reason`: Claude Code wrote their last block
  (a tool_use) before the response finished. They are counted here, with the
  usage they have. The transcript never records their final output count.
- When the transcript moves to another `sessionId`.
- Once the transcript has gone an hour without a write. This covers a session
  that ended mid-response. It also covers a response whose branch was cut
  (a rewind, or a following record too long to parse). Such a response waits
  until the transcript goes quiet, however long the session keeps writing.

A user record Claude Code injects (`isMeta`: a skill body, an image note, a
hook message) is not a turn. A record on another branch, such as the first
record of a history that a resumed agent copies back into its transcript,
does not close the response either.

Each counted `message.id` is remembered for the transcript, so no record of a
counted response is counted again. This includes a resumed agent's copy of its
whole history. The ids are kept as 8-byte hashes in a sidecar next to the
transcript's cursor (`codex-cursor-<dev>-<ino>.counted`). Each save appends
only the ids counted since the previous save, then writes the cursor state,
which records how many of them it owns. If the daemon stops between the two,
the cursor resumes from its previous offset with its previous count, so the
counted set always matches the bytes the cursor has consumed. As before, a
stop between delivering a poll and saving it re-delivers that poll. The set
grows with the transcript. On the largest local transcripts (a few thousand
responses each), rewriting the whole set with every save wrote about 16 times
as much as appending does.

A record without a `message.id` cannot be collapsed. Its usage is emitted as
it comes, without `message_id`. An id that is too long or malformed to carry
as `message_id` still collapses its response's records. The atom then has no
`message_id`.

The watcher retries a transcript line whose delivery failed part way. The
daemon recognizes a start or a USAGE it already made durable (by session id
and by `message_id`) and does not append it twice.

Before `parser_version` `codex-transcript-v2` every record became an atom.
Across a sample of local transcripts that summed to about 3x the fresh input,
1.3x the output and 2x the cache tokens of one atom per response.

## SESSION_LIFECYCLE start and model

The platform prices a session's usage at the model on its transcripts'
starts, and withholds the price when a transcript's start has no model. So a
transcript's start is emitted once a record names the model:

- **Claude:** at the first assistant record whose `message.model` is a model.
  Claude Code's `<synthetic>` placeholder records (API errors, interruptions)
  are not. The start's `occurred_at` is the session's earliest record time
  seen before it, which is the transcript's start (its first records, such as
  the queued prompt, come seconds before the first model record).
- **Codex:** at the first `turn_context` that names a model. The rollout's
  first `session_meta` names the session, and its time becomes the start's
  `occurred_at`. A forked rollout's copy of its parent's `session_meta` is
  ignored.

A transcript that never reports usage and never names a model emits no start.
If usage does arrive before any record named the model, the start is emitted
right before it, without a model, and the platform withholds that session's
price rather than guess the model.

A transcript that moves to another `sessionId` and back (A, then B, then A)
starts each session once. The cursor remembers which sessions it started, so a
return to A emits no second start, even across a restart.

The content side channel keys a transcript's snapshot by the session its
observations name, so it learns a transcript only once that transcript has
emitted something. Two consequences:

- A transcript that never names a model and never reports usage is not
  uploaded. Earlier builds uploaded it under a start without a model.
- A new transcript's content is uploaded once its first model record has been
  read, a few seconds after its first records.

Every observation parsed out of a transcript after its start also carries the
session from the cursor's persisted state, diagnostics included. A daemon
restart therefore keeps attributing a transcript's later usage to its session.
Before, the restarted daemon re-emitted Claude starts (often without a model)
and left Codex usage without a session.

Observations parsed out of a transcript carry `provenance.parser_version`
(`codex-transcript-v2` from this change). The Codex SessionStart hook's start
reads no transcript and carries none; the platform uses that to tell the two
apart.

## Upgrading from an earlier companion

A cursor state written by an earlier build has no session state. On the first
drain after the upgrade, the daemon reads the bytes that cursor already
consumed, once. It never reads before a forward-only floor.

- **Codex:** the daemon reads up to the first `session_meta`.
- **Claude:** the daemon reads to the end of the consumed bytes. It decodes
  only the records that can hold a response.

It takes the transcript's session as already started, because the earlier
build emitted its start. The earlier build also counted every Claude record it
consumed, so every response in those bytes is marked as counted. The derived
state is saved straight away, so a finished transcript that is never written
again is read once, not on every later start.

The effects are confined to transcripts captured before the upgrade:

- A Claude response whose records straddle the upgrade keeps what the earlier
  build counted for its earlier records. Its later records are not counted.
  A resumed agent's later copy of the transcript's history counts nothing.
- A transcript whose start the earlier build emitted without a model keeps
  that start. The platform keeps withholding that session's price. Sessions
  that start after the upgrade carry their model.

You can roll back. An earlier build ignores the new cursor fields and resumes
at the persisted offset with its own per-record counting. A Claude response
still waiting for its final record at the rollback is counted only from the
records the earlier build reads after that point. Rolling forward again reads
each transcript's consumed bytes once more, as above.
