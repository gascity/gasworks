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

- `input_tokens` becomes `input_tokens`. It includes cached input.
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
  Anthropic `message_start.message.id` that Manifold records. Claude Code
  splits one API message into several transcript records that share this id.
  The reader counts each matched spend row only once.
