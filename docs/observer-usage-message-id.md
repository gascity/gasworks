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
  - Codex 0.153.0 and later writes a `token_usage_record` line for every
    completed response. The line's `payload.response_id` is the response id.
    Codex writes it immediately before the `token_count` event that reports the
    same response's `last_token_usage`. The adapter latches the id and attaches
    it to that next `token_count` USAGE, then clears it. A later rate-limit-only
    `token_count` that repeats the previous usage therefore carries no id.
  - The assistant `response_item` id is the output **item** id (`msg_…`). It is
    never used as `message_id` because it never equals the metered response id.
    No other consumer reads it.
  - A rollout from before Codex 0.153 has no `token_usage_record`. Its atoms
    carry no `message_id` and use the heuristic lane only.
  - A record without a usable `response_id` clears the latch. An id is unusable
    when it is missing, longer than 128 bytes, or contains non-ASCII,
    whitespace or control characters. Dropping the id keeps the tokens.
  - Parse state is per poll buffer. If a poll lands between a record and its
    `token_count`, that one atom carries no `message_id`. Its tokens are still
    counted exactly once.

## Claude transcripts (`internal/observer/adapter/codex/claude.go`)

- `native_session_id` = the envelope's `sessionId`. This equals the
  `session_id` inside Claude Code's `metadata.user_id` request field, which
  Manifold records.
- `message_id` = the assistant record's `message.id` (`msg_…`). This equals the
  Anthropic `message_start.message.id` that Manifold records. Claude Code
  splits one API message into several transcript records that share this id.
  The reader counts each matched spend row only once.
