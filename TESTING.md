# TESTING.md — Engineering Testing Requirements

**Status:** Org standard (v1). Applies to every repo. Copy this file to each repo's root; CI and
code review enforce it. The reference *implementation* of these requirements is
[`gastownhall/gascity/TESTING.md`](https://github.com/gastownhall/gascity/blob/main/TESTING.md)
("Gas City Testing Philosophy") — when this doc says "do X," that repo shows what X looks like in
real Go.

> **The one rule.** A change is *done* when every behavior a caller can trigger has a test that
> exercises it against the **real dependency** it talks to — or against a double **proven** to behave
> like the real one — and asserts the **observable state**, not just a return value. A green suite
> that only drives fakes returning success is not coverage.

This standard has **teeth** (the rules above, kept sharp below) and an **on-ramp** (scoping,
waivers, a path for legacy code) so the teeth are adoptable rather than ignored.

---

## 1. Applicability — find your repo type first

The teeth apply where there's real state to get wrong. Scope before you start:

| Repo type | Required tiers | "boundary / write path" means | Notes |
|---|---|---|---|
| **Service + datastore** | unit, contract, integration (real DB), e2e (critical paths) | DB writes, auth decisions, external-service calls | The full standard. The motivating incident lived here. |
| **Frontend (web/mobile)** | unit, component/view, contract (vs the API schema) | API mutations the UI triggers | Real-dep = the API contract + a recorded fake client; e2e against a real backend for critical flows. |
| **Library / SDK (no external deps)** | unit | exported API + any state it mutates | **No integration tier.** Test the public contract + edge cases; skip the real-dependency rule (there is no boundary). |
| **CLI tool** | unit, golden/CLI (e.g. testscript) | side effects on fs/process/exit code | Exercise the real binary against a real (temp) filesystem; fake only the external service. |
| **Data / ETL / ML pipeline** | unit (transforms), integration (real source/sink on sample) | reads/writes to the store; schema | Test transforms on fixtures + one real-source/sink integration; assert output rows/schema. |
| **Infra / IaC / GitOps** | lint/validate, plan-diff, post-deploy smoke | the deployed resource's behavior | Real-dep tests run against a **non-prod env, nightly** (cloud APIs are slow) — not PR-gating. A deploy is verified by observed behavior after rollout, not "the manifest applied." |
| **Config-only / docs** | lint + schema validation | n/a | No code tiers. |

If a rule below is "n/a" for your repo type per this table, it's satisfied — don't rubber-stamp an
unsatisfiable checkbox.

---

## 2. Definitions (these terms ARE the teeth — read them)

- **Write path** — code that mutates external state (INSERT/UPDATE/DELETE, enqueue, file/object
  write, token revocation, any external side effect) or whose failure causes data loss. Includes
  the query/payload/signature builders and the validators that gate a mutation.
- **Real dependency** — an *actual instance* of the external system: an ephemeral container
  (Postgres/Redis), a CI service, or a non-prod environment running the real binary. **A double
  typed to the dependency's interface is NOT a real dependency.**
- **Observable state** — the persisted result read back from the backing store (DB/cache/file/queue)
  or surfaced via the system's own API/events *after* the operation. A test asserting only a return
  value or HTTP status has **not** verified observable state.
- **Proven (of a double)** — a contract/conformance test runs the *identical* assertions against
  **both** the double and the real implementation, and fails if they diverge. (Gas City: the
  `*test/conformance.go` suites run against `MemStore`, `FileStore`, real `tmux`, etc.)
- **Critical boundary** — a boundary on a write path, an authorization decision, secret/crypto
  handling, or a write to an external system. Teeth bite hardest here.

---

## 3. Definition of Done (every PR)

For the tiers your repo type requires (§1):

- [ ] Every new/changed **write path / critical boundary** has a test against the **real dependency**
      that asserts **observable state** — not a fake hardcoded to succeed, not return-value-only.
- [ ] Every **double** standing in for a real dependency is **proven** by a contract/conformance test
      (same assertions vs the double *and* the real impl).
- [ ] Every **caller-triggerable or behavior-silently-changing error branch** (e.g. a write that
      returns success on a 5xx; a false-negative auth check) is covered by **fault injection**.
- [ ] Tests fail if the behavior is wrong: assert state **before and after**, exact status codes, and
      returned ids. (Reads still assert the returned *data*, not merely a 200.)
- [ ] No PR-gating test **skips** because its dependency is absent (§6).
- [ ] The PR description's "verified" claim **cites the path and the test** (file:function) that
      exercised it against a real dependency — or links a waiver (§5).
- [ ] `lint`, `typecheck`/compile (including build-tagged tests), and the required tiers are green.

Can't check a box and no waiver applies? The change isn't done — say so in the PR.

---

## 4. Why this exists

A feature shipped marked "verified end-to-end" while its core write path returned 500 in
production. Unit tests were green because the in-memory fake returned `200`; the real database call
behind that path had **never been exercised by any test**. The "verification" had only checked that
endpoints returned `401`/`200` on reads — plumbing, not behavior. The bug was a one-line query
argument mismatch a single real-dependency test would have caught.

This is the *class* of failure the rules above kill. It is not about a coverage percentage; it's
about never confusing "the suite is green" with "the behavior works."

---

## 5. Adoption — new code, legacy code, and waivers

- **New code** follows this standard from day one.
- **Existing untested code:** do **not** gate merges on retro-fixing all of it — that kills
  adoption. Apply **test-on-modify**: any PR that touches an untested write path **MUST** add the
  real-dependency test for that path going forward. Keep a short risk-ordered `TESTING_ROADMAP.md`
  (mutation/auth/payment first, then handlers, then remaining boundaries) with target quarters.
  Untouched legacy code is a documented exception until its path is next modified.
- **Waivers:** a repo MAY file a boundary-specific exception in `TESTING_EXCEPTIONS.md` when (1)
  real-dependency testing is genuinely impractical (a vendor API billed per call, an unmigrated
  legacy system), **and** (2) a credible contract/fidelity test stands in, **and** (3) the entry has
  an owner, a sunset date, and a re-evaluation date. Waivers are public and approved by the repo's
  governance owner. **There is no waiver for the assertion rule** — even a waived boundary's stand-in
  test MUST assert behavior, never just a 200.

---

## 6. Principles (MUST / SHOULD)

1. **Real dependency for critical boundaries.** Every **critical boundary** (§2) **MUST** have ≥1
   test against a real instance that asserts observable state. A double may run for speed/breadth but
   is **never the sole coverage** of a critical boundary. Non-critical boundaries (read-only caches,
   logging, observability) **SHOULD** have a contract test; their real-dependency test **MAY** run
   nightly or skip-when-unavailable.
2. **Risk-based coverage.** Prioritize tests for code that builds/mutates a query, computes an
   allow/deny decision, handles secrets/crypto, or writes to an external system. Don't test the easy
   read path and skip the risky write sibling on the same surface.
3. **Doubles MUST NOT drift.** Every double substituting for a real dependency is **proven** by a
   conformance test (identical assertions vs double and real). Prefer hand-written doubles next to
   the interface over mock libraries; where a "double" can be a *real* in-memory implementation
   (Gas City's `MemStore`), that's strictly better.
4. **Failure paths are first-class.** Every caller-triggerable or silently-behavior-changing error
   branch **MUST** have a fault-injecting (spy) test proving the code fails loud. (Rare internal
   errors in non-critical paths MAY rely on contract tests alone.)
5. **No false-green.** A test **MUST** fail when behavior is wrong: assert the observable state
   transition, the exact status, and returned ids — never just "no error."
6. **"Verified" is a behavior, not a wire.** A mutation is verified when it **succeeded against the
   real backend and the result is observable**. Reads returning 200 and gates returning 401 verify
   plumbing only.
7. **No silent-skip-as-pass.** A test that skips when its dependency is absent provides **zero**
   coverage and **MUST NOT** count toward a boundary requirement. **CI MUST provision every
   dependency a PR-gating test needs**; a skip in PR CI is a failure, not a pass. (Local dev may skip
   when a dep is absent — the gate must run it for real. Gas City provisions dolt/tmux for exactly
   this reason.)
8. **Deterministic & isolated.** No shared/prod instances; uniquely-keyed per-test data; control the
   clock and seeds; no ordering dependencies.

---

## 7. The layers

Push coverage **down** for breadth/speed — but **every critical boundary gets ≥1 test up the stack
against the real thing.**

| Layer | Exercises | Dependencies | Runs |
|---|---|---|---|
| **Unit** | pure logic, one component | doubles | every PR, fast |
| **Contract / conformance** | a double's fidelity to the real impl; cross-service/-language wire shape | both double and real | every PR |
| **Integration** | one service against its real backing store | **real DB** (container/CI service) | every PR |
| **E2E (cross-service)** | the real call graph through the public surface, real session | real services (in-process or compose) | every PR for critical paths |
| **Nightly / real-external** | slow or external deps (IdP, KMS, 3rd-party, cloud APIs) | **real external**, behind build tags | nightly + manual; **never PR-gating** |

Build-tagged real-external tests **MUST** still be **compiled** every PR (a tag-compile gate) so
they can't rot between nightly runs.

---

## 8. Test doubles & proving they're honest

- **Fake** (working in-memory impl), **Stub** (canned data), **Spy** (records calls + injects
  faults), and — best — a **real in-memory implementation** usable in prod *and* tests.
- A double **MUST** sit behind the same interface the real impl satisfies, substituted at a real seam
  (interface/constructor/injection), never by editing the code under test.
- **Integration/conformance tests exist to prove the fakes are honest.** Every provider interface
  **SHOULD** have a conformance suite run against *all* its implementations (the double and the
  real). A double whose only test asserts it returns what it was told to return proves nothing.

---

## 9. Coverage = a path list, not a percentage

The artifact a reviewer checks is the set of caller-triggerable paths and the test exercising each:
every endpoint/handler, every mutation/write, every authz decision (allow **and** deny), every
mapped dependency-error branch, and every new cross-service contract (one generated source of truth
both sides assert against). Chase the path list to zero gaps. 90% line coverage with the one risky
write path untested is exactly how the incident happened.

---

## 10. Keeping real-dependency tests fast and trustworthy

Real-dep tests are worthless if they're so slow or flaky that teams disable them. Required practices:

- **Runtime budget.** Target the PR-gating suite under **~10 min**. Over budget → move the slowest
  real-dep tests to nightly and keep a contract-tested fake in the gate.
- **Cost knobs (keep the teeth, cut the cost):** one shared container per run with cleanup/rollback
  between tests (not one-per-PR); **transaction-rollback** for DB isolation; a *proven* fake in PR +
  the real dep nightly for slow/expensive externals.
- **Test data.** Uniquely-key every test's data (UUID/timestamp prefix — Gas City uses a
  `gctest-<hex>` isolation prefix) so parallel tests can't collide; prefer code factories over
  checked-in `fixtures.json`; create your own fixtures and clean them up **through the API**.
- **Flaky-test policy.** **No blind retries** (they hide intermittent bugs). A test flaking >1% in a
  week is **quarantined** to a non-gating queue and root-caused by the author/code-owner within a
  bounded window; quarantine count is tracked and trends to zero. Usual causes: a timeout, shared
  state, or a system-clock dependency.

---

## 11. Anti-patterns (call these out in review)

- **Plumbing-as-verification** — "it returns 401/200, so it works," for a feature whose job is to
  mutate state. (For a read feature, still assert the returned *data*, not just the 200.)
- **Fake-returns-200** — the only test of a boundary is a double hardcoded to succeed.
- **Easy-path-only** — testing the simple read path and skipping the risky write path on the same
  surface.
- **False-green** — asserting "no error"/"2xx" without asserting the state actually changed.
- **Drift-by-twins** — two hand-maintained copies of a contract that can silently diverge; use one
  generated source.
- **Silent-skip-as-pass** — an integration test that skips when its dependency is absent and is never
  run anywhere. CI MUST provision the dependency.

---

## 12. CI requirements

- **PR-gating MUST include** (for the tiers your repo type requires): lint, typecheck/compile
  (incl. compilation of build-tagged tests), unit, contract/conformance, integration (real DB via
  container/service), and critical-path e2e. Floor for *every* repo: lint + typecheck/compile.
- **PR-gating MUST NOT include** slow/flaky external-dependency tests — those run nightly.
- **A nightly job MUST** run the real-external (build-tagged) tests and fail loudly.
- **A change to a published contract/package MUST** bump its version and keep consumer fixtures in
  sync (enforced by a gate) so the wire contract can't drift unnoticed.

---

## 13. The reviewer's job

Before approving, ask: **"What can a caller do here, and which of those does a *real-dependency* test
exercise, asserting observable state?"** If a write path is covered only by a fake, request the real
test (or a waiver) before merging. **Approving green ≠ approving covered.**

---

## Out of scope for v1 (tracked for v2)

Performance/load testing + regression budgets, accessibility testing (frontend), security/abuse
fuzzing, and contract-version deprecation gates are important but deliberately deferred so v1 stays
adoptable. Teams that need them now should add them per-repo; org-wide requirements land in v2.
