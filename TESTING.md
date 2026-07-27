# TESTING.md — Engineering Testing Policy

**Status:** Organization standard (v2). This exact file is synchronized from
[`gascity/infra`](https://github.com/gascity/infra/blob/main/docs/standards/TESTING.md)
into each participating repository's root. Do not edit the synchronized copy by
hand.

This file is the canonical, normative source for how Gas City repositories
design, place, review, and time tests. The reference implementation is
[`gastownhall/gascity/TESTING.md`](https://github.com/gastownhall/gascity/blob/main/TESTING.md).
Gas City's repository-specific commands, inventories, and checked ledgers stay
there; this document carries the language-neutral policy.

> **The one rule.** A change is done when every distinct caller-visible risk it
> changes has one smallest owning proof; every reusable substitute is held to
> the same observable contract as each behaviorally distinct production
> implementation; every critical boundary retains an exact-production-path
> proof against the real dependency at a protected cadence; and every assertion
> observes the promised result rather than merely proving that plumbing returned
> success. The feedback budget changes where a proof runs, never whether the
> risk is proved.

## 1. Authority, applicability, and local supplements

This policy wins when an older plan, audit, or contributor document conflicts
with it. Existing exceptions are debt, not precedent. A repository may add
`TESTING.local.md` for its commands, provider inventory, test lanes, measured
budgets, and stronger repository-specific rules. A local supplement may
strengthen this standard but may not weaken or silently replace it.

Apply only the proof categories that match the repository:

| Repository type | Required proof categories | Boundary examples |
| --- | --- | --- |
| Service + datastore | unit, contract/conformance, real-store integration, small critical E2E portfolio | writes, authorization, queues, external services |
| Frontend | unit, component/view, generated API contract, small browser portfolio | mutations, state projection, accessibility-critical interaction |
| Library / SDK | unit; conformance when multiple implementations share a port | exported behavior, serialization, state mutation |
| CLI | unit, golden/CLI surface, focused real process/filesystem composition | arguments, output, exit status, files and subprocesses |
| Data / ETL / ML | unit transforms, schema contract, real source/sink integration on bounded data | rows, schemas, checkpoints, idempotency |
| Infrastructure / IaC / GitOps | lint/validate, plan or render diff, post-deploy smoke | deployed behavior, policy, rollout safety |
| Config-only / documentation | lint, schema, link/generated-content agreement | configuration and published docs |

An organization-owned front-door journey may compose several repositories. It
does not justify duplicating the same journey in every repository.

## 2. The outcome: protected PR feedback under five minutes

The required PR graph reaches terminal status at p95 **under five minutes**,
measured from validation submission or workflow creation until the last
required summary or status reaches a terminal conclusion. Each repository
documents one consistent CI-native start and end point. Use the most recent 20
comparable, non-superseded required graphs from the same runner, OS,
architecture, concurrency, and suite-policy cohort; include failures and
timeouts, and exclude only superseded-SHA cancellations. Report queue time
separately; target execution from the first required job starting through the
required summary completing at or below **4m30s**.

The budget determines cadence:

- **Pull request:** fast deterministic owners, fast conformance, affected
  coordination proofs, and relevant inexpensive real boundaries.
- **Protected main or merge queue:** broader real-provider and composition
  proofs that cannot fit the PR budget.
- **Scheduled or explicit profile:** credentialed external systems, cloud,
  destructive recovery, soak, load, and live-model journeys.

A slow test may move later only after lower layers own its branch and
error-detail matrix and the later lane retains its unique composition risk. A
release that depends on a non-PR proof needs fresh evidence for the exact
release SHA. Moving a test without that ownership map deletes quality; it does
not improve feedback.

A repository that cannot yet measure or meet this objective records a checked,
owned, expiring adoption exception. It does not silently redefine the metric.

## 3. Definitions

- **Risk / observable promise** — the regression a test must catch, stated in
  one sentence from the caller's perspective.
- **Owning proof** — the one smallest test or check responsible for detecting
  that risk.
- **Accountable owner** — the person or team responsible for a manifest,
  exception, or debt item, with a tracked work item when remediation remains.
- **Real dependency** — an actual downstream system, process, browser, protocol
  peer, cloud service, or real binary against an isolated filesystem. A
  production adapter pointed at a fake peer is not a real dependency.
- **Exact production path** — the constructor and adapter composition the
  application actually uses, connected to the real dependency. Testing either
  the adapter or dependency through a nearby test-only composition is
  insufficient.
- **Observable result** — the promised output or state: exact pure result,
  returned data, rendered user state, persisted transition read back, emitted
  event, protocol response, or documented interaction when arguments or order
  are themselves the contract.
- **Reusable substitute** — a fake, stub, spy, emulator, in-memory
  implementation, or other fast implementation used across consumer tests.
- **Proven substitute** — a reusable substitute exercised by the same shared
  observable-contract suite as every behaviorally distinct production
  implementation or composition of that port.
- **Critical boundary** — a write, authorization decision, secret or
  cryptographic operation, external side effect, recovery path, or failure that
  can lose or expose state.
- **Waiver** — a scoped exception naming its reason, accountable owner,
  replacement proof, protected cadence, approval, tracked work item, and
  CI-enforced expiry.

Conformance is a reusable testing pattern, not a separate execution tier. The
same contract can run against an in-memory implementation, a process-backed
adapter, and an external system at different cadences.

## 4. One risk, one smallest owning proof

Start with the regression sentence. Search for its current owning proof before
adding a test. Strengthen or parameterize that proof instead of creating
another journey.

Use this order:

1. **Provider or port promise:** add the case once to the shared conformance
   suite.
2. **Domain transition or implementation decision:** write a unit test beside
   the code.
3. **CLI, UI, or API surface behavior:** use a component, golden, or surface
   test with fast providers.
4. **Argument plumbing or lifecycle ordering:** use one focused coordination
   test with recording collaborators.
5. **Real process, protocol, filesystem, database, browser, or provider
   composition:** retain one integration proof for that boundary.
6. **Critical cross-boundary journey:** admit an E2E only when lower layers
   cannot own the composition risk.
7. **Documentation, schema, or generated-code agreement:** add a deterministic
   sync or freshness check.

Higher layers prove wiring; they do not repeat lower layers' branch matrix.
Coverage is an ownership map of distinct obligations, not a pyramid ratio or a
line percentage.

## 5. RED, GREEN, refactor, measure, verify

Every behavior change and bug fix follows this loop:

1. **RED:** add the smallest owning proof and observe it fail for the intended
   reason. Reproduce a reported bug before changing production code.
2. **GREEN:** make the narrowest production change that satisfies the proof.
3. **Refactor:** improve boundaries and names, replace expensive collaborators
   with proven substitutes, and remove duplicate assertions.
4. **Measure:** repeat the focused test and run the affected suite or shard.
   Record before/after wall time when adding, moving, or materially changing
   tests.
5. **Verify:** run the focused owning proof plus the relevant conformance,
   coordination, integration, or E2E proof.

A behavior-neutral test migration maps every retired assertion to its new
smallest owning proof and names the retained real-boundary proof. “The broad
test still passes” is not a semantic-parity argument.

## 6. Design production code for fast proofs

Core logic receives dependencies; composition edges choose production
implementations. Prefer an existing port. Inject a function for one isolated
side effect. Do not introduce an interface merely to satisfy a mocking tool.

| Nondeterminism | Fast seam | Retained real proof |
| --- | --- | --- |
| Persistence | repository/store port with in-memory implementation | store contract, durability, and lifecycle |
| Time, timers, backoff | injected clock, scheduler, or virtual time | real adapter behavior |
| Async completion | event, callback, channel/promise, watcher, notifier | public event/protocol composition |
| Subprocess | narrow executor with scripted results | argument-to-real-binary compatibility |
| IDs and randomness | injected deterministic generator | format/entropy adapter |
| Filesystem | filesystem port or isolated in-memory implementation | OS-specific semantics and atomicity |
| Network or external API | protocol emulator or narrow client double | contract plus one real endpoint composition |

Environment variables, current working directory, global clocks, package-level
mutable state, ambient credentials, and executable discovery belong at
composition edges. Consumer unit tests must not need them to steer domain
behavior.

## 7. Meaningful failure edges and observable assertions

Test distinct equivalence classes, not command × provider × error Cartesian
products. Consider only the applicable boundaries:

- invalid input or missing required value;
- collaborator failure before a side effect;
- partial success requiring rollback, idempotency, or recovery;
- cancellation or deadline propagation;
- concurrency conflict or lost update;
- serialization, schema, or protocol incompatibility; and
- restart, reconnect, or resume at a real lifecycle boundary.

If several consumers share one provider, shared provider failures belong in
conformance, each consumer's distinct translation belongs in a focused unit
test, and one consumer-to-real-provider integration retains the wiring risk.
Add another combination only when it represents a different contract.

Assertions must make wrong behavior fail:

- mutations assert state before and after, then read the result back;
- reads assert returned data, not only `200`;
- pure functions assert exact results and relevant invariants;
- CLI tests assert output, exit status, and side effects; and
- interaction assertions are used only when calls, arguments, or ordering are
  observable behavior.

## 8. Asynchronous tests wait for facts, not elapsed time

New or changed tests must not use fixed sleeps or open-coded polling to wait for
completion. Use events, callbacks, channels/promises, barriers, fake clocks,
virtual time, or deterministic schedulers. Subscribe before triggering work,
correlate completion by request or resource identity, then reread durable state.

At a true black-box boundary with no completion signal, polling is allowed only
through one context-aware bounded helper. The helper uses a ticker or bounded
backoff, reports the last observed state, and has one named boundary proof.
Busy loops and a fixed sleep before polling are forbidden.

Safety deadlines detect hangs; they do not determine normal duration. Making a
deadline larger does not repair a missing lifecycle signal.

## 9. Real boundaries, doubles, and conformance

When a provider method or invariant changes:

1. change the shared observable-contract suite first;
2. run it against every behaviorally distinct production implementation or
   composition;
3. run it against every reusable substitute; and
4. keep implementation-specific tests only for behavior outside the shared
   contract.

Production coverage enters through the exact constructor or composition the
application uses. Proving a nearby raw implementation is insufficient. A thin
alias with no state, transformation, or behavior may use a focused
exact-constructor wiring proof.

A skipped conformance case is a visible gap and requires a waiver. A
consumer-local stub modeling one narrow interaction does not need the full
provider suite, but it cannot satisfy a critical real-boundary requirement.

Prefer working in-memory implementations and small hand-written fakes over
interaction-heavy mocks. Add recording only when arguments or order are part of
the contract. A fake models observable behavior, not production internals.

## 10. Keep E2E and front-door portfolios deliberately small

Admit an E2E only when all are true:

- it protects a high-value user journey or high-blast-radius recovery path;
- the risk exists only when real boundaries are composed;
- lower layers already own branch and error-detail coverage;
- assertions use stable public outcomes rather than internal timing;
- setup is hermetic and cleanup is targeted;
- diagnostics name the last meaningful state;
- it has an accountable owner, lane, trigger, and measured budget.

Maintain a checked manifest of each E2E's journey, unique risk, lower-layer
owning proofs, real resources, trigger paths, cadence, budget, diagnostics, and
accountable owner. Reject empty, stale, duplicate, or unowned entries.

Whole-platform journeys run through the real front door inside a fenced
synthetic tenant and assert downstream side effects. They belong to one
organization-owned portfolio, with a small deployment-blocking subset and
broader scheduled/probe coverage. A major effort points to an existing journey
or adds the one missing composition proof; it does not receive an E2E for every
acceptance criterion.

## 11. First-attempt reliability, skips, and quarantine

A deterministic product-test failure on a SHA may not be retried into green.
Required status retains the worst product-test result across attempts. A
pre-test runner or service outage may be retried only with attached
infrastructure evidence and separate reporting. Every flake is a defect with
one accountable owner.

No required test skips because its dependency is absent. CI provisions the
dependency or the test runs in an equipped protected lane. Capability-based
local skips require that equipped lane or a waiver.

Quarantine is exceptional and requires a checked ledger with captured failure
evidence, a still-failing nonblocking lane, replacement coverage, accountable
owner, and CI-enforced expiry. Quarantined coverage cannot satisfy a required
gate. Do not weaken assertions, add sleeps, or broaden retries to hide an
unknown race.

## 12. Timing and resource ratchets

Performance claims require comparable evidence:

- repeat the focused test with result caching disabled;
- run the affected suite or shard;
- compare like runner, OS, architecture, concurrency, cache state, and suite
  variant; and
- treat one warm-cache run as diagnostic, never as a baseline.

An authoritative p95 needs at least 20 comparable samples. Checked per-profile
baselines fail material regressions and ratchet downward after sustained
improvement. Each repository defines its material-regression threshold;
increases require a waiver.

Repositories also ratchet test-resource use: fixed sleeps and polling,
subprocesses, listeners and test servers, containers and external services,
ambient environment or CWD mutation, and package/global mutable state.

A resource is not debt merely because a unique real-boundary proof requires
it. Every occurrence belongs to one of two checked categories:

- an exact manifest-owned proof naming its unique risk, resource, cleanup,
  cadence, and budget; or
- legacy or duplicated debt with a census, accountable owner, replacement
  proof, and expiry.

A clean repository starts at zero unowned debt. Fixed completion sleeps,
open-coded polling, ambient mutation, and hidden global state cannot be
reclassified as boundary proofs. The one sanctioned context-aware black-box
polling helper is inventory-owned. Reductions lower the census in the same
change; growth or duplication fails unless an explicit policy change proves
the unique need and updates the manifest. Wrapping a resource call must not
hide it from the inventory.

A source census is an anti-growth guard, not a universal hermeticity proof.
Individual resource-using proofs and retained real-composition proofs still
require review.

## 13. Adoption, legacy debt, and waivers

New code follows this standard immediately. Existing untested code uses
**test-on-modify**: touching an unowned critical path adds its smallest owning
proof and retained real-boundary proof. Untouched legacy debt stays visible in
a risk-ordered roadmap or checked ledger rather than blocking every unrelated
change.

A waiver is boundary-specific and contains:

- scope and reason;
- accountable owner and tracked work item;
- replacement proof;
- protected cadence;
- approving governance owner; and
- CI-enforced expiry and re-evaluation date.

There is no waiver for a meaningful assertion. A waived boundary's replacement
proof must still fail when the promised behavior is wrong.

## 14. Definition of Done

For the repository's applicable categories:

- [ ] Each changed risk has one regression sentence and one smallest owning
      proof.
- [ ] Distinct failure equivalence classes are covered without duplicating a
      lower layer's matrix.
- [ ] Reusable substitutes pass the shared contract against exact production
      compositions, or a scoped waiver names the gap.
- [ ] Each changed critical boundary retains one real-dependency proof at a
      protected cadence and asserts observable state.
- [ ] Async tests wait on facts; no new completion sleeps or open-coded polling.
- [ ] Required tests pass on the first attempt; skips and quarantine do not
      masquerade as coverage.
- [ ] Test changes include focused and affected-suite timing evidence.
- [ ] Lint, schema/typecheck/compile, and applicable proof categories are green.
- [ ] The PR names the test and retained boundary proof, or links its waiver.

## 15. CI contract

Every repository gates lint plus schema/typecheck/compile as applicable. Its
required PR graph also runs fast deterministic owners, conformance, affected
coordination proofs, and affordable real boundaries. Build-tagged, feature-
gated, or profile tests are compiled or otherwise validated on every PR so
later lanes cannot rot.

Protected-main, merge-queue, scheduled, and post-deploy lanes own the broader
proofs named in the ownership manifests. A published contract change updates
one generated source of truth and checks consumer fixtures. A deployment
cannot rely on stale evidence from another SHA.

Selective routing is allowed only when an executable dependency/ownership map
proves the omitted suites are unaffected. Until that exists, keep a
conservative broad fast sweep.

## 16. The reviewer's questions

Before approval, ask:

1. What regression must this catch?
2. What is its smallest owning proof?
3. What retained real-boundary proof demonstrates the wiring?
4. Does a higher-level test duplicate lower-layer branch coverage?
5. Does the cadence meet the feedback budget without deleting unique quality?

Call out these anti-patterns:

- plumbing-as-verification (`200` or “no error” without the promised result);
- a fake hardcoded to succeed as the only boundary proof;
- one test per command × provider × error combination;
- fixed sleeps and blind polling for asynchronous completion;
- retries or quarantine used to turn a deterministic failure green;
- broad E2E branch matrices that belong in unit or conformance owners;
- moving a slow unique proof later without exact-SHA freshness; and
- hand-maintained twin contracts that can drift.

Product load/capacity, accessibility, security/abuse fuzzing, and contract
deprecation may impose additional repository or platform standards. They do not
weaken this testing policy.
