# Plan

What has been built, and what is next. Three documents referenced this file
before it existed (`CHANGELOG.md`, `benchmark/README.md` twice) - a dangling
reference is the same class of drift Phase 7 exists to make impossible.

## Where the phases came from

Phases 1-6 are recorded here in summary; the authoritative record of what
each one changed is `CHANGELOG.md` and the git history. Phase 7 is the only
one written here as work to do.

| Phase | Theme | State |
|---|---|---|
| 1 | Core vault: scoped pseudonyms, keyed-HMAC lookup, per-scope AEAD blobs | done (v0.1.0) |
| 2 | Handoff: one-time identifiers, selective disclosure, consent gating | done (v0.2.0) |
| 3 | Pro parity: F1-F12 (derived search, value vault, file vault, shares, links, versions, portal, Shamir recovery) | done (v0.4.0) |
| 4 | Audit throughput: async sealing (P4.1), bucketed reads (P4.2), external sealer, Postgres sizing (P4.5) | done (v0.4.0) |
| 5 | Operations: Helm chart, anchoring, backup/DR, runbooks, provisioning | done (v0.4.0) |
| 6 | Two external review sweeps: 61 numbered findings + four roll-up tables | done (v0.5.0) |

## Phase 7 - Prove it under load and under failure, then keep it aligned

The motivation is measured, not theoretical. Three defects were found in the
final hours of v0.5.0, and **none of them was found by any of the seven
review rounds** that preceded it:

| Defect | Found by | Why review missed it |
|---|---|---|
| `FileKeystore.Ensure` mints over live key material | one CI matrix leg, once | a check-then-act window; the 16-way race test had been passing by luck |
| `Migrate` dies on a cold boot with two processes | `e2e-playground` on an empty volume | `CREATE TABLE IF NOT EXISTS` reads as idempotent and is not, under concurrency |
| The playground inbox refuses ~56% of real pseudonyms | the same leg, as a coin flip | an alphabet mismatch between two packages, each internally consistent |

All three are the same class: **check-then-act against external state**. That
class is invisible to reading and invisible to line coverage - every one of
those lines was "covered" by a test that passed for the wrong reason. An
eighth reading round has low expected yield. Executing the system under
adversarial schedules has high expected yield.

Phase 7 therefore has two halves: **execute** (7.1-7.4) and **keep aligned**
(7.5-7.6).

### 7.1 Repeated race stress on the concurrent paths

Not "run the tests with -race" - that already happens. Run the specific
concurrent paths under `-race -count=N` on a machine slower than a developer
laptop, where the loser of a race actually loses.

- Target set: keystore `Ensure`/rotation, both outbox workers (erasure
  events, portal mail), erasure vs. concurrent writer, OTI verify CAS, the
  read-bucket closer, the sealer, unique-value tokenization.
- Method: a CI job that runs each target with `-race -count=200 -shuffle=on`
  on the reference server, not on GitHub's runner.
- Exit criterion: 3 consecutive full runs with zero failures, and every
  target's test asserts an OBSERVABLE invariant (bytes agree, exactly one
  winner, no duplicate delivery) rather than "returned nil".

### 7.2 Fault injection at the commit boundaries

Every claim-before-side-effect design in the tree is *documented* as
crash-safe and *not tested* that way.

- Kill points: between the outbox claim commit and the HTTP POST; between
  the POST and the acknowledgement; between `writeKey`'s rename and the lock
  removal; between a cascade's plan write and the first child's erasure;
  between an erasure's blob wipe and its event enqueue.
- Method: a seam per kill point (the tree already uses this pattern:
  `randRead`, `afterLockWon`), plus a harness that runs the operation, kills
  at the seam, restarts, and asserts the invariant.
- Exit criterion: for each kill point, a named test stating the invariant it
  protects, and a documented recovery path in the runbook.

### 7.3 Cold-boot and multi-replica scenarios in CI

The migration race was found because one CI leg happened to boot two
processes against an empty volume. That should be a deliberate test, not an
accident.

- Scenarios: two replicas from an empty database and an empty keystore; a
  key rotation while traffic runs; sealer failover with
  `SUNDER_AUDIT_SEAL_EXTERNAL=true`; a replica joining mid-rekey; a rolling
  restart across a sealing-mode change.
- Exit criterion: each scenario is a compose or kind-based CI job that fails
  loudly, and each has an entry in the operations runbook describing what an
  operator sees when it goes wrong.

### 7.4 Scale re-measurement on the v0.5.0 build

The 26.8M-contact scale test was measured on the v0.4 code. The v0.5.0
remediation added tombstone predicates to `Lookup`, a `persons` join to the
rekey sweep, and a compare-and-swap on `updated_at` - all of which change
query plans in ways a small dataset cannot show.

- Method: reference server (12 cores, 47 GB, Postgres tuned per
  `docs/CONFIG.md`), `benchmark/bulkload`, then write/lookup/read at
  c=1/8/32/64, plus the rekey sweep and the retention sweep timed at size.
- Exit criterion: no plan regression against the v0.4 numbers, or a measured
  and documented explanation for any that appears.

### 7.5 Playground: every feature, not just the first four

The playground demonstrates lookup/handoff, consent, erasure and the audit
chain. F4-F8 exist only as `demo/*.sh` scripts. A visitor evaluating Sunder
sees less than half of what it does.

- Add walkthroughs for: value tokenization (including the unlock-gated bulk
  path), the file vault, cross-org shares, person links, attribute history,
  and a cascading erasure that RESUMES after an interruption.
- Each one is driven by `ops/playground_e2e.py` in CI, exactly as the four
  existing ones are - a scenario whose expected status the service no longer
  returns must fail the build.

### 7.6 Make the alignment gaps structurally impossible

v0.5.0 shipped with the Helm chart missing five config variables, the
Postman collection covering 14 of ~40 routes while the documentation claimed
otherwise, and `docs-site` missing 20 variables that `docs/CONFIG.md` had.
Each was found by a person asking. That is not a process.

The existing guards prove the shape works: `ops/check-config-docs.sh` makes
an undocumented `SUNDER_*` a build failure, and `TestEveryRouteIsDocumented`
does the same for routes. Extend the same idea to every artifact a feature
must land in:

| Guard | Fails the build when |
|---|---|
| config completeness (exists) | a `SUNDER_*` the code reads is in no reference table |
| route documentation (exists) | a `/v1` route is not in `api/openapi.yaml` |
| **Helm coverage** | a `SUNDER_*` in the reference is not settable through the chart |
| **Postman coverage** | a documented route has no request in the collection |
| **SDK parity** | a route in `openapi.yaml` is wrapped by some SDKs but not all six |
| **Playground coverage** | a shipped feature has no walkthrough (an explicit allow-list of deliberate omissions, so skipping one is a decision someone wrote down) |
| **Cross-doc mirror** | `docs/CONFIG.md` and `docs-site/.../configuration.md` disagree about a variable |

Plus the workflow tooling that makes following this cheap rather than
virtuous - the skills under `.claude/skills/`: a feature-completeness
checklist, a release procedure that verifies rather than trusts, and a code
review that spends its effort on the classes reading actually catches.

### Exit criteria for Phase 7

Not "no bugs" - that is unprovable. The claim Phase 7 supports is narrower
and checkable:

1. Every concurrent path has a test that fails when its invariant is broken,
   verified by breaking it.
2. Every crash-safety claim in the documentation has a kill-point test.
3. Cold-boot and multi-replica scenarios run in CI on every change.
4. Performance at 26.8M rows is measured on the shipped build.
5. A feature cannot reach `main` while absent from the docs, the SDKs, the
   Helm chart, the Postman collection, the tests or the playground - because
   the build fails.
