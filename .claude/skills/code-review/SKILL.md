---
name: code-review
description: Review Sunder code the way that has actually found defects here - trace each claim to its production call path, hunt the specific bug classes this codebase produces, and prove findings with executable repros. Use when asked to review, audit, check a diff, or verify that a fix is real.
---

# Reviewing Sunder

Seven review rounds have run against this tree. What they found, and more
importantly what they missed, is the design input for this skill.

## The two rules that produced every real finding

**1. Trace to the production call path. Never read a fix from a comment or a
commit message.** A comment describing a guard is evidence that someone
intended a guard. Open the caller. Follow it to the statement that runs in
production. Several "closed" findings across passes 1-4 were reopened by
doing exactly this.

**2. Prove it with an executable repro.** A finding without one is a
hypothesis. The findings that survived scrutiny came with a live exploit
test for the erasure bypass, a timing harness for the enumeration oracle, a
concurrency test for the blob races, a forgery test against the project's
own primitives, and `helm template` for chart values. Write the failing test
first; if it passes against the current code, the finding is wrong.

## What review reliably catches

Go here first - this is where reading pays.

- **Missing predicates.** A query that should filter tombstones and does
  not. `Lookup` was the only cid-producing read without one, for months.
- **Wrong scope or wrong grant.** A route checking `attributes.read` when it
  copies attributes across a scope boundary.
- **Fail-open error handling.** `if err != nil { log; continue }` on a path
  whose whole purpose is to refuse.
- **Documentation that outruns the code.** A guarantee in `docs/` with no
  enforcing statement. `TestEveryRouteIsDocumented` and
  `ops/check-config-docs.sh` exist because this kept happening.
- **Audit gaps.** An operation that mutates person data and writes no chain
  row, or writes one whose detail leaks a value.
- **Erasure completeness.** Any new person-linked table needs an explicit
  decision; `TestErasureInvariantSweep` discovers tables from
  `information_schema` and fails on an undecided one.

## What review reliably MISSES here

Three defects shipped past seven rounds, and all three are one class:
**check-then-act against external state**.

| Defect | Shape |
|---|---|
| `FileKeystore.Ensure` minting over a live key | read (absent) -> wait for lock -> act on the stale read |
| `Migrate` dying on a cold boot | `CREATE TABLE IF NOT EXISTS` is check-then-act inside Postgres |
| Playground refusing 56% of pseudonyms | two packages, each internally consistent, disagreeing on an alphabet |

They are invisible to reading because each line is locally correct, and
invisible to line coverage because each line was executed by a test that
passed for the wrong reason. Do not expect to find these by reading harder -
see the `race-hunt` skill for the method that does find them.

The general lesson: **a test that passes proves nothing until you have seen
it fail.** When reviewing a test, ask what change to the production code
would make it fail. If the answer is "none obvious", the test is decoration.

## The bug classes this codebase produces

Work down this list against the diff.

**Concurrency**
- READ COMMITTED check-then-act: a `SELECT` deciding what a later `UPDATE`
  does, without `FOR UPDATE` or a compare-and-swap on a column every writer
  moves.
- Lock ordering. Erasure takes `cids` then `persons`. Anything taking them
  in the other order is an ABBA deadlock whose victim Postgres picks.
- `ON CONFLICT DO NOTHING` with no arbiter: it swallows conflicts you meant
  to retry on. An explicit conflict target is usually what was intended.
- Claim-before-side-effect without a lease and a reaper: `SENDING` becomes
  absorbing the moment a worker is killed.

**Cryptography**
- Nonce reuse and nonce budgets - AES-GCM with 96-bit random nonces has a
  birthday bound; `SealBudget` and `sunder_kek_seals_total` exist for it.
- AAD binding: a blob must be bound to its subject and its generation, or a
  row swap decrypts cleanly.
- Key material minted where it should be loaded. Any new mint path needs the
  warning and the counter.
- Comparisons of secrets that are not constant-time.

**GDPR invariants**
- Article 17: does the new table die with the person? Does the new cache?
- Article 15: does the new holding appear in the access answer?
- Article 5(1)(e): does the retention sweep reach it?
- Does the erasure path leave an oracle - a 404 that differs from a
  never-existed 404, a timing difference, a count that changes?

**Operational**
- Config with no range check, or a boolean that accepts garbage silently.
- A knob the code reads that no reference table names.
- A failure mode with no metric, or a metric with no alert.
- Anything that behaves differently on a second replica: local file storage,
  in-process caches, per-process counters.

## Method

1. **Scope.** `git diff main...HEAD --stat`, then read the diff in full
   before forming opinions.
2. **Claims inventory.** List every claim the diff makes - in comments, in
   the commit message, in the docs it touches. Each becomes a thing to
   verify, not a thing to believe.
3. **Trace.** For each claim, find the production statement that enforces
   it. Note the ones where you could not.
4. **Class sweep.** Walk the bug-class list above against the diff.
5. **Repro.** For each suspected finding, write the failing test. Run it
   against current code. If it passes, discard the finding.
6. **Verify the fix.** After the fix, break it deliberately and confirm the
   test fails. A test that has never been seen red is not evidence.

## Reporting

Severity by consequence, not by how clever the bug is:

- **Severe** - data loss, an erasure that does not erase, key material
  destroyed, an authentication or authorization bypass.
- **High** - a documented guarantee that does not hold; a crash loop on a
  supported deployment; an oracle that leaks whether a person exists.
- **Medium** - a fail-open path, a missing audit row, a race with a bounded
  and recoverable blast radius.
- **Low** - drift between code and docs, a knob with no range check, a
  vacuous test.

Each finding: the production call path (`file:line`), the repro, the
consequence in one sentence, and the narrowest fix. If a fix would be
invasive, say what the cheap containment is - a warning, a metric, a
documented limitation - and let the owner choose.

Say plainly what you did not check. A review that implies uniform depth it
did not have is worse than a short one that states its scope.
