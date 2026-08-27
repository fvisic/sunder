---
name: race-hunt
description: Find check-then-act and crash-safety defects that reading and line coverage cannot see - the class that shipped past seven review rounds. Use when hardening concurrent paths, investigating a CI failure that reproduced once, testing crash safety, or when asked why coverage did not catch something.
---

# Hunting the class review misses

Three defects reached the final hours of v0.5.0 after seven review rounds
had passed over them. All three were **check-then-act against external
state**, all three were on lines with test coverage, and all three passed
locally hundreds of times.

| Defect | Local runs before it failed | Where it failed |
|---|---|---|
| `FileKeystore.Ensure` mints over a live key | 200 clean | one CI matrix leg |
| `Migrate` dies on a cold boot with two processes | never (fresh volume needed) | `e2e-playground` |
| Playground refuses ~56% of pseudonyms | ~50/50 | the same leg, as a coin flip |

Reading harder does not find these. This is the method that does.

## Recognising the shape

Three questions against any code that touches shared state:

1. **What did I read, and can it change before I act on it?**
   `os.ReadFile` then `os.OpenFile(O_EXCL)` then write - the write is
   justified by a read taken before the lock was held.
2. **Is this "idempotent" primitive actually atomic?** `CREATE TABLE IF NOT
   EXISTS`, `CREATE INDEX IF NOT EXISTS` and `INSERT ... ON CONFLICT` all
   read as idempotent; the first two are check-then-act inside Postgres and
   race on `pg_type`/`pg_class`.
3. **Two components agreeing about a format - who checks that they agree?**
   The playground validated a Crockford alphabet, the vault emitted RFC
   4648. Each was internally consistent. Nothing compared them.

## Concrete patterns in this tree

- `SELECT` then `UPDATE` under READ COMMITTED with no `FOR UPDATE` and no
  compare-and-swap on a column every writer moves (`updated_at`).
- Winning a lock and acting on a decision made before acquiring it. **The
  fix is always the same: re-check under the lock.**
- Claim-before-side-effect without a lease and a reaper.
- Two packages parsing or validating the same string shape.
- A per-process counter or cache treated as global state.
- Anything comparing `time.Now()` on the app side against a database clock.

## The four techniques

### 1. Deterministic seams beat repetition

Repetition finds a race eventually and proves nothing when it passes. A seam
occupies the exact window every time. The tree already uses this: `randRead`
in `internal/crypto/tokens.go`, `afterLockWon` in `keystore.go`.

```go
// Production: nil. Tests: occupy the window between winning the lock and
// deciding whether to mint.
var afterLockWon func(keyPath string)
```

The test then plays the other racer's part from inside the first racer's
call - no goroutines, no timing, fails deterministically on the old code.
This is how `TestEnsureDoesNotOverwriteAKeyMintedWhileWaitingForTheLock` was
written after the 16-way concurrent test had passed 200 times in a row.

**Every seam must be nil in production and carry a comment saying it is a
test seam, not a feature.**

### 2. Assert an observable invariant, never "returned nil"

The 16-way keystore test originally asserted that every `Ensure` returned
nil. All 16 could mint, all 16 could rename over each other, and every call
still returns nil. Rewritten to compare the key BYTES the racers ended up
with, it started catching the bug.

For each concurrent path, name the invariant an outside observer could
check:

| Path | Invariant |
|---|---|
| keystore `Ensure` | every reader sees the same 32 bytes |
| unique tokenization | concurrent callers converge on ONE token |
| outbox delivery | at-least-once, and the receiver can dedup on `(scope, cid, erasure_id)` |
| erasure vs. writer | no row referencing the person survives |
| OTI verify | exactly one caller consumes the token |
| read-bucket close | the digest covers exactly the sealed set |
| migrations | one row per version, no duplicates |

### 3. Kill points, not just races

Every claim-before-side-effect design in this tree is documented as
crash-safe and mostly not tested that way. For each, place a seam at the
kill point, kill, restart, assert:

| Kill point | Invariant after restart |
|---|---|
| after the outbox claim commits, before the POST | the reaper returns it to `PENDING` within the claim TTL |
| after the POST, before the acknowledgement | redelivery happens; the receiver dedups |
| after `writeKey`'s rename, before the lock is removed | the stale lock is reclaimed and the key is NOT reminted |
| after a cascade's plan write, before the first child | re-issuing the identical request resumes |
| after a blob wipe, before the event enqueue | the erasure is not silently half-done |

### 4. Run where the loser actually loses

A developer laptop has fast NVMe and spare cores; the window a race needs
closes before another goroutine can enter it. Run the targeted set with
`-race -count=200 -shuffle=on` on the reference server (slow disk, fewer
cores) - that is the machine that found the keystore bug.

```sh
go test ./internal/crypto/ -run TestFileKeystoreConcurrentEnsure -race -count=200
go test ./internal/service/ -run 'Race|Concurrent|Deadlock' -race -count=50 -shuffle=on
```

## Cold-boot scenarios

The migration race needed an EMPTY database AND two processes. Neither
condition occurs in a normal test run, because `testutil.NewDB` migrates on
the way out. Scenarios worth a dedicated test:

- two replicas, empty database, empty keystore, simultaneous start
- a replica joining while a rekey sweep runs
- a rolling restart across a sealing-mode change
- sealer failover with `SUNDER_AUDIT_SEAL_EXTERNAL=true`
- a `down -v` then `up` of the full compose stack, every time (this is how
  `e2e-playground` earns its place)

## Verify the test, not just the fix

The rule that closes the loop:

1. Write the test. Run it against the **unfixed** code. It must fail.
2. Apply the fix. It must pass.
3. Break the fix deliberately. It must fail again.

A test that has never been seen red is not evidence. When a fix is already
in place, `git stash` the fix, run the test, and confirm red before
believing it.

## When a CI leg fails once

Treat it as a finding, not a flake, until proven otherwise:

1. Read the exact assertion that failed and what it asserts about the world.
2. Reproduce locally with `-count=N` and `-shuffle=on`; if it will not
   reproduce, that is evidence about timing, not evidence of absence.
3. Reason about the interleaving that produces that specific message.
4. Write the deterministic seam test for that interleaving.
5. Only after all four, and only if the invariant genuinely holds, call it
   environmental - and say why in the commit message.

All three v0.5.0 defects presented as "one leg, once".
