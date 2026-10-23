# Changelog

All notable changes to Sunder. Dates are YYYY-MM-DD.

## Unreleased

### Import: 41x, measured end to end (273 -> 11,235 rows/s at 10M+ scale)
Three shipped changes and one mode. The dedup probe names the partial unique
index's predicate - the planner was sequential-scanning ALL of person_tokens
once per 5,000-row batch (49x on that statement, found by the new `-timing`
flag). Batch token INSERTs are sorted (`ORDER BY` per token: 1.5x, and it
removes run-to-run variance). `-parallel N` fans batches across workers
(default 4; 12 measured 4,630 rows/s online). `-offline` is the
initial-migration mode: refuses unless the vault is empty, drops the
secondary token indexes for the load, rebuilds them afterwards with
`ident_uq` UNIQUE so the dedup invariant is re-proven rather than assumed -
**10M rows in 20 minutes including the rebuilds** (1M in 89s; the pair also
measures the decay: -26% at 10x, pkey insert locality eroding as it outgrows
cache, which is the concrete case for the open time-ordered-id decision).
In-file duplicates resolve first-occurrence-wins, deterministically,
regardless of parallelism.


### Phase 7.3: two more multi-replica scenarios
`ops/coldboot-scenarios.sh` grows to six, all green. A replica joining while
a rekey sweep runs (40 pre-existing and 15 concurrently-created contacts must
all still resolve - the sweep's compare-and-swap on `updated_at` exists for
exactly this), and a sealing-mode switch performed WITH the fleet up, which
the runbook forbids. The second asserts the failure is VISIBLE: `verify-audit`
must give a clear verdict rather than crash or fail mutely. A documented rule
nobody can observe being broken is a rule nobody will follow.

### Phase 7.9: every language now fails on its own warnings
Two rounds of "a green job printed warnings nobody read" happened in one
release, both in the .NET SDK. Reading all six afterwards found the reason,
and it was not that .NET is worse: it was the only one with no policy.

| SDK | before | now |
|---|---|---|
| Java | `-Xlint:all -Werror` | unchanged - and it never accumulated one |
| TypeScript | `strict`, `noUncheckedIndexedAccess` | unchanged |
| .NET | nothing | `CS1591` + `xUnit2013` as errors |
| Go | `go vet` | **+ `staticcheck` in CI** |
| Python | nothing | **+ `ruff` (E,F,W,I,UP,B,SIM,RUF)** |
| PHP | nothing | **+ `phpstan` level 5** |

Adding them found real things rather than style noise: `staticcheck` found
**dead code in `internal/service`** (`isUniqueViolation`, unreferenced since
its call sites inlined the check), a value assigned and never used, and four
`nil` contexts passed where `context.Background()` was meant. `phpstan`
found `array_filter($x, 'strlen')` in three files - `strlen` returns `int`,
not `bool`, which PHP tolerates and the analyser correctly does not.

Fifteen `ruff` findings and three `phpstan` ones were fixed rather than
suppressed, so each guard starts from zero. The three PHP exceptions that
remain are written out in `phpstan.neon` with their reasons: each is a case
where the analyser trusts a docblock further than the runtime does, and
removing the defensive code to satisfy it would trade a real guarantee for a
clean report.

Every guard was verified by introducing a violation and watching the build
fail.

### Phase 7.2: the crash-safety claims are now tested, and one was wrong
Every claim-before-side-effect design in the tree was DOCUMENTED as
crash-safe and none was tested that way. Four kill points now have a test
that stops the operation exactly where a crash would land:

| Killed at | Invariant asserted |
|---|---|
| outbox claim committed, POST not sent | the reaper returns the row to `PENDING`; the notification is not lost |
| POST succeeded, acknowledgement not written | the event is RE-delivered rather than silently marked done |
| erasure transaction not yet committed | nothing happened at all - no wiped blob, no tombstone, no queued events, no deleted tokens |
| key renamed into place, generator lock not released | the reclaim does NOT re-mint over live key material |

Three passed. **The fourth found a real defect**: `Ensure` returns early
when the key already exists, so a lock left by a process killed between its
rename and its unlock was never reclaimed - harmless while the key exists,
and not harmless the moment it does not, when a generator waits out the full
timeout on a lock nobody holds. `Ensure` now sweeps up an aged lock on that
path too (only aged: a fresh lock belongs to a live generator racing the
call).

One test was rewritten after being written wrong: a panic-based seam cannot
model a `SIGKILL`, because Go runs deferred functions while panicking - the
lock would be removed on the way out, which is exactly what a kill does not
do. The on-disk state is now constructed directly, and the seam was deleted
rather than left in the production path pretending to be useful.

`docs-site/docs/admin/backup-dr.md` gains a recovery table: what each kill
leaves behind, what recovers it automatically, and what to do by hand if it
does not - including the two rules that follow, that a crash never produces
a half-erased person and that it CAN produce a duplicate webhook delivery.

### L6 complete: a cascading erasure is now bounded, self-healing and provable
The v0.4.1 backlog item shipped half-done in v0.5.0: the cascade got a
durable plan and a resume path, but none of the guards around them.

- **Bounded.** `dsr/erase` erases one person PER TRANSACTION. Unbounded, a
  request naming a link type with tens of thousands of members ran that many
  transactions inside one HTTP call - connections held for minutes, no way to
  stop it, and a client timeout that left the operator unable to tell how far
  it got. Above `SUNDER_MAX_CASCADE_CHILDREN` (default 1000) the request is
  **refused before anything is erased** (`400 cascade_too_large`, naming the
  count and the limit). The check sits after the plan is known and before the
  parent's transaction opens, because that transaction is what deletes
  `person_links` - refusing later would mean refusing after the only
  description of the work was destroyed.
- **Self-healing.** The durable plan made an interrupted cascade
  *recoverable*; nothing made it *recover*. Resuming required an operator
  re-issuing the identical call - which assumes they know it stopped, and the
  report that would have told them is exactly what the interruption
  swallowed. `RunPendingCascades` now runs in the same sweep as webhook
  delivery, attributed to `system` rather than to a client that did not ask.
- **Visible.** `sunder_erasure_cascade_pending` and
  `sunder_erasure_cascade_oldest_seconds`, with an alert on the AGE - a large
  cascade in progress and one that stopped an hour ago look identical by
  count, and the second is an Article 17 commitment not being kept.
- **Provable.** A cascade reaching zero outstanding children writes
  `dsr.cascade_completed` to the audit chain. Without it the only evidence
  was the ABSENCE of pending rows, which is indistinguishable from a plan
  that was never written.

Both new tests were verified by breaking what they protect: disabling the
bound makes the refusal test fail with `must be refused, got <nil>`, and
skipping the terminal record makes the worker test fail with `no
dsr.cascade_completed audit record`.

## v0.5.1 - 2026-08-28

A patch release with no API change and no new configuration beyond one knob:
everything here was found by RUNNING v0.5.0 against 26.9 million contacts,
not by reading it. Phase 7.4 turned out to be the highest-yield thing in the
plan - four defects, none of which seven review rounds had caught, and three
of them in the same sweep.

The headline: **`sunder keys rekey` was unusable at scale.** A full pass over
26.9M contacts measured **87 hours**; it is now projected at **~5.3 hours**,
with the remaining cost being actual arithmetic rather than waiting. Since a
key rotation is how an operator responds to a suspected key compromise, a
sweep nobody can finish is a capability nobody has.

### The sweep still fetched blobs one person at a time
Batching the WRITES left the READS untouched, and a measured breakdown showed
where the remaining 17.6 hours went:

| per person | | |
|---|---|---|
| the per-person `SELECT` | 1.65 ms | **70%** |
| decrypt + tokenize (CPU) | 0.71 ms | 30% |

Two thirds of the sweep was a single-threaded program waiting on a database
measured accepting 54,000 rows/s while being asked 424 times a second. The
page's blobs now come back in one `WHERE person_id = ANY($1::uuid[])`,
projecting 17.6 h down to the ~5.3 h of arithmetic that is actually left.

`TestRekeyFetchesBlobsPerPageNotPerPerson` asserts the fetch count scales
with PAGES, not people. Its first version counted scans in
`pg_stat_user_tables` and **passed after per-person fetching was deliberately
reintroduced** - those statistics are collected asynchronously, so it was
measuring noise. It now uses a seam and fails with `the sweep fetched blobs
40 times for 40 persons`. A test that cannot fail is worse than no test,
because it is claimed as coverage.

Parallelising the remaining CPU work is Phase 7.8, written up with the seven
things that can corrupt data if it is done carelessly - starting with the
resume point, which is a single row that means nothing once there are N
frontiers.

### The rekey sweep restarted from the first person every time
`lastID` lived in a local variable, so an interrupted sweep paid for its own
progress again. Measured mid-backfill on 26.9M contacts: 4.1M persons already
processed cost **2.7 hours** of re-reading before the sweep reached any
outstanding work - and the cost grows as the backfill advances, so the
operator forced to interrupt (window closed, database loaded) is punished
hardest. A 30-minute measurement run of the batched sweep wrote **zero**
tokens: it spent the whole window walking ground it had already covered.

Migration 0043 adds a single-row `rekey_progress`. Its `scope` column is the
safety argument: a resume point means "persons below this uuid are done",
true only for the outstanding set the interrupted run was working through.
Rotate a key, flip a derived-search flag, or rerun with `-reencrypt-pii`
after a run without it, and persons *below* the point have work again -
honouring a stale point would skip them permanently, because the point
advances past them on every later run. The scope fingerprints every input
that decides the outstanding set, so a mismatch restarts from the beginning.

### The sweep ran for seven hours in total silence
No progress output at all: an operator could not tell a working sweep from a
hung one. It now logs a start line, a progress line every 30 seconds
(persons, tokens, persons/sec, ETA) and a finish line. Both runbooks stop
describing `keys rekey` as a command and start describing it as a
maintenance window, with measured numbers: **~424 persons/sec**, **~17.6 h**
for a full pass over 26.9M contacts, roughly 40 minutes per million.

### `benchmark/bulkload` had no tests, and the scale numbers rest on it
The loader claims a bulk-loaded contact "resolves exactly as it would for a
contact registered through the API". Nothing verified it - and a loader that
wrote a token under the wrong key version, or an AEAD blob without the
server's AAD binding, would fail as a silent MISS on data no throughput
benchmark re-reads. Three tests now assert the claim through the server's own
lookup and attribute paths, and compare a loaded contact's token kinds, key
versions, blob key id and algorithm against a registered one. Both failure
modes were verified by introducing them.

### The rekey sweep wrote one token per statement (found by Phase 7.4)
With the pagination fixed, the sweep was still measured at **87 hours** for a
26.9M-contact backfill. The cause was the write shape, not the read: it
Exec'd once per token, so a person cost **7.2 synchronous round trips** and
the dataset cost 193.6 million of them.

The database was never the constraint. Measured on the same instance,
in-server, 1000 rows: 18.4 ms as single-row inserts, 7.0 ms as one multi-row
insert - about **54,000 rows/s** either way, against the sweep's 605
queries/s. A 90x gap that is pure round-trip latency.

Tokens now accumulate per batch and land in one `INSERT ... unnest(...)`.
The per-ROW liveness check moved from `WHERE EXISTS (... erased_at IS NULL)`
into a join on `persons` inside the same statement - it had to, because
batching WIDENS the window GDPR-ERASURE-2 lives in: a person read at the top
of a 500-person batch has their tokens written at the bottom of it.
`TestBatchedTokenFlushStillRefusesAnErasedPerson` erases someone in exactly
that window through a test seam, and fails if the join is weakened.

A failed batch is replayed row by row to name the offending person before
the error is returned: `person_tokens_ident_uq` is not the conflict target,
so a dedup-invariant violation aborts the statement, and "a batch of 500
failed" is a worse diagnostic than "this person failed".

`SUNDER_REKEY_BATCH` (default 500, `1`-`10000`) exposes the knob; `1`
restores the old behaviour and its duration.

### New configuration
`SUNDER_REKEY_BATCH` (default `500`, range `1`-`10000`): persons per page,
and how many persons' search tokens go into one `INSERT`. `1` restores the
pre-0.5.1 per-token behaviour and its 87 hours.

### Also in this release
- The .NET test suite's three `xUnit2013` warnings are gone
  (`Assert.Equal(1, xs.Count())` -> `Assert.Single(xs)`), and `xUnit2013` is
  now an error in that project. Those warnings had been printed by a GREEN
  CI job for a whole release - the same way two missing XML doc comments
  were, and for the same reason: nobody reads the output of a job that
  passes. The analyzer exists to keep failure MESSAGES useful, which is
  exactly what a test is for.
- The playground reaches **every** shipped surface (Phase 8): a cascading
  erasure walkthrough contrasting "erase the guardian" with
  `cascade:[guardian]` on one page, and an allow-list where each remaining
  omission names a docs page that must exist - a guard test that immediately
  caught a pointer at a retention page nobody had written.
- Two more assignment-style test corruptions fixed, plus a guard that fails
  the build on `overlay(... placing ...)` in any test.

### Upgrade notes
Migration `0043` adds a single-row `rekey_progress`. On the 26.9M-contact
dataset the v0.4 -> v0.5 batch applied in **0.63 s** with the process
answering `/readyz` **1.5 s** after start; `0043` is smaller than any of
them. No action required beyond the usual rolling restart.

## v0.5.0 - 2026-08-27

The second full external review (116 findings across eleven dimension audits)
closed end to end: every numbered finding plus all four LOW/INFORMATIONAL
roll-up tables. Eight migrations, ~90 new regression tests. The theme is the
same one the review names - "the specific places where a correct pattern was
implemented once and not carried across to its sibling" - so most of these
fixes generalise an existing guard rather than invent one.

### Data loss and Article 17 (the eight HIGH findings)
- **H1** the erasure webhook queue no longer strands claims. `SENDING` was an
  absorbing state: the claim committed before the POST, every settle
  statement rode the context that had just died, and no reaper or lease
  existed. `erasure_events` gains `claimed_at` and a status CHECK
  (migration 0035); settles run on a context detached from the caller's; a
  reaper runs at the top of every sweep, from `retention run`, and on demand
  via `sunder dsr requeue [-all]`; the post-erase delivery is detached and
  scoped to its own erasure instead of claiming a queue-wide batch;
  `sunder_erasure_events_sending` / `_failed` gauges and alert rules ship.
- **H2** concurrent registration of the same e-mail no longer mints two
  persons. The unarbitrated `ON CONFLICT DO NOTHING` swallowed the dedup
  unique violation, making the documented 23505 retry unreachable. When the
  probe found no owner the conflict target is now the primary key, so an
  identifier owned by another person aborts and the retry finds the winner;
  when it DID find one the old clause stays, because a secondary identifier
  belonging to a third party must be left with its owner, not stolen and not
  fatal.
- **GDPR-ERASURE-1/-2** the rekey sweep can no longer resurrect an erased
  person. Its `(key_id, alg)` guard could not see an erasure - both wipes NULL
  the key id and `COALESCE(NULL,'v1')` is exactly what an un-rekeyed row
  carries - so the write is now a compare-and-swap on `updated_at` (which
  every concurrent writer moves and the sweep does not) plus a `persons` join
  and `pii_encrypted IS NOT NULL`. Token inserts are scoped to a live person
  inside the statement, and `Lookup` - the only cid-producing read without a
  tombstone predicate - has one.
- **TOKENS-LOOKUP-5 / GDPR-ERASURE-6 / DB-TXN-3** OTI verification takes the
  person locks BEFORE the single-use CAS, in erasePerson's own cids -> persons
  order. That removes the ABBA deadlock (whose victim Postgres, not the
  application, chose) and supplies the in-transaction tombstone check the path
  never had: it does not merely write PII, it CREATES the cids row holding it,
  outside the set the erasure enumerated and queued webhooks for.
- **GAP-1** `portal_outbox.payload` - sealed under `pii-kek` by migration 0016,
  after the sweep was written - is re-sealed by `keys rekey`, and
  `keys retire` refuses a KEK version any store still references (`-force` to
  override). The documented cure for a leaked KEK no longer leaves plaintext
  e-mail addresses and live magic-link tokens under the retired key.
- **AUDIT-CHAIN-1** one plain INSERT could permanently destroy sealing,
  verification and anchoring - and, under sync sealing, the whole API.
  Migration 0036 adds `audit_seal_consistent` and a head-position trigger;
  verification degrades a pre-existing bad row to a VERDICT instead of an
  error, so it can never read as "the verifier is down".
- **OPS-CLI-CONFIG-1** the file keystore minted key material silently. Every
  mint now warns and moves `sunder_keystore_minted_total`, and `serve`
  REFUSES to mint for a version live data was written under - a lost volume
  fails closed instead of manufacturing a healthy-looking empty vault.
  `SUNDER_KEYSTORE_ALLOW_MINT` overrides; `bootstrap` always mints.

### Security
- **AUTHZ-1** the per-client rate limit moved from eleven hand-wired handlers
  into middleware over the whole `/v1/` mux - the primary PII read and
  `POST /v1/dsr/erase` were among the routes it had never covered - with a
  route-table guard so a new endpoint cannot skip it. Attribute-read misses
  now feed the enumeration detector.
- **AUTHZ-2** `CreateTx` (the constructor `sunder bootstrap` uses, i.e. every
  deployment's default provisioning) validates the unlock grant like every
  other path, `-ttl` defaults to `90d`, migration 0037 backs it with a CHECK,
  and `serve` warns about installed-base rows.
- **AUTHZ-3** `authfail:`, `share-public:` and the audit buckets fail CLOSED
  on a Redis outage regardless of `SUNDER_REDIS_FAIL_CLOSED` - an operator
  choosing availability for ordinary reads is not choosing to disable
  credential-stuffing protection.
- **AUTHZ-4** the M3 attribute allowlist filters BEFORE the copy and the
  predicate evaluation, inside the transaction. The post-commit
  `stripSharedAttr` - an unlocked read-modify-write that could clobber a
  concurrent merge, and that left the forbidden value in place whenever it
  failed - is gone.
- **TOKENS-LOOKUP-6** an OTI carrying attributes or predicates requires
  `attributes.read`, and a self-addressed token answers no predicates.
- **CRYPTO-2** retiring an HMAC key purges the DERIVED kinds it minted
  (`name_phonetic`, `phone_suffix`), not only the base kind.
- **CRYPTO-3** value-token dedup gets its own key kind (`hmac-value`) and a
  `unique_key_version` column (migration 0039). Borrowing `hmac-email` meant a
  rotation silently broke `unique:true` and a leak of the e-mail SEARCH key
  was an offline dictionary oracle over every tokenized IBAN and card number.
  Matching spans live versions and converges on touch and on sweep; the portal
  send-throttle row is carried across a rotation instead of resetting.
- **CRYPTO-4/-5** the AEAD now names what the ciphertext is FOR: value tokens
  bind the subject cid, version snapshots bind their generation
  (migration 0038, versioned so pre-existing rows keep opening). A repointed
  value token stops opening; a historical blob can no longer be transplanted
  over the live row to undo a rectification.
- **OPS-CLI-CONFIG-3** `client create`, `client grant`, `webhook set`,
  `keys rotate`, `keys retire` and `retention set` write to the audit chain,
  in the same transaction as the mutation.

### Concurrency and correctness
- **GDPR-ERASURE-5** consent, share and link writers re-check liveness inside
  their transaction under erasePerson's own lock prefix; the readers carry the
  tombstone predicate too.
- **GDPR-ERASURE-4** a cascade records its plan durably inside the parent's
  erasure transaction and erases children FIRST, so an interruption is
  describable and resumable - re-issuing the same request resumes it, and
  `sunder dsr cascade-status` lists what is outstanding.
- **GDPR-ERASURE-7** the search-token cleanup is level-triggered: a blocker at
  the instant of the wipe no longer strands a person's identifiers forever.
- **CONCURRENCY-CORE-4** `keys` carries an epoch every replica checks (~1s
  convergence instead of 30s), and `keys retire` waits out
  `SUNDER_KEY_RETIRE_GRACE` so a replica cannot still be writing under a
  version whose one-shot purge has already run.
- **QUEUE-WORKER-2/-3/-5/-6** `portal_outbox.claimed_at` is finally written
  and its reaper keys off claim age; both workers settle on a detached
  context and are drained at shutdown; `crypto.ErrDecrypt` and
  `crypto.ErrEngineUnavailable` separate "this payload is corrupt" from "the
  signer is restarting", so a blip no longer destroys the only copy of a
  citizen's login link; a missing webhook leaves the event PENDING (blocked,
  not failed).
- **AUDIT-CHAIN-2/-3/-4** a forged hour marker is refused by a unique index
  and a suppressed hour is reported distinctly; one `audit.VerifyAll` serves
  both the CLI and the HTTP endpoint, which had never checked read buckets;
  anchoring is idempotent in the root and exports before it commits.
- **AUDIT-CHAIN-7** sync mode keeps a low-frequency backlog sealer, so a
  rolling async -> sync restart cannot strand rows outside the chain.

### Reliability and ops
- **FILES-STORAGE-2/-3/-5/-7** the S3 driver takes the already-materialised
  body (peak upload memory is the documented 1x, not ~4x); the reap defer is
  registered before the PUT, so an ambiguous PUT cannot leave ciphertext no
  sweep could find; file routes get their own transport deadline, re-armed
  once the concurrency slot is granted, and a mid-stream failure aborts the
  connection instead of completing a short 200; file GC is ordered and
  demotes objects it cannot delete.
- **OPS-CLI-CONFIG-5/-6/-7/-8/-10/-11** the chart refuses a skewed
  `image.opsTag`, ships a `startupProbe` (a slow migration no longer
  crash-loops forever), gives the bootstrap Job its keystore configuration,
  gives the sealer a `/healthz` liveness probe and a PDB, makes
  `client grant` one transaction that refuses an unknown id, and applies one
  security-context baseline to all five workloads.
- **DOCS-2** alert rules and dashboard panels for the stalled sealer, stranded
  erasure notifications and runtime key minting - the gauges the threat model
  already called "the alarm".

### Contract, docs and tests
- **TOKENS-LOOKUP-7 / GAP-2** Article 15 and 20 answers carry the holdings
  that do not live in the attribute blob: value tokens, files, the RECIPIENTS
  of shares, and links. Value-token audit rows carry the subject's cid, so
  bucketed reads no longer collapse to `cid=''` and become unmatchable.
- **DOCS-1/-4/-5/-6/-7/-8/-9/-10/-11/-12/-13/-14/-15/-16** every documented
  guarantee the implementation did not provide is corrected at the source:
  the sealer's DB grant (four columns plus `audit_read_buckets`), the local
  file vault as single-instance-only and a separate backup unit, the OpenAPI
  gaps (`phone_suffix`, `user_id`, `cascade`, `linked`, `unlock_required`),
  the algorithm-migration verification query, boolean config validation,
  `user_id` in the chain hash, retention and consent semantics, cascade
  atomicity, the retracted throughput claim and the two shipped surfaces
  listed as non-goals.
- New CI guards: a field-level OpenAPI drift check, a retracted-claims grep,
  `ops/check-config-docs.sh` (every `SUNDER_*` the code reads must be in a
  reference table), and a fourth matrix leg (async, chained).
- The coverage gate moves into `ops/coverage-gate.sh`, which applies an
  explicit `//coverage:defensive <reason>` exclusion list before comparing
  against 90%. It excludes 49 statements (0.65% of the tree) - `rows.Scan`
  and `rows.Err` propagation in the new sweep and cascade loops, reachable
  only by injecting a database fault at that one statement - and refuses to
  run if a marker sits on a block that IS covered or if the excluded share
  passes a 1% ceiling. Measured 90.14% of 7,515 statements (raw 89.56%).
- Two alert rules ship for metrics added this release:
  `SunderKEKSealBudgetHigh` (per-version AES-GCM seal count past half the
  per-process budget - rotate on usage, not on incident) and
  `SunderRateLimitBackendFailing` (Redis unreachable, so with the default
  `SUNDER_REDIS_FAIL_CLOSED=false` the limits are not being enforced).
- **TESTS-1..16** the vacuous tests are gone: the concurrency test now
  rendezvous instead of racing a wall clock, the timing-oracle test asserts a
  location statistic and the constant-time floor, the keystore race asserts
  the racers agree on key BYTES, the read-bucket close is driven against a
  concurrent upsert, and each of the five retention guards has its own
  subtest.

### Behaviour changes worth a deployment note
- `sunder bootstrap` defaults to a 90-day credential; an explicitly empty
  `-ttl` is now an error, because the bootstrap admin holds `admin.unlock`.
- An erasure event for a scope with no webhook stays `PENDING` instead of
  being settled `NO_WEBHOOK`, and delivers once the endpoint is registered.
- `sunder keys retire` waits out `SUNDER_KEY_RETIRE_GRACE` (default 60s);
  `-force` overrides.
- A file download that fails mid-stream aborts the connection rather than
  completing a 200 with a short body.
- Every `/v1/` route spends the client's rate-limit budget.

### New configuration
`SUNDER_WORKER_CLAIM_TTL`, `SUNDER_KEYSTORE_ALLOW_MINT`,
`SUNDER_AUDIT_STALE_UNSEALED`, `SUNDER_KEY_RETIRE_GRACE`,
`SUNDER_API_CLIENT_IP_HEADER`, `SUNDER_SEALER_HEALTH_ADDR`. Booleans now
accept `true/false`, `1/0`, `yes/no`, `on/off` and REFUSE anything else.

### The rekey sweep was unusable at scale (found by Phase 7.4)
`sunder keys rekey` paginated with `id::text > $1 ORDER BY id::text`. Casting
the uuid makes `persons_pkey` unusable, so **every batch became a parallel
sequential scan of the whole table plus a top-N sort**. Measured on the
26.9M-contact dataset:

| | `id::text` | `id` |
|---|---|---|
| plan | Parallel Seq Scan + Sort 26.9M | Index Scan `persons_pkey` |
| shared buffers per batch | 172,867 | 513 |
| execution | - | 5.2 ms |

At `-batch 500` that is 53,842 batches; one sweep recorded **6.3 billion**
sequential tuple reads from `pg_stat_user_tables`, ran past 21 minutes
without finishing, and held its pool connections in `idle in transaction`
long enough that concurrent registrations timed out at 30 seconds.

Nothing about the sweep's RESULT was wrong, which is why every functional
test passed: it is a query-plan defect, invisible on a dataset small enough
to scan. Key rotation is a security operation - an operator whose response to
a suspected key compromise is unusable at their data size does not have that
option. `TestRekeyPaginationUsesThePrimaryKeyIndex` asserts on the plan's
sort key, so re-introducing the cast fails the build.

### Phase 7 groundwork
- **Cold-boot and multi-replica scenarios** run as their own CI job
  (`ops/coldboot-scenarios.sh`): two processes migrating one empty database,
  a second replica sharing the keystore (12/12 lookups must resolve across
  both - what a re-minted key breaks), a key rotation under 200 concurrent
  lookups, and a burst under the sealer. Each boots from nothing, because a
  stack restarted onto existing data cannot reproduce any of them.
  `docs-site/docs/admin/multi-replica.md` documents all four with sequence
  diagrams, what an operator sees when each goes wrong, and how to recover.
- **`ops/check-artifact-coverage.sh`** extends the shape of
  `check-config-docs.sh` to the four artifacts that had no guard: Helm
  reachability, Postman route coverage, SDK parity across all six languages,
  and the docs-site mirror of the config reference. It immediately found that
  **F4, F5 and F8 were not reachable through the Helm chart at all** - an
  operator on Kubernetes could not enable the value vault's search knobs, the
  file vault, public shares or attribute history. All fifteen variables are
  now settable, and `files.storage=local` fails the render with its reason
  rather than warning, because on a second replica it answers downloads with
  200 and an empty body.
- **The .NET SDK's published surface is enforced**: two of fourteen exception
  constructors had shipped a release with no XML documentation and an
  inconsistent signature. CS1591 is now an error in that project - with the
  documentation file generated, the doc IS the artifact.

### Two more races the CI matrix caught during this release
- **The file keystore could overwrite live key material.** `Ensure` reads,
  then queues on an O_EXCL lock. A caller that found no key, waited, and won
  the lock AFTER the first generator had already renamed its key into place
  minted straight over it - and `Ensure` returned nil either way, so the only
  symptom was two readers disagreeing about the key bytes while every blob
  encrypted under the previous key became unreadable. The decision is now
  re-checked under the lock. `TestEnsureDoesNotOverwriteAKeyMintedWhile
  WaitingForTheLock` occupies that exact window through a test seam instead of
  waiting for scheduling luck; the existing 16-way race test had been passing
  by chance and failed once on a CI runner.
- **The playground inbox refused most real pseudonyms.** Its `looksLikeCID`
  filter checked a CROCKFORD alphabet (digits `0-9`, no `U`) while the vault
  emits RFC 4648 base32 (`A-Z`, `2-7`). Roughly 56% of 26-character
  pseudonyms contain a `U`, so the erasure walkthrough's signed callback was
  discarded as "not a pseudonym" on about every second run - a coin-flip CI
  failure that looked like a webhook delivery problem. Two tests pin it: the
  alphabet itself, and a loop asserting the inbox accepts 500 freshly minted
  CIDs.

### Cold-boot migration race (found by the playground CI leg)
`Migrate` created its `schema_migrations` bookkeeping table OUTSIDE the
advisory lock meant to serialize concurrent replicas. `CREATE TABLE IF NOT
EXISTS` is not atomic - the existence check and the creation are separate
steps - so two replicas booting against a database with no schema at all
both passed the check and the loser died with `duplicate key value violates
unique constraint "pg_type_typname_nsp_index"` (a table creates its row type
too). On the playground stack, whose `deliver` worker and API server start
together on a fresh volume, that is a crash loop on the very first boot. The
table is now created inside the lock, and
`TestConcurrentMigrateOnAnEmptyDatabase` races two pools against one empty
database - it fails on the old code and passes on the new.

### SDKs - all six now cover the whole client surface
Every SDK moves to **0.5.0** and grows the routes that were previously
"plain JSON over HTTP": consent (`SetConsent`/`GetConsent`), the data-subject
rights endpoints (`DSRAccess`/`DSRExport`/`DSRErase`, cascade included), the
value vault (`Tokenize`/`Detokenize`/`DeleteToken` plus the two unlock-gated
bulk routes), the file vault (`UploadFile`/`ListFiles`/`DownloadFile`/
`DeleteFile`), cross-org shares, person links, attribute version history,
external claims, `admin/unlock` and `GET /readyz`. Each also takes an
optional `user_id`, sent as `X-Sunder-User-Id` on every call.

Three shared behaviours are asserted by tests in all six: an erasure with no
cascade sends **no `cascade` key** (an empty list would read as an opt-in), a
tokenize with no cid omits it rather than sending an empty one, and every
destructive or unlock-spending call is attempted exactly once. Roughly 130
new SDK tests; the .NET suite is the one leg not runnable on the release
machine (no `dotnet` toolchain) and is covered by the CI matrix.

The Java runner also gains a `System.exit(0)` after its summary: the mock
server's thread pool holds non-daemon threads, so `run-tests.sh` used to hang
after the last PASS line instead of exiting 0.

## v0.4.0 - 2026-08-27

Phase 3 complete (F1-F12), then a full internal security-review sweep - every
Severe, High, Medium and all-but-two Low findings closed across eight review
passes, each fix re-derived from its own exploit and re-verified against the
source rather than the commit message. Both CI legs (plus a new third leg)
green at 90.2%.

### Phase 3 - Pro parity features (F1-F12)
- **F1/F2** derived search: phonetic-name and phone-suffix lookup, off by
  default, keyed-HMAC, single-hit (a multi-hit is a miss).
- **F4** value tokenization: scope- and type-bound tokens, Luhn-shaped card
  tokens with no BIN, unique-dedup, DB-clock expiry, bulk always behind a
  single-use unlock token.
- **F5** file vault: PII KEK -> per-person record key -> per-file DEK,
  4 MiB AES-256-GCM chunks, crypto-shredding on erasure, local and
  hand-rolled-SigV4 S3 drivers.
- **F6** attribute versioning, off by default (count- and TTL-capped).
- **F7** sub-accounts / person links (guardian/member/owner) with opt-in
  erasure cascade.
- **F8** shared records: expiring, revocable, purpose- and consent-gated
  partner UUIDs.
- **F9** Shamir recovery (stdlib GF(256)) for file-keystore custody.
- **F11** multi-jurisdiction deployment example; **F12** role presets.
- Guides site, runnable F4-F9 example scripts, and an interactive playground
  (P3.7); audit verification over HTTP (P3.6).

### Security review - closed this release
- **Erasure / Article 17 invariant** re-established across every Phase 3
  table (shares, portal outbox, links, value tokens, blob history, consent
  state), enforced going forward by an information_schema-driven guard test
  that fails any new person-linked table without an erasure decision.
- **Audit integrity**: `user_id` joined the chain hash (versioned tuple, old
  chains keep verifying); forged sealed-bucket inserts refused; the sealer
  ages rows by the database clock; read-bucket sealing made race-free and
  collation-independent.
- **File vault**: streaming multipart upload (no disk spool before the
  concurrency slot), bounded upload memory, ciphertext reaped on every
  failure path, metadata redacted at crypto-shred time.
- **Shares / consent / lookup**: shares are delegated reads (purpose +
  consent + attributes.read); the F3 allowlist now gates lookup by
  identifier kind (no name oracle); consent revoke is cid- and
  purpose-precise.
- **Hardening**: per-IP limit on the credential-less share fetch; S3 driver
  refuses redirects; keystore warns loudly on key minting; rate limits on
  every previously-unmetered surface; `admin.unlock` refused on a
  non-expiring credential on every operator path; recovery-bundle name guard
  and no-silent-overwrite; constant-time recovery checksum.
- **Ops**: Helm gains full `SUNDER_AUDIT_*` plumbing, a dedicated sealer
  Deployment and a daily verify-audit CronJob; migration 0023 made
  idempotent; a third CI leg (sync, bucketed).
- **Contract**: `api/openapi.yaml` documents every endpoint (F4-F8 +
  admin/unlock), enforced by a go/ast route-coverage guard; a companion
  guard requires every route to carry at least one happy-path and two
  edge-case tests.

### Deferred to v0.4.1 (tracked, specs locked)
- **L6** durable cascade erasure (synchronous data destruction bounded by
  MaxCascadeChildren + idempotent entrance; a durable pending worker clears
  the tail with bounded retry, TTL cleanup, an oldest-pending metric and a
  terminal "cascade completed" audit record).
- **L8** split the lookup audit action (lookup / lookup.fuzzy /
  lookup.suffix) behind a consumer inventory and a measured bucket-row
  multiplier.

## v0.3.0 and earlier
See the git history.
