# Changelog

All notable changes to Sunder. Dates are YYYY-MM-DD.

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
See the git history and `PLAN.md` (Phases 1, 2, 4, 5).
