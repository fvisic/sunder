# Runbook: Backup & Disaster Recovery

## What state exists, and the one rule that matters

| State | Where | Loss means |
|---|---|---|
| PostgreSQL | persons, tokens, cids+blobs, clients, consents, audit chain, anchors, keys metadata | everything |
| Key material | keystore (file dir or Vault) | tokens unmatchable, PII undecryptable - **data loss even with a perfect DB backup** |
| Exported anchors | `.tsr` files (anchor dir / write-once storage) | tamper evidence against a DB-level attacker |
| **File vault objects** | `SUNDER_FILES_DIR` (local driver) or the S3 bucket | **uploaded files unrecoverable - and the loss is INVISIBLE.** The database keeps every `files` row: name, size, sha256, the wrapped DEK, and the `person_record_keys` row that unwraps it. Inventory reports show the files as present; `readyz`, `verify-audit` and the spot-check below all pass. It surfaces only when somebody downloads one. |

**The rule: database and key material are one unit.** Back them up together,
restore them together. A DB backup without the matching keys is a pile of
ciphertext; keys without the DB are useless. The strict keystore makes a
mismatch loud (missing-key errors), never silent.

**With the file vault enabled the unit is three-way**, and the ordering cuts
both ways: restoring the object store WITHOUT the matching
`person_record_keys` rows leaves the ciphertext permanently unopenable -
crypto-shredding does not distinguish an Article 17 erasure from a bad
restore. Restore all three to the same point.

## Backup

1. **PostgreSQL**: continuous WAL archiving + daily base backup
   (pgBackRest/WAL-G), or at minimum nightly `pg_dump`. Encrypt at rest.
2. **Keys**:
   - Vault keystore: Vault has its own HA/backup story (raft snapshots) -
     snapshot on the same schedule as the DB.
   - File keystore: the key directory is tiny; copy it (encrypted!) with
     every DB backup. It changes only at rotation - back up immediately
     after every `sunder keys rotate`.
3. **File vault objects** (only when `SUNDER_FILES_STORAGE` is set):
   - `s3`: enable bucket versioning plus cross-region replication, or
     snapshot on the DB's schedule.
   - `local`: back up `SUNDER_FILES_DIR` alongside the keystore, on the same
     schedule as the database. It is per-process state, so back up EVERY
     instance's directory - which is one of the reasons `local` is
     single-instance only.
4. **Anchors**: sync the `.tsr` export directory to write-once storage
   (S3 Object Lock or equivalent) - this copy is the whole point; it must
   live where a database attacker cannot reach.
5. Keep backups in a different failure domain than the primary.

## Restore procedure

1. Restore PostgreSQL (PITR to the desired point, or the latest dump).
2. Restore the matching key material (same or later rotation state - keys
   are only ever added, never changed, so a NEWER keystore is always safe;
   an older one is not).
3. Start the service; `readyz` must go green. The startup bootstrap only
   *ensures* keys for versions listed in the restored `keys` table - if it
   mints a key that should have existed, you restored the wrong keystore:
   **stop**, see "keystore mismatch" below.
4. Verify integrity:
   ```sh
   sunder verify-audit -anchors <anchor dir>
   ```
   - `chain intact` + anchors `token: OK; file: OK` - clean restore.
   - Anchors `MISSING FROM DATABASE`: you restored to a point before those
     anchors - expected for PITR; document which.
   - `ROOT NOT IN CHAIN`: the restored data diverges from anchored history -
     treat as an incident, not just a bad restore.
5. Spot-check one contact end to end: lookup → attribute read → OTI
   issue/verify.
6. **With the file vault enabled, download one file** (`GET /v1/files/{id}?purpose=...`)
   and check the received byte count against the response's
   `Content-Length`. This step exists because nothing else in this
   procedure can detect a missing object store: `Peek` answers from
   database metadata, so the response is a 200 with the right headers and a
   truncated - possibly empty - body. Steps 1-5 all pass with the entire
   file vault gone.

## Keystore mismatch symptoms

- Lookups return 404 for contacts that exist → HMAC keys don't match the
  stored tokens. Restore the correct keystore; as a last resort re-register
  contacts from source systems (dedup makes this idempotent) - but PII
  blobs under a lost pii-kek are gone for good.
- `pii decrypt` errors on attribute reads → wrong/missing pii-kek version.
- File downloads that break mid-transfer, or return far fewer bytes than
  `Content-Length` → the object store was not restored (or, in a
  multi-replica deployment, `SUNDER_FILES_STORAGE=local` is being used,
  which is unsupported there).

## RPO / RTO guidance

- RPO = WAL archiving interval (minutes) for the DB; zero for keys (they
  change only at rotation, which is an operator action).
- RTO: the service itself is stateless - restore time is PostgreSQL restore
  time plus one `readyz` (plus the object-store restore when the file vault
  is enabled). Rehearse the restore quarterly, **including step 6**; an
  unrehearsed runbook is a wish, not a plan.

## What is deliberately NOT recoverable

Erased persons (`dsr.erase`) stay erased: tokens are deleted and blobs
wiped inside the same transaction, so any restore newer than the erasure
keeps it. Restoring to a point BEFORE an erasure resurrects that data -
your retention/erasure obligations apply to backups too: set backup
expiry accordingly and re-run erasures executed after your restore point
(the `erasures` table lists them).
