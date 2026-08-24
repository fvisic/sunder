# Runbook: Backup & Disaster Recovery

## What state exists, and the one rule that matters

| State | Where | Loss means |
|---|---|---|
| PostgreSQL | persons, tokens, cids+blobs, clients, consents, audit chain, anchors, keys metadata | everything |
| Key material | keystore (file dir or Vault) | tokens unmatchable, PII undecryptable - **data loss even with a perfect DB backup** |
| Exported anchors | `.tsr` files (anchor dir / write-once storage) | tamper evidence against a DB-level attacker |

**The rule: database and key material are one unit.** Back them up together,
restore them together. A DB backup without the matching keys is a pile of
ciphertext; keys without the DB are useless. The strict keystore makes a
mismatch loud (missing-key errors), never silent.

## Backup

1. **PostgreSQL**: continuous WAL archiving + daily base backup
   (pgBackRest/WAL-G), or at minimum nightly `pg_dump`. Encrypt at rest.
2. **Keys**:
   - Vault keystore: Vault has its own HA/backup story (raft snapshots) -
     snapshot on the same schedule as the DB.
   - File keystore: the key directory is tiny; copy it (encrypted!) with
     every DB backup. It changes only at rotation - back up immediately
     after every `sunder keys rotate`.
3. **Anchors**: sync the `.tsr` export directory to write-once storage
   (S3 Object Lock or equivalent) - this copy is the whole point; it must
   live where a database attacker cannot reach.
4. Keep backups in a different failure domain than the primary.

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

## Keystore mismatch symptoms

- Lookups return 404 for contacts that exist → HMAC keys don't match the
  stored tokens. Restore the correct keystore; as a last resort re-register
  contacts from source systems (dedup makes this idempotent) - but PII
  blobs under a lost pii-kek are gone for good.
- `pii decrypt` errors on attribute reads → wrong/missing pii-kek version.

## RPO / RTO guidance

- RPO = WAL archiving interval (minutes) for the DB; zero for keys (they
  change only at rotation, which is an operator action).
- RTO: the service itself is stateless - restore time is PostgreSQL restore
  time plus one `readyz`. Rehearse the restore quarterly; an unrehearsed
  runbook is a wish, not a plan.

## What is deliberately NOT recoverable

Erased persons (`dsr.erase`) stay erased: tokens are deleted and blobs
wiped inside the same transaction, so any restore newer than the erasure
keeps it. Restoring to a point BEFORE an erasure resurrects that data -
your retention/erasure obligations apply to backups too: set backup
expiry accordingly and re-run erasures executed after your restore point
(the `erasures` table lists them).
