# Runbook: PII encryption algorithm migration

When to use this: the current AEAD is deprecated by policy or weakened by
research, or a compliance regime mandates a specific cipher. Sunder stores
each blob's algorithm alongside it (`cids.pii_alg`), so old and new
algorithms coexist during the migration - **no downtime, no big-bang
re-encryption window**.

Supported algorithms: `aes256gcm` (default), `xchacha20poly1305`.

## How it works

- **Reads** always use the algorithm stored with the blob.
- **Writes** (new registrations, merges, attribute shares) use the
  configured `SUNDER_PII_ALG`.
- **`sunder keys rekey`** re-encrypts every blob whose key version *or*
  algorithm is stale, converting the backlog in batches.

## Procedure

1. **Rotate the KEK first.** Do not reuse key material across algorithms:

   ```sh
   sunder keys rotate -kind pii-kek
   ```

   This mints the next `pii-kek` version; new writes pick it up immediately.

2. **Reconfigure and roll the deployment:**

   ```sh
   SUNDER_PII_ALG=xchacha20poly1305
   ```

   Restart replicas (rolling restart is fine - replicas on the old setting
   keep writing the old algorithm, which stays readable forever). From this
   point every new or touched blob uses the new AEAD under the new key.

3. **Convert the backlog:**

   ```sh
   sunder keys rekey -batch 500
   ```

   The sweep decrypts each blob with its stored key/algorithm and re-encrypts
   under the newest key and the configured algorithm. It covers **every**
   pii-kek-sealed store: `cids`, `cid_blob_versions`, `value_tokens`,
   `person_record_keys` and `portal_outbox`. It is idempotent and
   resumable - rerun until `blob(s) re-encrypted` reports `0`.

   **Budget the time before you start.** Measured on 26,872,537 contacts
   (34 GB, 12-core server, tuned PostgreSQL 16): **~424 persons/sec**, so a
   full pass is **~17.6 hours**, roughly 40 minutes per million contacts.
   Under a million this is a coffee break; over ten it is an overnight job
   and belongs in a maintenance window - the sweep holds pool connections
   for its duration and competes with live traffic.

   It prints progress every 30 seconds and records a resume point after each
   page, so interrupting it costs nothing but the current page:

   ```
   INFO rekey sweep progress persons_total=254000 persons_per_sec=424 eta=17h20m0s
   ^C
   $ sunder keys rekey     # in the next window
   INFO rekey sweep resuming from_person=3f2a... already_covered=254000
   ```

   A resume point is honoured only for **identical work**. Rotating another
   key, flipping a derived-search flag, or rerunning with `-reencrypt-pii`
   after a run without it all invalidate it, because persons before the
   point now have work again - the sweep then correctly starts over.

   `SUNDER_REKEY_BATCH` (default 500) trades memory and database pressure
   against speed. `1` restores the pre-0.5.1 per-token writes, which on the
   same dataset measured **87 hours** rather than 17.6: the difference was
   round-trip latency, never database throughput.

   A row the sweep found modified by a concurrent request between its read
   and its write is reported separately as `blob(s) were modified
   concurrently and NOT converted`. That is not a warning to skim past: those
   rows are still on the old algorithm, so rerun until it too reports `0`.

4. **Verify - every store, not just `cids`:**

   ```sql
   SELECT 'cids' AS store, COALESCE(pii_alg,'(null)') AS alg, count(*)
     FROM cids WHERE pii_encrypted IS NOT NULL GROUP BY 2
   UNION ALL SELECT 'cid_blob_versions', alg, count(*) FROM cid_blob_versions GROUP BY 2
   UNION ALL SELECT 'value_tokens', alg, count(*) FROM value_tokens GROUP BY 2
   UNION ALL SELECT 'person_record_keys', alg, count(*) FROM person_record_keys GROUP BY 2
   UNION ALL SELECT 'portal_outbox', alg, count(*) FROM portal_outbox GROUP BY 2
   ORDER BY 1, 2;
   ```

   Expect the new algorithm in every row. Checking `cids` alone is what let
   an earlier version of this runbook report a completed migration while the
   F4 value vault and the record key that wraps every file DEK were still on
   the deprecated AEAD. Spot-check a read:
   `GET /v1/contacts/{cid}/attributes/...` on a pre-migration contact, and a
   detokenization of a pre-migration value token.

5. **Retire the old key** once nothing references it:

   ```sh
   sunder keys retire -kind pii-kek -version v1
   ```

## Notes

- Search tokens (HMAC-SHA256) and the audit chain (SHA-256) are separate
  mechanisms with their own versioned keys; this runbook covers only the PII
  blobs. HMAC-SHA256 has no known weakness that would motivate migration.
- The algorithm is bound into the AEAD's associated data for non-default
  algorithms, so a hostile `pii_alg` downgrade in the database fails
  authentication instead of decrypting under the wrong cipher.
- Adding a *new* algorithm to Sunder itself is a code change: extend the
  registry in `internal/crypto/pii.go`, the CHECK constraint in a schema
  migration, and the allowlist in `internal/config/config.go`.
