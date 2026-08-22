# Runbook: PII encryption algorithm migration

When to use this: the current AEAD is deprecated by policy or weakened by
research, or a compliance regime mandates a specific cipher. Sunder stores
each blob's algorithm alongside it (`cids.pii_alg`), so old and new
algorithms coexist during the migration — **no downtime, no big-bang
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

   Restart replicas (rolling restart is fine — replicas on the old setting
   keep writing the old algorithm, which stays readable forever). From this
   point every new or touched blob uses the new AEAD under the new key.

3. **Convert the backlog:**

   ```sh
   sunder keys rekey -batch 500
   ```

   The sweep decrypts each blob with its stored key/algorithm and re-encrypts
   under the newest key and the configured algorithm. It is idempotent and
   resumable — rerun until `blob(s) re-encrypted` reports `0`.

4. **Verify:**

   ```sql
   SELECT pii_alg, count(*) FROM cids WHERE pii_encrypted IS NOT NULL GROUP BY pii_alg;
   ```

   Expect a single row with the new algorithm. Spot-check a read:
   `GET /v1/contacts/{cid}/attributes/...` on a pre-migration contact.

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
