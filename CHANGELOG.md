# Changelog

All notable changes to Sunder. Dates are YYYY-MM-DD.

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
