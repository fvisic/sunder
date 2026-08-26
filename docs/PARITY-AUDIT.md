# Databunker Parity Audit

Final audit of the Databunker(-Pro) feature matrix against what Sunder
ships, as required by the Phase 3 definition of done: every row is either
**SHIPPED** or an **explicitly approved NON-GOAL**. Nothing is left
undecided. Verified against `main` on 2026-08-26.

## Feature-by-feature

| Databunker feature | Sunder status | Evidence |
|---|---|---|
| Tokenization (values) - format-preserving cards, sliding/final expiry, unique dedup, bulk behind unlock | **SHIPPED (F4)** | `internal/service/valuetoken.go`, `POST /v1/tokens*`; Luhn-valid BIN-free card tokens, scope+type-bound dedup, DB-clock expiry, bulk always unlock-gated. Docs: [value tokenization](../docs-site/docs/concepts/value-tokenization.md). |
| File Vault - per-file DEK, local/S3, crypto-shredding | **SHIPPED (F5)** | `internal/service/files.go`, `internal/storage/`; per-person record key -> per-file DEK -> chunked AES-256-GCM; local + hand-rolled-SigV4 S3 drivers. GCS/Azure drivers are a NON-GOAL for now (S3 API covers R2/MinIO/most vendors); addable behind the same `Driver` interface if a client needs it. Docs: [file vault](../docs-site/docs/concepts/file-vault.md). |
| Fuzzy search - deterministic variants, admin-only, unlock, audited | **SHIPPED (F1)** | `internal/crypto/phonetic.go`, `person_tokens kind=name_phonetic`; off by default, keyed-HMAC, narrowing-only, bulk-deny. Docs: [fuzzy and partial search](../docs-site/docs/concepts/fuzzy-and-partial-search.md). |
| Partial search - group pre-indexing, exact + intersection | **SHIPPED (F2)** | phone-suffix HMAC index, single-hit semantics, scope-filtered candidates; we automate what Databunker makes users hand-maintain via groups. |
| Versioning - record history per update | **SHIPPED (F6)** | `internal/service/versions.go`, `cid_blob_versions`; off by default, count-capped + TTL-pruned, erased with the person. Docs: [attribute versioning](../docs-site/docs/concepts/attribute-versioning.md). |
| Select security - no bulk dump, 60 s unlock tokens, field masks, role policies | **SHIPPED (F3 + F12)** | attribute allowlist (`clients.allowed_attributes`), `unlock_tokens`, role presets (`RoleActions`), `POST /v1/admin/unlock`; enforced on reads, OTI share/verify, shares, bulk tokens. |
| Sub-accounts - tenants/CRBAC groups | **SHIPPED (F7)** | `internal/service/links.go`, `person_links`; guardian/member/owner links within a scope, opt-in erasure cascade. Docs: [sub-accounts](../docs-site/docs/concepts/sub-accounts.md). |
| Shared records - expiring UUID field views | **SHIPPED (F8), improved** | `internal/service/shares.go`; adds manual revoke and erasure/consent auto-revoke (Databunker only expires); default authenticated fetch. Docs: [shared records](../docs-site/docs/concepts/shared-records.md). |
| Shamir keys - 3-of-5 over a recovery key | **SHIPPED (F9)** | `internal/crypto/shamir.go` + `recovery.go`, `keys shamir-init/recover/rotate`; stdlib GF(256), file keystore only. Docs: [Shamir recovery](../docs-site/docs/admin/shamir-recovery.md). |
| Master key / admin bootstrap, unattended | **SHIPPED (F10)** | `sunder bootstrap [-unattended]`; migrates, ensures keys, prints the first admin credential once. Docs: [bootstrap](../docs-site/docs/install/bootstrap.md). |
| Access control - CRBAC roles, conditions, field masks | **SHIPPED (F12)** | role presets + per-attribute allowlist + credential TTL/rotation on the client model; `sunder client create/grant -role/-attributes`. |
| Multi-jurisdiction deployment | **SHIPPED (F11) as a deployment pattern** | per-region instances + OTI handoff; two-instance EU->US example. Explicit NON-GOAL: in-product data-plane federation (by design - see the guide). Docs: [multi-jurisdiction](../docs-site/docs/install/multi-jurisdiction.md). |
| Multi-tenancy - paid tenants | **NON-GOAL (approved)** | Managed single-tenant, decided (plan section 15). The [Databunker migration guide](../docs-site/docs/migrations/from-databunker.md) explains tenants -> per-org instances. |
| Oracle Database backend | **NON-GOAL (approved)** | PostgreSQL only, decided. Rationale in the docs. |
| Sessions / field masking (session layer) | **NON-GOAL (approved)** | Out of scope; field-level disclosure is handled by purpose-checked reads + the F3 allowlist, not a session/masking layer. |
| Licensing & limits | **REPLACED (approved 2026-08-22)** | Apache-2.0, no seat/record limits, no license mechanism; "Update license" how-to dropped. |

## Sunder capabilities with no Databunker equivalent

These are covered by their own guides and are not parity items, listed for
completeness: scoped pseudonyms + OTI handoff with attribute sharing;
consent enforcement on reads and handoffs; hash-chained audit with RFC 3161
anchoring and off-host cross-check; purpose binding; retention TTLs; erasure
webhooks with signed payloads; algorithm agility (`pii_alg` + rekey);
Redis-backed rate limiting + enumeration detection; the benchmark suite; the
Databunker migration tool; signed releases + SBOM.

## Result

Every matrix row is resolved: **12 shipped** (F1-F12), **4 approved
non-goals / replacements** (multi-tenancy, Oracle, session masking,
licensing), with the single scoped narrowing being GCS/Azure file drivers
(deferred behind the existing `storage.Driver` interface, S3 covers the
common vendors). No row is left undecided.
