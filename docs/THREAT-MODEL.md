# Threat Model

Maps the twelve classic weaknesses of pseudonymous-identity systems to
Sunder's concrete mitigations, plus residual risk. Design rationale lives
in docs/DESIGN.md.

| # | Threat | Mitigation in Sunder | Residual risk |
|---|---|---|---|
| 1 | Central identity provider becomes a super-target | No central party exists: one instance per organization (docs/DESIGN.md); scoped CIDs are unlinkable across organizations by construction | The instance is still the org's crown jewel - harden per the reference deployment (docs/DESIGN.md) |
| 2 | HMAC lookup mistaken for anonymization; stolen key regenerates tokens | Keyed HMAC per attribute, material outside the DB (keystore; Vault driver), strict no-mint keystore, dual-key rotation (`sunder keys rotate`), re-key on touch | KEK compromise: rotate + re-key; keys in RAM: run the signer split (`SUNDER_SIGNER_SOCKET`) so the API process never holds key material; the supply-chain notes in docs/DESIGN.md still apply to the signer |
| 3 | Lookup API enables enumeration (dialing numbers to see what exists) | Per-client sliding-window rate limits (429), miss counter + enumeration warning at 100 misses/10 min, every lookup audited, `LOOKUP != AUTHENTICATION` doctrine | A patient attacker under the limit; alerting must be watched |
| 4 | Name matches too many people | Name alone rejected (400); name is only a narrowing key beside email/phone | - |
| 5 | Social engineering of staff | Out of technical scope; audit chain makes every employee lookup attributable and tamper-evident, which deters and proves | Process controls remain the org's job |
| 6 | CID becomes the new internal OIB | CIDs are per-scope; a client only ever sees its own scope; attributes are per-scope blobs; `scopes.issue` is an explicit, audited, sparingly-granted privilege | An org granting `scopes.issue` to everything recreates the problem - documentation warns |
| 7 | Migration is enormous | Start with one read-path integration (the quickstart demo storyline); SDKs + conformance suite keep per-system cost constant | Organizational, not technical |
| 8 | Legacy systems re-import the national identifier | No OIB column exists anywhere; the service never accepts or returns one | A client system storing OIB beside the CID is outside Sunder's reach - pilot checklist item |
| 9 | Availability becomes critical | Stateless service (scale by replicas), Postgres HA (Patroni reference deployment), graceful shutdown, readiness probes | Rate limiter is in-memory per replica (documented; a shared-counter backend is planned) |
| 10 | Privacy could worsen (central operator sees usage) | Self-hosted: the operator IS the organization; no third party in any flow; TSA anchoring leaks only a 32-byte digest | - |
| 11 | One-time tokens cannot replace stable business identity | Both exist: CID (stable, per-scope) + OTI (5 min, single-use, purpose- and audience-bound, atomic VALID->USED) | - |
| 12 | The system silently degrades into "OIB 2.0" | Random CIDs (nothing derivable), per-scope unlinkability, OTIs as the only inter-system currency, tamper-evident audit anchored to an external TSA | Governance: reviewing client grants stays a human duty |

## Attacker matrix

| Adversary | What they get | What stops them |
|---|---|---|
| Stolen client DB (e.g. CRM dump) | CIDs + the attributes that scope stored; no OIB, no search keys, unjoinable with other scopes | Scoped CIDs; per-scope AAD-bound blobs; HMAC-only search columns |
| Stolen Sunder DB, no keys | HMAC tokens (keyed - no dictionary attacks), encrypted blobs, audit chain | Keys live outside the DB (keystore/Vault) |
| Stolen bearer credential | Only that client's actions/purposes/rate, fully audited | `allowed_actions`/`allowed_purposes`, rate limits, enumeration detection |
| Network attacker replaying an OTI | Nothing: single-use CAS, 5-minute TTL, audience+purpose binding | Atomic VALID->USED; PASETO v4 signature |
| Insider/DBA rewriting history | Chain break at a provable position; a full-chain rewrite orphans TSA anchors, and deleted anchor rows are exposed by the exported `.tsr` files | Hash chain + append-only triggers on `audit` AND `audit_anchor` + RFC 3161 anchoring **with off-host export**: `sunder anchor -out <dir>` and sync that directory to write-once storage the DB attacker cannot reach; `sunder verify-audit -anchors <dir>` cross-checks. Anchors kept only in the database are circular and defeat nobody privileged. |
| Compromised service process | Working keys in RAM - game over for that instance's crypto | Mitigated by the P2.1 signer split (`SUNDER_SIGNER_SOCKET`): the API process holds no keys, only a six-operation socket; a compromised API process can still USE operations at rate, which the audit chain and rate limits bound. The signer itself stays the honest limit: minimal deps, no network, Vault audit trail |

## Deliberate non-goals

No verifiable credentials/selective disclosure, no
cross-vendor federation, no OIB resolution, no multi-tenancy. The GDPR
data-subject rights layer shipped in v1.5: consent enforcement,
org-wide right of access and erasure with signed webhooks, portability
export, and per-scope retention. The self-service privacy portal remains
v2 (it requires citizen authentication - wallet/OTP - outside this layer).
