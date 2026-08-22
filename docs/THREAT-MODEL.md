# Threat Model

Maps the twelve weaknesses identified in the design phase (docs/PLAN.md and
its source analysis) to Sunder's concrete mitigations, plus residual risk.
Section numbers reference docs/PLAN.md.

| # | Threat | Mitigation in Sunder | Residual risk |
|---|---|---|---|
| 1 | Central identity provider becomes a super-target | No central party exists: one instance per organization (PLAN §1); scoped CIDs are unlinkable across organizations by construction | The instance is still the org's crown jewel — harden per §9 |
| 2 | HMAC lookup mistaken for anonymization; stolen key regenerates tokens | Keyed HMAC per attribute, material outside the DB (keystore; Vault driver), strict no-mint keystore, dual-key rotation (`sunder keys rotate`), re-key on touch | KEK compromise: rotate + re-key; keys in RAM are readable by a compromised process (see §8.1 supply-chain policy) |
| 3 | Lookup API enables enumeration (dialing numbers to see what exists) | Per-client sliding-window rate limits (429), miss counter + enumeration warning at 100 misses/10 min, every lookup audited, `LOOKUP != AUTHENTICATION` doctrine | A patient attacker under the limit; alerting must be watched |
| 4 | Name matches too many people | Name alone rejected (400); name is only a narrowing key beside email/phone | — |
| 5 | Social engineering of staff | Out of technical scope; audit chain makes every employee lookup attributable and tamper-evident, which deters and proves | Process controls remain the org's job |
| 6 | CID becomes the new internal OIB | CIDs are per-scope; a client only ever sees its own scope; attributes are per-scope blobs; `scopes.issue` is an explicit, audited, sparingly-granted privilege | An org granting `scopes.issue` to everything recreates the problem — documentation warns |
| 7 | Migration is enormous | Wedge strategy (PLAN §13.4): one read-path integration first; SDKs + conformance suite keep per-system cost constant | Organizational, not technical |
| 8 | Legacy systems re-import the national identifier | No OIB column exists anywhere; the service never accepts or returns one | A client system storing OIB beside the CID is outside Sunder's reach — pilot checklist item |
| 9 | Availability becomes critical | Stateless service (scale by replicas), Postgres HA (Patroni reference deploy §9.2), graceful shutdown, readiness probes | Rate limiter is in-memory per replica in v1 (documented; Redis interface planned) |
| 10 | Privacy could worsen (central operator sees usage) | Self-hosted: the operator IS the organization; no third party in any flow; TSA anchoring leaks only a 32-byte digest | — |
| 11 | One-time tokens cannot replace stable business identity | Both exist: CID (stable, per-scope) + OTI (5 min, single-use, purpose- and audience-bound, atomic VALID->USED) | — |
| 12 | The system silently degrades into "OIB 2.0" | Random CIDs (nothing derivable), per-scope unlinkability, OTIs as the only inter-system currency, tamper-evident audit anchored to an external TSA | Governance: reviewing client grants stays a human duty |

## Attacker matrix

| Adversary | What they get | What stops them |
|---|---|---|
| Stolen client DB (e.g. CRM dump) | CIDs + the attributes that scope stored; no OIB, no search keys, unjoinable with other scopes | Scoped CIDs; per-scope AAD-bound blobs; HMAC-only search columns |
| Stolen Sunder DB, no keys | HMAC tokens (keyed — no dictionary attacks), encrypted blobs, audit chain | Keys live outside the DB (keystore/Vault) |
| Stolen bearer credential | Only that client's actions/purposes/rate, fully audited | `allowed_actions`/`allowed_purposes`, rate limits, enumeration detection |
| Network attacker replaying an OTI | Nothing: single-use CAS, 5-minute TTL, audience+purpose binding | Atomic VALID->USED; PASETO v4 signature |
| Insider/DBA rewriting history | Chain break at a provable position; full-chain rewrite leaves orphaned TSA anchors | Hash chain + append-only triggers + RFC 3161 anchoring (`sunder verify-audit -ca ...`) |
| Compromised service process | Working keys in RAM — game over for that instance's crypto | The honest limit: minimize dependencies (§8.1), consider process split (v2), Vault audit trail for key access |

## Deliberate non-goals (v1)

Documented in PLAN §12: no verifiable credentials/selective disclosure, no
cross-vendor federation, no OIB resolution, no multi-tenancy. GDPR
data-subject rights layer lands in v1.5 (PLAN §14).
