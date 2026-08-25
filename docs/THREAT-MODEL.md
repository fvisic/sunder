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
| 9 | Availability becomes critical | Stateless service (scale by replicas), Postgres HA (Patroni reference deployment), graceful shutdown, readiness probes | Rate limiter is in-memory per replica by default; set `SUNDER_REDIS_ADDR` for shared counters across replicas (implemented, fail-open or fail-closed) |
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


## Audit content boundary (P2.3 decision)

The audit chain deliberately stores no attribute values and no derived
assertions about a person - only the operation, the actor, the pseudonym
and what was requested. Predicate verifications therefore record
`predicates_asked: ["birthdate age_gte 18"]` and not the boolean result.

Consequence accepted: from the chain alone you cannot reconstruct what a
verifier concluded, only what it was authorised to ask and when. That is
the intended trade-off - the chain is an accountability record, not a
derived-data warehouse, and it is the one store that survives erasure.


## Portal enumeration resistance (P2.5, measured)

The login-start endpoint answers identically for known and unknown
addresses in body, status AND timing. The last part is not free:

- mail delivery is queued to `portal_outbox` and sent by the background
  worker, so no request blocks on a network round-trip;
- the address lookup queries every live key version on both outcomes;
- a **constant-time floor** (40 ms) dominates the remaining difference (the
  hit path does one extra sealed INSERT, about 2 ms, which separated
  perfectly under measurement before the floor was added);
- the route is capped at 5 requests/minute per requester, plus 3 mails per
  address per 15 minutes, and the limiter fails CLOSED here.

`internal/api/portal_hardening_test.go` measures the hit/miss distributions
and fails the build on perfect separation - the property is tested, not
asserted.

## Portal data at rest

The outbox holds a live login token. It is therefore SEALED with the PII
KEK through the crypto engine (AAD-bound like attribute blobs), and the
per-address send throttle is keyed by an HMAC search token, never a bare
hash of the address. A database reader without key access can neither log
in as anyone nor enumerate registered addresses from these tables.


## Audit chain: the cost of linearity (measured 2026-08-24)

The hash chain is linear by construction, and `audit.AppendTx` holds
`pg_advisory_xact_lock` across the appending transaction to keep it that
way. That lock is instance-wide, so audited operations serialize.

Measured on a 12-core server: throughput flattens at roughly 460 audited
operations per second and does not improve past four concurrent clients.
Sampling `pg_locks` under load shows one session inside the append and
every other active session waiting.

**Corrected 2026-08-25.** This section previously attributed the ceiling to
storage commit latency (`fdatasync` at 2,003 ops/sec on that machine). A
scale test at 26.8M contacts disproved that. Group commit amortizes
`fsync` across concurrent committers, and the same storage sustains 4,914
commits/sec once the advisory lock is taken out of an otherwise identical
transaction - a 13.8x difference at 32 concurrent clients. The lock is the
ceiling on its own; storage never was. During that run 117 of 124
active-backend samples sat in `Lock/advisory` against 3 in `IO/WALSync`.
Scale is not a factor either: lookup throughput is flat from 1M to 20M
contacts, and the index probe itself is 0.046 ms of a 4.99 ms request.

This is a deliberate trade, not a defect: the linear chain is what makes
silent tampering detectable, and a lock is what keeps it linear. What
changed in P4.1 is WHEN the chain is built, not whether.

## Audit sealing window (P4.1, default since this change)

`SUNDER_AUDIT_SEALING=async` (the default) takes the chain lock off the
request path: audited operations INSERT rows unsealed (no `hash`,
`prev_hash`, `chain_seq`) and a single sealer chains them in batches,
within roughly `SUNDER_AUDIT_SEAL_DELAY` + `SUNDER_AUDIT_SEAL_INTERVAL`
(2.2s at defaults). The resulting chain is bit-identical to one built
synchronously, and a chain built partly in each mode verifies as one.

**What an attacker gains.** An unsealed row is protected against edits
from birth - the append-only trigger allows exactly one transition,
filling the three seal columns with all hashed content bit-identical, and
nothing else, ever. What the window changes is DELETION: removing an
unsealed row breaks no hash, because the row is not in the chain yet.

- Before P4.1 this exposure existed for exactly one row (the newest;
  deleting the chain tail is invisible to hash verification and is what
  anchoring exists to catch).
- After P4.1 it covers every row in the sealing window: at 4,000 rps and
  default settings, up to roughly 8,000 rows.

**Who can use it.** Deleting the row still requires defeating the
append-only trigger - DBA-level access, the same actor who could already
truncate the tail before anchoring. The fail-closed property is
unchanged in both modes: an operation whose audit INSERT fails does not
happen.

**Mitigations, in order of strength:**

- `SUNDER_AUDIT_SEALING=sync`: the zero-window mode, at the measured
  serialized throughput (~300-460 rps instance-wide). Choose per
  deployment; the switch is restart-only and the server drains the
  backlog before serving when switched to sync (tested in both
  directions).
- `SUNDER_AUDIT_SEAL_EXTERNAL=true` + a split DB role: the API role gets
  INSERT but no UPDATE on `audit`; the `sunder sealer` role gets UPDATE
  on the three seal columns only. A compromised API can then insert lies
  but can never seal them itself nor forge hashes over its own rows -
  STRONGER than the pre-P4.1 single-role setup.
- Shorter `SUNDER_AUDIT_SEAL_INTERVAL`/`DELAY` narrow the window at the
  cost of more sealer transactions.
- The `sunder_audit_unsealed_rows` gauge is the alarm: a stalled sealer
  is an incident, because the window grows without bound while it is
  down. `sunder verify-audit` prints the mode and the pending count on
  every run; pending rows are reported as pending, never as a break.
- Anchoring (M5) stamps only the sealed head, so an anchor never
  vouches for rows the chain cannot yet prove.
