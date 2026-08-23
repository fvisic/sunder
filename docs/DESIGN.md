# Design

Why Sunder exists, what it guarantees, and the reasoning behind the
mechanisms. The API surface is in [API.md](API.md), the component layout in
[ARCHITECTURE.md](ARCHITECTURE.md), the adversary analysis in
[THREAT-MODEL.md](THREAT-MODEL.md).

## 1. The problem

A national identifier (like the Croatian OIB), or a raw email/phone used as
a database key, is a permanent, universal join key. Once it leaks, it is
compromised forever: it cannot be rotated, and it lets any two leaked
databases be joined into a profile. Regulation is moving the same way -
the EU Digital Identity framework (eIDAS 2.0) is built around
relying-party-specific pseudonyms, selective disclosure and data
minimisation.

Sunder applies that principle *inside* one organization: no central party,
no shared identifiers between systems, self-hosted by design. Every
organization runs its own instance and is the identity provider for its
own contacts.

## 2. Identity model

```
             person (real identity - represented only by search tokens)
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
   CID (crm)    CID (billing)  CID (web)     ← one pseudonym per scope
       │
       └──→ OTI ── 5 min, 1 use, 1 audience, 1 purpose
```

- **CID** - a random 128-bit pseudonym, one per `(person, scope)`. A scope
  is an internal domain (crm, billing, analytics, …). Random, never derived
  from PII: there is nothing to reverse or brute-force. Systems key their
  own records by their own scope's CID; only Sunder can map between scopes.
- **OTI** - a PASETO v4.public token (Ed25519; the version pins the
  algorithm, eliminating JWT-style algorithm confusion) bound to one
  purpose and one audience, valid five minutes, single-use enforced by an
  atomic `VALID -> USED` database transition - not just the signature.
  OTIs are the only identity currency systems exchange: the verifier
  receives *its own* scoped CID, the issuer's pseudonym never crosses the
  scope boundary. A handoff shares no attributes by default; the issuer may
  list `share_attributes` to copy specific fields into the verifier's scope
  - the pattern behind delayed actions (escalation e-mails and similar):
  consume the token immediately, fetch the shared attribute just-in-time
  when the delayed action fires, store nothing in between.
- **Search tokens** - keyed HMAC-SHA256 over normalized identifiers
  (Unicode NFKC; email lowercased; phone to E.164), separate keys per
  attribute. A contact can carry several searchable emails and phones (one
  row per token per key version). Plain hashes would allow dictionary
  attacks over the small email/phone space; the key never leaves the
  service. `LOOKUP != AUTHENTICATION`: a lookup hit returns a pseudonym,
  never proves you are talking to that person.
- **Attributes** - AEAD blobs (AES-256-GCM by default, XChaCha20-Poly1305
  selectable via `SUNDER_PII_ALG`) stored **per scope** on the CID row,
  AAD-bound to the CID (no cross-row ciphertext transplant). Per-scope
  storage means dedup onto a shared person never exposes attributes another
  scope stored. Reads are field-level, purpose-checked, consent-checked and
  audited; encryption keys never leave the service.
- **Self-service privacy portal** - citizens authenticate with a
  single-use magic link (delivered by the org's own mailer via a signed
  webhook), see everything every scope stores about them, flip consents,
  and erase with a mandatory second confirmation. No enumeration oracle:
  the start endpoint answers identically for known and unknown addresses.
- **Selective disclosure (predicate claims)** - an OTI can carry
  issuer-authorized predicates (`age_gte`, `exists`) evaluated against the
  issuer's data at verification. The verifier receives booleans; the value
  never crosses the scope boundary. Attribute absence reports
  `known: false`, deliberately distinct from a failed check.
- **Algorithm agility** - each blob records its algorithm (`cids.pii_alg`);
  reads follow the stored value, writes use the configured one, and the
  `keys rekey` sweep converts the backlog. Should the current AEAD ever be
  deprecated, the migration is a config change plus one idempotent sweep -
  no downtime (docs/RUNBOOK-ALG-MIGRATION.md).

## 3. Client model

Every system in the organization is a registered *client* with its own
credential (bearer key, hashed at rest; optional mTLS), a scope, a set of
allowed actions (what it may call) and allowed purposes (why). A
compromised credential is capped by its grants and fully audited. Two
deliberately linkage-capable privileges exist - `scopes.issue` and the
`dsr.*` actions - for trusted integration and privacy-officer tooling only.

## 4. Audit: tamper-evident, then anchored

Every operation writes an audit record (client, action, CID,
purpose/outcome - never attribute values or raw identifiers) **inside the
same transaction** as the operation: the log cannot record what did not
happen, nor miss what did. Records form a hash chain
(`hash_N = SHA-256(canonical(prev_hash, record))`, JSON-array canonical
encoding so field contents cannot shift across boundaries); append-only
triggers block UPDATE/DELETE/TRUNCATE at the database layer.

A bare chain proves internal consistency, not existence-at-a-time - a
privileged attacker could rewrite it consistently. `sunder anchor`
therefore signs the chain head at an RFC 3161 Time Stamp Authority (only a
32-byte digest ever leaves the system) and exports the token as a `.tsr`
file meant for write-once storage **off the database host**; anchors kept
only in the database would be circular. `sunder verify-audit` recomputes
the chain, validates every token offline against a vendored CA, and
cross-checks the export directory - deleted anchor rows are exposed by the
surviving files.

## 5. Key management

Envelope model: a keystore (file driver for pilots, HashiCorp Vault for
production, PKCS#11 stub for HSM demand) holds 32-byte working keys -
HMAC keys per attribute, the PII KEK, the OTI signing seed. The keystore
is **strict**: a missing key is an error, never silently regenerated
(silent regeneration would mask key loss as healthy operation). Material
is created only at bootstrap and rotation, and cached in process memory
(immutable per versioned name).

Rotation is DB-driven: `sunder keys rotate` mints `v(N+1)` and demotes the
previous version to RETIRING. Lookups and OTI verification accept every
live version (dual-key window); rows re-key to the newest version on
touch. `sunder keys retire` is the cure for a leaked key: retired versions
stop matching and stop verifying, and their search-token rows are purged.

### Supply chain

The crypto hot path is Go stdlib only (Ed25519, HMAC, AES-GCM, TLS); the
sole runtime dependency is pgx. A "stdlib first" policy applies - a new
dependency needs justification - because the honest limit of any key
handling is a compromised process reading working keys from RAM: the fewer
third-party lines in that process, the smaller that risk. CI gates on
`govulncheck` and `go vet`; builds are `CGO_ENABLED=0`, images distroless
and non-root.

## 6. GDPR layer

- **Consent** per `(cid, purpose)`: an explicit `granted=false` blocks
  attribute reads and OTI issuance for that purpose; absence of a record
  means the purpose is governed by another legal basis. Enforcement runs
  only after scope-ownership checks, so consent state can never become an
  oracle about foreign CIDs.
- **Right of access / erasure, org-wide**: Sunder is the only component
  that knows which scopes hold a person, so it can orchestrate both. Erase
  wipes every scope's blob, deletes all search tokens, revokes outstanding
  OTIs, tombstones the person (client-side CID references never break) and
  pushes signed webhook events (`X-Sunder-Signature`, HMAC-SHA256) to each
  scope, with audited delivery tracking and a bounded retry queue.
- **Portability** per scope; **retention** TTLs keyed on last activity;
  audit rows are never pruned - the chain and its anchors are the tamper
  evidence.

## 7. Performance targets

Reference targets (measured by `loadtest/` and `benchmark/`): p99 under
1,000 rps on one node - OTI verify < 10 ms, attribute read / lookup
< 15 ms, OTI issue < 20 ms. The hot paths are single indexed point queries
(an HMAC token is an exact match); at 200M contacts the working set
(~90–100 GB of tokens and indexes) fits in RAM on one 128–256 GB server.
Laptop numbers in the repo are indicative; contractual numbers come from a
reference deployment (service replicas behind a load balancer, PostgreSQL
primary + sync standby, PgBouncer).

## 8. SDK design rules

One canonical interface, defined once and implemented identically in
TypeScript, Python, PHP, Java and .NET: same method names, same error
taxonomy (mapped from the JSON `error` field first, then HTTP status;
network failures are `ServiceUnavailable` with code `service_unavailable`
everywhere), same retry policy (lookups and OTI issue retry once on
5xx/network; **OTI verify is never blind-retried** - a retry after an
ambiguous failure would legitimately return `token_used`). SDKs contain
zero cryptography: they are ~500-line transport clients, so nothing
security-critical exists in five copies.

## 9. Deliberate non-goals

No central or multi-tenant deployment (a multi-tenant instance holding CID
mappings for many companies would recreate the super-target this design
eliminates - small operators should get *managed single-tenant*
instances). No verifiable credentials / selective disclosure yet, no
cross-organization federation, no national-identifier storage or
resolution - the schema has no column for one, by design.
