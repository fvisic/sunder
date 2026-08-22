# CID/OTI Identity Provider — Prototype Plan

Based on the concept in `uvod.txt`, with one deliberate deviation:
**there is no central national Identity Provider.** Each vendor (organization)
runs its **own instance** of this microservice and is the identity provider
for its own contacts/contracts. The service is a product every client can
deploy, not shared infrastructure.

## 1. Why per-vendor instances (the twist)

- Removes weakness #1 from `uvod.txt` (central IdP as a "super-target"):
  there is no single database that links CIDs across organizations.
- Breach containment: compromising vendor A's instance yields only
  A-scoped pseudonyms, useless anywhere else.
- Data sovereignty: each vendor owns its keys, its storage, its audit trail.
- Trade-off accepted for v1: no cross-vendor identity verification or
  national attribute proofs (age >= 18 etc.). That becomes a v2 federation
  layer on top; the API is designed so it can be added without breaking changes.

## 2. Goals

| Goal | Concrete target |
|---|---|
| Ultra secure | No raw PII in lookup paths; per-purpose HMAC keys; signed single-use tokens; replay-proof; append-only audit; no PII in logs |
| Fast | p99: OTI verify < 10 ms, OTI issue < 20 ms, lookup < 15 ms, at 1,000 RPS on one node |
| Easy to adopt | One Docker container + one database; single config file; OpenAPI spec; thin SDKs; demo integration app; < 1 day to first integration |

## 3. Core objects

### CID — Contact ID (stable pseudonym)
- Random 128-bit value, base32-encoded (e.g. `CID-9F72A81C...`).
- **Random, not derived from PII** — nothing to reverse or brute-force.
- Scoped: one CID per `(contact, scope)` pair. `scope` defaults to the whole
  organization, but a vendor can issue separate CIDs per internal domain
  (CRM vs. billing vs. analytics) to prevent the "CID becomes the new OIB
  inside the company" failure mode (weakness #6 in `uvod.txt`).

### OTI — One-Time Identifier
- PASETO v4.public token signed with Ed25519 (alternative: JWT EdDSA if
  client-ecosystem support matters more).
- Claims: `jti`, `cid`, `purpose`, `audience`, `iat`, `exp` (max 5 minutes).
- Single use enforced server-side: atomic `VALID -> USED` state transition
  in the database (compare-and-set), not just signature checking.
- Verification requires the caller to state expected `audience` and
  `purpose`; mismatch = invalid even if the signature is good.

### Search tokens (lookup without PII)
- `email_token = HMAC-SHA256(K_email, normalize(email))`
- `phone_token = HMAC-SHA256(K_phone, normalize(phone))` (E.164)
- `name_token` used only to *narrow* results, never as a unique key.
- Separate keys per attribute and per purpose; keys held outside the DB
  (env/file in prototype, KMS/HSM interface stubbed for production).
- Dual-key rotation window (old + new key both accepted during rotation).

## 4. Architecture

```
 vendor's apps (CRM, billing, web, call-center UI)
        │  mTLS / per-app API key
        ▼
 ┌─────────────────────────────┐
 │  cid-provider (one binary)  │
 │  ├─ REST API (JSON)         │
 │  ├─ crypto core (Ed25519,   │
 │  │   HMAC, AES-GCM for PII) │
 │  ├─ rate limiter + anomaly  │
 │  │   detection (enumeration)│
 │  └─ hash-chained audit log  │
 └──────────────┬──────────────┘
                ▼
        PostgreSQL (v1: Postgres only — D6;
        demo via docker-compose)
```

- **Language: Go** (confirmed — decision D1, section 15). Single static
  binary (~15 MB), no runtime dependencies, first-class crypto stdlib,
  trivial Docker image, excellent p99 latency.
- Stateless service; all state in the DB → horizontal scaling is "run more
  replicas", HA story stays simple for clients.
- OTI verify hot path: single indexed CAS update, no joins — this is what
  makes the p99 < 10 ms target realistic.

## 5. API surface (v1)

| Endpoint | Purpose |
|---|---|
| `POST /v1/contacts` | Register/import a contact → `{cid}`; optional encrypted PII blob |
| `POST /v1/contacts/{cid}/scopes` | Issue an additional scoped CID for the same contact |
| `GET /v1/contacts/{cid}/attributes/{name}` | Field-level attribute fetch, `purpose` required (D4): the provider decrypts server-side, checks the caller's `allowed_purposes`, returns **only** the requested field; decryption keys never leave the provider; every fetch audited |
| `POST /v1/lookup` | `{email}` or `{phone}` or `{name + second factor}` → `{cid}` |
| `POST /v1/oti` | `{cid, purpose, audience}` → `{token, expires_at}` |
| `POST /v1/oti/verify` | `{token, audience, purpose}` → `{cid, status}`; marks USED atomically |
| `GET /healthz`, `GET /metrics` | Liveness + Prometheus metrics |
| `POST /v1/admin/keys/rotate` | Rotate HMAC/signing keys (admin-authenticated) |

Rules baked into the API (from the weaknesses list in `uvod.txt`):
- **LOOKUP ≠ AUTHENTICATION** — lookup returns a CID, never asserts identity.
- Name-only lookup is rejected; name requires a second factor (phone/email).
- All lookups are rate-limited per client app and audited; a mass-lookup
  detector (sliding-window counter per client) raises an alert and can
  auto-throttle (mitigates phone-number enumeration, weakness #3).

## 6. Inter-system OTI handoff (the pattern that makes it org-wide)

The provider serves **all** systems in the organization — web, mobile, ERP,
CRM, billing, DWH, marketing, ticketing, internal tools — not just
customer-facing ones. Systems never exchange identity data directly: no
email, no OIB, and not even their own CIDs. The **only identity currency
between systems is the OTI**; each system works internally with its own
scoped CID.

```
 system A (e.g. web shop)          cid-provider                system B (e.g. ERP)
    │                                    │                          │
    │ 1. POST /v1/oti                    │                          │
    │    {cid: CID-WEB-x,                │                          │
    │     purpose: create_order,         │                          │
    │     audience: erp}                 │                          │
    │◄── token (5 min, single use) ──────│                          │
    │                                    │                          │
    │ 2. business payload + token ──────────────────────────────────►
    │                                    │                          │
    │                                    │◄── 3. POST /v1/oti/verify│
    │                                    │    {token, audience: erp,│
    │                                    │     purpose: create_order}
    │                                    │─── {cid: CID-ERP-y} ────►│
    │                                    │   (atomic VALID -> USED) │
```

1. System A holds only its own scoped CID for the person.
2. A requests an OTI bound to a specific `purpose` and `audience` (system B).
3. A sends the business payload plus the token to B over any channel
   (API call, queue, event).
4. B verifies the token; the provider checks signature, expiry, audience
   and purpose, atomically marks it USED, and returns **B's own scoped
   CID** for the same person.
5. B continues entirely within its own scope.

Properties this guarantees:

- **CIDs never cross scope boundaries** — the provider is the only component
  that can map CID-WEB-x to CID-ERP-y. A leak of any one system's database
  is unjoinable with any other.
- **A stolen token is worthless**: 5-minute TTL, single use, bound to one
  audience and one purpose. Replay or redirection to another system fails
  verification.
- **Constant integration cost**: every system-to-system integration in the
  organization (web -> ERP, CRM -> billing, ERP -> DWH, ...) follows this
  one pattern. Onboarding a new system = one `clients` row + the SDK.
- **Purpose-scoped authorization caps blast radius**: `allowed_purposes`
  per client means e.g. DWH may call `verify` but never `lookup`; a
  compromised credential can only do what its purposes allow, and
  everything it does is in the hash-chained audit log.

## 7. Data model

```
contacts  (cid PK, scope, email_token IDX, phone_token IDX, name_token,
           pii_encrypted BYTEA NULL, created_at)
oti       (jti PK, cid FK, purpose, audience, expires_at,
           status VALID|USED|EXPIRED, used_at, used_by)
clients   (client_id PK, name, key_hash, allowed_purposes[], rate_limit)
audit     (seq PK, ts, client_id, action, cid NULL, detail,
           prev_hash, hash)          -- hash-chained, append-only
keys      (key_id PK, kind email|phone|name|signing, status ACTIVE|RETIRING,
           created_at)               -- key material itself lives outside DB
audit_anchor (id PK, root_hash, tsa_url, stamped_at, tsr BLOB)
                                     -- RFC 3161 token over the chain head (8.2)
```

Notes:
- The service can run **PII-free**: `pii_encrypted` is optional; a vendor may
  keep PII only in its existing CRM and store nothing but tokens here.
- **OIB is never stored** in the prototype, in any column. If a legal process
  requires OIB↔CID resolution later, that is a separate, heavily-audited
  component — explicitly out of scope for v1 (avoids weakness #8).

## 8. Security controls checklist

- [ ] mTLS or per-app bearer keys between vendor apps and the service
- [ ] Input normalization before hashing (lowercase email, E.164 phone)
- [ ] Constant-time comparisons for all token/key checks
- [ ] Per-purpose, per-attribute HMAC keys; rotation with dual-key window
- [ ] OTI single-use via atomic DB compare-and-set (no TOCTOU)
- [ ] Rate limiting + enumeration detection + alerting on lookup
- [ ] Hash-chained audit log with daily RFC 3161 anchoring (see 8.2);
      no PII and no raw tokens in logs
- [ ] AES-256-GCM for the optional PII blob; key outside the DB
- [ ] Threat-model review mapped 1:1 against the 12 weaknesses in `uvod.txt`

### 8.1 Supply-chain security (Go dependency policy)

Why Go keeps this risk structurally low for this service:

- **The crypto core needs zero third-party packages.** Ed25519, HMAC-SHA256,
  AES-GCM, TLS/mTLS and constant-time comparison all live in the stdlib
  (`crypto/*`), maintained by the Go team. The hot path (HMAC lookup,
  OTI sign/verify) is 100% stdlib.
- **No classic supply-chain vectors**: Go modules have no install scripts
  (no npm `postinstall`-style attacks); `go.sum` plus the public checksum
  database (transparency log) make silent replacement of a published
  module version detectable by everyone.
- **Minimal Version Selection**: Go resolves the *minimum* satisfying
  version, never auto-pulls a freshly published (possibly compromised)
  release — new versions enter only on an explicit, reviewed upgrade.
- **Small footprint**: expected ~10-15 direct dependencies (pgx, router,
  Redis client, PASETO lib, Prometheus client, Vault client),
  ~50-100 transitive. A comparable Node service carries 1000+.
- **`govulncheck` is call-graph aware** — it reports only vulnerabilities
  in code paths the binary actually reaches, so warnings get read.

Residual risks and their mitigations:

| Risk | Mitigation |
|---|---|
| CVE in the Go stdlib/runtime (e.g. HTTP/2 Rapid Reset) | track Go patch releases; rebuild + redeploy is trivial with one static binary |
| Vulnerability in a used package (pgx, PASETO lib) | `govulncheck` gate in CI; PASETO itself removes the JWT "alg confusion" class |
| Malicious new version / typosquatting on upgrade | Renovate/Dependabot with mandatory human review of diffs — never auto-merge |
| CGO dependencies weaken guarantees | `CGO_ENABLED=0` everywhere; the only exception is the `pkcs11` keystore driver, kept isolated |
| **Malicious code inside the process reads working keys from RAM** | the worst case, and no scanner helps: enforce a "stdlib first" policy for the crypto core, review every upgrade; v2 option — split signing into a separate small process with a narrow IPC boundary |

CI/build controls:

- [ ] `govulncheck` + `go vet` as blocking CI gates
- [ ] `-mod=readonly` builds; pinned versions; `go.sum` committed
- [ ] `CGO_ENABLED=0`; distroless/scratch image, no shell, non-root
- [ ] SBOM per release + signed releases (see section 13.3)
- [ ] "stdlib first" dependency policy: a new dependency requires
      justification in the PR description

### 8.2 Tamper-evident audit: hash chain + RFC 3161 anchoring

The pattern is already proven in the author's BarkWatch project (forensic
hash chain over evidence + trusted timestamping); adopted here for the
audit log:

- **Chain**: `hash_N = SHA-256(prev_hash || canonical(record))` over the
  append-only `audit` table. Unlike a file-set chain, audit events are
  never recomputed — there is no rebuild/DELETE path; any edit, deletion
  or insertion breaks the chain at a provable position.
- **External anchoring (RFC 3161)**: a daily job sends the current chain
  head to a Time Stamp Authority, which cryptographically signs it —
  proof the log existed in exactly this form on that date. Default TSA:
  freetsa.org (free); enterprise deployments point the config at an
  internal or qualified TSA. The signed token is stored in `audit_anchor`
  (and optionally exported as a `.tsr` file to write-once storage).
  **Only the 32-byte digest ever leaves the system** — no audit content,
  no PII.
- **Offline verification**: `cid-provider verify-audit` recomputes the
  whole chain and validates every anchor token against a vendored TSA
  root CA — no network needed, works in front of an auditor or court.
  Output pinpoints exactly where a break occurs and why (record changed
  vs. chain mismatch vs. anchor mismatch).
- **Guarantee achieved**: rewriting history now requires compromising
  both the database *and* every previously issued TSA token — silent
  tampering by an insider or DBA becomes provable. This closes the gap
  that a bare hash chain leaves (full-chain rewrite by someone with DB
  access).
- **Signed documents (optional, same toolbox)**: DSR exports
  (section 14) and the pilot sign-off report (section 13.4) can be
  issued as PAdES-signed PDFs — self-signed cert for the prototype,
  CA-issued/qualified certificate in production with no code change.

Data model addition (section 7): `audit_anchor (id PK, root_hash,
tsa_url, stamped_at, tsr BLOB)`.

## 9. Deployment sizing & key management (200M contacts, lookup < 10 ms)

### 9.1 Why the target is achievable

Lookup is an exact-match point query (32-byte HMAC token -> indexed row),
not a search over PII. At 200M contacts: `contacts` table ~40-50 GB, three
token indexes ~35-40 GB -> working set ~90-100 GB, which fits in RAM on a
single 128-256 GB server. A B-tree over 200M rows has depth ~4; a point
lookup served from RAM is < 1 ms in the database.

Latency budget: LB + TLS ~1 ms, HMAC computation ~µs, PgBouncer + PG point
lookup 1-3 ms warm -> p99 < 10 ms with headroom. Read replicas are added
only if lookup RPS outgrows one node.

### 9.2 Reference deployment (per vendor)

| # | Component | Role | Notes |
|---|---|---|---|
| 1 | `cid-provider` x 2-3 replicas | application tier | stateless, behind the LB |
| 2 | Load balancer (HAProxy / nginx / k8s ingress) | routing, TLS termination or mTLS passthrough | ~1 ms of the budget |
| 3 | PostgreSQL 16 primary + sync standby (Patroni) | source of truth | NVMe, 128-256 GB RAM, `shared_buffers` ~25% RAM; hash-partitioning of `contacts` optional (maintenance, not performance) |
| 4 | PgBouncer (transaction pooling) | keeps latency stable under thousands of connections | without it, p99 degrades first |
| 5 | Redis (or Dragonfly) | shared counters; see below | one small cluster |
| 6 | Prometheus + Grafana | p99 measurement per endpoint | targets are guesses without it |

Redis usage policy:

- **Yes**: rate-limiting and enumeration-detection counters (sliding windows
  must be shared across service replicas — the strongest reason Redis
  exists here), and optionally the OTI replay cache if verify RPS outgrows
  the Postgres CAS.
- **Cautiously**: caching lookup results (`token -> cid`). The mapping is
  near-immutable, so a 60 s TTL cache is safe — but **start without it**;
  a well-indexed Postgres with indexes in RAM holds p99 < 10 ms on its own.
  Add the cache only if the k6 benchmark (M6) proves it necessary. Fewer
  moving parts = easier client deployment.
- **Never**: caching PII, and caching *negative* lookups (it helps an
  attacker enumerate what exists).

### 9.3 Key management (envelope encryption; HSM off the hot path)

An HMAC operation inside an HSM costs 1-5 ms with limited throughput — at
thousands of lookups per second it destroys p99. The HSM/KMS therefore
protects the **root key (KEK)** only; working keys live in service memory:

```
        KMS / HSM  (root key / KEK — never leaves it)
              │  unwrap once at service startup
              ▼
   working keys in cid-provider RAM:
   K_email, K_phone, K_name   (HMAC search)
   Ed25519 signing key        (OTI signatures)
   AES-256-GCM KEK for per-record PII DEKs
```

- Working keys exist on disk/DB **only as KEK-wrapped blobs**; at startup
  the service authenticates to the KMS, unwraps them, holds them in
  `mlock`-ed memory, and zeroizes on shutdown. The `keys` table stores
  metadata only (key_id, kind, status) — never material.
- Rotation: dual-key window (already in the plan). Rotating an HMAC search
  key implies a batch re-HMAC of 200M values — rotate per-attribute keys
  rarely and deliberately. KEK compromise != HMAC key compromise and
  vice versa.
- Ed25519: OTI signing stays in RAM as above; signing inside the HSM is
  feasible for stricter clients (signing RPS << verify RPS), and verify
  needs only the public key.

### 9.4 Keystore backends (config choice, no code change)

The service exposes a thin `keystore` interface with three drivers,
selected in the config file:

| Driver | Environment | Backing |
|---|---|---|
| `file` | dev/prototype | env/file keys, SoftHSM |
| `vault` | production default | HashiCorp Vault (or OpenBao) Transit engine, 3-node Raft, auto-unseal |
| `pkcs11` | compliance-heavy clients | physical HSM behind Vault or direct: Thales Luna / Utimaco (enterprise), YubiHSM 2 (~700 EUR, small clients); cloud: AWS KMS/CloudHSM, Azure Key Vault Managed HSM, GCP Cloud KMS |

## 10. Client SDKs (TypeScript, Python, Java, PHP, .NET)

Goal: a developer in any of these languages integrates with **minimal
adaptation** — every SDK exposes the same interface with the same method
names, semantics, errors and defaults; only the syntax is idiomatic to
the language.

### 10.1 One canonical interface

Defined once, language-neutrally (IDL-style); every SDK implements exactly
this — an intersection, no language gets extra methods:

```
interface CidProviderClient {

    // contacts
    registerContact(attributes, options?)      -> { cid }
    issueScopedCid(cid, scope)                 -> { cid }

    // lookup  (LOOKUP != AUTHENTICATION)
    lookupByEmail(email)                       -> { cid } | NotFound
    lookupByPhone(phone)                       -> { cid } | NotFound
    lookupByName(name, secondFactor)           -> { cid } | NotFound | Ambiguous

    // attributes (field-level, purpose-checked; D4)
    getAttribute(cid, name, purpose)           -> { value } | NotFound
                                                          | PurposeNotAllowed

    // OTI
    issueOti(cid, purpose, audience)           -> { token, expiresAt }
    verifyOti(token, purpose, audience)        -> { cid } | TokenInvalid
                                                          | TokenExpired
                                                          | TokenUsed
                                                          | AudienceMismatch
    // ops
    health()                                   -> { status }
}
```

Unified error taxonomy across all languages: `NotFound`, `Ambiguous`,
`Unauthorized`, `PurposeNotAllowed`, `RateLimited`, `TokenInvalid`,
`TokenExpired`, `TokenUsed`, `AudienceMismatch`, `ServiceUnavailable` —
mapped to idiomatic exceptions (Python/Java/PHP/.NET) or typed results (TS),
but with identical names and identical trigger conditions.

### 10.2 Design rules that keep adaptation minimal

- **Zero cryptography in SDKs.** HMAC, normalization, signing and
  verification all happen server-side. Each SDK is a thin client
  (~500 lines): transport, auth, timeouts, retries, error mapping.
  Nothing security-critical exists per-language, so nothing
  security-critical needs a per-language audit.
- **Spec-first**: the OpenAPI document is the source of truth. The
  transport layer is generated from it; the handwritten part is only the
  thin facade above. An API change regenerates all five SDKs.
- **Identical configuration everywhere**: same env var names
  (`CIDP_URL`, `CIDP_CLIENT_ID`, `CIDP_CLIENT_KEY`, `CIDP_TLS_*`),
  same defaults (timeouts, retry counts) in every language.
- **Per-endpoint retry policy baked in**: `lookup*` and `issueOti` are
  safely retryable; `verifyOti` is **never blind-retried** (single-use
  token — a retry after an ambiguous network failure would legitimately
  return `TokenUsed`; the SDK surfaces that distinctly so the caller can
  decide).
- **Shared conformance suite**: one language-neutral set of JSON test
  vectors + a mock server; every SDK must pass it in CI before release.
  This is what guarantees "same behavior", not code review.
- **Identical quickstart**: the same ~20-line example (register ->
  lookup -> issue OTI -> verify) ported 1:1 to each language.

### 10.3 Distribution & versioning

| Language | Registry | Package |
|---|---|---|
| TypeScript | npm | `@<org>/cid-provider` |
| Python | PyPI | `cid-provider` |
| Java | Maven Central | `<org>:cid-provider` |
| PHP | Packagist | `<org>/cid-provider` |
| .NET (C#) | NuGet | `<Org>.CidProvider` — one package covers C#, F# and VB.NET; targets `netstandard2.0` + current `net8.0`+ for maximum reach |

Lockstep semver with the API: SDK major version = API version (`v1.x`
SDKs speak `/v1/*`). Release order for the prototype: TypeScript + Python
first (M6), Java + PHP + .NET after the conformance suite is stable.

## 11. Milestones

| # | Deliverable | Est. |
|---|---|---|
| M1 | Repo skeleton: config, healthz, migrations, CI, Docker | 1 day |
| M2 | CID core: contact registration, scoped CID issuance, encrypted PII blob + field-level attribute serving (purpose-checked, audited — D4) | 2–3 days |
| M3 | Lookup: HMAC search tokens, normalization, name-narrowing rules, rate limits | 1–2 days |
| M4 | OTI: issue + verify, replay protection, key management + rotation | 2 days |
| M5 | Hardening: audit chain, enumeration detection, per-app authn, threat-model pass | 2 days |
| M6 | DX: docker-compose, OpenAPI spec, first SDKs per section 10 (TypeScript + Python) with conformance suite, demo CRM app, k6 load test proving the latency targets | 2 days |

Total: ~2 weeks of focused work for a demonstrable, benchmarked prototype.

## 12. Non-goals for v1 (explicit)

- Verifiable credentials / selective disclosure (`AGE >= 18`) — v2.
- Cross-vendor federation and national IdP / EU Digital Identity Wallet
  integration — v2 (API shaped so it can plug in later).
- OIB storage or OIB↔CID resolution — deliberately excluded.
- Multi-tenant SaaS mode — v1 is strictly one instance per vendor
  (deliberate; see 12.1).

### 12.1 Multi-tenancy: deliberate decision, not a gap

Scoped CIDs and per-system credentials are **not** multi-tenancy under
another name — they are different axes:

- **Our scopes/clients** = separation *within one organization*: one data
  owner, one database, one master-key set, one audit. Scopes provide
  unlinkability and blast-radius capping between internal systems.
- **Multi-tenancy** (Databunker Pro: Postgres RLS) = multiple
  *independent organizations* sharing one deployed instance, hard-isolated
  from each other. A business model, not an internal security refinement.

Decision: **no true multi-tenant mode**, for a reason rooted in section 1 —
a multi-tenant instance holding CID mappings for many companies recreates
weakness #1 from `uvod.txt` (the central super-target) at the operator
level, and undermines the core pitch ("your keys, your instance, your
jurisdiction"). Wedge customers (banks, telecoms) would never share an
instance anyway.

The real demand behind "multi-tenant" — small clients who cannot operate
the Patroni + Vault stack — is served by **managed single-tenant**
instead: automated provisioning of a dedicated instance per customer
(Kubernetes operator or compose template; the deployment is already
"one container + one database", section 9), each with its own database
and its own keys. SaaS economics, intact isolation story.

If hosting partners/MSPs ever justify RLS-style multi-tenancy
commercially, it is a natural **paid feature** under the open-core option
(section 13.2) — exactly where Databunker prices it — and then mandatory:
per-tenant KEK, row-level security, tenant id in every audit record.

## 13. Going public: open-source licensing & visibility

Two goals: (a) the author becomes publicly known as the one offering the
solution, (b) the code is genuinely open source.

### 13.1 Recommended license: Apache-2.0

Rationale, specific to this project:

- **Target adopters are banks, telecoms, insurers** — their legal
  departments routinely approve Apache-2.0 and routinely block AGPL.
  A copyleft license would suppress adoption in exactly the audience
  that creates the reputation.
- **Explicit patent grant** (MIT lacks one) — important for a security
  product; adopters get protection from patent claims by contributors.
- **NOTICE file attribution survives forks**: every redistribution must
  carry the NOTICE file — put the author's name and project origin there.
  This is the license-level mechanism for goal (a).
- Standard for comparable infrastructure (Kubernetes, Keycloak, OpenBao).

### 13.2 Alternative: AGPL-3.0 + commercial dual license

Choose this instead **only** if the business model is selling commercial
licenses or a hosted version: AGPL forces SaaS competitors to open their
changes, and enterprises that refuse AGPL buy the commercial license.
Requires a CLA from day one (the author must retain relicensing rights).
Trade-off: significantly slower adoption. Decide before the first public
release — relicensing later requires consent of every contributor.

Avoid: MIT (no patent grant, no NOTICE mechanism), BUSL/SSPL (not open
source by OSI definition — undermines goal (b) and public trust in a
security product).

### 13.3 Visibility & trust package (what actually builds the reputation)

- **Name as trademark**: the license does not protect the project name.
  Pick a distinctive name, claim it (domain, GitHub org), state trademark
  policy in the README. Forks may take the code, not the name.
- **Copyright line + NOTICE**: `Copyright (c) <year> <author>` in NOTICE
  and file headers.
- **Security credibility artifacts**: SECURITY.md with responsible
  disclosure policy, signed releases (Sigstore/cosign), SBOM per release,
  reproducible builds, public threat model (reuse section 8 + `uvod.txt`
  mapping).
- **Whitepaper**: publish the concept (this plan, sections 1-6) as a
  standalone paper/blog post under the author's name — the concept, not
  just the repo, is what gets cited.
- **DCO** (Developer Certificate of Origin) for contributions if
  Apache-2.0; **CLA** if the dual-license route is taken.

### 13.4 Adoption wedge: "OIB out of the call-center/CRM lookup in 30 days"

Do not sell the whole architecture first. The first offering targets one
painful, measurable use case: **replace PII-keyed customer lookup (OIB /
email / phone as search keys) in the call center and CRM with CID +
HMAC lookup**, in a 30-day pilot.

Why this wedge specifically:

- **Highest breach exposure**: the CRM customer table, searchable by every
  agent, is exactly what leaks in real incidents.
- **Lowest integration depth**: it touches only the read/search path —
  no billing, ERP, or accounting changes; the SDK (section 10) and the
  lookup endpoint (section 5) cover it entirely.
- **Measurable result**: after cutover, a stolen CRM database contains no
  OIB and no searchable PII keys, and every employee lookup is in the
  hash-chained audit log (insider deterrence as a bonus).
- **Demo-able**: fits the M6 demo scenario one-to-one.

30-day pilot playbook:

| Week | Step |
|---|---|
| 1 | Batch import: tokenize existing contacts (HMAC email/phone), issue CIDs; CRM runs unchanged (dual-run) |
| 2 | Integrate the agent lookup UI via SDK; shadow mode — both paths answer, results compared |
| 3 | Shadow-mode review: latency report vs. the 10 ms target, audit-log review, enumeration alerts live |
| 4 | Cutover: PII search keys dropped from the CRM search index, OIB column quarantined; sign-off report |

Success metrics (contractual, not aspirational): zero raw PII search keys
in the CRM database; p99 lookup within target; 100% of lookups audited;
enumeration detection active.

Expansion path after the wedge: first OTI handoff to the next system
(billing — section 6 pattern), then org-wide rollout system by system.

Positioning language (important): the product is **"designed in line with
eIDAS 2.0 / EUDI Wallet principles"** (relying-party-specific pseudonyms,
selective disclosure, data minimisation) — never "eIDAS compliant" or
"certified". Compliance and certification apply to wallet providers and
relying parties under the implementing acts; this service is neither. The
sales narrative uses the December 2026 member-state wallet deadline as the
regulatory tailwind: organizations that adopt CID/OTI now are structurally
ready for wallet integration (v2).

### 13.5 Competitive comparison: Databunker

Databunker (github.com/securitybunker/databunker) is the closest existing
open-source project: MIT-licensed, written in Go, self-hosted, REST API,
Docker deployment, MySQL/PostgreSQL backends, ~1.5k stars. It is a
**PII vault**: encrypted storage (AES-256) of personal records, UUID
tokenization, hash-based lookup indexes (email/phone/login), audit
logging, bulk retrieval disabled by default, and strong GDPR data-subject
tooling (consent management, right of access / erasure / portability).
Pro (commercial) adds multi-tenancy via Postgres row-level security and
tamper-evident audit.

Where the concepts genuinely overlap — and where this plan differs:

| Dimension | Databunker | This plan |
|---|---|---|
| Category | PII **storage** vault: "put the data here, reference it by token" | **Identity decoupling layer**: systems keep working, but share no linkable identifiers |
| Pseudonym model | One UUID token per user record — effectively global within the org | **Scoped CIDs** per internal domain (section 3): CRM/billing/DWH leaks are mutually unjoinable |
| Inter-system handoff | Not a concept; systems share the same user token | **OTI** (section 6): signed, purpose- and audience-bound, atomically single-use — the only identity currency between systems |
| Lookup hardening | Documented as "hash-based indexing" | Keyed **HMAC** with per-attribute keys held in KMS, dual-key rotation, enumeration detection, per-client rate limits, LOOKUP != AUTHENTICATION doctrine |
| Key management | KMS/HSM integration not publicly documented | Envelope encryption with `file`/`vault`/`pkcs11` keystore drivers (section 9.3) |
| Client authorization | Role-based access control | Per-system `allowed_purposes` capping blast radius of one compromised credential |
| Performance | No public benchmarks | Explicit p99 targets + 200M-contact sizing, proven by k6 in M6 |
| GDPR data-subject rights | **Strong — consent, access, erasure, portability out of the box** | Not in v1 (honest gap — see below) |
| Sessions / field masking | Built in | Out of scope |

Consequences for this plan:

- **Differentiation to lead with** (whitepaper, README): scoped pseudonyms
  + OTI handoff. Databunker protects the data *at rest in one vault*;
  this plan removes the *linkability of identifiers between systems* —
  a breach-blast-radius argument Databunker does not make.
- **Steal the good ideas**: bulk-retrieval-denied-by-default is worth
  adopting in v1 (add to section 8 checklist mentally: `lookup` never
  returns lists, admin export is a separate audited privilege). Consent
  management and data-subject-rights endpoints (access/erasure/
  portability per CID) are the strongest v2 candidates — they turn the
  GDPR story from "aligned" into "operationally useful".
- **Do not compete on vault storage**: Databunker already does encrypted
  PII storage well and free. This plan's optional `pii_encrypted` blob
  stays optional; the pitch is the identity layer, not the storage.

## 14. GDPR & data-subject rights layer (v1.5 scope)

Adopted from the vault ecosystem (Databunker's strongest area — see 13.5),
legally unproblematic: features and ideas carry no license constraints,
and even direct MIT code reuse is Apache-2.0-compatible (retain their
copyright + MIT text in `THIRD-PARTY-NOTICES`). In practice this is a
clean-room reimplementation — their global-UUID model doesn't fit our
scoped-CID architecture anyway. Fair attribution ("inspired by
Databunker's DSR model") in the README is good practice.

### 14.1 The architectural advantage to exploit

Databunker executes data-subject rights over data *inside its own vault*.
Our provider knows something no other component in the organization knows:
**which systems hold a scoped CID for the same person**. Data-subject
rights can therefore be **orchestrated across the whole organization** —
a GDPR control plane, not just a vault:

```
  erasure request (person)
          │
          ▼
    cid-provider ── knows all scoped CIDs of that person
          │
   ┌──────┼─────────┬──────────┐
   ▼      ▼         ▼          ▼
  CRM   billing   DWH      marketing
  (webhook: erase CID-CRM-x, confirm + audit)
```

### 14.2 Feature set

| Feature | Design | Origin |
|---|---|---|
| Consent management | Consent records per `(cid, purpose)` — reuses our existing `purpose` concept; `issueOti`/`lookup` can enforce consent as a policy hook | Databunker |
| Right of access | Export everything the provider and (via webhooks) registered systems hold for a person, plus the audit trail of who looked them up | Databunker, extended org-wide |
| Right to erasure | Erase PII blob + search tokens; CID becomes a tombstone (FKs in client systems don't break); erasure events pushed to every system holding a scoped CID, confirmations audited | Databunker, extended org-wide |
| Right to portability | Machine-readable (JSON) export per CID | Databunker |
| Rectification | Attribute update -> re-tokenization (new HMAC search tokens), old tokens invalidated | Databunker |
| Retention policies | Per-scope TTL; contacts and OTI/audit records auto-expire per configured policy | Databunker |
| Bulk-deny + audited export | `lookup` never returns lists; any mass export is a separate admin privilege, dual-controlled and audited (formalizes the 13.5 note) | Databunker |
| Privacy portal | Self-service page for citizens (view consents, request access/erasure) — open-source equivalent of their commercial Pro feature | Databunker Pro (reimagined) |

New API surface (additive, `/v1/dsr/*` and `/v1/consent/*`; no breaking
changes): `POST /v1/consent`, `DELETE /v1/consent`, `GET /v1/dsr/access`,
`POST /v1/dsr/erase`, `GET /v1/dsr/export`, plus a webhook contract for
client systems (`erase`, `rectify` events with per-system scoped CID).

### 14.3 Scheduling

v1 ships without this layer (unchanged — sections 11-12). This becomes
**v1.5**: after the M6 wedge is proven, before wallet federation (v2).
Rationale: the wedge sells breach containment; the DSR layer sells
*ongoing operational value* — together they answer both "what if we leak"
and "what does this do for us every day". Competitive framing: Databunker
= vault-local GDPR; this product = organization-wide GDPR orchestration.

## 15. Resolved decisions (v1)

All former open questions are decided (2026-08-22):

| # | Decision |
|---|---|
| D1 | **Stack: Go.** Single static binary; the supply-chain policy in 8.1 applies as written. |
| D2 | **License: Apache-2.0** + DCO for contributions (13.1). Headers and NOTICE from the first commit. |
| D3 | **Name: Sunder.** Personal GitHub account (the author is an individual, no org): repo `github.com/fvisic/sunder` (created 2026-08-22, private, empty); Go module `github.com/fvisic/sunder`. Packages per 10.3 with `<org>` = an npm/NuGet scope to be registered at first SDK release (an individual can register the free npm scope `@sunder-id`); bare `sunder` on npm/PyPI is squatted by dead projects, so scoped/suffixed names are used. `cid-provider` remains the generic component name inside this document. Trademark claim per 13.3. |
| D4 | **PII: v1 includes the encrypted PII blob + field-level attribute serving.** `GET /v1/contacts/{cid}/attributes/{name}` with mandatory `purpose`, checked against the caller's `allowed_purposes`; server-side decryption only (keys never leave the provider); one field per request; every fetch audited. Systems may therefore hold no PII at all. |
| D5 | **Client auth: both in v1** — bearer API keys (default, `clients.key_hash`) and mTLS as a config option. |
| D6 | **Database: PostgreSQL only in v1.** SQLite eval mode deferred; the try-it-out story is docker-compose. |
| D7 | **Keystore drivers in v1: `file` + `vault`.** The `pkcs11` driver stays an interface stub until the first compliance-driven demand. |
| D8 | **M6 demo: call-center lookup flow** — matches the adoption wedge (13.4). |
| D9 | **Local working directory:** `~/voice/labs/CID-OIB/sunder` (code next to the plans). |
| D10 | **Push policy:** local commits continuously, push to GitHub after each completed milestone (M1–M6). Go toolchain (1.25 via auto-upgrade); k6 runs via the `grafana/k6` Docker image at M6. |
| D11 | **Multi-value identifiers (added during implementation, 2026-08-22):** a contact can carry several searchable emails and phones (`person_tokens` table, one row per token per key version); addresses and other multi-valued data live as free-form attributes. Dedup matches any identifier (email priority); identifiers owned by another person are never silently stolen; `keys retire` purges retired-version token rows. |

## 16. Implementation status (v1)

Executed 2026-08-22 in `github.com/fvisic/sunder` (private). All six
milestones completed, each followed by a critical multi-agent review in
separate sessions with findings fixed before proceeding (the reviews
surfaced and fixed, among others: audit-chain hash canonicalization, a
cross-scope PII enrichment oracle — solved with per-scope AAD-bound blobs —
verifier purpose caps, key retirement, and a pii-kek rotation no-op).
Verified live: call-center demo end-to-end, RFC 3161 anchoring against
freetsa.org, k6 load test at 100% checks (laptop p99: lookup ~9–10.5 ms,
attributes 8.4 ms, OTI 13 ms). SDKs shipped for TypeScript and Python with
mock-server test suites; Java/PHP/.NET pending per section 10.3.
