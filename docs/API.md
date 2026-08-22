# API

All `/v1/*` endpoints require authentication. Errors are JSON:
`{"error": "<code>"}` with optional `detail`. Codes: `unauthorized` (401),
`forbidden` / `purpose_not_allowed` / `audience_mismatch` (403),
`not_found` (404), `validation` / `bad_json` / `token_invalid` (400),
`token_used` (409), `token_expired` (410), `rate_limited` (429),
`internal` (500).

## Authentication

`Authorization: Bearer <client_id>.<secret>` — issued once by
`sunder client create`; only a hash is stored server-side. With
`SUNDER_MTLS_CA` set, the listener additionally requires a valid client
certificate (decision D5: bearer default, mTLS option).

Every client has: a **scope** (which CID namespace it lives in),
**allowed actions** (what it may call) and **allowed purposes** (why).
A client can only ever reference CIDs of its own scope — foreign CIDs are
indistinguishable from nonexistent ones (404).

## Endpoints (M2)

### POST /v1/contacts — register a contact
Action: `contacts.register`.

```json
{"email": "Filip@Example.com", "phone": "+385 91 123 4567",
 "name": "Filip Visic", "attributes": {"loyalty_tier": "gold"}}
```

At least one email or phone is required. A contact can carry **several
searchable emails and phones**: the singular field is the primary, the
plural lists (`"emails": [...]`, `"phones": [...]`) add more; every one is
HMAC-tokenized, searchable and dedup-relevant. Normalized identifiers are
stored as attributes `email`, `email_2`, …, `phone`, `phone_2`, …; those
names plus `name` are reserved (rejected inside `attributes`). Identifiers
are normalized (Unicode NFKC; email lowercased; phone to E.164), and all
values land in the **caller-scope** AES-256-GCM blob. Multiple addresses or
any other multi-valued data go into `attributes` under caller-chosen names
(`address_home`, `address_billing`, …).

Dedup: an existing person is matched by ANY of their email tokens first,
then any phone token (deterministic email priority; an ambiguous claim
naming person A's email and person B's phone resolves to A) and reused —
re-registering returns the same scoped CID, merges new attributes into the
caller's blob (new values win) and adds missing identifier tokens. An
identifier already owned by another person is never silently stolen.
Attributes stored by other scopes are never readable through dedup
(per-scope blobs).

`201 {"cid": "CID-..."}` — the pseudonym in the *caller's* scope.

### POST /v1/contacts/{cid}/scopes — issue a CID in another scope
Action: `scopes.issue`. Body: `{"scope": "billing"}`.
`200 {"cid": "CID-..."}` — a different pseudonym for the same person.

**Grant sparingly**: this action is linkage-capable — the caller learns the
target scope's pseudonym. It exists for trusted integration components;
regular cross-system handoff should use OTIs, where the verifier learns its
own CID and the issuer learns nothing.

### GET /v1/contacts/{cid}/attributes/{name}?purpose=... — fetch one field
Action: `attributes.read`; `purpose` mandatory and must be in the caller's
allowed purposes. Decryption is server-side only; exactly one field is
returned; every fetch is written to the audit chain.
`200 {"value": "filip@example.com"}`

## Endpoints (M3)

### POST /v1/lookup — find a contact without exposing PII
Action: `lookup`. Rate-limited per client (429 `rate_limited` beyond the
client's per-minute limit); every miss increments
`sunder_lookup_misses_total` and feeds a sliding 10-minute enumeration
detector that logs a warning when a client crosses 100 weighted misses.

Valid key combinations:

```json
{"email": "filip@example.com"}
{"phone": "+385 91 123 4567"}
{"name": "Filip Visic", "email": "filip@example.com"}
{"name": "Filip Visic", "phone": "+385911234567"}
```

Name alone is rejected (400) — a name is a narrowing key, never an
identifier. The primary identifier is email (priority) or phone; extra
identifiers narrow *softly*: they must match when the person has that token,
but a person registered without it is not excluded. Identifiers are
normalized, HMAC-tokenized under every live (ACTIVE + RETIRING) key version
(rotation window) and matched against the token indexes; no PII is compared
or stored in plaintext anywhere on this path.

`200 {"cid": "CID-..."}` — the pseudonym in the caller's scope.
`404 not_found` — no match, **including** the case where the person exists
but has no CID in the caller's scope (anything else would let one scope
enumerate another's customer base). Every lookup, hit or miss, is audited.

Remember: **LOOKUP != AUTHENTICATION** — a hit never proves the caller is
talking to that person.

## Endpoints (M4)

### POST /v1/oti — issue a one-time identifier
Action: `oti.issue`; `purpose` must be in the caller's allowed purposes;
`cid` must belong to the caller's scope.

```json
{"cid": "CID-...", "purpose": "create_order", "audience": "erp",
 "share_attributes": ["email"]}
```

`201 {"token": "v4.public...", "expires_at": "..."}` — a PASETO v4.public
token (Ed25519, no negotiable algorithm) valid for **5 minutes, one use,
one audience, one purpose**. The signing key version travels as `kid`;
verification only accepts key versions the keyring lists as live.

`share_attributes` (optional) lists attributes from the **issuer's** scope
that are copied into the **verifier's** scope blob at verification — a
handoff shares nothing unless the issuer says so. This is the mechanism for
delayed flows (see `demo/escalation.sh`): the verifier holds only its own
CID, then fetches the shared attribute just-in-time (purpose- and
consent-checked, audited) when the delayed action fires. Tokens cannot be
"saved for later" — they expire in five minutes by design.

### POST /v1/oti/verify — verify and consume
Action: `oti.verify`. The caller's scope must equal `audience` — you can
only verify tokens addressed to you.

```json
{"token": "v4.public...", "purpose": "create_order", "audience": "erp"}
```

`200 {"cid": "CID-..."}` — **the verifier's own scoped CID** for the person
(auto-issued if absent); the issuer's pseudonym never crosses the scope
boundary. Single use is enforced by an atomic `VALID -> USED` database
transition, not just the signature. Errors: `token_invalid` (400, bad
signature/purpose/shape), `audience_mismatch` (403), `token_used` (409),
`token_expired` (410). Issue and verify are both audited.

## Endpoints (v1.5 — GDPR / data-subject rights)

### POST /v1/consent — record a consent decision
Action: `consent.manage`; CID must be caller-scope.
Body: `{"cid": "...", "purpose": "newsletter", "granted": false}`.
Absence of a record means "not consent-governed" (contract/legitimate-
interest bases); an explicit `granted:false` **blocks** attribute reads and
OTI issuance for that purpose (403 `consent_denied`) until re-granted.
Decisions survive erasure for accountability.

### GET /v1/consent/{cid} — list recorded decisions
Action: `consent.manage`. `200 {"consents": [{purpose, granted, updated_at}]}`

### GET /v1/dsr/access?cid=... — right of access (org-wide)
Action: `dsr.access` — a high-privilege, linkage-capable action for the
privacy-officer client only. Returns every scope's data for the person
(scope, CID, decrypted attributes, consents) plus the audit trail of who
touched them. Audited.

### POST /v1/dsr/erase — right to be forgotten (org-wide)
Action: `dsr.erase`. Body `{"cid": "..."}`. In one transaction: every
scope's blob is wiped, all search tokens deleted, the person becomes a
tombstone (client-side CID references never break), and one erasure event
per scope is queued. Events are delivered to each scope's webhook
(`sunder webhook set -scope crm -url ...`) as JSON signed with
`X-Sunder-Signature: hex(HMAC-SHA256(secret, body))`; a worker retries
PENDING deliveries every minute (`sunder dsr events` shows the queue).
Re-registering the same identifiers afterwards creates a brand-new person.

### GET /v1/dsr/export?cid=... — data portability (caller scope)
Action: `dsr.export`. Machine-readable JSON of what the caller's scope
holds: `{scope, cid, attributes, consents}`. Audited.

**Grant sparingly**: export is a bulk read — it returns the whole
caller-scope blob in one audited call, without per-attribute purpose or
consent gating (data portability is its own legal basis under GDPR Art. 20;
a withdrawn marketing consent does not block the subject's right to their
data). A client holding `dsr.export` can therefore read everything its
scope stores; treat the grant like `scopes.issue` — privacy-officer and
subject-request tooling only.

## Retention

`sunder retention set -scope crm -days 365` + `sunder retention run` (cron):
wipes caller-scope blobs older than the TTL (audited) and prunes OTI rows
expired for more than 30 days. Search tokens survive a retention wipe (it is
not an erasure); audit rows are NEVER pruned — the chain and its anchors are
the tamper evidence.

## Key rotation

`sunder keys rotate -kind <hmac-email|hmac-phone|hmac-name|pii-kek|oti-sign>`
mints the next version (new material first, then metadata) and demotes the
previous version to RETIRING. Lookups and dedup match tokens under every
live version (dual-key window); rows re-key to the newest version when
touched by a registration. `sunder keys list` shows the ring.

## Operational endpoints

- `GET /healthz` — liveness (no auth)
- `GET /readyz` — DB-backed readiness (no auth)
- `GET /metrics` — Prometheus text format (no auth; protect at the network layer)

## Audit

Actions `contacts.register`, `scopes.issue`, `attributes.read`, `lookup`
(hits and misses), `oti.issue` and `oti.verify` append to the hash-chained
audit log (client, action, CID, purpose/jti — never attribute values or raw
identifiers), inside the same transaction as the operation they record.
See docs/ARCHITECTURE.md and docs/THREAT-MODEL.md.

## Operational notes

- `GET /metrics` exposes per-client counters; set `SUNDER_METRICS_TOKEN`
  to require a bearer token where network isolation is not enough.
- Anchoring: schedule `sunder anchor -out <dir>` (cron, daily) and sync
  `<dir>` to write-once storage OFF the database host — anchors kept only in
  the database are circular against a privileged attacker. `sunder
  verify-audit -anchors <dir>` verifies the chain, every TSA token offline
  (CA resolved from `-ca`, `SUNDER_TSA_CACERT`, or the vendored FreeTSA
  bundle) and cross-checks exported files against the database; it refuses
  to report success when anchors exist but cannot be cryptographically
  verified.
