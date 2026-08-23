# API

All `/v1/*` endpoints require authentication. Errors are JSON:
`{"error": "<code>"}` with optional `detail`. Codes:
`unauthorized` / `credential_expired` (401),
`forbidden` / `consent_denied` / `purpose_not_allowed` / `audience_mismatch` (403),
`not_found` (404), `validation` / `bad_json` / `token_invalid` (400),
`token_used` (409), `token_expired` (410), `rate_limited` (429),
`service_unavailable` (503), `internal` (500).

`credential_expired` means the secret is correct but past its expiry -
rotate (`sunder client rotate-secret`), do not retry. `consent_denied`
means the data subject withdrew consent for that purpose - distinct from
`purpose_not_allowed`, which is a missing grant on the client.

## Authentication

`Authorization: Bearer <client_id>.<secret>` - issued once by
`sunder client create`; only a hash is stored server-side. With
`SUNDER_MTLS_CA` set, the listener additionally requires a valid client
certificate (decision D5: bearer default, mTLS option).

Every client has: a **scope** (which CID namespace it lives in),
**allowed actions** (what it may call) and **allowed purposes** (why).
A client can only ever reference CIDs of its own scope - foreign CIDs are
indistinguishable from nonexistent ones (404).

## Endpoints (M2)

### POST /v1/contacts - register a contact
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
values land in the **caller-scope** AEAD blob (AES-256-GCM by default; see `SUNDER_PII_ALG`). Multiple addresses or
any other multi-valued data go into `attributes` under caller-chosen names
(`address_home`, `address_billing`, …).

Dedup: an existing person is matched by ANY of their email tokens first,
then any phone token (deterministic email priority; an ambiguous claim
naming person A's email and person B's phone resolves to A) and reused -
re-registering returns the same scoped CID, merges new attributes into the
caller's blob (new values win) and adds missing identifier tokens. An
identifier already owned by another person is never silently stolen.
Attributes stored by other scopes are never readable through dedup
(per-scope blobs).

`201 {"cid": "CID-..."}` - the pseudonym in the *caller's* scope.

### POST /v1/contacts/{cid}/scopes - issue a CID in another scope
Action: `scopes.issue`. Body: `{"scope": "billing"}`.
`200 {"cid": "CID-..."}` - a different pseudonym for the same person.

**Grant sparingly**: this action is linkage-capable - the caller learns the
target scope's pseudonym. It exists for trusted integration components;
regular cross-system handoff should use OTIs, where the verifier learns its
own CID and the issuer learns nothing.

### GET /v1/contacts/{cid}/attributes/{name}?purpose=... - fetch one field
Action: `attributes.read`; `purpose` mandatory and must be in the caller's
allowed purposes. Decryption is server-side only; exactly one field is
returned; every fetch is written to the audit chain.
`200 {"value": "filip@example.com"}`

## Endpoints (M3)

### POST /v1/lookup - find a contact without exposing PII
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

Name alone is rejected (400) - a name is a narrowing key, never an
identifier. The primary identifier is email (priority) or phone; extra
identifiers narrow *softly*: they must match when the person has that token,
but a person registered without it is not excluded. Identifiers are
normalized, HMAC-tokenized under every live (ACTIVE + RETIRING) key version
(rotation window) and matched against the token indexes; no PII is compared
or stored in plaintext anywhere on this path.

`200 {"cid": "CID-..."}` - the pseudonym in the caller's scope.
`404 not_found` - no match, **including** the case where the person exists
but has no CID in the caller's scope (anything else would let one scope
enumerate another's customer base). Every lookup, hit or miss, is audited.

Remember: **LOOKUP != AUTHENTICATION** - a hit never proves the caller is
talking to that person.

## Endpoints (M4)

### POST /v1/oti - issue a one-time identifier
Action: `oti.issue`; `purpose` must be in the caller's allowed purposes;
`cid` must belong to the caller's scope.

```json
{"cid": "CID-...", "purpose": "create_order", "audience": "erp",
 "share_attributes": ["email"]}
```

`201 {"token": "v4.public...", "expires_at": "..."}` - a PASETO v4.public
token (Ed25519, no negotiable algorithm) valid for **5 minutes, one use,
one audience, one purpose**. The signing key version travels as `kid`;
verification only accepts key versions the keyring lists as live.

`share_attributes` (optional) lists attributes from the **issuer's** scope
that are copied into the **verifier's** scope blob at verification - a
handoff shares nothing unless the issuer says so. This is the mechanism for
delayed flows (see `demo/escalation.sh`): the verifier holds only its own
CID, then fetches the shared attribute just-in-time (purpose- and
consent-checked, audited) when the delayed action fires. Tokens cannot be
"saved for later" - they expire in five minutes by design.

`share_predicates` (optional) is selective disclosure: issuer-authorized
claims evaluated against the **issuer's** data at verification, e.g.

```json
{"cid": "CID-...", "purpose": "age_check", "audience": "webshop",
 "share_predicates": [{"attr": "birthdate", "op": "age_gte", "value": 18}]}
```

The verifier receives booleans only - the birthdate itself never crosses
the scope boundary and nothing is copied into the verifier's blob.
Supported ops: `age_gte` (attribute read as an ISO date `YYYY-MM-DD` or
RFC 3339; `value` is REQUIRED - an omitted threshold is rejected at issue
time rather than silently meaning 0), `exists` (takes no value). At most 8 predicates per token; unknown ops are
rejected at issue time.

### POST /v1/claims/external - accept an issuer-signed claim envelope
Action: `claims.external`; `cid` must belong to the caller's scope.

```json
{"cid": "CID-...", "envelope": "v4.public..."}
```

The envelope is a PASETO v4.public token signed by a REGISTERED issuer
(`sunder issuer add`, see docs/DESIGN-EUDI-GATEWAY.md) whose payload is
`{"iss": "gov.wallet", "jti": "<unique>", "cid": "CID-...", "claims": {"age_gte_18": "true"}, "iat": ..., "exp": ...}`.
Accepted only when the issuer is trusted, the signature verifies, `exp` is
in the future, the SIGNED `cid` matches the target (subject binding), the
`jti` was never used before (anti-replay) and every claim is in the
issuer's allowlist (`*` = any, empty = none). Claims are
stored as normal attributes with provenance in the name
(`age_gte_18@gov.wallet`), audited.

`200 {"stored": ["age_gte_18@gov.wallet"]}`

### POST /v1/oti/verify - verify and consume
Action: `oti.verify`. The caller's scope must equal `audience` - you can
only verify tokens addressed to you.

```json
{"token": "v4.public...", "purpose": "create_order", "audience": "erp"}
```

`200 {"cid": "CID-...", "shared": [...], "predicates": [...]}` - **the
verifier's own scoped CID** for the person (auto-issued if absent), the
attribute names copied via `share_attributes` (when any), and the evaluated
predicate results (when the token carried any; returned to the verifier but
NOT written to the audit chain - see the audit-content boundary in
docs/THREAT-MODEL.md), each
`{"attr", "op", "value", "result", "known"}`. `known` is op-specific: for `age_gte` it is false when the attribute is
absent or unparseable (so "we do not know the birthdate" never reads as
"under 18"); for `exists` it is always true, because absence IS the answer
that predicate asks for. The
issuer's pseudonym never crosses the scope
boundary. Single use is enforced by an atomic `VALID -> USED` database
transition, not just the signature. Errors: `token_invalid` (400, bad
signature/purpose/shape), `audience_mismatch` (403), `token_used` (409),
`token_expired` (410). Issue and verify are both audited.

## Endpoints (v1.5 - GDPR / data-subject rights)

### POST /v1/consent - record a consent decision
Action: `consent.manage`; CID must be caller-scope.
Body: `{"cid": "...", "purpose": "newsletter", "granted": false}`.
Absence of a record means "not consent-governed" (contract/legitimate-
interest bases); an explicit `granted:false` **blocks** attribute reads and
OTI issuance for that purpose (403 `consent_denied`) until re-granted.
Decisions survive erasure for accountability.

### GET /v1/consent/{cid} - list recorded decisions
Action: `consent.manage`. `200 {"consents": [{purpose, granted, updated_at}]}`

### GET /v1/dsr/access?cid=... - right of access (org-wide)
Action: `dsr.access` - a high-privilege, linkage-capable action for the
privacy-officer client only. Returns every scope's data for the person
(scope, CID, decrypted attributes, consents) plus the audit trail of who
touched them. Audited.

### POST /v1/dsr/erase - right to be forgotten (org-wide)
Action: `dsr.erase`. Body `{"cid": "..."}`. In one transaction: every
scope's blob is wiped, all search tokens deleted, the person becomes a
tombstone (client-side CID references never break), and one erasure event
per scope is queued. Events are delivered to each scope's webhook
(`sunder webhook set -scope crm -url ...`) as JSON signed with
`X-Sunder-Signature: hex(HMAC-SHA256(secret, body))`; a worker retries
PENDING deliveries every minute (`sunder dsr events` shows the queue).
Re-registering the same identifiers afterwards creates a brand-new person.

### GET /v1/dsr/export?cid=... - data portability (caller scope)
Action: `dsr.export`. Machine-readable JSON of what the caller's scope
holds: `{scope, cid, attributes, consents}`. Audited.

**Grant sparingly**: export is a bulk read - it returns the whole
caller-scope blob in one audited call, without per-attribute purpose or
consent gating (data portability is its own legal basis under GDPR Art. 20;
a withdrawn marketing consent does not block the subject's right to their
data). A client holding `dsr.export` can therefore read everything its
scope stores; treat the grant like `scopes.issue` - privacy-officer and
subject-request tooling only.

## Retention

`sunder retention set -scope crm -days 365` + `sunder retention run` (cron):
wipes caller-scope blobs older than the TTL (audited) and prunes OTI rows
expired for more than 30 days. Search tokens survive a retention wipe (it is
not an erasure); audit rows are NEVER pruned - the chain and its anchors are
the tamper evidence.

## Key rotation

`sunder keys rotate -kind <hmac-email|hmac-phone|hmac-name|pii-kek|oti-sign>`
mints the next version (new material first, then metadata) and demotes the
previous version to RETIRING. Lookups and dedup match tokens under every
live version (dual-key window); rows re-key to the newest version when
touched by a registration. `sunder keys list` shows the ring.

## Operational endpoints

- `GET /healthz` - liveness (no auth)
- `GET /readyz` - DB-backed readiness (no auth)
- `GET /metrics` - Prometheus text format (no auth; protect at the network layer)

## Audit

Actions `contacts.register`, `scopes.issue`, `attributes.read`, `lookup`
(hits and misses), `oti.issue` and `oti.verify` append to the hash-chained
audit log (client, action, CID, purpose/jti - never attribute values or raw
identifiers). Mutating operations (register, scopes.issue, oti.issue,
oti.verify, consent, DSR) write their audit record inside the SAME
transaction as the operation - both commit or neither does. Read
operations (`attributes.read`, `lookup`) append in their own transaction
BEFORE the value is released, so an audit failure fails the read closed
rather than disclosing unaudited data.
See docs/ARCHITECTURE.md and docs/THREAT-MODEL.md.

## Operational notes

- `GET /metrics` exposes per-client counters; set `SUNDER_METRICS_TOKEN`
  to require a bearer token where network isolation is not enough.
- Anchoring: schedule `sunder anchor -out <dir>` (cron, daily) and sync
  `<dir>` to write-once storage OFF the database host - anchors kept only in
  the database are circular against a privileged attacker. `sunder
  verify-audit -anchors <dir>` verifies the chain, every TSA token offline
  (CA resolved from `-ca`, `SUNDER_TSA_CACERT`, or the vendored FreeTSA
  bundle) and cross-checks exported files against the database; it refuses
  to report success when anchors exist but cannot be cryptographically
  verified.


## Self-service privacy portal (P2.5)

Citizen-facing, cookie-authenticated surface at `/portal/` (self-contained
SPA, CSP-locked) with its own per-IP rate limits. NOT behind client
credentials - authentication is a magic link:

1. `POST /portal/api/start {"email": ...}` - always answers `202` with the
   same body (no enumeration oracle). When the address resolves to a
   person, a one-time login token (15 min, single-use, stored hashed) is
   POSTed as a signed `portal_login` event to the webhook registered under
   the reserved scope `_portal` - the ORG's mailer turns it into an e-mail;
   Sunder itself sends none. Configure with:
   `sunder webhook set -scope _portal -url https://mailer.internal/hook`.
2. `POST /portal/api/session {"token": ...}` - redeems the link, sets an
   HttpOnly, SameSite=Strict session cookie (30 min).
3. `GET /portal/api/me` - everything every scope stores about the person +
   the audit trail (the v1.5 right-of-access path, self-served).
4. `POST /portal/api/consent {"cid", "purpose", "granted"}` - flip a
   consent on one of the person's OWN CIDs; takes effect immediately on
   reads and handoffs.
5. `POST /portal/api/erase` then `POST /portal/api/erase/confirm
   {"confirm_token"}` - two-step erasure (a hijacked session cannot erase
   in one call); runs the full org-wide erasure with webhooks, audited as
   `portal:<cid>`.

Every portal action is audited; tokens and sessions exist in the database
only as SHA-256 hashes; sessions die with the person's erasure.