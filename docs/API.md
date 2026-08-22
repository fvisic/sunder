# API

All `/v1/*` endpoints require authentication. Errors are JSON:
`{"error": "<code>"}` with optional `detail`. Codes: `unauthorized`,
`forbidden`, `purpose_not_allowed`, `not_found`, `validation`, `bad_json`,
`rate_limited`, `internal`.

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

At least one of `email`/`phone` is required. `email`, `phone` and `name`
are reserved attribute names (rejected inside `attributes`); the service
stores the normalized identifiers under them. Identifiers are normalized
(Unicode NFKC; email lowercased; phone to E.164), HMAC search tokens are
computed, and all values land in the **caller-scope** AES-256-GCM blob.

Dedup: an existing person is matched by email token first, then phone
(deterministic priority) and reused — re-registering returns the same
scoped CID, merges new attributes into the caller's blob (new values win)
and fills in identifier tokens the person was missing. Attributes stored by
other scopes are never readable through dedup (per-scope blobs).

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
client's per-minute limit); misses feed the enumeration detector (warning
log + `sunder_lookup_misses_total` metric at 100 misses/10 min).

Valid key combinations:

```json
{"email": "filip@example.com"}
{"phone": "+385 91 123 4567"}
{"name": "Filip Visic", "email": "filip@example.com"}
{"name": "Filip Visic", "phone": "+385911234567"}
```

Name alone is rejected (400) — a name is a narrowing key, never an
identifier. Identifiers are normalized, HMAC-tokenized under every active
key version (rotation window) and matched against the token indexes; no PII
is compared or stored in plaintext anywhere on this path.

`200 {"cid": "CID-..."}` — the pseudonym in the caller's scope.
`404 not_found` — no match, **including** the case where the person exists
but has no CID in the caller's scope (anything else would let one scope
enumerate another's customer base). Every lookup, hit or miss, is audited.

Remember: **LOOKUP != AUTHENTICATION** — a hit never proves the caller is
talking to that person.

## Operational endpoints

- `GET /healthz` — liveness (no auth)
- `GET /readyz` — DB-backed readiness (no auth)
- `GET /metrics` — Prometheus text format (no auth; protect at the network layer)

## Audit

Actions `contacts.register`, `scopes.issue` and `attributes.read` append to
the hash-chained audit log (client, action, CID, purpose — never attribute
values). See docs/ARCHITECTURE.md.
