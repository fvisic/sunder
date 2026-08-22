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

At least one of `email`/`phone` is required. Identifiers are normalized
(email lowercased; phone to E.164), HMAC search tokens are computed, and all
values land in the AES-256-GCM encrypted attribute blob. An existing person
(matched by email or phone token) is reused — re-registering returns the
same scoped CID.

`201 {"cid": "CID-..."}` — the pseudonym in the *caller's* scope.

### POST /v1/contacts/{cid}/scopes — issue a CID in another scope
Action: `scopes.issue`. Body: `{"scope": "billing"}`.
`200 {"cid": "CID-..."}` — a different pseudonym for the same person.

### GET /v1/contacts/{cid}/attributes/{name}?purpose=... — fetch one field
Action: `attributes.read`; `purpose` mandatory and must be in the caller's
allowed purposes. Decryption is server-side only; exactly one field is
returned; every fetch is written to the audit chain.
`200 {"value": "filip@example.com"}`

## Operational endpoints

- `GET /healthz` — liveness (no auth)
- `GET /readyz` — DB-backed readiness (no auth)
- `GET /metrics` — Prometheus text format (no auth; protect at the network layer)

## Audit

Actions `contacts.register`, `scopes.issue` and `attributes.read` append to
the hash-chained audit log (client, action, CID, purpose — never attribute
values). See docs/ARCHITECTURE.md.
