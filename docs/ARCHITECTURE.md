# Architecture

Sunder is a single stateless Go service in front of PostgreSQL. Every
system in the organization (CRM, billing, web, …) is a registered *client*
with its own credentials, scope, allowed actions and purposes.

```
 org systems (CRM, billing, web shop, ticketing, DWH, ...)
        │  bearer key or mTLS, per-system credentials
        ▼
 ┌──────────────────────────────┐
 │ sunder (static binary)       │
 │  api/       HTTP + middleware│
 │  service/   business logic   │
 │  crypto/    HMAC, PASETO, AES│
 │  audit/     hash chain + TSA │
 │  store/     pgx + migrations │
 └──────────────┬───────────────┘
                ▼
           PostgreSQL 16
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/sunder` | entrypoint: `serve`, `migrate`, plus milestone-added admin subcommands |
| `internal/config` | `SUNDER_*` environment configuration |
| `internal/store` | pgx pool, embedded SQL migrations |
| `internal/api` | routing (stdlib `http.ServeMux`), health/readiness, metrics, logging middleware |
| `internal/metrics` | minimal Prometheus text-format registry (stdlib-first, no client_golang) |

Added in later milestones: `internal/service` (contacts, lookup, OTI,
attributes), `internal/crypto` (search tokens, PASETO v4.public, PII
encryption, keystore drivers), `internal/audit` (hash chain, RFC 3161
anchoring), `internal/ratelimit`.

## Ground rules

- **No PII in logs or metrics** - the logging middleware records method,
  route pattern, status and duration only; never query strings, bodies or
  headers.
- **No OIB anywhere** - the schema has no column for a national identifier,
  by design.
- **Stdlib first** - a new dependency requires justification in the PR;
  the only runtime dependency is pgx.
- **Postgres only (v1)** - decision D6; local development uses
  `deploy/docker-compose.yml`.

## Identity model

`persons` holds one row per real person: HMAC search tokens only. Encrypted
attributes live per-scope on the `cids` row (AES-256-GCM, AAD-bound to the
CID), so each scope reads exactly the attributes it stored itself - dedup
onto a shared person never exposes another scope's data. `cids` maps a
person to one pseudonym per *scope* (internal domain: crm, billing, …).

Clients only ever reference CIDs of their own scope. Two deliberate,
audited exceptions exist: the `scopes.issue` action (returns another
scope's CID for a person - a linkage-capable privilege for trusted
integration components only) and OTI verification (the verifier receives
its own scoped CID). Day-to-day cross-system handoff uses OTIs
(docs/DESIGN.md).
