# Architecture

Sunder is a single stateless Go service in front of PostgreSQL. Every
system in the organization (CRM, billing, web, …) is a registered *client*
with its own credentials, scope, allowed actions and purposes.

```
 org systems (CRM, billing, web, call-center, DWH, ...)
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

- **No PII in logs or metrics** — the logging middleware records method,
  route pattern, status and duration only; never query strings, bodies or
  headers.
- **No OIB anywhere** — the schema has no column for a national identifier,
  by design.
- **Stdlib first** — a new dependency requires justification in the PR;
  the only runtime dependency is pgx.
- **Postgres only (v1)** — decision D6; local development uses
  `deploy/docker-compose.yml`.

## Identity model

`persons` holds one row per real person: HMAC search tokens plus an
AES-256-GCM encrypted attribute blob. `cids` maps a person to one pseudonym
per *scope* (internal domain: crm, billing, …). Systems only ever see CIDs
from their own scope; OTIs are the only identity currency exchanged between
systems (PLAN.md section 6).
