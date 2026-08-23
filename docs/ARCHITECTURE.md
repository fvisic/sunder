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
  runtime dependencies are deliberately few: pgx (database), golang.org/x/text
  (Unicode NFKC normalization on every registration and lookup) and
  golang.org/x/crypto (XChaCha20-Poly1305, one of the two PII algorithms).
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


## Signer process split (P2.1)

The worst case in the threat model is malicious code inside the API
process reading working keys from RAM. The split removes that class:

```
+---------------------+        unix socket        +--------------------+
|  sunder serve       |  MAC / Seal / Open /      |  sunder signer     |
|  (no key material)  | ------------------------> |  (sole keystore    |
|  HTTP, DB, audit    |  Sign / Verify / Ensure   |   holder, no DB,   |
|                     | <------------------------ |   no network)      |
+---------------------+   length-prefixed JSON    +--------------------+
```

- The main process is compiled against `crypto.Engine` - six operations,
  none of which returns key bytes. With `SUNDER_SIGNER_SOCKET` set it uses
  the RemoteEngine; without it, the in-process LocalEngine (default).
- The signer (`sunder signer -socket ...`) opens the keystore and serves
  the six operations on a 0600 Unix socket in a 0700 directory. It needs
  no database credentials (`config.FromEnvNoDB`) and, deployed as a
  container, no network at all.
- A dead or stopped signer fails every crypto path closed - there is no
  local fallback, by design.
- Deploy: Helm `signer.enabled=true` (sidecar + in-memory emptyDir socket
  volume) or `deploy/docker-compose.signer.yml` for a local demonstration.
