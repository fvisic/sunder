# Sunder

**Stop using emails, phone numbers and national IDs as database keys.**

Every internal system that keys on the same identifier - CRM, billing,
analytics, ticketing - is one breach away from becoming a *join table for
your entire customer base*. A leaked email column from the ticketing tool
links to the CRM dump from last year links to the analytics warehouse.
That linkage is permanent: nobody can rotate their national ID.

Sunder is a self-hosted identity decoupling layer that breaks the join:

```mermaid
flowchart LR
    subgraph before["Without Sunder: one shared join key"]
        A1["CRM<br/>ana@example.com"] --- B1["Billing<br/>ana@example.com"] --- C1["Analytics<br/>ana@example.com"]
    end
    subgraph after["With Sunder: unjoinable per-scope pseudonyms"]
        A2["CRM<br/>CID-K7Q2..."] -.- B2["Billing<br/>CID-9XWF..."] -.- C2["Analytics<br/>CID-P3RM..."]
    end
    before ==> after
```

Same person, three databases, three unrelated random pseudonyms. Leak any
one of them - or all three - and there is nothing to join on. Only your
Sunder instance can map between scopes, and every mapping is audited in a
tamper-evident hash chain.

> **Status**: feature-complete v1 with a GDPR layer and six SDKs
> (v0.2.0). Pre-1.0 - interfaces may still move; read the threat model
> in `docs/` before production use.

## Try it in 60 seconds

```sh
git clone https://github.com/fvisic/sunder && cd sunder/deploy
docker compose up --build -d
../demo/quickstart.sh   # narrated end-to-end storyline
```

The demo registers a contact, looks it up from a CRM, hands the
identity to an ERP via a single-use token, reads one attribute under a
declared purpose, and then erases the person GDPR-style - printing every
HTTP request as it goes.

Prefer clicking to reading? The same stories, plus a consent gate, the
erasure webhook inbox and the audit chain, as an interactive playground:

```sh
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.playground.yml up --build -d
open http://localhost:8081
```

## Why not just use ...?

| | Sunder | Databunker | HashiCorp Vault | DIY encryption |
|---|---|---|---|---|
| Breaks cross-system linkability | **yes - per-scope pseudonyms** | no (one token per person, org-wide) | no (secrets store, not identity) | almost never done |
| System-to-system identity handoff | **signed single-use tokens** (purpose + audience bound) | shared token | n/a | ad-hoc |
| Search encrypted PII by email/phone | keyed HMAC indexes | hash indexes | no | rarely |
| GDPR: consent, access, erasure, portability, retention | built in, with signed erasure webhooks | built in | no | months of work |
| Tamper-evident audit | hash chain + **RFC 3161 anchoring** (provable to an auditor offline) | Pro feature | audit log | rarely |
| Attribute proof without the value (`age >= 18`) | **yes - predicate claims** | no | no | no |
| Performance (same box, PostgreSQL 16, measured interleaved) | **2,729 writes/s, 3,439 lookups/s** | 1,295 / 2,032 | n/a | ? |
| License | **Apache-2.0, no limits** | MIT core + paid Pro | BSL | yours |

The benchmark harness and raw results are in [`benchmark/`](benchmark/) -
reproduce them with one script. On a laptop head-to-head (both systems
in the same window, five interleaved rounds plus a clean 5,000-request
pass, zero errors) Sunder is **+111% on writes, +69% on lookups and +61%
on reads**, with p99 latency 2.7-3.4x lower - *while writing a hash-chained
audit record per operation*.

A later run on a 12-core server found the limit those numbers hide: the
audit chain serializes on one advisory lock, so instance throughput is
bounded by storage commit latency (~460 audited ops/s where `fdatasync`
runs at 2,000/s) and does not scale past about four concurrent clients.
Per-request latency is unaffected and stays ahead. The benchmark README
carries both runs, the measured lock contention, and the design options.

## What you get

- **CID** - random per-scope pseudonym; CRM, billing and analytics each
  see a different one for the same person. No derivation, nothing to reverse.
- **OTI** - PASETO v4 signed, single-use, 5-minute handoff token bound to
  one purpose and one audience; atomically consumed. The only identity
  currency systems exchange. Optional issuer-approved attribute sharing
  powers delayed flows (escalation e-mails) without the receiver storing
  PII, and **predicate claims** prove facts without revealing values:
  the verifier learns `age >= 18: true`, never the birthdate.
- **Lookup** - find a contact by email/phone via keyed HMAC search tokens;
  the database stores no searchable plaintext. `LOOKUP != AUTHENTICATION`.
- **Attributes** - PII encrypted per scope (AES-256-GCM or
  XChaCha20-Poly1305, per-blob algorithm tag, live migration via one
  sweep); systems fetch single fields on demand, purpose-checked,
  consent-checked, audited *before* the value is released.
- **Audit you can prove** - append-only hash chain, anchored to an
  RFC 3161 timestamp authority, exported off-host and cross-checked:
  a privileged database attacker cannot silently rewrite history. Two
  write modes: **async sealing** (default) keeps the chain off the
  request path - measured on a 26.8M-contact dataset it takes lookup
  from a flat ~420 rps ceiling to 1,959 rps and still climbing, at the
  price of a ~2s window in which fresh rows are trigger-protected but
  not yet hash-chained; **sync** seals every row at insert (zero window,
  serialized throughput) for deployments that want the strictest
  posture. The trade-off is measured and documented, not hidden:
  `docs/THREAT-MODEL.md` ("Audit sealing window").
- **Keys that actually rotate** - versioned HMAC/KEK/signing keys,
  dual-key lookup window, batch rekey, retirement; file, Vault and
  PKCS#11 keystore drivers.
- **GDPR layer** - consent per purpose (enforced on reads and handoffs),
  org-wide right of access, erasure with signed webhooks per scope,
  portability export, retention TTLs.
- **Six SDKs** - Go, TypeScript, Python, PHP, Java, .NET; identical
  interface and error taxonomy, zero runtime dependencies each.

## What's in the box

| Path | Contents |
|---|---|
| `cmd/sunder`, `internal/` | the service + CLI (`serve`, `signer`, `bootstrap`, `migrate`, `client create/rotate-secret`, `keys rotate/rekey/retire`, `anchor`, `verify-audit`, `webhook`, `retention`, `dsr`, `issuer`, `sealer`) |
| `api/` | OpenAPI 3.1 contract (also served at `/openapi.yaml`) + Postman collection |
| `sdks/` | the six SDKs (Go, TypeScript, Python, PHP, Java, .NET), each with a mock-server test suite |
| `demo/` | narrated demos: lookup + one-time handoff, escalation e-mail handoff |
| `examples/playground/`, `cmd/playground` | the interactive demo: guide scenarios as clickable walkthroughs, with the HTTP wire view, over a real instance |
| `benchmark/`, `loadtest/` | Databunker head-to-head + k6 latency targets |
| `migrate/databunker/` | migration tool: Databunker records to Sunder contacts |
| `deploy/` | Docker Compose + Helm chart (TLS/mTLS, Vault, signer sidecar, NetworkPolicy, anchor/retention cron jobs) + per-customer provisioning script |
| `ops/` | Grafana dashboard + Prometheus alert rules |
| `docs/` | design, architecture, threat model, config reference, runbooks (backup/DR, mTLS rotation, algorithm migration) |

## Development

Requirements: Go 1.25+, Docker (for PostgreSQL).

```sh
docker compose -f deploy/docker-compose.yml up -d postgres
export SUNDER_DB_URL=postgres://sunder:sunder-dev-only@localhost:5432/sunder
export SUNDER_TEST_DB_URL=$SUNDER_DB_URL
go test ./...
go run ./cmd/sunder serve
```

Configuration is environment-only; see `docs/CONFIG.md` for the full
`SUNDER_*` reference (deployment tunables - OTI TTL, PII encryption
algorithm, webhook delivery caps - included).

Test coverage is gated at **>= 90%** in CI (currently ~90% across the
server and CLI - the uncovered remainder is almost entirely defensive
branches for mid-transaction database failures); the SDKs carry their own
mock-server suites, and the CI `e2e-demo` job boots the real stack and
runs the narrated demo on every push. Releases are cosign-signed with an
SPDX SBOM ([RELEASING.md](RELEASING.md)).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy. The threat model
and architecture decisions live in `docs/`.

## About

Sunder is an independent personal open-source project by its author. It is
not affiliated with, endorsed by, or developed for any employer or
commercial product, and works for any set of internal systems - a web
shop, an ERP, a ticketing tool, a data warehouse - anywhere two databases
should not share a person identifier.

## License

Apache-2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE). No limits, no
license keys, no paid tier. Contributions require a DCO sign-off
(`git commit -s`).
