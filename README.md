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

> **Status**: feature-complete v1 with a GDPR layer and five SDKs
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

## Why not just use ...?

| | Sunder | Databunker | HashiCorp Vault | DIY encryption |
|---|---|---|---|---|
| Breaks cross-system linkability | **yes - per-scope pseudonyms** | no (one token per person, org-wide) | no (secrets store, not identity) | almost never done |
| System-to-system identity handoff | **signed single-use tokens** (purpose + audience bound) | shared token | n/a | ad-hoc |
| Search encrypted PII by email/phone | keyed HMAC indexes | hash indexes | no | rarely |
| GDPR: consent, access, erasure, portability, retention | built in, with signed erasure webhooks | built in | no | months of work |
| Tamper-evident audit | hash chain + **RFC 3161 anchoring** (provable to an auditor offline) | Pro feature | audit log | rarely |
| Attribute proof without the value (`age >= 18`) | **yes - predicate claims** | no | no | no |
| Performance (same box, PostgreSQL 16) | **2,173 writes/s, 2,837 lookups/s** | 1,091 / 1,885 | n/a | ? |
| License | **Apache-2.0, no limits** | MIT core + paid Pro | BSL | yours |

The benchmark harness and raw results are in [`benchmark/`](benchmark/) -
reproduce them with one script. Sunder is 50-99% faster than Databunker on
every operation with p99 latency 2.2-3.3x lower, *while writing a
same-transaction audit record per operation*.

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
  a privileged database attacker cannot silently rewrite history.
- **Keys that actually rotate** - versioned HMAC/KEK/signing keys,
  dual-key lookup window, batch rekey, retirement; file, Vault and
  PKCS#11 keystore drivers.
- **GDPR layer** - consent per purpose (enforced on reads and handoffs),
  org-wide right of access, erasure with signed webhooks per scope,
  portability export, retention TTLs.
- **Five SDKs** - TypeScript, Python, PHP, Java, .NET; identical
  interface and error taxonomy, zero runtime dependencies each.

## What's in the box

| Path | Contents |
|---|---|
| `cmd/sunder`, `internal/` | the service + CLI (`serve`, `signer`, `bootstrap`, `migrate`, `client create/rotate-secret`, `keys rotate/rekey/retire`, `anchor`, `verify-audit`, `webhook`, `retention`, `dsr`, `issuer`) |
| `api/` | OpenAPI 3.1 contract (also served at `/openapi.yaml`) + Postman collection |
| `sdks/` | the five SDKs, each with a mock-server test suite |
| `demo/` | narrated demos: lookup + one-time handoff, escalation e-mail handoff |
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

Test coverage is gated at **>= 88%** in CI (currently ~90% across the
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
