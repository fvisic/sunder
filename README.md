# Sunder

Per-organization identity decoupling layer: scoped pseudonyms (**CID**),
one-time identifiers (**OTI**), HMAC-based lookup and purpose-checked
attribute serving — so the systems inside an organization never share a
linkable person identifier, and a leak of any one database is unjoinable
with any other.

Sunder is self-hosted: every organization runs its own instance and is the
identity provider for its own contacts. There is no central party.

> **Status**: v1 under active development, milestone by milestone — the
> feature list below is the v1 target; see `docs/PLAN.md` for what has
> landed. Not production-ready yet.

## Why

A national identifier (like the Croatian OIB) or a raw email/phone used as
a database key is a permanent, universal join key — once leaked, it is
compromised forever. Sunder replaces it inside the organization:

- **CID** — a random, per-scope pseudonym: CRM, billing and analytics each
  see a different CID for the same person; only Sunder can map between them.
- **OTI** — a signed, single-use token bound to one purpose and one
  audience; the only identity currency systems exchange.
- **Lookup** — find a contact by email/phone via keyed HMAC search tokens;
  the database stores no searchable PII. `LOOKUP != AUTHENTICATION`.
- **Attributes** — PII lives encrypted in Sunder; systems fetch single
  fields on demand, purpose-checked and audited.
- **Audit** — append-only hash chain, anchored daily to an RFC 3161
  timestamp authority: silent tampering is provable.

## Quick start

```sh
cd deploy && docker compose up --build
curl http://localhost:8080/healthz
```

## What's in the box

| Path | Contents |
|---|---|
| `cmd/sunder`, `internal/` | the service: CID/OTI, HMAC lookup, purpose-checked attributes, hash-chained + TSA-anchored audit, key rotation, GDPR layer (consent, org-wide access/erasure with signed webhooks, portability, retention) |
| `api/openapi.yaml` | OpenAPI 3.1 contract |
| `sdks/typescript`, `sdks/python` | zero-dependency SDKs (same canonical interface; Java/PHP/.NET follow) |
| `demo/callcenter.sh` | narrated call-center pilot storyline (doubles as a smoke test) |
| `loadtest/lookup.js` | k6 scenarios encoding the latency targets |
| `docs/` | architecture, API, threat model, design plan |

CLI: `sunder serve | migrate | client create | keys rotate/retire/list |
anchor | verify-audit | webhook set/list | retention set/run |
dsr deliver/events`.

## Development

Requirements: Go 1.25+, Docker (for PostgreSQL).

```sh
docker compose -f deploy/docker-compose.yml up -d postgres
export SUNDER_DB_URL=postgres://sunder:sunder-dev-only@localhost:5432/sunder
export SUNDER_TEST_DB_URL=$SUNDER_DB_URL
go test ./...
go run ./cmd/sunder serve
```

Configuration is environment-only; see `internal/config/config.go` for the
full `SUNDER_*` list. Documentation lives in `docs/`.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy. Design docs:
threat model and architecture decisions are in `docs/`.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Contributions require a DCO sign-off (`git commit -s`).
