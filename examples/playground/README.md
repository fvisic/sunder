# Playground (interactive demo)

The guide scenarios as clickable walkthroughs against a real instance, with
the HTTP request and response under every step. Full guide:
[docs-site/docs/get-started/playground.md](../../docs-site/docs/get-started/playground.md).

## Run it

```sh
docker compose -f deploy/docker-compose.yml \
               -f deploy/docker-compose.playground.yml up --build -d
open http://localhost:8081
```

That is all: the overlay's `seed` service creates the demo clients and the
erasure webhook on first boot and writes the credentials to a shared
volume, so nothing has to be copied by hand.

Tear down with `down -v`. After rebuilding the `playground` service alone,
also `up -d --force-recreate deliver` (it shares the playground's network
namespace).

## Where the pieces live

| Path | What |
|---|---|
| `internal/playground/scenarios/*.json` | the walkthroughs - one file per story, compiled into the binary |
| `internal/playground/ui/` | the SPA (vanilla JS, no build step) and the vendored RapiDoc bundle for the reference tab |
| `internal/playground/` | scenario model, step runner, HTTP surface, webhook inbox |
| `cmd/playground/` | the `sunder-playground` binary (Dockerfile target `playground`) |
| `deploy/docker-compose.playground.yml` | the overlay: `seed`, `playground`, `deliver` |
| `ops/playground_e2e.py` | drives every walkthrough through the API; the `e2e-playground` CI job |

## Running it without compose

Against a stack you already have, with credentials you already created:

```sh
export PLAYGROUND_CRED_CRM='crm.<secret>'
export PLAYGROUND_CRED_ERP='erp.<secret>'
export PLAYGROUND_CRED_PRIVACY='dpo.<secret>'
export PLAYGROUND_CRED_AUDITOR='auditor.<secret>'
go run ./cmd/playground -sunder http://localhost:8080
```

A walkthrough whose roles have no credential is shown as unavailable rather
than failing at click time, so a partial set is fine.

The clients each walkthrough needs (`sunder client create`):

| Role | Scope | Actions | Purposes |
|---|---|---|---|
| `crm` | `crm` | `contacts.register,lookup,attributes.read,oti.issue,consent.manage` | `support,create_order` |
| `erp` | `erp` | `oti.verify,attributes.read` | `create_order` |
| `privacy` | `crm` | `dsr.access,dsr.erase,dsr.export,consent.manage,contacts.register` | `support,admin` |
| `auditor` | `crm` | `audit.verify` | `support` |
| `vault` | `crm` | the F4-F8 feature actions (see the compose overlay) | `support` |

For the erasure inbox, point the scope's webhook at the playground and pass
the printed secret as `PLAYGROUND_WEBHOOK_SECRET`:

```sh
sunder webhook set -scope crm -url http://127.0.0.1:8081/hooks/erasure
```

Sunder accepts plain `http` webhooks only for a loopback host - that rule
is not relaxed for the demo, which is why the compose `deliver` sidecar
shares the playground's network namespace instead.

## Authoring a walkthrough

```sh
go run ./cmd/playground -scenarios internal/playground/scenarios -sunder http://localhost:8080
```

A scenario declares its roles, then steps with `method`, `path`, `body`,
the `expect`ed status, optional `capture` of response fields into
`{{variables}}`, and optional `assert` blocks comparing two variables (that
is how "the two systems hold different pseudonyms" becomes a checked
property). Placeholders live inside JSON strings; a step referencing a
variable no earlier step captures fails at load, not mid-demo.

`panel` picks the visualization above the steps: `handoff`, `consent`,
`webhook`, `audit`, or omit it for the plain step list. A panel name the UI
does not implement fails a test.

Run the shipped walkthroughs against a fake instance (no stack needed):

```sh
go test ./internal/playground/
```
