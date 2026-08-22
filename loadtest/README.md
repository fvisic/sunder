# Load test (M6)

k6 benchmark for the three hot paths, encoding the design latency
targets as pass/fail thresholds:

| Scenario | Endpoint(s) | Share of RATE | p99 threshold |
|---|---|---|---|
| `lookup_hit` | `POST /v1/lookup` (seeded email, always a hit) | 70% | < 10 ms |
| `attribute_read` | `GET /v1/contacts/{cid}/attributes/email` | 20% | < 15 ms |
| `oti_roundtrip` | `POST /v1/oti` then `POST /v1/oti/verify` | 10% (5% iterations x 2 requests) | < 20 ms each |

Each scenario also asserts on status codes (`checks` rate > 99.9%).
`setup()` registers `SEED_COUNT` contacts (`seed-<i>@loadtest.example`,
`+38591<7 digits>`) and hands their CIDs to the scenarios; registration is
dedup-idempotent, so repeated runs reuse the same persons.

> **Indicative vs. contractual numbers.** Results measured on a laptop
> (single container, k6 on the same machine) are *indicative only* — they
> show trends and regressions. The contractual numbers are measured on the
> reference deployment described in docs/DESIGN.md (LB + 2-3 stateless replicas +
> PostgreSQL with the token indexes in RAM + PgBouncer), with Prometheus
> confirming the per-endpoint p99.

## 1. Create the two clients

The script needs two credentials (printed once by `sunder client create`):

```sh
# Source system: registers the seed contacts, looks them up, reads
# attributes and issues OTIs. The default lookup rate limit is 60/min —
# far below the test rate — so raise it explicitly.
docker compose -f deploy/docker-compose.yml exec sunder /sunder client create -id loadtest -name "Load test" -scope webshop \
  -actions contacts.register,lookup,attributes.read,oti.issue \
  -purposes loadtest -rate 100000

# Target system: verifies OTIs. Its scope MUST be "erp" — a client can only
# verify tokens addressed to its own scope, and the script issues tokens
# with audience "erp".
docker compose -f deploy/docker-compose.yml exec sunder /sunder client create -id loadtest-verify -name "Load test verifier" -scope erp \
  -actions oti.verify -purposes loadtest
```

## 2. Run

Via Docker (no local k6 install; `-i` because the script is piped on
stdin). On Docker Desktop (macOS/Windows) `host.docker.internal` reaches the
host; on Linux replace it with `--network host` + `localhost`:

```sh
docker run --rm -i \
  -e BASE_URL=http://host.docker.internal:8080 \
  -e CRED='loadtest.<secret>' \
  -e CRED_VERIFY='loadtest-verify.<secret>' \
  grafana/k6 run - <loadtest/lookup.js
```

Or with a locally installed k6:

```sh
BASE_URL=http://localhost:8080 CRED=... CRED_VERIFY=... k6 run loadtest/lookup.js
```

k6 exits non-zero when any threshold fails, so the same invocation works in CI.

## 3. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `BASE_URL` | — (required) | Base URL of the running instance |
| `CRED` | — (required) | `<client_id>.<secret>` of the source client (step 1) |
| `CRED_VERIFY` | — (required) | `<client_id>.<secret>` of the verifier client (step 1) |
| `SEED_COUNT` | `2000` | Contacts registered in `setup()` |
| `RATE` | `200` | Total target request rate (rps), split 70/20/10 |
| `DURATION` | `1m` | Length of the measurement window |

The default rate is deliberately modest (200 rps) so the test is safe to run
against a laptop. For the design target of 1,000 rps on the reference
deployment, run with `-e RATE=1000` (and a larger `SEED_COUNT` if you want a
colder cache).
