# Multi-Replica Deployments

You want to run more than one Sunder instance behind a load balancer
without each replica quietly enforcing its own private rate limit, and
without an unnoticed Redis outage silently changing what "rate limited"
means.

```mermaid
flowchart LR
  LB["Load balancer"] --> R1["Sunder replica 1"]
  LB --> R2["Sunder replica 2"]
  LB --> R3["Sunder replica N"]
  R1 -->|"reads/writes"| PG[("Shared PostgreSQL")]
  R2 -->|"reads/writes"| PG
  R3 -->|"reads/writes"| PG
  R1 -->|"shared sliding-window counters"| RD[("Redis<br/>SUNDER_REDIS_ADDR")]
  R2 -->|"shared sliding-window counters"| RD
  R3 -->|"shared sliding-window counters"| RD
  RD -.->|"unreachable"| FO{"SUNDER_REDIS_FAIL_CLOSED"}
  FO -->|"false (default): fail-open"| Serve["serve the request<br/>no shared limit enforced"]
  FO -->|"true: fail-closed"| Block["block the lookup<br/>(rate_limited / service_unavailable)"]
```

## Set it up

**1. Run stateless replicas.** Sunder itself holds no state - point every
replica at the same PostgreSQL and scale by adding replicas behind the
load balancer.

!!! danger "Two settings make a replica NOT stateless"

    - **`SUNDER_KEYSTORE=file`** keeps key material in a per-process
      directory. The Helm chart refuses it outright for this reason; use
      `vault` (or the signer split).
    - **`SUNDER_FILES_STORAGE=local`** keeps file **ciphertext** in a
      per-process directory (`SUNDER_FILES_DIR`) while its metadata and
      wrapped DEK live in the shared database. A download routed to a
      replica that does not hold the object answers **200 with the recorded
      `Content-Length` and an empty body** - it is not an error the caller
      can detect except by counting bytes. `sunder retention run` on one
      replica also garbage-collects only that replica's objects.
      `local` is single-instance only; **`s3` is the multi-replica driver.**
      Both are logged as a startup warning.

**2. Share rate-limit windows across replicas.** Unset, each replica
counts in memory: with a naive round-robin load balancer, a per-client
limit meant to be N requests/min becomes effectively N × replica-count.
Point every replica at the same Redis to make the limit real again:

```sh
export SUNDER_REDIS_ADDR=redis.internal:6379
export SUNDER_REDIS_PASSWORD=$(cat /run/secrets/redis-password)   # optional
```

**3. Decide the failure mode for when Redis itself goes down:**

```sh
# default: false - availability wins, requests proceed unlimited during the outage
export SUNDER_REDIS_FAIL_CLOSED=false

# strict: true - lookups are blocked while Redis is unreachable
export SUNDER_REDIS_FAIL_CLOSED=true
```

**4. Confirm the shared limit is real** by driving one client over its
per-minute cap through the load balancer VIP (not a single replica) and
watching for `429`:

```sh
for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://sunder-lb.internal/v1/lookup \
    -H "Authorization: Bearer $CLIENT_ID.$CLIENT_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"email":"filip@example.com"}'
done | sort | uniq -c
```

Expect a mix of `200`/`404` until the client crosses its limit, then
`429` with body `{"error":"rate_limited"}` - and the same limit regardless
of which replica happened to answer. There is no SDK call for this check;
it is exercising the ordinary lookup call under load, and every SDK's
lookup method surfaces `429` as its `RateLimited` error the same way.

## Other multi-replica behavior worth knowing

Audit sealing mode (`SUNDER_AUDIT_SEALING`) also has a multi-replica rule:
switching a fleet from `async` to `sync` requires stopping ALL replicas
first. A lingering `async` replica whose transaction commits after the new
instance's startup drain leaves that row outside the chain until the next
drain - `sunder verify-audit` will fail visibly on exactly this state. The
reverse direction, `sync -> async`, needs nothing special.

## Security notes

- **Fail-open is the default, deliberately.** `SUNDER_REDIS_FAIL_CLOSED`
  defaults to `false`: when Redis is unreachable, lookups keep serving
  rather than the fleet going down. This is an explicit availability
  trade-off, not an oversight - set it to `true` only where an
  under-enforced rate limit during a Redis outage is worse than blocking
  lookups.
- **The privacy portal does not get this choice.** Regardless of
  `SUNDER_REDIS_FAIL_CLOSED`, the citizen-facing portal's rate limiter
  always fails **closed** if Redis is unreachable - a portal outage that
  degrades into "no rate limit" would expose the mail-sending route to
  enumeration and mail-bombing, which the API's own trade-off is not
  allowed to inherit.
- **Redis is rate-limit state only, never identity or credential state.**
  Losing Redis entirely (data flush, failover) resets counters, not
  authorization - a client still needs a valid bearer credential (or mTLS
  certificate) on every request, with or without Redis, and Redis holds no
  PII: only per-client sliding-window counters.
- **Sharing Redis does not make replicas share anything else.** Keys,
  audit chain state, and the database connection are each their own
  concern; a shared rate limiter does not imply a shared cache of lookups
  or attributes - every request still resolves against PostgreSQL.
