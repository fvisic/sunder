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

## Scenarios a fleet meets that a single instance never does

Four situations behave differently with more than one replica, and the
difference is invisible in a single-instance test. Each is exercised by
`ops/coldboot-scenarios.sh`, which boots from nothing every time - a stack
restarted onto existing data cannot reproduce any of them.

### 1. Cold boot: two processes, empty database

The first `up` of a new deployment is the only moment where two processes
migrate a schemaless database at the same time. Sunder serializes migrations
with an advisory lock; the subtlety is that the bookkeeping table must be
created INSIDE that lock, because `CREATE TABLE IF NOT EXISTS` is not atomic
- the existence check and the creation are separate steps.

```mermaid
sequenceDiagram
    participant A as Replica A
    participant B as Replica B
    participant DB as PostgreSQL (empty)

    A->>DB: BEGIN, pg_advisory_xact_lock(SUNM)
    B->>DB: BEGIN, pg_advisory_xact_lock(SUNM)
    Note over B,DB: B blocks - the lock is instance-wide
    A->>DB: CREATE TABLE IF NOT EXISTS schema_migrations
    A->>DB: apply 0001..00NN, INSERT one row each
    A->>DB: COMMIT (lock released)
    DB-->>B: lock acquired
    B->>DB: CREATE TABLE IF NOT EXISTS - now a real no-op
    B->>DB: every version already present, applies nothing
    B->>DB: COMMIT
    Note over A,B: exactly one row per migration, both replicas live
```

Before the table moved inside the lock, both replicas passed the not-exists
check and the loser died with `duplicate key value violates unique
constraint "pg_type_typname_nsp_index"` - a table creates its row type too.
On Kubernetes that is a crash loop on the very first deployment, and it
never reproduces once the database has a schema.

**What an operator sees when it goes wrong:** one pod `Running`, the other in
`CrashLoopBackOff` with a `pg_type` duplicate-key error, and a partially
migrated database. **Recovery:** scale to one replica, let it finish, scale
back up.

### 2. A replica joins and shares the keystore

Two replicas on one keystore volume must agree on key BYTES, not merely both
"have a key". The file driver elects a single generator with `O_EXCL`; the
elected process must then re-check whether the key already exists, because
its decision to mint was made before it held the lock.

```mermaid
sequenceDiagram
    participant A as Replica A
    participant KS as Keystore volume
    participant B as Replica B

    A->>KS: read hmac-email/v1 - absent
    B->>KS: read hmac-email/v1 - absent
    A->>KS: O_EXCL lock - won
    B->>KS: O_EXCL lock - busy, waits
    A->>KS: generate, write .tmp, rename into place
    A->>KS: release lock
    B->>KS: O_EXCL lock - won (A released it)
    Note over B,KS: B's decision to mint is now STALE
    B->>KS: re-check under the lock - the key exists
    B-->>B: use A's key, mint nothing
```

Skip that re-check and B mints over A's key. Every search token A wrote is
then unmatchable and every blob sealed under it is unreadable, while both
replicas report healthy: `/healthz` 200, and lookups simply return 404. The
observable invariant is the one the scenario asserts - a contact registered
through A resolves through B.

!!! danger "The file keystore is not the multi-replica answer"
    It needs a `ReadWriteMany` volume and it is single-writer by design. On
    Kubernetes use `keystore.type: vault`; the chart defaults to it. The
    scenario above exists because a shared-volume deployment is *possible*,
    not because it is recommended.

### 3. Key rotation while traffic runs

Rotation mints the next version and new writes pick it up immediately.
Reads must keep working under the old version throughout - there is no
window where a lookup misses because its token was written under a version
that is no longer current.

```mermaid
flowchart TB
    R["sunder keys rotate -kind hmac-email"] --> V2["v2 minted, marked current"]
    V2 --> W["new writes tokenize under v2"]
    V2 --> L["lookups try EVERY live version"]
    L --> H1["v2 token - hit"]
    L --> H2["v1 token - hit"]
    W --> RK["sunder keys rekey backfills v1 rows to v2"]
    RK --> RT["sunder keys retire -kind hmac-email -version v1"]
    RT --> G{"SUNDER_KEY_RETIRE_GRACE elapsed<br/>on EVERY replica?"}
    G -->|no| Refuse["refused - a replica may still write under v1"]
    G -->|yes| Purge["purge v1"]
```

The grace period is the multi-replica part. `KeyRing` caches key material per
process, so a replica can still be writing under v1 for as long as its cache
is stale. The purge is one-shot: a replica writing v1 tokens after it leaves
rows nothing will ever match or delete. Set `tunables.keyRetireGrace` above
the worst-case cache staleness across the whole fleet, and never set it to
`0` with more than one replica.

### 4. Sealing across a fleet

Under `async` (the default) each replica seals the rows it can see, and the
chain stays linear because `chain_seq` is assigned under a lock. The
hardened arrangement moves sealing out of the API entirely.

```mermaid
flowchart LR
    subgraph API["API replicas (SUNDER_AUDIT_SEAL_EXTERNAL=true)"]
      A1["replica 1"]
      A2["replica 2"]
      A3["replica N"]
    end
    A1 -->|"INSERT unsealed row"| AUD[("audit")]
    A2 -->|"INSERT unsealed row"| AUD
    A3 -->|"INSERT unsealed row"| AUD
    S["sunder sealer<br/>single replica"] -->|"UPDATE prev_hash, hash,<br/>chain_seq, hash_v"| AUD
    S --> HP["/healthz<br/>SUNDER_SEALER_HEALTH_ADDR"]
    AUD --> G["sunder_audit_unsealed_rows"]
    G --> AL{"backlog growing<br/>or not shrinking?"}
    AL -->|yes| Page["SunderAuditSealerStalled /<br/>SunderAuditSealerStopped"]
```

With the API role holding `INSERT` but no `UPDATE` on `audit`, a compromised
API replica cannot seal or forge hashes over its own rows. The sealer's own
`/healthz` answers 200 only while its last SUCCESSFUL pass is recent - it
logs-and-continues on error by design, so without that probe a sealer that
lost its `UPDATE` grant stays `Running` and `Ready` forever while the backlog
grows.

**Sealing mode changes are the one operation that needs the whole fleet
stopped**, and only in one direction - see below.

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
