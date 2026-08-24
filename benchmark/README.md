# Benchmark: Sunder vs Databunker (head-to-head)

Goal: same machine, same database engine, same load tool, comparable
operations - and Sunder at least 50% more efficient.

## Server measurement (2026-08-24): a ceiling the laptop runs hid

Run on a 12-core / 47 GB Debian server (load average 0.14 at the start),
both systems in Docker on PostgreSQL 16, benchmark client on the same host
network. This was meant to be the clean re-measurement the laptop numbers
below still owed. It found something more useful than a better number.

**Sunder does not scale past four concurrent clients on this machine.**

| Concurrency | Sunder (write) | Databunker (write) |
|---|---|---|
| 1  | 131 rps | 92 rps |
| 4  | 451 rps | 270 rps |
| 16 | 468 rps | 443 rps |
| 32 | 459 rps | 463 rps |

Per request Sunder is still faster (+43% at c=1, +67% at c=4). But its
total throughput flattens at roughly 460 rps and stays there, while
Databunker keeps climbing and overtakes it at c=32.

**Cause, measured rather than inferred.** Sampling `pg_locks` during a
24-client run shows 7 of 8 held advisory locks in a waiting state: at any
moment exactly one session is inside the audit append and every other
active session is blocked behind it. `audit.AppendTx` takes
`pg_advisory_xact_lock` so the hash chain stays linear, and that lock is
held across a transaction that must commit to disk. The instance-wide
ceiling is therefore roughly one audited operation per serialized commit.

This machine's storage does `fdatasync` at 2,003 ops/sec (499 us/op).
A laptop NVMe is an order of magnitude faster at the same call, which is
why the laptop runs below never reached the plateau: the serialization was
always there, it was just cheap enough to stay invisible.

**What this means honestly.**

- The throughput advantage in the laptop numbers below is real but
  conditional: it holds where storage `fsync` is fast and concurrency is
  moderate. It is not a general claim about throughput under load.
- Sunder's maximum audited-operation rate is bounded by storage commit
  latency, not by cores. More CPU does not raise it.
- ~460 audited operations per second is still ample for the internal
  identity traffic of most organisations, and the per-request latency
  advantage is unaffected. But an instance fronting a high-volume public
  path needs either faster storage or a change to the chain design.
- Nothing here is a correctness problem. The linear chain is what makes
  the audit log tamper-evident; the lock is what keeps it linear.

**Options if this ceiling matters for a deployment** (none implemented, all
trade something away): a chain per scope instead of one per instance
(parallel writers, but "which scope touched this person" needs a join
across chains); batching several records under one lock acquisition
(higher throughput, coarser ordering); or moving the chain to an append
log outside the transaction (much faster, but loses the same-transaction
guarantee that an operation and its audit record commit together).

## Result summary (2026-08-23, review pass 4 build, quieter machine)

Re-measured on the pass-4 build with the machine largely free (load average
~4 at the start, drifting to ~8 under the benchmark's own load). Both
systems in the same window, interleaved, five rounds of n=3000 at 16
concurrent clients, plus one clean 5,000-request pass per operation. Zero
errors on both sides in the clean pass.

| Operation | Sunder | Databunker | Advantage |
|---|---|---|---|
| **write** | **2,729 rps**, p50 5.62 ms, p99 9.77 ms | 1,295 rps, p50 12.09 ms, p99 26.29 ms | **+111%**, p99 2.7x lower |
| **lookup** | **3,439 rps**, p50 4.53 ms, p99 6.25 ms | 2,032 rps, p50 7.18 ms, p99 20.02 ms | **+69%**, p99 3.2x lower |
| **read** | **3,443 rps**, p50 4.51 ms, p99 5.64 ms | 2,139 rps, p50 6.45 ms, p99 19.33 ms | **+61%**, p99 3.4x lower |

Medians of the five interleaved rounds agree and are slightly wider:
write +134%, lookup +78%, read +75% (Sunder 2,572 / 3,374 / 3,277 rps
against 1,098 / 1,893 / 1,871). Two Databunker measurements in round 5
(lookup 328 rps, read no result) were discarded as a failed run rather than
averaged in - noting it here because silently dropping them would flatter
the comparison.

**The +50% target now holds on every operation**, and by a wider margin
than the 2026-08-22 run below - which also settles the previous round's
open question: the +30% read figure measured under load average 10-14 was
machine noise, not the pass-4 tombstone join. Sunder does more work per
request throughout: a hash-chained audit record in the same transaction,
keyed-HMAC search tokens per identifier, purpose and consent checks.

One asymmetry worth stating: across the five rounds both systems accumulate
rows, and their trends diverge - Sunder's write throughput rose (2,108 ->
2,824 rps, caches warming) while Databunker's fell (1,325 -> 1,076 rps).
Part of the advantage above therefore reflects Databunker degrading with
table size within a single run. Neither system was tuned; both ran their
default configuration on PostgreSQL 16 in Docker.

This is a laptop under a real desktop load, not a controlled server
benchmark: quote the ratios, not the absolute numbers.

## Result summary (2026-08-22, idle machine, pre-Phase-2 build)

n=5000 requests per op, 16 concurrent clients, zero errors on both sides:

| Operation | Sunder | Databunker (OSS) | Throughput advantage | p99 advantage |
|---|---|---|---|---|
| **write** (create contact/user) | **2,173 rps**, p50 6.95 ms, p99 11.9 ms | 1,091 rps, p50 13.7 ms, p99 38.9 ms | **+99%** | **3.3× lower** |
| **lookup** (find by email) | **2,837 rps**, p50 5.38 ms, p99 9.4 ms | 1,885 rps, p50 8.13 ms, p99 20.9 ms | **+50%** | **2.2× lower** |
| **read** (by CID / token) | **2,843 rps**, p50 5.41 ms, p99 8.4 ms | 1,811 rps, p50 8.12 ms, p99 23.9 ms | **+57%** | **2.8× lower** |

Sunder clears the +50% efficiency target on every operation - while doing
MORE work per request than Databunker does: every Sunder operation writes a
hash-chained audit record inside the same transaction, computes keyed-HMAC
search tokens per identifier, and enforces per-client purpose checks.

Against Databunker **Pro's published numbers** (their AWS m6i benchmark:
read p50/p95/p99 ≈ 14/15/16 ms, ~660 reads/s at 16 clients): Sunder on a
laptop reads at p99 8.4 ms and 2,843 rps. Hardware differs, so the
head-to-head above is the defensible comparison; the published-number gap
is directional only.

## Methodology

- **Same machine** (Apple Silicon laptop), both systems and both databases
  in Docker Desktop.
- **Same engine**: PostgreSQL 16 for both (Databunker configured with its
  PGSQL backend, not the demo SQLite).
- **Same tool**: `benchmark/bench.go` (this directory) - one Go harness,
  worker pool, full latency capture, exact percentiles (no HDR bucketing).
- **Same payload semantics**: create = email + phone + name + 2 custom
  fields; lookup = by email; read = by handle obtained beforehand (handles
  resolved before the measured phase).
- Fresh identity namespace per run (`-seed`), phone numbers namespaced per
  seed so unique indexes never collide across runs.

Known asymmetries (called out, not hidden):

| | Sunder | Databunker OSS |
|---|---|---|
| Read returns | one attribute (field-level, purpose-checked) | full record |
| Audit per op | hash-chained, same-transaction, globally ordered | own audit (not hash-chained) |
| Search index | keyed HMAC per identifier per live key version | hash index |
| Edition | open-source (= the product) | open-source (Pro not publicly runnable) |

## Reproduce

```sh
# 1. Sunder (from repo root)
docker compose -f deploy/docker-compose.yml up --build -d
CRED=$(docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
  -id bench -name Bench -scope crm \
  -actions contacts.register,lookup,attributes.read -purposes benchmark -rate 10000000 | tail -1)

# 2. Databunker on its own PostgreSQL 16
docker network create bench-net
docker run -d --name bench-pg --network bench-net \
  -e POSTGRES_PASSWORD=benchpass postgres:16
docker exec bench-pg psql -U postgres -c "CREATE DATABASE databunkerdb"
MK=$(python3 -c "import secrets;print(secrets.token_hex(24))")
docker run --rm --network bench-net -e PGSSLMODE=disable -e DATABUNKER_MASTERKEY=$MK \
  -e DATABUNKER_ROOTTOKEN=DEMO -e PGSQL_USER_NAME=postgres -e PGSQL_USER_PASS=benchpass \
  -e PGSQL_HOST=bench-pg --entrypoint /databunker/bin/databunker \
  securitybunker/databunker:latest -init -db databunkerdb
docker run -d --name bench-dbunker --network bench-net -p 127.0.0.1:3000:3000 \
  -e PGSSLMODE=disable -e DATABUNKER_MASTERKEY=$MK -e DATABUNKER_ROOTTOKEN=DEMO \
  -e PGSQL_USER_NAME=postgres -e PGSQL_USER_PASS=benchpass -e PGSQL_HOST=bench-pg \
  --entrypoint /databunker/bin/databunker securitybunker/databunker:latest \
  -start -db databunkerdb -conf /databunker/conf/databunker.yaml

# 3. Run (fresh seed per round; write must precede lookup/read)
for op in write lookup read; do
  go run ./benchmark -target sunder     -base http://localhost:8080 -cred "$CRED" -op $op -n 5000 -c 16 -seed round1
done
for op in write lookup read; do
  go run ./benchmark -target databunker -base http://localhost:3000 -cred DEMO    -op $op -n 5000 -c 16 -seed round1
done
```

## What made Sunder fast

- Single indexed point queries on the hot paths (HMAC token = exact match).
- `CachingKeystore`: key material is immutable per versioned name, so it is
  cached in process memory - zero keystore I/O per request.
- pgx connection pooling, stdlib HTTP router, no middleware stack.
- The audit chain's global ordering lock is held only for the final
  append+commit window of each transaction.

Laptop numbers are indicative; contractual targets run on the reference
deployment (docs/DESIGN.md, performance targets).
