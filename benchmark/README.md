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
why the laptop runs below never reached the plateau.

> **Correction (2026-08-25).** The paragraph that used to follow blamed
> that `fdatasync` figure for the ceiling: "bounded by storage commit
> latency, not by cores". The 26.8M-contact scale test disproved it. Group
> commit amortizes `fsync` across concurrent committers, and the same
> storage sustains **4,914 commits/sec** when the advisory lock is removed
> from an otherwise identical transaction. Storage was never the bound.
> The lock is, on its own. See the scale-test section below and Phase 4 in
> `PLAN.md`.

**What this means honestly.**

- The throughput advantage in the laptop numbers below is real but
  conditional: it holds at moderate concurrency, below the plateau. It is
  not a general claim about throughput under load.
- Sunder's maximum audited-operation rate is bounded by one serialized
  critical section, not by cores and not by storage. Neither more CPU nor
  faster disks raise it; removing the serialization does.
- ~460 audited operations per second is still ample for the internal
  identity traffic of most organisations, and the per-request latency
  advantage is unaffected. But an instance fronting a high-volume public
  path needs a change to the chain design.
- Nothing here is a correctness problem. The linear chain is what makes
  the audit log tamper-evident; the lock is what keeps it linear.

## Scale test (2026-08-25): 26.8M contacts, and where the ceiling really is

Same server, Postgres tuned off its 128 MB defaults first (`shared_buffers`
12GB, `effective_cache_size` 32GB, `max_wal_size` 16GB,
`random_page_cost` 1.1). Loaded with `benchmark/bulkload`, which COPYs
rows carrying real keyed-HMAC tokens and real AEAD blobs computed through
the server's own engine - a bulk-loaded contact resolves through the API
exactly like a registered one, verified before measuring.

**Dataset size barely moves lookup throughput**, even as the token index
grows past what the buffer cache holds:

| contacts | DB size | person_tokens index | buffer hit | lookup c=16 | lookup c=1 |
|---------:|--------:|--------------------:|-----------:|------------:|-----------:|
|  1M      | 1.6 GB  |   858 MB            | 100.00%    | 423.6 rps   | 241.8 rps  |
|  5M      | 8.0 GB  |  4289 MB            | 100.00%    | 398.9 rps   | 222.5 rps  |
| 10M      |  16 GB  |  8581 MB            |  99.52%    | 269.7 rps   | 183.4 rps  |
| 20M      |  31 GB  |    17 GB            |  98.77%    | 366.2 rps   | 253.2 rps  |

**Concurrency does not move it either.** At 26.8M contacts, throughput
flattens at ~420 rps from c=8 while p50 doubles with every doubling of
concurrency - added clients buy queueing delay and nothing else:

| concurrency | rps   | p50      | p95       |
|------------:|------:|---------:|----------:|
| 1           | 160.4 |  4.99 ms |  12.12 ms |
| 4           | 380.0 |  8.75 ms |  16.67 ms |
| 8           | 423.6 | 15.32 ms |  31.27 ms |
| 16          | 415.7 | 31.89 ms |  61.61 ms |
| 32          | 449.2 | 60.06 ms | 103.89 ms |

**Where the backends are.** Sampling `pg_stat_activity` during the c=32
run: 117 of 124 active-backend samples sat in `Lock/advisory`, against 3
in `IO/WALSync`.

**Apportioning the cost.** pgbench against a clone of the audit table,
each variant stripping one mechanism:

| variant                                         | c=1 | c=8  | c=32     |
|-------------------------------------------------|----:|-----:|---------:|
| V1 lock + head SELECT + INSERT + COMMIT (today) | 492 |  342 | **298**  |
| V2 head SELECT + INSERT + COMMIT (no lock)      | 379 | 1821 | **4114** |
| V3 INSERT + COMMIT only                         | 618 | 2609 | **4914** |

V1 scales negatively. Removing the advisory lock alone is **13.8x** at
c=32, on the same hardware and the same durability settings.

**Not the index.** `EXPLAIN (ANALYZE, BUFFERS)` on the production lookup
query at 26.8M contacts: Index Scan, 6 shared buffers, 0.046 ms warm /
0.144 ms cold - about 1% of a 4.99 ms request.

**Two real scale effects, neither on the request path.** COPY ingest falls
from 28,319 rows/s at 1M to ~2,700 rows/s past 25M, because HMAC output is
uniformly random and index inserts have no locality. And indexes dominate
storage: `person_tokens` carried 6.9 GB of heap under 23 GB of indexes,
14 GB of which `pg_stat_user_indexes` showed was never once read - those
two indexes exist only to enforce uniqueness.

**Index diet, applied and measured.** Migration 0020 dropped
`person_tokens_person_idx` (a strict prefix of the primary key, which the
planner already preferred) and narrowed `person_tokens_lookup_idx` to
`WHERE kind='name'`, letting email and phone fall through to the
`ident_uq` index the dedup invariant already pays for:

| | before | after |
|---|---|---|
| `person_tokens` indexes | 23 GB | **14 GB** |
| database | 42 GB | **33 GB** |
| migration runtime | | 15.7 s |

Throughput did not change (171.6 / 363.7 / 343.6 rps at c=1/8/32), and was
not expected to: the plateau is the lock, not the index. What this buys is
storage and cache headroom for when P4.1 removes the plateau.

Phase 4 in `PLAN.md` specifies the rest of the work these numbers imply.

## P4.1 applied (2026-08-25): the ceiling is gone

Same server, same 26.8M dataset, the only change being
`SUNDER_AUDIT_SEALING=async` (the new default): audited operations INSERT
unsealed audit rows with no lock and a batched sealer chains them within
~2.2s. Lookup, before and after, side by side:

| concurrency | before (rps) | after (rps) | after p50 | after p95 |
|------------:|-------------:|------------:|----------:|----------:|
| 1           | 160.4        | 110.6       |  7.99 ms  | 11.98 ms  |
| 4           | 380.0        | 559.2       |  6.81 ms  | 11.55 ms  |
| 8           | 423.6        | **1,183.0** |  5.74 ms  | 12.13 ms  |
| 16          | 415.7        | **1,452.3** |  9.00 ms  | 20.87 ms  |
| 32          | 449.2        | **1,773.0** | 14.93 ms  | 35.42 ms  |
| 64          | (plateaued)  | **1,959.4** | 25.70 ms  | 64.01 ms  |

The plateau is gone: throughput now scales with concurrency instead of
flattening at ~420 rps, reaching **4.3x at c=32** and still climbing at
c=64. Latency IMPROVED under load (p50 at c=8: 15.32 -> 5.74 ms) because
requests queue on the pool, not on one advisory lock. Writes (full
registration: person + tokens + blob + consents) went from the shared
~460 rps ceiling to 750 rps at c=32, still scaling.

Chain integrity under that load, measured, not assumed: 374,504 audit
rows written during the sweeps, backlog of 1,303 unsealed rows drained to
0 within 4 s of load stopping, `chain_seq` dense from 1 to 374,504, and
`sunder verify-audit` reports the chain intact with 0 pending.

The single-client number (110.6 vs 160.4 rps) is the one honest
regression: p50 rose ~3 ms because the lookup's audit INSERT is a second
statement on a connection that previously did its work under an
already-held lock's shadow. It disappears into queueing gains from c=4
up, and c=1 is not a deployment shape anyone runs.

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
  SUNDER_CRED="$CRED" go run ./benchmark -target sunder     -base http://localhost:8080 -op $op -n 5000 -c 16 -seed round1
done
for op in write lookup read; do
  SUNDER_CRED=DEMO      go run ./benchmark -target databunker -base http://localhost:3000 -op $op -n 5000 -c 16 -seed round1
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

## Head-to-head re-run on the P4.1 build (2026-08-25)

Same server, interleaved, zero errors both sides. Deliberately tilted
AGAINST Sunder: Sunder answers over 20M contacts (dense id range of the
scale dataset), Databunker over its own ~10k set, and Sunder does more
per request (hash-chained audit, purpose and consent checks).

| operation | Sunder | Databunker | delta |
|---|---:|---:|---:|
| lookup c=8  |   840.0 rps | 472.1 rps | +78% |
| lookup c=32 | 1,134.8 rps | 772.5 rps | +47% |
| lookup c=64 | 1,386.7 rps | 698.1 rps | +99% |
| read  c=16  | 1,040.1 rps | 526.6 rps | +98% |
| write c=8   |   382.6 rps | 290.9 rps | +32% |
| write c=32  |   518.7 rps | 432.2 rps | +20% |

p99 is 1.5-2.6x lower on every operation (read: 57.2 vs 149.9 ms). The
pre-P4.1 server picture - Databunker overtaking Sunder past c=32 - is
inverted: Sunder now scales past it at every point and the gap WIDENS
with concurrency (Databunker declines from c=32 to c=64, Sunder climbs).

Honesty note on the earlier 1,959 rps figure: that sweep drew from a
26.8M keyspace whose top stripe had holes left by the interrupted bulk
load, so ~8% of probes were misses - audited, full-cost lookups, but
misses. The dense-keyspace numbers above are the ones to quote.

## Head-to-head on the completed Phase 4 build (2026-08-26)

Same server and dataset as above, now with `SUNDER_AUDIT_READS=bucketed`
(P4.2 default: hourly read buckets instead of a chained row per lookup).
Zero errors both sides on lookups and reads:

| operation | Sunder | Databunker | delta |
|---|---:|---:|---:|
| lookup c=8  | 1,589.1 rps | 716.5 rps | **2.2x** |
| lookup c=32 | 2,746.7 rps | 884.5 rps | **3.1x** |
| lookup c=64 | 2,466.9 rps | 599.7 rps | **4.1x** |
| read  c=16  | 1,568.9 rps | 723.4 rps | **2.2x** |

p99 is 2-4x lower throughout (lookup c=32: 29.0 vs 107.6 ms), and the gap
WIDENS with concurrency. Relative to the pre-P4.2 run, bucketed read
auditing lifted Sunder's lookup another ~1.5x (1,135 -> 2,747 rps at
c=32): the per-lookup chained INSERT became an UPSERT into a hot bucket
row.

Writes needed a third attempt to measure honestly: the first reused
seeds (turning Databunker's writes into duplicate rejections and Sunder's
into cheap reuse hits) and the second ran into an unrelated host I/O
stall that froze every in-flight request for 30 s. The clean run, load
average ~1, zero errors both sides:

| operation | Sunder | Databunker | delta |
|---|---:|---:|---:|
| write c=8  |   377.7 rps | 277.8 rps | **+36%** |
| write c=32 | 1,014.3 rps | 503.3 rps | **2.0x** |

## F1+F2 enabled: the cost of fuzzy and partial search (2026-08-26)

Same server, same 20M+ dataset, `SUNDER_SEARCH_FUZZY_NAME` and
`SUNDER_SEARCH_PHONE_SUFFIX` both ON (they default off):

| operation | measured | note |
|---|---:|---|
| lookup by exact email, c=8  | 2,196.2 rps | the path F1/F2 does not touch - fastest run yet |
| lookup by exact email, c=32 | 3,362.7 rps | ditto |
| write c=8  | 434.5 rps | inside the 378-1,014 band this host shows run to run |
| write c=32 | 629.4 rps | ditto - the 2 extra HMACs + 2 index rows per contact are lost in host noise |

Functional smoke on the same instance: a fresh contact registered as
"Ivana Đurđević" / +385957779999 resolves over HTTP by
`phone_suffix: "0957779999"` (national spelling) plus fuzzy
`name: "ivana djurdjevic"` (dj spelling) to the same CID - the vCard
caller-ID case end to end.

Migration note for large datasets: applying 0023 revalidates the
person_tokens kind constraint and rebuilds one partial index; on 53.6M
token rows that took a few minutes of `sunder serve` startup. Plan the
first deploy after this migration as a maintenance window at scale.
