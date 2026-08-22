# Benchmark: Sunder vs Databunker (head-to-head)

Goal: same machine, same database engine, same load tool, comparable
operations - and Sunder at least 50% more efficient.

## Result summary (2026-08-22)

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
