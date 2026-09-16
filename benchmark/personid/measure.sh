#!/usr/bin/env bash
# A/B the person-id shape (SUNDER_PERSON_ID=v4 vs v7) on `sunder import
# -offline`, the long batch that decides a storage question - not rps cells.
#
# Protocol (see .claude/skills/measure/SKILL.md, every rule of which this
# script exists to enforce):
#   - one dedicated Postgres container with a bounded memory budget, so the
#     index-to-RAM ratio is a parameter (PG_MEM / SHARED_BUFFERS), not
#     whatever the host happens to have;
#   - a fresh database per run (DROP/CREATE + migrate), so no run inherits
#     another's bloat, cache history or half-imported rows;
#   - variants INTERLEAVED (v4 v7 v4 v7 ...), REPEATS rounds, median reported,
#     every raw run kept;
#   - deterministic metrics first: relation sizes after the load and after
#     VACUUM ANALYZE, and the WAL written over the run;
#   - one measurement at a time (lock dir), the database asserted alive
#     before each run, the binary built from THIS tree and its revision
#     recorded.
#
# usage: benchmark/personid/measure.sh [ROWS] [REPEATS]
# env:   PG_MEM=6g SHARED_BUFFERS=1536MB PARALLEL=8 PG_PORT=55433 PG_IMAGE=postgres:18
#        OUT=benchmark/personid/results/<stamp>
set -euo pipefail
cd "$(dirname "$0")/../.."

ROWS="${1:-1000000}"
REPEATS="${2:-3}"
PG_MEM="${PG_MEM:-6g}"
SHARED_BUFFERS="${SHARED_BUFFERS:-1536MB}"
PARALLEL="${PARALLEL:-8}"
PG_PORT="${PG_PORT:-55433}"
PG_IMAGE="${PG_IMAGE:-postgres:18}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-benchmark/personid/results/$STAMP}"
CONTAINER="sunder-personid-pg"
LOCK="/tmp/sunder-personid-measure.lock"

mkdir "$LOCK" 2>/dev/null || { echo "another measurement holds $LOCK - one at a time" >&2; exit 1; }
trap 'rm -rf "$LOCK"' EXIT
mkdir -p "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/log.txt"; }

# ---- binary from THIS tree, revision recorded ------------------------------
BIN="$OUT/sunder"
go build -o "$BIN" ./cmd/sunder
REV="$(git rev-parse --short HEAD)$(git diff --quiet || echo '-dirty')"
{
  echo "rev=$REV rows=$ROWS repeats=$REPEATS parallel=$PARALLEL"
  echo "pg_image=$PG_IMAGE pg_mem=$PG_MEM shared_buffers=$SHARED_BUFFERS"
  echo "host=$(uname -srm) go=$(go version | awk '{print $3}')"
  echo "docker=$(docker info --format '{{.NCPU}} cpus, {{.MemTotal}} bytes VM' 2>/dev/null)"
} | tee "$OUT/conditions.txt"

# ---- fixture: identical bytes for every variant -----------------------------
DATA="$OUT/contacts-$ROWS.jsonl"
log "generating $ROWS contacts"
python3 benchmark/personid/gen-contacts.py "$ROWS" 20260917 > "$DATA"
log "fixture: $(wc -l < "$DATA") lines, $(du -h "$DATA" | cut -f1)"

# ---- one Postgres with a bounded memory budget -------------------------------
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --memory="$PG_MEM" --memory-swap="$PG_MEM" \
  -e POSTGRES_USER=sunder -e POSTGRES_PASSWORD=sunder -e POSTGRES_DB=postgres \
  -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" \
  postgres -c "shared_buffers=$SHARED_BUFFERS" -c max_wal_size=4GB -c random_page_cost=1.1 \
           -c effective_cache_size="$SHARED_BUFFERS" -c checkpoint_timeout=15min >/dev/null
trap 'rm -rf "$LOCK"; docker rm -f "$CONTAINER" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 60); do
  docker exec "$CONTAINER" pg_isready -U sunder -q && break
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U sunder -q || { log "postgres never became ready"; exit 1; }
psql_admin() { docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U sunder -d postgres -qAt "$@"; }
psql_bench() { docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U sunder -d sunder_bench -qAt "$@"; }
psql_admin -c "SHOW shared_buffers" | sed 's/^/shared_buffers (effective): /' | tee -a "$OUT/conditions.txt"
psql_admin -c "SELECT version()" | tee -a "$OUT/conditions.txt"

# ---- keystore shared by every run: same keys => same tokens for same input ---
KS="$OUT/keystore"; mkdir -p "$KS"
export SUNDER_KEYSTORE=file SUNDER_KEYSTORE_PATH="$KS"
export SUNDER_DB_URL="postgres://sunder:sunder@127.0.0.1:$PG_PORT/sunder_bench"

SIZES_SQL="SELECT relname, pg_relation_size(oid) FROM pg_class
           WHERE relname IN ('person_tokens','person_tokens_pkey','person_tokens_ident_uq',
                             'person_tokens_search_idx','persons','persons_pkey','cids','cids_pkey')
           ORDER BY relname"

RESULTS="$OUT/runs.tsv"
echo -e "round\tvariant\tseconds\trows_per_s\twal_mb\tpkey_mb_after_load\tpkey_mb_after_vacuum\ttokens_heap_mb\tident_uq_mb\tsearch_idx_mb\tcids_pkey_mb" > "$RESULTS"

run_one() {
  local round="$1" variant="$2" tag="r${1}-${2}"
  # Alive, and fresh: a run against a dead or half-loaded database is fiction.
  docker exec "$CONTAINER" pg_isready -U sunder -q || { log "$tag: postgres not alive, refusing"; exit 1; }
  psql_admin -c "DROP DATABASE IF EXISTS sunder_bench" >/dev/null
  psql_admin -c "CREATE DATABASE sunder_bench" >/dev/null
  "$BIN" migrate >"$OUT/$tag.migrate.log" 2>&1
  psql_bench -c "CHECKPOINT" >/dev/null
  local wal0; wal0="$(psql_bench -c "SELECT pg_current_wal_lsn()")"
  local t0; t0="$(date +%s.%N)"
  SUNDER_PERSON_ID="$variant" "$BIN" import -file "$DATA" -scope bench -offline -parallel "$PARALLEL" -timing \
    >"$OUT/$tag.import.log" 2>&1 || { log "$tag: import FAILED, see $OUT/$tag.import.log"; exit 1; }
  local t1; t1="$(date +%s.%N)"
  local wal1; wal1="$(psql_bench -c "SELECT pg_current_wal_lsn()")"
  local secs; secs="$(python3 -c "print(round($t1-$t0,1))")"
  local imported; imported="$(grep -oE 'import done: [0-9]+ imported' "$OUT/$tag.import.log" | grep -oE '[0-9]+' | head -1)"
  [ "$imported" = "$ROWS" ] || { log "$tag: imported $imported of $ROWS - not a valid run"; exit 1; }
  local rps; rps="$(python3 -c "print(round($ROWS/$secs))")"
  local walmb; walmb="$(psql_bench -c "SELECT round(pg_wal_lsn_diff('$wal1','$wal0')/1048576.0)")"
  psql_bench -c "$SIZES_SQL" > "$OUT/$tag.sizes-after-load.tsv"
  psql_bench -c "VACUUM ANALYZE" >/dev/null
  psql_bench -c "$SIZES_SQL" > "$OUT/$tag.sizes-after-vacuum.tsv"
  # Proves the rebuild re-proved the invariant: the unique index must exist.
  psql_bench -c "SELECT indexdef FROM pg_indexes WHERE indexname='person_tokens_ident_uq'" | grep -q UNIQUE \
    || { log "$tag: ident_uq is not UNIQUE after the import - invalid vault"; exit 1; }
  mb() { awk -F'|' -v n="$1" '$1==n {printf "%.0f", $2/1048576}' "$2"; }
  echo -e "$round\t$variant\t$secs\t$rps\t$walmb\t$(mb person_tokens_pkey "$OUT/$tag.sizes-after-load.tsv")\t$(mb person_tokens_pkey "$OUT/$tag.sizes-after-vacuum.tsv")\t$(mb person_tokens "$OUT/$tag.sizes-after-vacuum.tsv")\t$(mb person_tokens_ident_uq "$OUT/$tag.sizes-after-vacuum.tsv")\t$(mb person_tokens_search_idx "$OUT/$tag.sizes-after-vacuum.tsv")\t$(mb cids_pkey "$OUT/$tag.sizes-after-vacuum.tsv")" >> "$RESULTS"
  log "$tag: ${secs}s = $rps rows/s, WAL ${walmb} MB, pkey after load $(mb person_tokens_pkey "$OUT/$tag.sizes-after-load.tsv") MB"
}

for round in $(seq 1 "$REPEATS"); do
  for variant in v4 v7; do
    run_one "$round" "$variant"
  done
done

# ---- summary: medians per variant, raw rounds kept above ---------------------
python3 - "$RESULTS" "$OUT/summary.md" "$ROWS" "$PARALLEL" "$PG_MEM" "$SHARED_BUFFERS" "$REV" <<'PY'
import csv, statistics, sys
path, out, rows, par, mem, sb, rev = sys.argv[1:]
runs = list(csv.DictReader(open(path), delimiter="\t"))
cols = ["seconds", "rows_per_s", "wal_mb", "pkey_mb_after_load", "pkey_mb_after_vacuum",
        "tokens_heap_mb", "ident_uq_mb", "search_idx_mb", "cids_pkey_mb"]
med = {}
for v in ("v4", "v7"):
    rs = [r for r in runs if r["variant"] == v]
    med[v] = {c: statistics.median(float(r[c]) for r in rs) for c in cols}
    med[v]["raw_rps"] = [r["rows_per_s"] for r in rs]
lines = [f"### person-id shape, `sunder import -offline -parallel {par}`, {int(rows):,} rows, Postgres {mem} RAM / shared_buffers {sb}, rev {rev}", "",
         "| metric | v4 (random) | v7 (time-ordered) | v7 / v4 |", "|---|---|---|---|"]
for c, label in [("rows_per_s", "rows/s (median)"), ("seconds", "wall seconds (median)"),
                 ("wal_mb", "WAL written, MB"), ("pkey_mb_after_load", "person_tokens_pkey after load, MB"),
                 ("pkey_mb_after_vacuum", "person_tokens_pkey after VACUUM ANALYZE, MB"),
                 ("tokens_heap_mb", "person_tokens heap, MB"), ("ident_uq_mb", "ident_uq, MB"),
                 ("search_idx_mb", "search_idx, MB"), ("cids_pkey_mb", "cids_pkey, MB")]:
    a, b = med["v4"][c], med["v7"][c]
    ratio = f"{b/a:.2f}x" if a else "-"
    lines.append(f"| {label} | {a:,.0f} | {b:,.0f} | {ratio} |")
lines += ["", f"raw rows/s per round - v4: {', '.join(med['v4']['raw_rps'])}; v7: {', '.join(med['v7']['raw_rps'])}",
          "", "WAL ratio vs time ratio: if they track, the run is I/O bound and the timing comparison means something; if not, it measures CPU."]
open(out, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
log "done: $OUT"
