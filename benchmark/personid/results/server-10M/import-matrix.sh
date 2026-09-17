#!/usr/bin/env bash
# The import matrix, rebuilt to the reviewer's protocol:
#
#   - INTERLEAVED rounds (v4, v7, bigint | v4, v7, bigint | ...) so thermal
#     drift, cache history and autovacuum cycles cannot correlate with a
#     variant. Blocked ordering (AAA BBB CCC) folds any drift into the result
#     as if it were signal.
#   - N rounds per variant; the MEDIAN is the reported number.
#   - No rps cells here at all - the rps harness has ~±30% run variance and
#     answers a different question. This matrix measures the long batch.
#   - Per run, the metrics that have NO variance and explain the rest:
#       * WAL delta over the import (pg_current_wal_lsn before/after) - the
#         causal variable: if WAL ratios track time ratios, the import is
#         I/O bound and the timing comparison is meaningful.
#       * relation sizes after load and after VACUUM (heap, pkey, ident_uq,
#         search_idx) - bloat as a number instead of a hypothesis.
#   - SB=<size> runs the same import with shared_buffers deliberately small,
#     simulating the index-to-RAM ratio of a 200M deployment on 10M data.
#
# One instance of this script at a time; each run gets a FRESH stack.
set -uo pipefail
export PATH=$PATH:/usr/local/go/bin
ROUNDS=${ROUNDS:-3}
N=${N:-10000000}
SB=${SB:-12GB}
LOCK=/tmp/measure4.lock
if ! mkdir "$LOCK" 2>/dev/null; then echo "another measurement is running"; exit 1; fi
trap 'rm -rf "$LOCK"' EXIT
OUT=~/phase7/import-matrix-sb$SB.txt
: > "$OUT"
log() { echo "$*" | tee -a "$OUT"; }
psql_() { docker compose -f import-stack.yml exec -T sunder-db psql -U sunder -d sunder "$@" 2>/dev/null; }

# shared_buffers is parameterized through the compose file once.
cd ~/sunder-bench
python3 - "$SB" <<PY
import sys
sb = sys.argv[1]
s = open("import-stack.yml").read()
import re
s2 = re.sub(r"shared_buffers=\S+", "shared_buffers=%s" % sb, s)
open("import-stack.yml","w").write(s2)
print("shared_buffers=%s" % sb)
PY

tree_for() { case "$1" in bigint) echo ~/sunder-bigint-tree;; *) echo ~/sunder-main-tree;; esac; }

one_run() { # variant round
  local V=$1 R=$2 STAMP; STAMP=$(date +%s)
  log ""
  log "=== round $R  variant $V  ==="
  rsync -a --delete --exclude bench-stack.yml --exclude import-stack.yml "$(tree_for $V)/" ~/sunder-bench/
  cd ~/sunder-bench
  export PERSON_ID=$V
  docker compose -f import-stack.yml down -v >/dev/null 2>&1
  rm -rf ~/import-keys/* 2>/dev/null; chmod 777 ~/import-keys
  docker compose -f import-stack.yml build sunder >/tmp/im-build.log 2>&1 || { log "BUILD FAILED"; tail -5 /tmp/im-build.log | tee -a "$OUT"; return 1; }
  docker compose -f import-stack.yml up -d --wait sunder sunder-db >/dev/null 2>&1
  docker compose -f import-stack.yml exec -T sunder /sunder bootstrap >/dev/null 2>&1
  chmod 644 ~/import-keys/*.key 2>/dev/null

  python3 - "$N" "$STAMP" > /tmp/im.jsonl <<PY
import json, sys
n, stamp = int(sys.argv[1]), sys.argv[2]
for i in range(n):
    print(json.dumps({
        "email": "im-%s-%d@bench.example" % (stamp, i),
        "phone": "+385%012d" % (i + 300000000000),
        "name": "Matrix Row %d" % i,
        "attributes": {"segment": "bulk"},
    }, ensure_ascii=False))
PY
  docker cp /tmp/im.jsonl "$(docker compose -f import-stack.yml ps -q sunder)":/tmp/im.jsonl >/dev/null
  local wal0; wal0=$(psql_ -t -A -c "SELECT pg_current_wal_lsn()")
  local t0; t0=$(date +%s)
  docker compose -f import-stack.yml exec -T -e SUNDER_PERSON_ID=$V sunder \
    /sunder import -file /tmp/im.jsonl -scope crm -offline -parallel 12 -timing > /tmp/im-out.txt 2>&1
  local rc=$? t1; t1=$(date +%s)
  local wal1; wal1=$(psql_ -t -A -c "SELECT pg_current_wal_lsn()")
  local walgb; walgb=$(psql_ -t -A -c "SELECT round(pg_wal_lsn_diff('$wal1','$wal0')/1024.0/1024/1024, 2)")
  log "TOTAL exit=$rc wall=$(( t1 - t0 ))s  rows/s=$(( N / (t1 - t0) ))  WAL=${walgb}GB"
  grep -E "import done|timing:|index rebuilt" /tmp/im-out.txt | sed 's/^/  /' | tee -a "$OUT"
  log "  sizes after load:"
  psql_ -t -A -F"|" -c "SELECT relname, pg_size_pretty(pg_relation_size(oid)) FROM pg_class WHERE relname IN ('persons','person_tokens','person_tokens_pkey','person_tokens_ident_uq','person_tokens_search_idx','persons_pkey') ORDER BY relname" | sed 's/^/    /' | tee -a "$OUT"
  local tv0; tv0=$(date +%s)
  psql_ -c "VACUUM ANALYZE person_tokens, persons, cids" >/dev/null
  log "  VACUUM: $(( $(date +%s) - tv0 ))s; sizes after vacuum:"
  psql_ -t -A -F"|" -c "SELECT relname, pg_size_pretty(pg_relation_size(oid)) FROM pg_class WHERE relname IN ('person_tokens_pkey','person_tokens_ident_uq','person_tokens_search_idx') ORDER BY relname" | sed 's/^/    /' | tee -a "$OUT"
  rm -f /tmp/im.jsonl
}

log "import matrix: rounds=$ROUNDS n=$N shared_buffers=$SB interleaved v7,bigint"
for R in $(seq 1 "$ROUNDS"); do
  for V in v7 bigint; do   # v4 dropped from the product - not measured (Filip)
    one_run "$V" "$R" || log "round $R $V FAILED"
  done
done
log ""
log "ALL DONE $(date -Is)"
