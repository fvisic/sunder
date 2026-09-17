#!/usr/bin/env bash
# The person-id experiment: one FULL protocol per variant, so v4, v7 and (on
# its own branch) bigint are compared on identical ground. Per variant:
#
#   1. a FRESH stack - down -v, empty database, the variant's id shape
#   2. offline import of 10M rows, timed end to end (the decay measurement)
#   3. write / lookup / read at c=8 and c=32 against ONE instance
#   4. the same three ops against THREE instances at once (one bench process
#      per instance, its own seed, summed) - the horizontal-scaling question
#      is whether the DATABASE serves three stateless replicas at 3x or
#      contends; the app itself holds no state that could stop it.
#
# Everything lands in ~/phase7/variant-$V.txt. One variant per invocation,
# under the same lock the other measurements use - two of these running at
# once would invalidate both.
set -uo pipefail
export PATH=$PATH:/usr/local/go/bin
V=${1:?usage: variant-bench.sh v4|v7 [rows]}
N=${2:-10000000}
LOCK=/tmp/measure4.lock
if ! mkdir "$LOCK" 2>/dev/null; then echo "another measurement is running"; exit 1; fi
trap 'rm -rf "$LOCK"' EXIT
STAMP=$(date +%s)
OUT=~/phase7/variant-$V.txt
: > "$OUT"
cd ~/sunder-bench
log() { echo "$*" | tee -a "$OUT"; }
psql_() { docker compose -f import-stack.yml exec -T sunder-db psql -U sunder -d sunder "$@" 2>/dev/null; }

log "=== variant $V: fresh stack, $N rows ==="
export PERSON_ID=$V
if [ "${SKIP_IMPORT:-0}" = "1" ]; then
  log "(SKIP_IMPORT=1: reusing the standing dataset, benches only)"
else
docker compose -f import-stack.yml down -v >/dev/null 2>&1
rm -rf ~/import-keys/* 2>/dev/null
docker compose -f import-stack.yml build sunder sunder2 sunder3 >/tmp/vb-build.log 2>&1 || { log "BUILD FAILED"; tail -5 /tmp/vb-build.log | tee -a "$OUT"; exit 1; }
docker compose -f import-stack.yml up -d --wait sunder sunder-db >/dev/null 2>&1
chmod 644 ~/import-keys/*.key 2>/dev/null
docker compose -f import-stack.yml exec -T sunder /sunder bootstrap >/dev/null 2>&1
chmod 644 ~/import-keys/*.key 2>/dev/null
state=$(docker compose -f import-stack.yml ps --format '{{.Service}} {{.State}}' | grep '^sunder ' | awk '{print $2}')
[ "$state" = "running" ] || { log "SUNDER NOT RUNNING"; docker compose -f import-stack.yml logs --tail=5 sunder | tee -a "$OUT"; exit 1; }

log ""
log "--- offline import, $N rows, parallel=12 ---"
python3 - "$N" "$STAMP" > /tmp/vb.jsonl <<PY
import json, sys
n, stamp = int(sys.argv[1]), sys.argv[2]
for i in range(n):
    print(json.dumps({
        "email": "vb-%s-%d@bench.example" % (stamp, i),
        "phone": "+385%012d" % (i + 200000000000),
        "name": "Variant Bench %d" % i,
        "attributes": {"segment": "bulk"},
    }, ensure_ascii=False))
PY
docker cp /tmp/vb.jsonl "$(docker compose -f import-stack.yml ps -q sunder)":/tmp/vb.jsonl >/dev/null
t0=$(date +%s)
docker compose -f import-stack.yml exec -T -e SUNDER_PERSON_ID=$V sunder \
  /sunder import -file /tmp/vb.jsonl -scope crm -offline -parallel 12 -timing > /tmp/vb-import.out 2>&1
rc=$?
wall=$(( $(date +%s) - t0 ))
log "import: exit=$rc wall=${wall}s -> $(( N / wall )) rows/s incl. index rebuild"
grep -E "import done|timing:|index rebuilt" /tmp/vb-import.out | tee -a "$OUT"
rm -f /tmp/vb.jsonl
psql_ -t -A -F"|" -c "SELECT (SELECT count(*) FROM persons), (SELECT count(*) FROM person_tokens), pg_size_pretty(pg_total_relation_size('person_tokens'::regclass))" | tee -a "$OUT"
fi

CRED=$(docker compose -f import-stack.yml exec -T sunder /sunder client create \
  -id vb$STAMP -name VB -scope crm \
  -actions contacts.register,lookup,attributes.read -purposes benchmark \
  -rate 100000000 -ttl 7d 2>/dev/null | tail -1)
[ -n "$CRED" ] || { log "NO CREDENTIAL"; exit 1; }
export SUNDER_CRED="$CRED"

cell() { # base op c seed -> table row
  local base=$1 op=$2 c=$3 seed=$4 f=/tmp/vb-cell.json
  go run ./benchmark -target sunder -base "$base" -op "$op" -n 3000 -c "$c" -seed "$seed" > $f 2>/tmp/vb-cell.err
  python3 ~/phase7/parse_cell.py $f
}

log ""
log "--- single instance (18090) ---"
log "op       c    rps       p50      p95      p99   errors"
# One seed per concurrency level, shared across ops IN ORDER: write creates
# the 3000 contacts that lookup then resolves and read then fetches. Per-op
# seeds made lookup search for contacts nobody had written - 3000 misses
# reported as a measurement.
for c in 8 32; do
  for op in write lookup read; do
    log "$(printf '%-8s %-4s %s' "$op" "$c" "$(cell http://127.0.0.1:18090 $op $c s-$STAMP-$c)")"
  done
done

log ""
log "--- three instances (18090/18081/18082), c=8 EACH, concurrently ---"
docker compose -f import-stack.yml up -d --wait sunder2 sunder3 >/dev/null 2>&1
sleep 5
for op in write lookup read; do
  pids=""
  for port in 18090 18081 18082; do
    ( go run ./benchmark -target sunder -base http://127.0.0.1:$port -op $op -n 3000 -c 8 \
        -seed m-$STAMP-$port > /tmp/vb-m-$port.json 2>/tmp/vb-m-$port.err ) &
    pids="$pids $!"
  done
  wait $pids
  python3 - "$op" <<PY | tee -a "$OUT"
import json, re, sys
op = sys.argv[1]
tot = 0.0; errs = 0; p99s = []
for port in (18090, 18081, 18082):
    raw = open("/tmp/vb-m-%d.json" % port).read()
    m = re.search(r"\{[^{}]*\"rps\"[^{}]*\}", raw, re.S)
    if not m:
        print("%-8s port %d: NO-JSON %r" % (op, port, raw[:60])); continue
    d = json.loads(m.group(0))
    tot += float(d["rps"]); errs += int(d["errors"]); p99s.append(float(d["p99_ms"]))
print("%-8s 3x c=8: TOTAL %8.0f rps  errors %d  worst p99 %6.1f ms" % (op, tot, errs, max(p99s) if p99s else -1))
PY
done
log ""
log "done $(date -Is)"
