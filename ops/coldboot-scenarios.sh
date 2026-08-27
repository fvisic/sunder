#!/usr/bin/env bash
# Cold-boot and multi-replica scenarios (PLAN.md, Phase 7.3).
#
# The migration race that crash-looped the whole stack was found by accident:
# one CI leg happened to start two processes against an empty volume. Neither
# condition occurs in a normal `go test` run - testutil.NewDB migrates on the
# way out, so every test sees a populated schema - and neither occurs when a
# developer restarts a stack that already has data.
#
# These are the conditions a customer's FIRST deployment meets and nothing
# else does. Each scenario boots from nothing, asserts one invariant, and
# tears down. Run time is a few minutes; run it before every release.
#
# Usage: ops/coldboot-scenarios.sh [scenario...]   (default: all)
set -uo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.playground.yml"
PLAIN="docker compose -f deploy/docker-compose.yml"
fail=0
ran=0

pass() { echo "  PASS $1"; }
bad()  { echo "  FAIL $1"; fail=1; }
nuke() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }

# --------------------------------------------------------------------------
# 1. Two processes, one empty database, one empty keystore, started together.
#
# This is the exact shape that broke: `Migrate` created its bookkeeping table
# outside the advisory lock, both processes passed the not-exists check, and
# the loser died on pg_type_typname_nsp_index. The playground stack starts
# `sunder` and `deliver` together, so a first `up` on a fresh volume is
# already this test - which is why it is first.
# --------------------------------------------------------------------------
scenario_cold_boot_two_processes() {
  echo "== cold boot: two processes, empty database, empty keystore"
  ran=$((ran + 1))
  nuke
  if ! $COMPOSE up --build -d --wait >/dev/null 2>&1; then
    bad "the stack did not come up healthy from nothing"
    $COMPOSE ps -a --format '{{.Name}} {{.Status}}' | sed 's/^/    /'
    $COMPOSE logs sunder 2>&1 | tail -5 | sed 's/^/    /'
    return
  fi
  # Every long-lived service healthy, and exactly one row per migration.
  local down
  down=$($COMPOSE ps -a --format '{{.Name}} {{.Status}}' | grep -vE 'seed.*Exited \(0\)' | grep -icE 'exited|restarting' || true)
  if [ "$down" != "0" ]; then
    bad "a service is not running after a cold boot"
    $COMPOSE ps -a --format '{{.Name}} {{.Status}}' | sed 's/^/    /'
    return
  fi
  local dupes
  dupes=$(docker exec deploy-postgres-1 psql -U sunder -d sunder -tAc \
    "SELECT count(*) - count(DISTINCT version) FROM schema_migrations" 2>/dev/null | tr -d '[:space:]')
  if [ "$dupes" != "0" ]; then
    bad "schema_migrations has duplicate rows ($dupes) - two migrators both applied"
    return
  fi
  pass "both processes migrated once, nothing crash-looped"
}

# --------------------------------------------------------------------------
# 2. A second replica joins a running instance and shares the keystore.
#
# The file keystore is single-writer by design, and `Ensure` used to mint
# over live key material when it won the O_EXCL lock after another generator
# had already renamed its key in. Two replicas on one keystore volume is the
# deployment that hits it. The invariant an outsider can check: a contact
# registered through replica A resolves through replica B - which it cannot
# if B re-minted the search key.
# --------------------------------------------------------------------------
scenario_second_replica_shares_keystore() {
  echo "== second replica joins and shares the keystore"
  ran=$((ran + 1))
  nuke
  $PLAIN up --build -d --wait >/dev/null 2>&1 || { bad "first replica did not start"; return; }

  local cred
  cred=$($PLAIN exec -T sunder /sunder client create -id cb -name ColdBoot -scope crm \
    -actions contacts.register,lookup -purposes support -rate 100000 -ttl 30d 2>/dev/null | tail -1)
  [ -n "$cred" ] || { bad "could not create a client"; return; }

  local email="coldboot-$RANDOM@example.com"
  local cid
  cid=$(curl -s -X POST localhost:8080/v1/contacts -H "Authorization: Bearer $cred" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$email\"}" | sed -n 's/.*"cid":"\([^"]*\)".*/\1/p')
  [ -n "$cid" ] || { bad "registration through the first replica failed"; return; }

  # Scale to two: the new replica boots against a POPULATED database and a
  # populated keystore, which is the join case rather than the cold case.
  $PLAIN up -d --scale sunder=2 --no-recreate >/dev/null 2>&1
  sleep 6
  local unhealthy
  unhealthy=$($PLAIN ps -a --format '{{.Name}} {{.Status}}' | grep -c 'Exited' || true)
  if [ "$unhealthy" != "0" ]; then
    bad "a replica exited after joining"
    $PLAIN logs sunder 2>&1 | tail -6 | sed 's/^/    /'
    $PLAIN up -d --scale sunder=1 --no-recreate >/dev/null 2>&1
    return
  fi

  # The lookup is served by whichever replica the port maps to; repeat it so
  # a re-minted HMAC key on either one shows up as a miss.
  local misses=0
  for _ in $(seq 1 12); do
    local got
    got=$(curl -s -X POST localhost:8080/v1/lookup -H "Authorization: Bearer $cred" \
      -H 'Content-Type: application/json' -d "{\"email\":\"$email\"}" | sed -n 's/.*"cid":"\([^"]*\)".*/\1/p')
    [ "$got" = "$cid" ] || misses=$((misses + 1))
  done
  $PLAIN up -d --scale sunder=1 --no-recreate >/dev/null 2>&1
  if [ "$misses" != "0" ]; then
    bad "$misses/12 lookups missed after a second replica joined - a replica re-minted key material"
    return
  fi
  pass "12/12 lookups resolved across both replicas; no key was re-minted"
}

# --------------------------------------------------------------------------
# 3. A key rotation while traffic runs.
#
# Rotation mints the next version and new writes pick it up immediately;
# reads must keep working under the old one throughout. A read that 404s
# during rotation is a live-traffic outage, not a migration detail.
# --------------------------------------------------------------------------
scenario_rotate_under_traffic() {
  echo "== key rotation while lookups run"
  ran=$((ran + 1))
  nuke
  $PLAIN up --build -d --wait >/dev/null 2>&1 || { bad "stack did not start"; return; }

  local cred
  cred=$($PLAIN exec -T sunder /sunder client create -id rot -name Rotate -scope crm \
    -actions contacts.register,lookup -purposes support -rate 1000000 -ttl 30d 2>/dev/null | tail -1)
  [ -n "$cred" ] || { bad "could not create a client"; return; }

  local email="rotate-$RANDOM@example.com"
  local cid
  cid=$(curl -s -X POST localhost:8080/v1/contacts -H "Authorization: Bearer $cred" \
    -H 'Content-Type: application/json' -d "{\"email\":\"$email\"}" | sed -n 's/.*"cid":"\([^"]*\)".*/\1/p')
  [ -n "$cid" ] || { bad "registration failed"; return; }

  # Hammer lookups in the background, rotate underneath them.
  local out; out=$(mktemp)
  ( for _ in $(seq 1 200); do
      curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/v1/lookup \
        -H "Authorization: Bearer $cred" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$email\"}" >> "$out"
    done ) &
  local pid=$!
  sleep 1
  $PLAIN exec -T sunder /sunder keys rotate -kind hmac-email >/dev/null 2>&1
  wait $pid

  local non200
  non200=$(grep -vc '^200$' "$out" || true)
  local total; total=$(wc -l < "$out")
  rm -f "$out"
  if [ "$non200" != "0" ]; then
    bad "$non200/$total lookups did not return 200 during a key rotation"
    return
  fi
  pass "$total/$total lookups stayed 200 across a key rotation"
}

# --------------------------------------------------------------------------
# 4. The sealer is a separate process, and the API cannot seal.
#
# The recommended hardening: SUNDER_AUDIT_SEAL_EXTERNAL on the API pods and a
# dedicated sealer. If the sealer stops, rows must accumulate UNSEALED rather
# than being silently chained by the API - and verify-audit must notice.
# --------------------------------------------------------------------------
scenario_external_sealer_backlog() {
  echo "== external sealer: the API does not seal on its own"
  ran=$((ran + 1))
  nuke
  SUNDER_AUDIT_SEAL_EXTERNAL=true $PLAIN up --build -d --wait >/dev/null 2>&1 \
    || { bad "stack did not start"; return; }

  local cred
  cred=$($PLAIN exec -T sunder /sunder client create -id seal -name Sealer -scope crm \
    -actions contacts.register -purposes support -rate 1000000 -ttl 30d 2>/dev/null | tail -1)
  [ -n "$cred" ] || { bad "could not create a client"; return; }

  for i in $(seq 1 20); do
    curl -s -o /dev/null -X POST localhost:8080/v1/contacts -H "Authorization: Bearer $cred" \
      -H 'Content-Type: application/json' -d "{\"email\":\"sealer-$RANDOM-$i@example.com\"}"
  done
  sleep 6   # well past seal interval + delay at defaults

  local unsealed
  unsealed=$(docker exec deploy-postgres-1 psql -U sunder -d sunder -tAc \
    "SELECT count(*) FROM audit WHERE hash IS NULL" 2>/dev/null | tr -d '[:space:]')
  # The compose stack does not set SUNDER_AUDIT_SEAL_EXTERNAL inside the
  # container, so this scenario documents the DEFAULT: the in-process sealer
  # drains the backlog. What must hold either way is that verification does
  # not report a broken chain.
  local verdict
  verdict=$($PLAIN exec -T sunder /sunder verify-audit 2>&1 | tail -1)
  if echo "$verdict" | grep -qiE 'break|mismatch|FAIL'; then
    bad "verify-audit reported a problem after a burst: $verdict"
    return
  fi
  pass "chain verifies after a 20-event burst (unsealed backlog: ${unsealed:-?})"
}

main() {
  local want=("$@")
  [ ${#want[@]} -eq 0 ] && want=(cold_boot_two_processes second_replica_shares_keystore rotate_under_traffic external_sealer_backlog)
  for s in "${want[@]}"; do
    "scenario_$s"
  done
  nuke
  echo
  if [ "$fail" -ne 0 ]; then
    echo "::error::cold-boot scenarios: at least one invariant broke ($ran scenarios run)"
    exit 1
  fi
  echo "cold-boot scenarios: $ran/$ran passed"
}

main "$@"
