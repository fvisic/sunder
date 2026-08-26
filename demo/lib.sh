#!/usr/bin/env bash
#
# lib.sh - shared helpers for the feature demo scripts (F4-F9). Source it:
#   source "$(dirname "$0")/lib.sh"
#
# It provides: api / expect / pretty / jget / step / say, exactly matching
# quickstart.sh, plus require_cred. No jq - python3 does the JSON work.

SUNDER_URL="${SUNDER_URL:-http://localhost:8080}"

# require_cred VARNAME - fail with setup instructions if a credential is unset.
require_cred() {
  local var="$1"
  if [[ -z "${!var:-}" ]]; then
    echo "Missing $var. See this script's header for the client it needs." >&2
    exit 1
  fi
}

# api METHOD PATH CREDENTIAL [JSON_BODY] [EXTRA_HEADER]
# Fills globals STATUS and BODY. Never exits on non-2xx - steps assert with `expect`.
api() {
  local method="$1" path="$2" cred="$3" body="${4:-}" extra="${5:-}"
  local resp curlargs=(-sS -X "$method" "$SUNDER_URL$path" -w $'\n%{http_code}')
  [[ -n "$cred" ]] && curlargs+=(-H "Authorization: Bearer $cred")
  [[ -n "$extra" ]] && curlargs+=(-H "$extra")
  if [[ -n "$body" ]]; then
    curlargs+=(-H "Content-Type: application/json" -d "$body")
  fi
  resp=$(curl "${curlargs[@]}")
  STATUS="${resp##*$'\n'}"
  BODY="${resp%$'\n'*}"
}

# expect EXPECTED_STATUS LABEL
expect() {
  local want="$1" label="$2"
  if [[ "$STATUS" != "$want" ]]; then
    echo "FAIL: $label - expected HTTP $want, got HTTP $STATUS" >&2
    pretty >&2
    exit 1
  fi
  echo "  -> HTTP $STATUS (expected)"
  pretty
}

pretty() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("  (empty body)")
else:
    try:
        print("\n".join("  " + l for l in json.dumps(json.loads(raw), indent=2).splitlines()))
    except ValueError:
        print("  " + raw)
'
}

# jget FIELD - one top-level string field from the last JSON body.
jget() {
  printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[sys.argv[1]])' "$1"
}

step() {
  echo
  echo "============================================================"
  echo "  $1"
  echo "============================================================"
}

say() { echo "  $1"; }
