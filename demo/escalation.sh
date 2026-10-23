#!/usr/bin/env bash
# escalation.sh - Sunder demo: the delayed-notification (escalation e-mail)
# flow. Shows why a delayed send can never be "an OTI saved for later"
# (tokens live five minutes) and how issuer-authorized attribute sharing +
# just-in-time reads solve it: the notifier service stores ZERO PII, yet can
# e-mail the customer hours later - and a consent withdrawal stops it cold.
#
# Requires a running stack (deploy/docker-compose.yml) and two credentials:
#
#   SUNDER_CRED_CRM       scope crm:      contacts.register, oti.issue,
#                                         attributes.read,
#                                         purposes: escalation_notify
#
# attributes.read on the ISSUER is not decoration: an OTI carrying
# share_attributes IS a delegated read, so the read boundary applies to the
# credential that authorizes it (TOKENS-LOOKUP-6). Without it, step 2 is a
# 403 - which is how this script was found broken, having drifted out of
# sync with the server while nothing ran it.
#   SUNDER_CRED_NOTIFIER  scope notifier: oti.verify, attributes.read,
#                                         consent.manage,
#                                         purposes: escalation_notify
set -euo pipefail

SUNDER_URL="${SUNDER_URL:-http://localhost:8080}"

if [[ -z "${SUNDER_CRED_CRM:-}" || -z "${SUNDER_CRED_NOTIFIER:-}" ]]; then
  cat >&2 <<'EOF'
Missing credentials. Create them with:

  docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
    -id crm-esc -name CRM -scope crm \
    -actions contacts.register,oti.issue,attributes.read \
    -purposes escalation_notify -rate 1000

  docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
    -id notifier -name Notifier -scope notifier \
    -actions oti.verify,attributes.read,consent.manage \
    -purposes escalation_notify -rate 1000

then export SUNDER_CRED_CRM and SUNDER_CRED_NOTIFIER and re-run.
EOF
  exit 2
fi

say()  { printf '\n============================================================\n  %s\n============================================================\n' "$1"; }
note() { printf '  %s\n' "$1"; }

api() { # api CRED METHOD PATH [JSON] -> body + status in globals
  local cred="$1" method="$2" path="$3" body="${4:-}"
  local out
  if [[ -n "$body" ]]; then
    out=$(curl -sS -w $'\n%{http_code}' -X "$method" "$SUNDER_URL$path" \
      -H "Authorization: Bearer $cred" -H 'Content-Type: application/json' -d "$body")
  else
    out=$(curl -sS -w $'\n%{http_code}' -X "$method" "$SUNDER_URL$path" \
      -H "Authorization: Bearer $cred")
  fi
  RESP_STATUS="${out##*$'\n'}"
  RESP_BODY="${out%$'\n'*}"
}

expect() { # expect STATUS  (uses RESP_STATUS/RESP_BODY)
  note "-> HTTP $RESP_STATUS (expected $1)"
  echo "$RESP_BODY" | python3 -m json.tool 2>/dev/null | sed 's/^/  /' || true
  [[ "$RESP_STATUS" == "$1" ]] || { echo "  UNEXPECTED STATUS" >&2; exit 1; }
}

jsonval() { echo "$RESP_BODY" | python3 -c "import json,sys;print(json.load(sys.stdin)['$1'])"; }

RUN_ID=$(date +%s)
EMAIL="ana.$RUN_ID@example.com"

say "Step 1: ticket opened - CRM registers the customer"
api "$SUNDER_CRED_CRM" POST /v1/contacts \
  "{\"email\":\"$EMAIL\",\"name\":\"Ana Anic\",\"attributes\":{\"ticket\":\"T-$RUN_ID\"}}"
expect 201
CRM_CID=$(jsonval cid)

say "Step 2: handoff to the notifier - sharing ONLY the email"
note "An OTI lives 5 minutes: it cannot be saved for the escalation moment."
note "Instead the notifier consumes it NOW; share_attributes authorizes the"
note "email (and nothing else) to appear in the notifier's own scope."
api "$SUNDER_CRED_CRM" POST /v1/oti \
  "{\"cid\":\"$CRM_CID\",\"purpose\":\"escalation_notify\",\"audience\":\"notifier\",\"share_attributes\":[\"email\"]}"
expect 201
TOKEN=$(jsonval token)

api "$SUNDER_CRED_NOTIFIER" POST /v1/oti/verify \
  "{\"token\":\"$TOKEN\",\"purpose\":\"escalation_notify\",\"audience\":\"notifier\"}"
expect 200
NOTIFIER_CID=$(jsonval cid)
note "Notifier stores ONLY: ticket T-$RUN_ID -> $NOTIFIER_CID (no e-mail, no name)"
note "CRM's pseudonym was $CRM_CID - the two do not correlate."

say "Step 3: hours later, the ticket escalates - just-in-time e-mail fetch"
api "$SUNDER_CRED_NOTIFIER" GET "/v1/contacts/$NOTIFIER_CID/attributes/email?purpose=escalation_notify"
expect 200
note ">>> the notifier sends the escalation e-mail now and stores nothing;"
note ">>> the fetch is purpose-checked, consent-checked and in the audit chain."

say "Step 4: attributes the issuer did NOT share are simply absent"
api "$SUNDER_CRED_NOTIFIER" GET "/v1/contacts/$NOTIFIER_CID/attributes/name?purpose=escalation_notify"
expect 404

say "Step 5: the customer clicks unsubscribe - consent withdrawn"
api "$SUNDER_CRED_NOTIFIER" POST /v1/consent \
  "{\"cid\":\"$NOTIFIER_CID\",\"purpose\":\"escalation_notify\",\"granted\":false}"
expect 200

say "Step 6: the next escalation is blocked at the source"
api "$SUNDER_CRED_NOTIFIER" GET "/v1/contacts/$NOTIFIER_CID/attributes/email?purpose=escalation_notify"
expect 403
note ">>> consent_denied: no code change in the notifier, no list to scrub -"
note ">>> the e-mail address is simply no longer obtainable for this purpose."

say "Demo complete."
note "A notifier database leak contains ticket ids and pseudonyms - zero PII."
