#!/usr/bin/env bash
#
# callcenter.sh — Sunder M6 demo: the call-center lookup flow (decision D8).
#
# This walks the adoption-wedge storyline from PLAN.md 13.4 against a running
# stack: a CRM client registers and looks up a contact without ever storing a
# searchable PII key, then hands the customer to the ERP with a one-time
# identifier (OTI) — and the two systems end up with two different, unlinkable
# pseudonyms for the same person.
#
# Requirements: bash, curl, python3 (for JSON pretty-printing/parsing — no jq).
#
# Configuration:
#   SUNDER_URL       base URL of the running service (default http://localhost:8080)
#   SUNDER_CRED_CRM  credential of the "crm" client (client_id.secret)
#   SUNDER_CRED_ERP  credential of the "erp" client (client_id.secret)

set -euo pipefail

SUNDER_URL="${SUNDER_URL:-http://localhost:8080}"

# ---------------------------------------------------------------------------
# Credentials check — print exact setup instructions if they are missing.
# ---------------------------------------------------------------------------
if [[ -z "${SUNDER_CRED_CRM:-}" || -z "${SUNDER_CRED_ERP:-}" ]]; then
  cat >&2 <<'EOF'
Missing SUNDER_CRED_CRM and/or SUNDER_CRED_ERP.

Create the two demo clients (each command prints the credential exactly once —
copy the "client_id.secret" line it outputs):

  docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
      -id crm -name "Call-center CRM" -scope crm \
      -actions contacts.register,lookup,attributes.read,oti.issue \
      -purposes support,create_order

  docker compose -f deploy/docker-compose.yml exec sunder /sunder client create \
      -id erp -name "Order ERP" -scope erp \
      -actions oti.verify \
      -purposes create_order

Then export the printed credentials and re-run:

  export SUNDER_CRED_CRM='crm.<secret>'
  export SUNDER_CRED_ERP='erp.<secret>'
  ./callcenter.sh
EOF
  exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# api METHOD PATH CREDENTIAL [JSON_BODY]
# Performs the request and fills the globals STATUS and BODY. Never exits on a
# non-2xx HTTP status — several demo steps *expect* one; each step asserts the
# status it wants via `expect`.
api() {
  local method="$1" path="$2" cred="$3" body="${4:-}"
  local resp
  if [[ -n "$body" ]]; then
    resp=$(curl -sS -X "$method" "$SUNDER_URL$path" \
      -H "Authorization: Bearer $cred" \
      -H "Content-Type: application/json" \
      -d "$body" \
      -w $'\n%{http_code}')
  else
    resp=$(curl -sS -X "$method" "$SUNDER_URL$path" \
      -H "Authorization: Bearer $cred" \
      -w $'\n%{http_code}')
  fi
  STATUS="${resp##*$'\n'}"
  BODY="${resp%$'\n'*}"
}

# expect EXPECTED_STATUS LABEL — assert the last call's status, pretty-print body.
expect() {
  local want="$1" label="$2"
  if [[ "$STATUS" != "$want" ]]; then
    echo "FAIL: $label — expected HTTP $want, got HTTP $STATUS" >&2
    pretty >&2
    exit 1
  fi
  echo "  -> HTTP $STATUS (expected)"
  pretty
}

# pretty — pretty-print the last response body as indented JSON.
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

# jget FIELD — extract one string field from the last JSON response body.
jget() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
print(json.loads(sys.stdin.read())[sys.argv[1]])
' "$1"
}

step() {
  echo
  echo "============================================================"
  echo "  $1"
  echo "============================================================"
}

say() { echo "  $1"; }

# ---------------------------------------------------------------------------
# Preflight: is the stack up?
# ---------------------------------------------------------------------------
echo "Sunder call-center demo (PLAN 13.4 storyline) against $SUNDER_URL"
if ! curl -sSf "$SUNDER_URL/healthz" >/dev/null 2>&1; then
  echo "FAIL: $SUNDER_URL/healthz is not answering — is the stack running?" >&2
  echo "      Try: docker compose -f deploy/docker-compose.yml up --build" >&2
  exit 1
fi
echo "Service is healthy."

# ---------------------------------------------------------------------------
# Step 1 — a customer calls in for the first time: the CRM registers them.
# ---------------------------------------------------------------------------
step "Step 1: CRM registers a contact (POST /v1/contacts)"
say "The agent captures name, email, phone and a loyalty tier. Sunder"
say "normalizes the identifiers, stores everything encrypted in the CRM's"
say "own scope, and returns a stable pseudonym (CID) — no PII leaves the"
say "vault, and nothing searchable-by-PII lands in the CRM database."
api POST /v1/contacts "$SUNDER_CRED_CRM" '{
  "email": "Ana.Horvat@Example.com",
  "phone": "+385 91 234 5678",
  "name": "Ana Horvat",
  "attributes": {"loyalty_tier": "gold"}
}'
expect 201 "register contact"
CRM_CID="$(jget cid)"
say ""
say "CRM's pseudonym for Ana: $CRM_CID"
say "(re-running this script returns the same CID — dedup by email/phone token)"

# ---------------------------------------------------------------------------
# Step 2 — Ana calls again: the agent looks her up by phone.
# ---------------------------------------------------------------------------
step "Step 2: agent lookup by phone (POST /v1/lookup) — HIT"
say "The agent types the number from caller-ID. The service HMAC-tokenizes"
say "it and matches against the token index — no plaintext PII is compared"
say "or stored on this path, and the lookup lands in the audit chain."
api POST /v1/lookup "$SUNDER_CRED_CRM" '{"phone": "+385912345678"}'
expect 200 "lookup by phone"
LOOKUP_CID="$(jget cid)"
if [[ "$LOOKUP_CID" == "$CRM_CID" ]]; then
  say ""
  say "Same CID as registration: $LOOKUP_CID — the agent found Ana's record."
else
  echo "FAIL: lookup returned $LOOKUP_CID, expected $CRM_CID" >&2
  exit 1
fi
say "Remember: LOOKUP != AUTHENTICATION — a hit never proves the caller is Ana."

# ---------------------------------------------------------------------------
# Step 3 — the agent needs one field, and must say why.
# ---------------------------------------------------------------------------
step "Step 3: fetch a single attribute with a purpose (GET .../attributes/email)"
say "Field-level access: the agent gets exactly one decrypted value, only"
say "with an allowed purpose (here: support), and the read is audited."
api GET "/v1/contacts/$CRM_CID/attributes/email?purpose=support" "$SUNDER_CRED_CRM"
expect 200 "read email attribute (purpose=support)"

# ---------------------------------------------------------------------------
# Step 4 — what the platform refuses to do: fish by name.
# ---------------------------------------------------------------------------
step "Step 4: lookup by name alone is REJECTED (400)"
say "A name is a narrowing key, never an identifier — 'find me every Ana"
say "Horvat' is exactly the enumeration a breached CRM enables today."
api POST /v1/lookup "$SUNDER_CRED_CRM" '{"name": "Ana Horvat"}'
expect 400 "lookup by name alone"
say ""
say "Name works only as a second factor next to email or phone."

# ---------------------------------------------------------------------------
# Step 5 — misses are counted: enumeration does not go unnoticed.
# ---------------------------------------------------------------------------
step "Step 5: lookup miss (404) — fuel for the enumeration detector"
say "A nonexistent identifier returns 404 not_found. Every miss is audited"
say "and feeds the enumeration detector (alert + metric at 100 misses/10 min);"
say "past the per-client rate limit the answer becomes 429 rate_limited."
MISS_EMAIL="nobody-$(date +%s)@example.com"
api POST /v1/lookup "$SUNDER_CRED_CRM" "{\"email\": \"$MISS_EMAIL\"}"
expect 404 "lookup miss ($MISS_EMAIL)"

# ---------------------------------------------------------------------------
# Step 6 — Ana places an order: the CRM issues a one-time handoff token.
# ---------------------------------------------------------------------------
step "Step 6: CRM issues an OTI for the ERP (POST /v1/oti)"
say "The order has to move to the ERP — but the CRM's pseudonym must not"
say "cross the scope boundary. The CRM asks for a one-time identifier:"
say "5 minutes, one use, one audience (erp), one purpose (create_order)."
api POST /v1/oti "$SUNDER_CRED_CRM" "{
  \"cid\": \"$CRM_CID\",
  \"purpose\": \"create_order\",
  \"audience\": \"erp\"
}"
expect 201 "issue OTI"
OTI_TOKEN="$(jget token)"

# ---------------------------------------------------------------------------
# Step 7 — the ERP verifies the token and gets ITS OWN pseudonym.
# ---------------------------------------------------------------------------
step "Step 7: ERP verifies the OTI (POST /v1/oti/verify) — unlinkability"
say "The ERP redeems the token and receives a CID in the ERP scope."
api POST /v1/oti/verify "$SUNDER_CRED_ERP" "{
  \"token\": \"$OTI_TOKEN\",
  \"purpose\": \"create_order\",
  \"audience\": \"erp\"
}"
expect 200 "verify OTI as ERP"
ERP_CID="$(jget cid)"
say ""
say "  CRM's pseudonym for Ana: $CRM_CID"
say "  ERP's pseudonym for Ana: $ERP_CID"
if [[ "$ERP_CID" == "$CRM_CID" ]]; then
  echo "FAIL: ERP received the CRM's CID — scope isolation is broken" >&2
  exit 1
fi
say ""
say ">>> Two different pseudonyms for the same person. Neither system can"
say ">>> join its records against the other's — even if both databases leak,"
say ">>> the CIDs do not correlate. The issuer never learns the ERP's CID."

# ---------------------------------------------------------------------------
# Step 8 — replay the same token: single use is enforced by the database.
# ---------------------------------------------------------------------------
step "Step 8: replaying the same OTI fails (409 token_used)"
say "Single use is an atomic VALID -> USED transition in the database, not"
say "just a signature check — a stolen or replayed token is worthless."
api POST /v1/oti/verify "$SUNDER_CRED_ERP" "{
  \"token\": \"$OTI_TOKEN\",
  \"purpose\": \"create_order\",
  \"audience\": \"erp\"
}"
expect 409 "replay OTI"

# ---------------------------------------------------------------------------
echo
echo "============================================================"
echo "  Demo complete."
echo "============================================================"
echo "  What the pilot cutover means (PLAN 13.4): after this flow replaces"
echo "  PII-keyed lookup, a stolen CRM database contains no OIB and no"
echo "  searchable PII keys, every agent lookup is in the hash-chained audit"
echo "  log, and cross-system handoff leaks nothing but a one-time token."
