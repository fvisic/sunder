#!/usr/bin/env bash
# handoff.sh - F11 EU -> US cross-jurisdiction handoff walk-through.
#
# The point this demonstrates: the US instance never stores an EU-resident's
# identifiers. The EU side registers the person with full PII (email, name),
# then issues a one-time identifier (OTI) that authorizes sharing ONLY a
# non-identifying attribute (loyalty tier). The EU app unpacks that OTI - an
# intra-EU operation, proving the share was authorized - and hands the US
# instance ONLY the shared field. The US instance registers a fresh,
# US-scoped person from those fields alone. Two separate databases, two
# separate keystores, two separate audit chains; the border is crossed by a
# tier value, never by an email.
#
# Requires the two-instance stack up:
#   docker compose -f examples/multi-jurisdiction/docker-compose.yml up --build -d
# and one credential per instance (create them with `sunder client create`
# inside each container, or bootstrap):
#   EU_CRED  scope eu-crm:  contacts.register, oti.issue, oti.verify,
#                           attributes.read; purposes: partner_handoff
#   US_CRED  scope us-crm:  contacts.register; purposes: partner_handoff
set -euo pipefail

EU_URL="${EU_URL:-http://localhost:8080}"
US_URL="${US_URL:-http://localhost:8081}"

if [[ -z "${EU_CRED:-}" || -z "${US_CRED:-}" ]]; then
  cat >&2 <<'EOF'
Set EU_CRED and US_CRED to a bearer credential for each instance.

  # inside the EU container:
  sunder client create -id partner -scope eu-crm \
    -actions contacts.register,oti.issue,oti.verify,attributes.read \
    -purposes partner_handoff
  # inside the US container:
  sunder client create -id importer -scope us-crm \
    -actions contacts.register -purposes partner_handoff
EOF
  exit 1
fi

say() { printf '\n=== %s ===\n' "$1"; }

say "EU: register an EU resident with full PII plus a loyalty tier"
EU_CID=$(curl -fsS -X POST "$EU_URL/v1/contacts" \
  -H "Authorization: Bearer $EU_CRED" -H 'Content-Type: application/json' \
  -d '{"email":"ana@example.eu","name":"Ana Horvat","attributes":{"tier":"gold"}}' \
  | grep -o '"cid":"[^"]*"' | cut -d'"' -f4)
echo "EU cid: $EU_CID  (email + name live only in the EU database)"

say "EU: issue an OTI that authorizes sharing ONLY the tier (no identifiers)"
OTI=$(curl -fsS -X POST "$EU_URL/v1/oti" \
  -H "Authorization: Bearer $EU_CRED" -H 'Content-Type: application/json' \
  -d "{\"cid\":\"$EU_CID\",\"purpose\":\"partner_handoff\",\"audience\":\"eu-crm\",\"share_attributes\":[\"tier\"]}" \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "OTI issued (5-minute lifetime); it names exactly one shareable field: tier"

say "EU: unpack the OTI in-EU to read the authorized field"
TIER=$(curl -fsS -X POST "$EU_URL/v1/oti/verify" \
  -H "Authorization: Bearer $EU_CRED" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$OTI\",\"purpose\":\"partner_handoff\",\"audience\":\"eu-crm\"}" \
  | grep -o '"tier":"[^"]*"' | cut -d'"' -f4)
echo "Shared field recovered: tier=$TIER  (this is the ONLY value that crosses the border)"

say "US: register a fresh US-scoped person from the shared field ALONE"
# The only identifier is a US-side-generated partner reference (never the
# EU email or name). The US instance sees a synthetic handle and a tier.
US_REF="partner-eu-$(date +%s)@us.local"
US_CID=$(curl -fsS -X POST "$US_URL/v1/contacts" \
  -H "Authorization: Bearer $US_CRED" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$US_REF\",\"attributes\":{\"tier\":\"$TIER\"}}" \
  | grep -o '"cid":"[^"]*"' | cut -d'"' -f4)
echo "US cid: $US_CID  (holds only tier=$TIER; its audit chain shows one registration, no EU PII)"

say "Done"
cat <<EOF
What just happened, and what did NOT:
  - The EU database holds ana@example.eu / Ana Horvat / tier=gold.
  - The US database holds tier=$TIER and a partner reference - nothing that
    identifies the EU resident.
  - Each instance kept its own audit chain: the EU chain records the OTI
    issue + verify; the US chain records one registration. Neither chain
    references the other's pseudonym.
  - Revoking, exporting or erasing on either side is a local operation on
    local data - there is no shared state to reconcile.
EOF
