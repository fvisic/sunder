#!/usr/bin/env bash
#
# f6-versioning.sh - F6 attribute versioning: overwrite an attribute, then
# read the previous value from history.
#
# Requires the stack to have SUNDER_VERSIONS_KEEP > 0.
# Client (SUNDER_CRED_VAULT), scope crm, actions:
#   contacts.register, attributes.read, attributes.history; purposes: support
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cred SUNDER_CRED_VAULT
C="$SUNDER_CRED_VAULT"

EMAIL="version-demo-$(date +%s)@example.com"

step "Register with tier=bronze, then overwrite to silver, then gold"
api POST /v1/contacts "$C" "{\"email\":\"$EMAIL\",\"attributes\":{\"tier\":\"bronze\"}}"
expect 201 "register bronze"
CID=$(jget cid)
api POST /v1/contacts "$C" "{\"email\":\"$EMAIL\",\"attributes\":{\"tier\":\"silver\"}}"
expect 201 "update to silver"
api POST /v1/contacts "$C" "{\"email\":\"$EMAIL\",\"attributes\":{\"tier\":\"gold\"}}"
expect 201 "update to gold"
say "cid: $CID  (live value is now gold)"

step "List version history (metadata: who wrote each, when)"
api GET "/v1/contacts/$CID/versions" "$C"
expect 200 "list versions"

step "Read the earliest version's tier - purpose required, audited like a live read"
api GET "/v1/contacts/$CID/versions/1/attributes/tier?purpose=support" "$C"
expect 200 "read version 1"
say "version 1 tier was: $(jget value)  (the value before the first overwrite)"

echo
say "Done. History is off by default; when on it is count-capped, TTL-pruned,"
say "and deleted with the person on erasure - it is the same personal data."
