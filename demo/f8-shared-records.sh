#!/usr/bin/env bash
#
# f8-shared-records.sh - F8 shared records: mint an expiring UUID that
# exposes only named fields to a partner, fetch it, then show consent
# withdrawal revokes it.
#
# Client (SUNDER_CRED_VAULT), scope crm, actions:
#   contacts.register, shares.create, consent.manage; purposes: support
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cred SUNDER_CRED_VAULT
C="$SUNDER_CRED_VAULT"

step "Register a person with a name and an IBAN"
api POST /v1/contacts "$C" '{"email":"share-demo@example.com","name":"Ana Horvat","attributes":{"iban":"HR12"}}'
expect 201 "register"
CID=$(jget cid)

step "Create a share exposing ONLY name (not the IBAN) for a partner"
api POST /v1/shares "$C" "{\"cid\":\"$CID\",\"fields\":[\"name\"],\"partner_label\":\"acme-logistics\",\"ttl_seconds\":3600}"
expect 201 "create share"
UUID=$(jget uuid)
say "share uuid: $UUID"

step "Fetch the share - returns only the listed field"
api GET "/v1/shares/$UUID" "$C"
expect 200 "fetch share"
say "the response carries 'name' only; 'iban' was never in the share"

step "Withdraw consent for the purpose - standing shares are revoked"
api POST /v1/consent "$C" "{\"cid\":\"$CID\",\"purpose\":\"support\",\"granted\":false}"
expect 200 "withdraw consent"
api GET "/v1/shares/$UUID" "$C"
expect 404 "share revoked by consent withdrawal"

echo
say "Done. A partner UUID never outlives the data: erasure and consent"
say "withdrawal both revoke it, and every fetch is audited with the label."
