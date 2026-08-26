#!/usr/bin/env bash
#
# f7-sub-accounts.sh - F7 person links: link a guardian to a minor, list the
# relationship, and show that erasure LISTS linked children but cascades
# only on explicit opt-in.
#
# Client (SUNDER_CRED_VAULT), scope crm, actions:
#   contacts.register, links.manage, dsr.erase
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cred SUNDER_CRED_VAULT
C="$SUNDER_CRED_VAULT"
TS=$(date +%s)

step "Register a guardian and a minor"
api POST /v1/contacts "$C" "{\"email\":\"guardian-$TS@example.com\"}"
expect 201 "register guardian"
PARENT=$(jget cid)
api POST /v1/contacts "$C" "{\"email\":\"minor-$TS@example.com\"}"
expect 201 "register minor"
CHILD=$(jget cid)

step "Link them (guardian)"
api POST /v1/links "$C" "{\"parent_cid\":\"$PARENT\",\"child_cid\":\"$CHILD\",\"link_type\":\"guardian\"}"
expect 201 "link"

step "List links from the guardian - the minor shows as a child"
api GET "/v1/contacts/$PARENT/links" "$C"
expect 200 "list links"

step "Erase the guardian WITHOUT cascade: the minor is listed but untouched"
api POST /v1/dsr/erase "$C" "{\"cid\":\"$PARENT\"}"
expect 200 "erase guardian (no cascade)"
say "response 'linked' reports the minor with cascaded=false - its data is intact"

step "The minor is still resolvable (not erased) - listing its links succeeds"
api GET "/v1/contacts/$CHILD/links" "$C"
expect 200 "minor still resolves (an erased person would 404)"

echo
say "Done. A silent cascade is how a child's data gets deleted by accident;"
say "cascade only happens when the request names the link type in 'cascade'."
