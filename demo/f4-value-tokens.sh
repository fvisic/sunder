#!/usr/bin/env bash
#
# f4-value-tokens.sh - F4 value tokenization: swap a single sensitive value
# for an opaque handle, redeem it, prove card shape, and show that bulk
# always needs an unlock token.
#
# Client (SUNDER_CRED_VAULT), scope any, actions:
#   tokens.create, tokens.read, tokens.delete, admin.unlock
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cred SUNDER_CRED_VAULT
C="$SUNDER_CRED_VAULT"

step "Tokenize one value"
api POST /v1/tokens "$C" '{"value":"HR1210010051863000160"}'
expect 201 "create string token"
TOK=$(jget token)
say "token: $TOK"

step "Redeem it"
api GET "/v1/tokens/$TOK" "$C"
expect 200 "detokenize"

step "Card token: Luhn-valid, length-preserving, no BIN"
api POST /v1/tokens "$C" '{"type":"card","value":"4111 1111 1111 1111"}'
expect 201 "create card token"
CARD=$(jget token)
say "card token: $CARD  (16 digits, valid Luhn, BIN is not 411111)"

step "A non-Luhn card is refused"
api POST /v1/tokens "$C" '{"type":"card","value":"4111111111111112"}'
expect 400 "reject non-Luhn card"

step "Bulk WITHOUT an unlock token is refused (403), regardless of config"
api POST /v1/tokens/bulk "$C" '{"items":[{"value":"a"},{"value":"b"}]}'
expect 403 "bulk without unlock"

step "Mint a bulk-tokens unlock, then the bulk call succeeds"
api POST /v1/admin/unlock "$C" '{"purpose":"bulk-tokens"}'
expect 201 "mint unlock"
UNLOCK=$(jget unlock_token)
api POST /v1/tokens/bulk "$C" '{"items":[{"value":"a"},{"value":"b"}]}' "X-Sunder-Unlock: $UNLOCK"
expect 201 "bulk with unlock"

step "Delete a token, then it misses"
api DELETE "/v1/tokens/$TOK" "$C"
expect 200 "delete"
api GET "/v1/tokens/$TOK" "$C"
expect 404 "deleted token misses"

echo
say "Done. The values were sealed under the PII KEK, AEAD-bound to token+scope;"
say "the tokens above are opaque handles only this scope can redeem."
