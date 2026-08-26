#!/usr/bin/env bash
#
# f5-file-vault.sh - F5 file vault: attach an encrypted file to a person,
# download it with a purpose, and show crypto-shredding on erasure.
#
# Requires the stack to have a storage driver enabled (SUNDER_FILES_STORAGE).
# Client (SUNDER_CRED_VAULT), scope crm, actions:
#   contacts.register, files.write, files.read, dsr.erase; purposes: support
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cred SUNDER_CRED_VAULT
C="$SUNDER_CRED_VAULT"

step "Register a person to attach a file to"
api POST /v1/contacts "$C" '{"email":"vault-demo@example.com"}'
expect 201 "register"
CID=$(jget cid)
say "cid: $CID"

step "Upload an encrypted file (multipart)"
TMP=$(mktemp); echo "signed mandate, confidential" > "$TMP"
resp=$(curl -sS -X POST "$SUNDER_URL/v1/contacts/$CID/files" \
  -H "Authorization: Bearer $C" -F "file=@$TMP;filename=mandate.txt" \
  -w $'\n%{http_code}')
rm -f "$TMP"
STATUS="${resp##*$'\n'}"; BODY="${resp%$'\n'*}"
expect 201 "upload"
FID=$(jget id)
say "file id: $FID  (stored as AEAD ciphertext; the driver never sees plaintext)"

step "List files (metadata only)"
api GET "/v1/contacts/$CID/files?purpose=support" "$C"
expect 200 "list"

step "Download needs a purpose"
api GET "/v1/files/$FID" "$C"
expect 400 "download without purpose"
api GET "/v1/files/$FID?purpose=support" "$C"
expect 200 "download with purpose"

step "Erase the person: the record key is destroyed - the file is unrecoverable"
api POST /v1/dsr/erase "$C" "{\"cid\":\"$CID\"}"
expect 200 "erase"
api GET "/v1/files/$FID?purpose=support" "$C"
expect 404 "file gone after erasure (crypto-shredded)"

echo
say "Done. Erasure deleted one row (the person's record key); every file below"
say "it became undecryptable at commit, with no round trip to object storage."
