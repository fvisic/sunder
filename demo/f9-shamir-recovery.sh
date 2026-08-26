#!/usr/bin/env bash
#
# f9-shamir-recovery.sh - F9 Shamir recovery for the file keystore: seal the
# keystore into k-of-n shares, simulate a keystore loss, and recover.
#
# This is a CLI flow (not HTTP). It runs the sunder binary via SUNDER_EXEC,
# which defaults to the compose stack:
#   SUNDER_EXEC='docker compose -f deploy/docker-compose.yml exec -T sunder /sunder'
# or point it at a local binary:  SUNDER_EXEC='sunder'
set -euo pipefail

EXEC="${SUNDER_EXEC:-docker compose -f deploy/docker-compose.yml exec -T sunder /sunder}"
run() { echo "  \$ sunder $*"; $EXEC "$@"; }
step() { echo; echo "============================================================"; echo "  $1"; echo "============================================================"; }

step "Issue 3-of-5 recovery shares (printed once)"
OUT=$(run keys shamir-init -n 5 -k 3)
echo "$OUT"
# Extract the five hex shares from the printed output.
SHARES=($(printf '%s\n' "$OUT" | sed -n 's/.*share [0-9]*\/5: \([0-9a-f]*\).*/\1/p'))
if [[ "${#SHARES[@]}" -ne 5 ]]; then
  echo "FAIL: expected 5 shares, parsed ${#SHARES[@]}" >&2
  exit 1
fi
echo "  parsed ${#SHARES[@]} shares (each would go to a SEPARATE custodian)"

step "Recover using any 3 shares (1, 3, 5)"
run keys shamir-recover -shares "${SHARES[0]},${SHARES[2]},${SHARES[4]}"

step "Too few shares (2 of 3) must fail"
if $EXEC keys shamir-recover -shares "${SHARES[0]},${SHARES[1]}" 2>/dev/null; then
  echo "FAIL: recovery with 2 shares should have failed" >&2
  exit 1
fi
echo "  -> recovery with 2 shares refused (expected)"

step "Annual drill: re-seal under the same shares (picks up any new keys)"
run keys shamir-rotate -shares "${SHARES[0]},${SHARES[1]},${SHARES[2]}"

echo
echo "  Done. The recovery key was never written to disk; recovery.bundle holds"
echo "  only ciphertext. Custodian separation is the whole guarantee."
