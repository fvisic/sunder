#!/usr/bin/env bash
#
# provision.sh - stamp out one isolated Sunder instance per customer
# (managed single-tenant, docs/PROVISIONING.md). One namespace, one
# database, one keystore, one bootstrap - full isolation, SaaS economics.
#
# Usage:
#   ./provision.sh <customer> <values-file> [--db-url <postgres-url>]
#
# Prerequisites: kubectl + helm pointed at the target cluster; a PostgreSQL
# database provisioned per customer (never shared); a Vault namespace or
# path per customer when using the vault keystore.

set -euo pipefail

CUSTOMER="${1:?usage: provision.sh <customer> <values-file> [--db-url <url>]}"
VALUES="${2:?values file required (start from values.example.yaml)}"
DB_URL="${4:-}"
[[ "${3:-}" == "--db-url" ]] || DB_URL=""

if ! [[ "$CUSTOMER" =~ ^[a-z0-9-]{2,40}$ ]]; then
  echo "customer must be lowercase alphanumeric/dash" >&2; exit 1
fi
NS="sunder-${CUSTOMER}"
CHART="$(cd "$(dirname "$0")/../helm/sunder" && pwd)"

echo "==> namespace ${NS}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NS" sunder-customer="$CUSTOMER" --overwrite

if [[ -n "$DB_URL" ]]; then
  echo "==> database secret"
  kubectl -n "$NS" create secret generic sunder-db \
    --from-literal=SUNDER_DB_URL="$DB_URL" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

echo "==> helm install/upgrade"
helm upgrade --install sunder "$CHART" -n "$NS" -f "$VALUES" --wait

echo "==> bootstrap (idempotent: first run creates the admin client)"
kubectl -n "$NS" run "sunder-bootstrap-$(date +%s)" --restart=Never --rm -i \
  --image="$(helm get values sunder -n "$NS" -o json | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v.get("image",{}).get("repository","ghcr.io/fvisic/sunder")+":"+v.get("image",{}).get("tag","latest"))')" \
  --overrides='{"spec":{"containers":[{"name":"bootstrap","image":"PLACEHOLDER","args":["bootstrap","-unattended","-credential-file","/dev/stdout"],"envFrom":[{"secretRef":{"name":"sunder-db"}}]}]}}' \
  2>/dev/null || kubectl -n "$NS" logs -l job-name --tail=5 || true

cat <<DONE

Instance for '${CUSTOMER}' is up in namespace ${NS}.
Next steps:
  1. Store the printed admin credential in your secret manager NOW - it is
     shown exactly once.
  2. Register the customer's systems: sunder client create ...
  3. Offboarding: docs/PROVISIONING.md#offboarding (export, erase, key
     destruction proof via the audit chain, then delete the namespace AND
     the database).
DONE
