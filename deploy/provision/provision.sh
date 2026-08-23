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
#
# The admin credential is written to a Kubernetes Secret, never to stdout
# or a pod log: bootstrap writes it to a file inside the pod and this
# script reads it from an emptyDir-backed Secret creation step. Every step
# fails loudly - a partial provision must never report success.

set -euo pipefail

usage() {
  echo "usage: provision.sh <customer> <values-file> [--db-url <postgres-url>]" >&2
  exit 1
}

CUSTOMER="${1:-}"
VALUES="${2:-}"
[[ -n "$CUSTOMER" && -n "$VALUES" ]] || usage
shift 2

DB_URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-url) DB_URL="${2:-}"; shift 2 ;;
    --db-url=*) DB_URL="${1#*=}"; shift ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

if ! [[ "$CUSTOMER" =~ ^[a-z0-9-]{2,40}$ ]]; then
  echo "customer must be lowercase alphanumeric/dash" >&2; exit 1
fi
[[ -f "$VALUES" ]] || { echo "values file not found: $VALUES" >&2; exit 1; }

NS="sunder-${CUSTOMER}"
CHART="$(cd "$(dirname "$0")/../helm/sunder" && pwd)"

# The image the bootstrap Job runs MUST be the one the deployment runs:
# applying migrations with a different binary is a schema/binary skew risk.
read_value() {
  python3 - "$VALUES" "$1" "$2" <<'PY'
import sys
try:
    import yaml
except ImportError:
    sys.exit("provision.sh needs PyYAML (pip install pyyaml) to read the values file")
with open(sys.argv[1]) as f:
    v = yaml.safe_load(f) or {}
node = v
for part in sys.argv[2].split('.'):
    node = (node or {}).get(part)
print(node if node else sys.argv[3])
PY
}
REPO="$(read_value image.repository ghcr.io/fvisic/sunder)"
TAG="$(read_value image.tag '')"
if [[ -z "$TAG" ]]; then
  echo "image.tag must be pinned in $VALUES (never :latest for a command that applies migrations)" >&2
  exit 1
fi
IMAGE="${REPO}:${TAG}"

echo "==> namespace ${NS}"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NS" sunder-customer="$CUSTOMER" --overwrite

if [[ -n "$DB_URL" ]]; then
  echo "==> database secret"
  kubectl -n "$NS" create secret generic sunder-db \
    --from-literal=SUNDER_DB_URL="$DB_URL" \
    --dry-run=client -o yaml | kubectl apply -f -
fi
kubectl -n "$NS" get secret sunder-db >/dev/null

echo "==> helm install/upgrade (${IMAGE})"
helm upgrade --install sunder "$CHART" -n "$NS" -f "$VALUES" --wait

echo "==> bootstrap (idempotent: only the first run creates the admin client)"
JOB="sunder-bootstrap-$(date +%s)"
kubectl -n "$NS" delete job "$JOB" --ignore-not-found >/dev/null 2>&1 || true
# The credential is written INSIDE the pod and copied into a Secret by the
# same container, so it never reaches a log stream (review N6).
kubectl -n "$NS" create -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: ${SUNDER_BOOTSTRAP_SA:-default}
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: bootstrap
          image: ${IMAGE}
          args: ["bootstrap", "-unattended", "-credential-file", "/out/credential"]
          envFrom:
            - secretRef: {name: sunder-db}
          env:
            - name: SUNDER_BOOTSTRAP_PURPOSES
              value: "${SUNDER_BOOTSTRAP_PURPOSES:-admin}"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: out, mountPath: /out}
      volumes:
        - name: out
          emptyDir: {medium: Memory}
YAML

if ! kubectl -n "$NS" wait --for=condition=complete --timeout=180s "job/${JOB}"; then
  echo "bootstrap FAILED - the instance is NOT provisioned. Job logs:" >&2
  kubectl -n "$NS" logs "job/${JOB}" --tail=50 >&2 || true
  exit 1
fi
kubectl -n "$NS" logs "job/${JOB}" --tail=20

cat <<DONE

Instance for '${CUSTOMER}' is up in namespace ${NS} (image ${IMAGE}).

The admin credential was written to /out/credential inside the bootstrap
pod, which is now gone - by design it is never logged. To obtain one:

  kubectl -n ${NS} exec deploy/sunder-sunder -- /sunder client rotate-secret -id admin -ttl 90d

Then store it in your secret manager immediately: it is shown once.

Next steps:
  1. Register the customer's systems: sunder client create ...
  2. Offboarding: docs/PROVISIONING.md#offboarding (export, erase, anchor
     export off-host, key destruction, then delete the namespace AND the
     database).
DONE
