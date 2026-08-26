# Helm chart install

You want Sunder running on Kubernetes with the production posture the
chart enforces by default: Vault-backed keys, an optional signer split, TLS
and mTLS termination, network policy, and the anchor/retention cron jobs -
without hand-writing that YAML.

```mermaid
flowchart LR
    Ing["Ingress / mesh"] -- TLS from tls.secretName, client cert if mtlsSecretName --> Pod
    subgraph Pod["sunder pod"]
        API["sunder container\n(serve)"]
        Signer["signer container\n(if signer.enabled)"]
        API -- "crypto ops over /signer/signer.sock\n(emptyDir, memory-backed)" --> Signer
    end
    API -- "SUNDER_DB_URL from Secret\ndatabase.existingSecret" --> DB[(PostgreSQL)]
    Signer -- "SUNDER_VAULT_ADDR + token\n(only holder of key material)" --> Vault[(Vault KV v2)]
    API -. "if signer disabled" .-> Vault
    Cron1["CronJob: sunder-anchor\n(anchor.schedule)"] -- "RFC3161 request" --> TSA["SUNDER_TSA_URL"]
    Cron1 -- ".tsr digest" --> PVC[(anchor PVC)]
    Cron2["CronJob: sunder-retention\n(retention.schedule)"] --> DB
    NetPol["NetworkPolicy\n(networkPolicy.enabled)"] -. "allows only clientLabel pods\n+ allowedNamespaces" .-> Pod
```

## Steps

1. Point the chart at your Postgres and Vault credentials via existing
   Secrets - never inline them in a values file you commit:

```bash
kubectl create secret generic sunder-db \
  --from-literal=SUNDER_DB_URL='postgres://sunder:REDACTED@pg-primary:5432/sunder'
kubectl create secret generic sunder-vault \
  --from-literal=SUNDER_VAULT_TOKEN='hvs.REDACTED'
```

2. Write a values override. The chart hard-fails if `keystore.type` is
   anything but `vault` - the `file` driver needs a shared writable volume,
   which would `CrashLoopBackOff` under the chart's `readOnlyRootFilesystem`:

```yaml
# values-prod.yaml
image:
  tag: v0.3.0
  opsTag: v0.3.0-ops
replicaCount: 3
database:
  existingSecret: sunder-db
keystore:
  type: vault
  vault:
    addr: https://vault.internal:8200
    mount: secret
    existingSecret: sunder-vault
signer:
  enabled: true          # crypto isolated in a sidecar; API container never sees keys
tls:
  enabled: true
  secretName: sunder-tls
  mtlsSecretName: sunder-mtls   # omit to skip client-cert enforcement
redis:
  addr: redis.internal:6379    # shared rate-limit windows; recommended when replicaCount > 1
networkPolicy:
  enabled: true
  clientLabel: sunder-client
  monitoringNamespace: monitoring
anchor:
  enabled: true
  schedule: "17 2 * * *"
retention:
  enabled: true
  schedule: "43 3 * * *"
```

3. Install:

```bash
helm install sunder deploy/helm/sunder -f values-prod.yaml
```

SDK/CLI equivalent for day-2 changes: `helm upgrade sunder deploy/helm/sunder -f values-prod.yaml`.

## What each block actually wires up

- **`signer.enabled`** mounts a memory-backed `emptyDir` socket volume
  shared between the `sunder` and `signer` containers, points the API
  container at it via `SUNDER_SIGNER_SOCKET=/signer/signer.sock`, and gives
  the signer container ONLY the keystore env vars (`sunder.signerEnv`) - no
  `SUNDER_DB_URL`, no service config. The API container then never holds a
  Vault token or key material at all.
- **`tls.mtlsSecretName`** flips the deployment's readiness/liveness probes
  from `httpGet` to a bare `tcpSocket` check. A kubelet HTTP probe presents
  no client certificate, and `RequireAndVerifyClientCert` would reject
  every one of those probes - so with mTLS on, the probe can only confirm
  the port accepts a TCP connection, not that `/readyz` succeeds.
- **`networkPolicy.enabled`** refuses to render if both `clientLabel` and
  `allowedNamespaces` are empty (that combination would produce an
  allow-all ingress rule). Egress is narrowed to DNS, Postgres
  (`dbPort`/`dbCIDR`), Redis when `redis.addr` is set, and HTTPS/Vault
  (`443`, `8200`, optionally scoped by `egressCIDRs`).
- **`anchor` CronJob** runs the ops image (`image.opsTag`) as
  `anchor -out /anchors -ca <anchor.caPath>` on `anchor.schedule`, writing
  RFC 3161 timestamp tokens to a dedicated PVC (`anchor.pvc`). Only a
  32-byte digest ever leaves the cluster to the TSA. A custom TSA needs its
  own CA bundle mounted via `anchor.caSecretName` - pointing `tsaUrl` at a
  different TSA without also supplying its CA makes anchoring hard-fail
  silently.
- **`retention` CronJob** runs `retention run` on `retention.schedule` with
  no extra volumes - it only touches the database.

## Security notes

- The chart deliberately refuses `keystore.type: file` outright - there is
  no override to make a shared-nothing keystore work across
  `replicaCount > 1` pods, because the underlying driver has no
  cross-writer locking.
- `signer.enabled: false` is a valid, supported mode (single-process, keys
  in the API container) but is NOT the chart's opinionated default posture
  for production - `signer.enabled: true` is what actually satisfies "the
  API container never holds key material."
- `networkPolicy.enabled: true` requires a CNI that enforces
  `NetworkPolicy` (Cilium, Calico, ...); on a CNI that ignores the
  resource, the policy YAML applies but enforces nothing, and the chart
  cannot detect that at install time.
- The portal's dedicated `portal.listenPort` exists specifically so a
  browser-facing citizen can reach the portal even when the main API port
  requires mTLS - browsers cannot present a client certificate, so mounting
  the portal on the mTLS listener would lock out every citizen.
