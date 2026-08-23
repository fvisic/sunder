# Provisioning and offboarding (managed single-tenant)

Sunder's answer to "we want multi-tenant SaaS" is **managed
single-tenant**: one isolated instance per customer - its own database, its
own keys, its own audit chain - provisioned by one command. The isolation
story stays intact (docs/DESIGN.md section on multi-tenancy); only the
operations are centralized.

## What "isolated" means here

| Resource | Per customer | Never shared |
|---|---|---|
| Kubernetes namespace | `sunder-<customer>` | - |
| PostgreSQL database | dedicated | connection string, credentials |
| Keystore | dedicated Vault mount or file volume | key material, KEK versions |
| Audit chain + anchors | dedicated | chain heads, `.tsr` exports |
| Admin credential | one, printed once at bootstrap | - |

## Provisioning

```sh
cp deploy/provision/values.example.yaml customers/acme.yaml
# edit: vault mount, DB subnet CIDR, image tag, TLS secrets

deploy/provision/provision.sh acme customers/acme.yaml \
    --db-url 'postgres://acme:...@pg.internal:5432/sunder_acme'
```

The script creates the namespace, the database secret, installs the chart,
and runs `sunder bootstrap -unattended`, which:

1. applies migrations,
2. ensures key material for every live key version,
3. creates the first admin client and emits its credential **once**.

`bootstrap` is idempotent: rerunning it against an initialized instance
reports "already exists" and changes nothing, so the script is safe to
re-run after a failed step.

Store the admin credential in your secret manager immediately - it is not
recoverable. Rotate it with `sunder client rotate-secret -id admin -ttl 90d`.

## Recommended per-customer settings

- `signer.enabled: true` - key material lives only in the signer sidecar.
- `networkPolicy.enabled: true` with `dbCIDR` narrowed to that customer's
  database subnet.
- `tls.enabled: true` plus `tls.mtlsSecretName` - client certificates for
  every calling system.
- A dedicated Vault mount (`keystore.vault.mount: customer-acme`), never a
  shared path.

## Offboarding

Offboarding is a data-protection operation, not a `helm uninstall`. In order:

1. **Export** what the customer is entitled to take:
   `GET /v1/dsr/export` per CID, or a bulk export from their own systems.
2. **Erase** on request: run erasures so every scope receives its signed
   webhook and the audit chain records the deletions
   (`POST /v1/dsr/erase`, or the portal). Verify with
   `sunder verify-audit -ca <bundle>`.
3. **Anchor the final state**: `sunder anchor` and copy the `.tsr` export
   off-host. This is the evidence that the chain was intact at teardown -
   after the database is gone it is the only proof.
4. **Destroy keys**: delete the customer's Vault mount (or shred the
   keystore volume). Without the KEK, any surviving ciphertext backup is
   unreadable - crypto-shredding is the real deletion.
5. **Delete the deployment and the database**:
   `helm uninstall sunder -n sunder-acme && kubectl delete ns sunder-acme`,
   then drop the database and its backups per your retention policy.
6. **Record** the offboarding: keep the exported anchors and the erasure
   report. Restoring an old backup after step 4 yields ciphertext without
   keys; restoring one from BEFORE the erasures would resurrect data, which
   is why the runbook order matters (docs/RUNBOOK-BACKUP-DR.md).

## Multi-instance operations

Anchoring, retention and webhook delivery run as CronJobs inside each
namespace, so nothing is centralized by default. For fleet visibility,
scrape each instance's `/metrics` (bearer-token gated) into one Prometheus
with a `customer` label, and use the shared Grafana dashboard
(`ops/grafana-dashboard.json`) plus alerts (`ops/prometheus-alerts.yaml`)
per instance.
