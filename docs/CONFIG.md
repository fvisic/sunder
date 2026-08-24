# Configuration reference

Sunder is configured exclusively through `SUNDER_*` environment variables -
no config files, no flags (except where a CLI subcommand documents one). All
defaults match the documented v1 behaviour, so an existing deployment that
sets none of the new variables behaves identically after an upgrade.

## Core

| Variable | Default | Description |
|---|---|---|
| `SUNDER_DB_URL` | *(required)* | PostgreSQL connection URL. |
| `SUNDER_LISTEN` | `:8080` | HTTP(S) listen address. |
| `SUNDER_TLS_CERT` / `SUNDER_TLS_KEY` | - | Certificate/key paths; set both to enable TLS (1.3 minimum). |
| `SUNDER_MTLS_CA` | - | Client-CA bundle path; presence enables mandatory client-certificate verification. Requires TLS. |

## Keystore

| Variable | Default | Description |
|---|---|---|
| `SUNDER_KEYSTORE` | `file` | `file`, `vault` or `pkcs11` (stub). |
| `SUNDER_KEYSTORE_PATH` | `./keystore` | Key directory for the `file` driver. |
| `SUNDER_VAULT_ADDR` / `SUNDER_VAULT_TOKEN` | - | Required for the `vault` driver (KV v2). |
| `SUNDER_VAULT_MOUNT` | `secret` | KV v2 mount point. |
| `SUNDER_SIGNER_SOCKET` | - | When set, ALL cryptography runs in a separate `sunder signer` process reachable on this Unix socket; this process then never holds key material and needs no keystore configuration. The signer is started with `sunder signer -socket <path>` and needs the keystore variables but no database. See the signer split section in `docs/ARCHITECTURE.md`. |

## Audit anchoring

| Variable | Default | Description |
|---|---|---|
| `SUNDER_TSA_URL` | `https://freetsa.org/tsr` | RFC 3161 timestamping endpoint. Point production at a qualified or internal TSA. |
| `SUNDER_TSA_CACERT` | vendored FreeTSA CA | TSA root CA bundle for offline token verification. |
| `SUNDER_ANCHOR_DIR` | - | Directory where `sunder anchor` exports `.tsr` files. Sync it to write-once storage **off this host**. |

## Rate limiting

| Variable | Default | Description |
|---|---|---|
| `SUNDER_REDIS_ADDR` | - | `host:port`; set for shared windows across replicas. Unset = in-memory per replica. |
| `SUNDER_REDIS_PASSWORD` | - | Optional AUTH password. |
| `SUNDER_REDIS_FAIL_CLOSED` | `false` | `true` blocks lookups when Redis is unreachable (availability trade-off). |

## Observability

| Variable | Default | Description |
|---|---|---|
| `SUNDER_METRICS_TOKEN` | - | When set, `/metrics` requires this bearer token (per-client counters reveal client ids and activity). |

## Tunables

Every value below is a **security trade-off, not a preference** - read the
notes before changing it.

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_OTI_TTL` | `5m` | `30s`–`24h` | One-time-identifier lifetime (Go duration, e.g. `90s`, `15m`). An OTI is a bearer credential: a longer TTL widens the window in which an intercepted token is usable. Raise it only when the receiving system genuinely cannot verify within 5 minutes (slow queue consumers, batch handoffs); shorten it for same-network service-to-service handoffs. |
| `SUNDER_PII_ALG` | `aes256gcm` | `aes256gcm` \| `xchacha20poly1305` | AEAD used for **newly written** PII blobs. Reads always follow the algorithm stored with each blob, so changing this is safe on a live system; convert the backlog with `sunder keys rekey` (see `docs/RUNBOOK-ALG-MIGRATION.md`). |
| `SUNDER_WEBHOOK_TIMEOUT` | `5s` | `1s`–`5m` | Per-delivery HTTP timeout for erasure webhooks. |
| `SUNDER_WEBHOOK_MAX_ATTEMPTS` | `10` | ≥ `1` | Failed deliveries before an erasure event is marked `FAILED` (audited). A higher cap tolerates flakier receivers but lets one dead endpoint occupy the retry queue longer. |
| `SUNDER_DELIVER_INTERVAL` | `1m` | `5s`–`1h` | Cadence of the background webhook retry worker. `Erase` always attempts one inline delivery regardless. |

## Privacy portal

The self-service portal is **off by default**: an upgrade must never
silently open a new unauthenticated public surface.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_PORTAL_ENABLED` | `false` | `true` mounts the citizen-facing portal. |
| `SUNDER_PORTAL_LISTEN` | - | Separate bind address for the portal (e.g. `:8081`). **Required when the API runs with mTLS**: browsers cannot present a client certificate, so a portal on the API listener would refuse every citizen. |
| `SUNDER_PORTAL_BASE_URL` | - | Public base URL used to build the magic link in the mail payload (`https://privacy.acme.example` -> `.../portal/#token=...`). Without it the payload carries only the raw code. Must be https (loopback http allowed for development). |
| `SUNDER_PORTAL_COOKIE_INSECURE` | `false` | Drops `Secure` from the session cookie. Local development only - the default keeps it set even when TLS terminates at the ingress. |
| `SUNDER_PORTAL_CLIENT_IP_HEADER` | - | Header trusted for per-requester rate limiting behind a proxy (e.g. `X-Forwarded-For`). Opt-in: unset means `RemoteAddr`, which behind an ingress is the proxy for everyone. The **right-most** entry is used - the one the adjacent proxy appended - because the left-most is whatever the caller sent. With nginx-ingress's default `$proxy_add_x_forwarded_for` (which appends) this is correct as-is; if your proxy *overwrites* the header instead, any entry works. |
| `SUNDER_PORTAL_TRUSTED_PROXY_HOPS` | `0` | Extra proxies between the client and this service; that many entries are skipped from the right. Getting this wrong hands each requester their own rate-limit bucket, so verify it against a real request before relying on the limits. |

Also required: the org's mailer endpoint registered under the reserved
scope `_portal` (`sunder webhook set -scope _portal -url ...`). Sunder
sends no e-mail itself - it POSTs a signed `portal_login` /
`portal_erase_confirm` event and the org turns it into a message. Without a
mailer, links are queued and marked `NO_MAILER`; the citizen-facing
response never reveals whether an address exists or the mailer works.

Portal rate limits are per route and per requester: the mail-sending route
is the strictest (5/min), reads are 60/min, and there is an independent
per-address cap of 3 login mails per 15 minutes so one requester cannot
mail-bomb a chosen victim. On the portal surface the limiter always fails
**closed** if Redis is unreachable.

Invalid values (unparseable durations, out-of-range numbers, unknown
algorithm names) fail startup with a specific error - a typo can never
silently fall back to a default.
