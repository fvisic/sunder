# Configuration Reference

You are about to deploy Sunder and need to know every `SUNDER_*` variable that exists, what it defaults to, what range it accepts, and - for the ones that are security trade-offs rather than preferences - what you give up by changing it.

## How configuration reaches the running process

Sunder takes no config file and no flags (aside from the CLI subcommand flags below). Everything is `SUNDER_*` environment variables, read once at process start. An invalid value - an unparseable duration, an out-of-range number, an unknown algorithm name - fails startup with a specific error; a typo can never silently fall back to a default.

```mermaid
flowchart LR
    ENV["SUNDER_* environment"] -->|"parsed once, fail-fast"| LOADER["Config loader (startup)"]
    LOADER -->|SUNDER_DB_URL| DB[(PostgreSQL)]
    LOADER -->|"SUNDER_KEYSTORE, SUNDER_SIGNER_SOCKET"| KEY["Keystore driver or\nseparate signer process"]
    LOADER -->|"SUNDER_TLS_CERT/KEY, SUNDER_MTLS_CA"| API["API listener\n(SUNDER_LISTEN)"]
    LOADER -->|SUNDER_REDIS_ADDR| RL["Rate limiter"]
    LOADER -->|"SUNDER_AUDIT_SEALING\nSUNDER_AUDIT_SEAL_*"| SEALER["Sealer\n(inline or external)"]
    LOADER -->|SUNDER_PORTAL_*| PORTAL["Portal listener\n(SUNDER_PORTAL_LISTEN)"]
    API -->|"INSERT unsealed row"| AUDIT[(audit table\nhash chain)]
    SEALER -->|"UPDATE prev_hash, hash, chain_seq"| AUDIT
    RL -->|"allow / deny\n(fail open or closed)"| API
    PORTAL -->|"POST portal_login event"| API
    KEY -->|"sign / decrypt on demand"| API
```

Every subsystem reads its own slice of the environment once; nothing here is reloaded without a restart.

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
| `SUNDER_SIGNER_SOCKET` | - | When set, ALL cryptography runs in a separate `sunder signer` process reachable on this Unix socket; this process then never holds key material and needs no keystore configuration. Started with `sunder signer -socket <path>`; needs the keystore variables but no database. |

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

Every value below is a **security trade-off, not a preference** - read the description before changing it.

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_OTI_TTL` | `5m` | `30s`-`24h` | One-time-identifier lifetime (Go duration, e.g. `90s`, `15m`). An OTI is a bearer credential: a longer TTL widens the window in which an intercepted token is usable. Raise it only when the receiving system genuinely cannot verify within 5 minutes; shorten it for same-network service-to-service handoffs. |
| `SUNDER_PII_ALG` | `aes256gcm` | `aes256gcm` \| `xchacha20poly1305` | AEAD used for **newly written** PII blobs. Reads always follow the algorithm stored with each blob, so changing this is safe on a live system; convert the backlog with `sunder keys rekey`. |
| `SUNDER_WEBHOOK_TIMEOUT` | `5s` | `1s`-`5m` | Per-delivery HTTP timeout for erasure webhooks. |
| `SUNDER_WEBHOOK_MAX_ATTEMPTS` | `10` | >= `1` | Failed deliveries before an erasure event is marked `FAILED` (audited). A higher cap tolerates flakier receivers but lets one dead endpoint occupy the retry queue longer. |
| `SUNDER_DELIVER_INTERVAL` | `1m` | `5s`-`1h` | Cadence of the background webhook retry worker. `Erase` always attempts one inline delivery regardless. |

## Audit sealing

How audit records enter the hash chain - the one setting with a measured order-of-magnitude throughput effect.

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_SEALING` | `async` | `async` \| `sync` | `async`: audited operations INSERT unsealed rows with no lock; a sealer chains them within `interval + delay`. Measured at 298 -> 4,114 tps on the audit write path at c=32 in the 26.8M-contact scale test. Opens a sealing window: a row is tamper-evident against edits from birth (trigger), but its chain hash exists only after sealing. `sync`: chain lock inside the business transaction, hash at insert, zero window, serialized throughput - measured at a ~420 rps instance-wide ceiling regardless of data size, hardware or concurrency. |
| `SUNDER_AUDIT_SEAL_INTERVAL` | `200ms` | `50ms`-`30s` | Sealer cadence. Shorter narrows the sealing window and spends more sealer transactions. |
| `SUNDER_AUDIT_SEAL_DELAY` | `2s` | `100ms`-`5m` | How long a row must settle before sealing. Not a correctness knob (`chain_seq` handles commit-order races, so a late-committing row enters the chain late rather than being lost) - it only keeps chain order close to wall-clock order. |
| `SUNDER_AUDIT_SEAL_BATCH` | `5000` | >= `100` | Rows per sealing transaction: one lock acquisition and one fsync per batch. |
| `SUNDER_AUDIT_SEAL_EXTERNAL` | `false` | boolean | `true`: this process seals nothing; run `sunder sealer` separately, on a DB role that may UPDATE only `prev_hash`/`hash`/`chain_seq` - the API role gets INSERT but no UPDATE, so a compromised API cannot forge hashes over its own rows. |

Mode changes are restart-only: `sync -> async` needs nothing; `async -> sync` drains every unsealed row before the listeners open, so no record is left outside the chain by the switch. On a multi-replica deployment switching to `sync`, stop ALL replicas first - a lingering async replica committing after the new instance's startup drain leaves that row outside the chain until the next drain.

## Privacy portal

Off by default: an upgrade must never silently open a new unauthenticated public surface.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_PORTAL_ENABLED` | `false` | `true` mounts the citizen-facing portal. |
| `SUNDER_PORTAL_LISTEN` | - | Separate bind address for the portal (e.g. `:8081`). **Required when the API runs with mTLS**: browsers cannot present a client certificate. |
| `SUNDER_PORTAL_BASE_URL` | - | Public base URL used to build the magic link in the mail payload. Without it the payload carries only the raw code. Must be https (loopback http allowed for development). |
| `SUNDER_PORTAL_COOKIE_INSECURE` | `false` | Drops `Secure` from the session cookie. Local development only. |
| `SUNDER_PORTAL_CLIENT_IP_HEADER` | - | Header trusted for per-requester rate limiting behind a proxy (e.g. `X-Forwarded-For`). Opt-in: unset means `RemoteAddr`, which behind an ingress is the proxy for everyone. The right-most entry is used. |
| `SUNDER_PORTAL_TRUSTED_PROXY_HOPS` | `0` | Extra proxies between the client and this service; that many entries are skipped from the right. Verify against a real request before relying on the limits. |

Also required: the org's mailer endpoint registered under the reserved scope `_portal`. Portal rate limits are per route and per requester: mail-sending is strictest (5/min), reads are 60/min, and there is an independent per-address cap of 3 login mails per 15 minutes. The portal limiter always fails **closed** if Redis is unreachable.

## Audit read events

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_READS` | `bucketed` | `bucketed` \| `chained` | `bucketed`: reads UPSERT into hourly buckets keyed `(client_id, user_id, cid, action, hour)`; a closer turns each finished hour into ONE chained row carrying a digest over the hour's buckets. Cuts audit growth by the repeat-access factor. `chained`: every read is its own chained row - per-event tamper evidence, more storage. |

Tamper evidence for reads under `bucketed` holds at hour granularity (an open bucket of the current hour can be altered by a DBA-level attacker without breaking a digest); mutations - register, erase, consent, OTI - are always chained per event in both modes.

## Derived search indexes

Both OFF by default: each widens the search surface and adds token rows per contact.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_SEARCH_FUZZY_NAME` | `false` | Phonetic name narrowing: each word of a name is reduced to a versioned phonetic code and the code is HMAC-tokenized. Names remain narrowing-only - never a primary key. |
| `SUNDER_SEARCH_PHONE_SUFFIX` | `false` | Partial phone lookup: the last 8 digits of each number are HMAC-tokenized (domain-separated). Answers ONLY when exactly one person matches after narrowing - a multi-hit is a miss, never a list, never a count. |

Enabling either on an existing dataset is "flip the variable, run `sunder keys rekey`" - the rekey sweep backfills the derived tokens from the encrypted blobs. The database stores only keyed HMACs of the derived values, never the values themselves.

PostgreSQL memory and WAL settings (not `SUNDER_*` variables) live on the [Postgres Sizing](postgres-sizing.md) page.

## Setting variables

Minimal viable process - just the required variable:

```bash
export SUNDER_DB_URL="postgres://sunder:sunder@localhost:5432/sunder?sslmode=disable"
sunder serve
```

Enable TLS, an external Redis-backed limiter that fails closed, and the observability token:

```bash
export SUNDER_DB_URL="postgres://sunder:sunder@db:5432/sunder"
export SUNDER_TLS_CERT=/etc/sunder/tls.crt
export SUNDER_TLS_KEY=/etc/sunder/tls.key
export SUNDER_REDIS_ADDR=redis:6379
export SUNDER_REDIS_FAIL_CLOSED=true
export SUNDER_METRICS_TOKEN="$(openssl rand -hex 32)"
sunder serve
```

Read the metrics endpoint with the token set above:

```bash
curl -sS https://localhost:8080/metrics \
  -H "Authorization: Bearer $SUNDER_METRICS_TOKEN"
```

No SDK equivalent for `/metrics` - it is meant for a scraper, not application code.

Register the mailer webhook the privacy portal needs before setting `SUNDER_PORTAL_ENABLED=true`:

```bash
sunder webhook set -scope _portal -url https://mailer.internal.example/hooks/portal
```

Run the sealer once by hand (or from cron) instead of waiting for the interval, and check the chain:

```bash
sunder sealer -once
sunder verify-audit
```

## Security notes

- Sunder deliberately refuses to start on an invalid value instead of substituting a default - a mistyped duration or algorithm name never silently downgrades security.
- The privacy portal and the derived search indexes are opt-in and default OFF specifically so an upgrade never opens a new unauthenticated surface or widens the search surface without an operator decision.
- `SUNDER_AUDIT_SEAL_EXTERNAL` does not let the API process seal its own rows even if compromised - it deliberately only grants that process INSERT, not UPDATE, on the audit table.
- `SUNDER_PORTAL_COOKIE_INSECURE` and loopback-http for `SUNDER_PORTAL_BASE_URL` are development affordances, not production paths - the code does not detect environment for you.
- None of these variables are hot-reloaded. A value read wrong at startup stays wrong until the process restarts; there is no live config endpoint to patch around that.
