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
    SEALER -->|"UPDATE prev_hash, hash, chain_seq, hash_v"| AUDIT
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
| `SUNDER_API_CLIENT_IP_HEADER` | - | Header (e.g. `X-Forwarded-For`) whose right-most entry is the client IP on the **API** listener, used by the per-IP limit on the credential-less share fetch. Unset means `RemoteAddr`. Deliberately separate from `SUNDER_PORTAL_CLIENT_IP_HEADER`: the two listeners have different trust boundaries, and trusting a header on a socket nothing appends to hands every requester a fresh rate-limit bucket. |

## Keystore

| Variable | Default | Description |
|---|---|---|
| `SUNDER_KEYSTORE` | `file` | `file` or `vault`. **`pkcs11` is NOT IMPLEMENTED**: the value passes validation, but the server then REFUSES TO START - `keystore bootstrap: keystore: pkcs11 driver not implemented yet`. It fails at startup rather than per request, so a misconfigured deployment never serves traffic. Not merely unfinished: the keystore interface asks for the key BYTES, and an HSM exists so the key never leaves the hardware - real support means implementing the ENGINE interface instead. To keep key material out of the API process today, use `SUNDER_SIGNER_SOCKET`. |
| `SUNDER_KEYSTORE_PATH` | `./keystore` | Key directory for the `file` driver. |
| `SUNDER_VAULT_ADDR` / `SUNDER_VAULT_TOKEN` | - | Required for the `vault` driver (KV v2). |
| `SUNDER_VAULT_MOUNT` | `secret` | KV v2 mount point. |
| `SUNDER_KEYSTORE_ALLOW_MINT` | `false` | Let `serve` create key material for a version that live data was already written under. Off by default, because minting there does not recover anything - it manufactures a vault that cannot read its own contents and reports healthy (`/healthz` 200, every lookup a 404). A first boot against a vault with **no** data still mints without this: nothing references the missing versions. `sunder bootstrap` always mints; it is the explicit "create this vault" act. |
| `SUNDER_KEY_RETIRE_GRACE` | `60s` | How long a key version must sit `RETIRING` before `sunder keys retire` will purge it (range `0`-`24h`). Must exceed the worst-case `KeyRing` cache staleness across the fleet: the purge is one-shot, so a replica still writing under the old version afterwards leaves search-token rows nothing will ever delete or match again. `0` disables the wait (single node); `sunder keys retire -force` overrides it per call. |
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
| `SUNDER_WORKER_CLAIM_TTL` | `10m` | `1m`-`24h` | How long a claimed (`SENDING`) erasure event or portal mail row may go unsettled before a reaper returns it to `PENDING`. Both outboxes commit the claim **before** the side effect, so this is the only thing that recovers a claim abandoned by a killed worker. Set it above the worst-case sweep time (`SUNDER_WEBHOOK_TIMEOUT` x batch size) or a slow endpoint causes a duplicate delivery - deliveries are at-least-once, so a duplicate is safe but noisy. |
| `SUNDER_REKEY_BATCH` | `500` | `1`-`10000` | Persons per page in `sunder keys rekey`, and how many persons' search tokens go into ONE `INSERT`. The sweep used to write one token per statement: on a 26.9M-contact dataset that is 193.6 million synchronous round trips and roughly **87 hours**, with the database idle - it accepts ~54,000 rows/s in-server, so the bottleneck was round-trip latency, not PostgreSQL. Since a key rotation is a security response, a sweep nobody can finish is a capability nobody has. Lower it to hold less memory per batch and be gentler on a loaded database; `1` restores the old behaviour and its duration. `keys rekey -batch N` overrides it per run. |
| `SUNDER_MAX_CASCADE_CHILDREN` | `1000` | `1`-`1000000` | Upper bound on ONE cascading erasure. `dsr/erase` with a cascade type erases one person PER TRANSACTION, children first; unbounded, a link type that happens to have tens of thousands of members holds connections for minutes inside one HTTP call, with no way to stop it. Above this count the request is **REFUSED before anything is erased** (`400 cascade_too_large`, naming the count and the limit) - the parent and every child stay untouched, so the operator chooses between batching and raising the bound rather than discovering the size from a timeout. |

## Audit sealing

How audit records enter the hash chain - the one setting with a measured order-of-magnitude throughput effect.

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_SEALING` | `async` | `async` \| `sync` | `async`: audited operations INSERT unsealed rows with no lock; a sealer chains them within `interval + delay`. Measured at 298 -> 4,114 tps on the audit write path at c=32 in the 26.8M-contact scale test. Opens a sealing window: a row is tamper-evident against edits from birth (trigger), but its chain hash exists only after sealing. `sync`: chain lock inside the business transaction, hash at insert, zero window, serialized throughput - measured at a ~420 rps instance-wide ceiling regardless of data size, hardware or concurrency. |
| `SUNDER_AUDIT_SEAL_INTERVAL` | `200ms` | `50ms`-`30s` | Sealer cadence. Shorter narrows the sealing window and spends more sealer transactions. |
| `SUNDER_AUDIT_SEAL_DELAY` | `2s` | `100ms`-`5m` | How long a row must settle before sealing. Not a correctness knob (`chain_seq` handles commit-order races, so a late-committing row enters the chain late rather than being lost) - it only keeps chain order close to wall-clock order. |
| `SUNDER_AUDIT_SEAL_BATCH` | `5000` | >= `100` | Rows per sealing transaction: one lock acquisition and one fsync per batch. |
| `SUNDER_AUDIT_SEAL_EXTERNAL` | `false` | boolean | `true`: this process seals nothing; run `sunder sealer` separately, on a DB role with `UPDATE (prev_hash, hash, chain_seq, hash_v)` and `INSERT` on `audit`, plus `UPDATE (sealed_at)` on `audit_read_buckets` - the API role gets INSERT but no UPDATE, so a compromised API cannot seal or forge hashes over its own rows. The exact GRANTs are in the audit-operations runbook; omitting `hash_v` makes every seal cycle fail. |

Two more variables cover the sealer's own health rather than its cadence:

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_STALE_UNSEALED` | `15m` | `1s`-`24h` | How old the OLDEST unchained row may get before `sunder verify-audit` calls it a failure. Under async sealing a backlog is normal; a stale one is the stalled-sealer incident, and the hard failure used to be gated on sync mode alone, so the daily verification CronJob exited 0 with an unbounded backlog. |
| `SUNDER_SEALER_HEALTH_ADDR` | - | `host:port` | Address for the `sunder sealer` process's own `/healthz`, which answers 200 only while its last SUCCESSFUL seal pass is recent. The sealer logs-and-continues on error by design, so without a probe a process that lost `UPDATE` on `audit` stays Running and Ready forever. The Helm chart sets it and wires a liveness probe. |

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
| `SUNDER_AUDIT_LOOKUP_ACTIONS` | `single` | `single` \| `split` | `single`: every lookup records as the one action `lookup`. `split`: the trail separates `lookup` (exact), `lookup.fuzzy` (phonetic name codes), `lookup.suffix` (partial phone suffix) and `lookup.suffix.fuzzy` (both). Useful under bucketed reads, where the per-event detail is dropped and the action is all the auditor sees. Costs at most 4.00x the read-bucket rows (measured worst case); consumers filtering `action = 'lookup'` must move to the `lookup.*` prefix first. |

Tamper evidence for reads under `bucketed` holds at hour granularity (an open bucket of the current hour can be altered by a DBA-level attacker without breaking a digest); mutations - register, erase, consent, OTI - are always chained per event in both modes.

## Derived search indexes

Both OFF by default: each widens the search surface and adds token rows per contact.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_SEARCH_FUZZY_NAME` | `false` | Phonetic name narrowing: each word of a name is reduced to a versioned phonetic code and the code is HMAC-tokenized. Names remain narrowing-only - never a primary key. |
| `SUNDER_SEARCH_PHONE_SUFFIX` | `false` | Partial phone lookup: the last 8 digits of each number are HMAC-tokenized (domain-separated). Answers ONLY when exactly one person matches after narrowing - a multi-hit is a miss, never a list, never a count. |
| `SUNDER_SEARCH_UNLOCK` | `false` | Strict posture: fuzzy and partial lookups additionally spend a 60-second single-use unlock token (`POST /v1/admin/unlock` with `{"purpose":"search"}`, sent as `X-Sunder-Unlock`). Default off: single-hit lookups are rate-limited and audited already, and a pre-flight round trip per caller-ID lookup kills that flow. Genuinely BULK surfaces (bulk tokenization) require an unlock token always, regardless of this switch. |

Enabling either on an existing dataset is "flip the variable, run `sunder keys rekey`" - the rekey sweep backfills the derived tokens from the encrypted blobs. The database stores only keyed HMACs of the derived values, never the values themselves.

PostgreSQL memory and WAL settings (not `SUNDER_*` variables) live on the [Postgres Sizing](postgres-sizing.md) page.

## File vault (F5)

Off unless `SUNDER_FILES_STORAGE` is set. Objects are encrypted client-side of the storage driver with a per-file DEK wrapped by the person's record key, so erasing the person shreds the file.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_FILES_STORAGE` | *(disabled)* | `local` or `s3`. **`local` is SINGLE-INSTANCE ONLY**: ciphertext lives in a per-process directory while its metadata and wrapped DEK live in the shared database, so a second replica answers a download with 200, the recorded `Content-Length` and an empty body, and `retention run` collects only its own replica's objects. `s3` is the multi-replica driver. Logged as a startup warning. |
| `SUNDER_FILES_DIR` | `./filestore` | Local-driver directory. A **separate backup unit** from the database and the keystore - restoring those two leaves every `files` row intact with its DEK and no object behind it ([backup/DR runbook](../admin/backup-dr.md)). |
| `SUNDER_FILES_MAX_MB` | `25` | Per-file cap, `1`-`4096` - but `1`-`256` with the `s3` driver, whose single-PUT body must be buffered to hash it for SigV4. Above the driver's cap startup fails. File routes get their own read/write deadline sized from this value. |
| `SUNDER_FILES_MAX_CONCURRENT_UPLOADS` | `4` | Simultaneous uploads, `1`-`1024`. A single-PUT body is buffered whole, so peak upload memory is this times `SUNDER_FILES_MAX_MB`; excess uploads wait rather than being rejected. |
| `SUNDER_FILES_S3_ENDPOINT` | - | S3-compatible endpoint (AWS/MinIO/R2), https. |
| `SUNDER_FILES_S3_BUCKET` | - | Bucket name. |
| `SUNDER_FILES_S3_REGION` | `us-east-1` | SigV4 region. |
| `SUNDER_FILES_S3_ACCESS_KEY` / `SUNDER_FILES_S3_SECRET_KEY` | - | S3 credentials. |
| `SUNDER_FILES_S3_PATH_STYLE` | `false` | `true` for MinIO. |

## Blob version history

| Variable | Default | Description |
|---|---|---|
| `SUNDER_VERSIONS_KEEP` | `0` | Keep the N most recent prior blob versions per CID (`0` = off, max `1000`). Version history is personal data: it is pruned by the retention sweep and destroyed by erasure like any other blob. |
| `SUNDER_VERSIONS_TTL` | `0s` | Also prune versions older than this via `sunder retention run`. Range `0s`-`3650d`; `0s` means the count cap alone. |

## Cross-org shares

| Variable | Default | Description |
|---|---|---|
| `SUNDER_SHARES_PUBLIC` | `false` | When true, `GET /v1/shares/{uuid}` needs no credential (the UUID is the bearer) for cross-org partners. Default requires any valid client credential. Turning it on logs a startup warning: it exposes a credential-less read surface, rate-limited per IP via `SUNDER_API_CLIENT_IP_HEADER`. |

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
