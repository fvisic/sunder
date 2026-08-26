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

## Audit sealing (P4.1)

How audit records enter the hash chain. This is the one setting with a
measured order-of-magnitude throughput effect, and it is a **security
trade-off**: read `docs/THREAT-MODEL.md` ("Audit chain") before changing
it in either direction.

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_SEALING` | `async` | `async` \| `sync` | `async`: audited operations INSERT unsealed rows with no lock; a sealer chains them within `interval + delay`. Removes the instance-wide serialization (298 -> 4,114 tps on the audit write path at c=32 in the 26.8M-contact scale test). Opens a sealing window: a row is tamper-evident against edits from birth (trigger), but its chain hash exists only after sealing. `sync`: pre-P4.1 behaviour - chain lock inside the business transaction, hash at insert, zero window, serialized throughput. |
| `SUNDER_AUDIT_SEAL_INTERVAL` | `200ms` | `50ms`-`30s` | Sealer cadence. Shorter narrows the sealing window and spends more sealer transactions. |
| `SUNDER_AUDIT_SEAL_DELAY` | `2s` | `100ms`-`5m` | How long a row must settle before sealing. Not a correctness knob (a late-committing row enters the chain late rather than being lost - `chain_seq` handles commit-order races); it only keeps chain order close to wall-clock order. |
| `SUNDER_AUDIT_SEAL_BATCH` | `5000` | >= `100` | Rows per sealing transaction: one lock acquisition and one fsync per batch. |
| `SUNDER_AUDIT_SEAL_EXTERNAL` | `false` | boolean | `true`: this process seals nothing; run `sunder sealer` separately. The point is privilege separation (same pattern as the P2.1 signer split): give the sealer a DB role that may UPDATE only `prev_hash`/`hash`/`chain_seq` on `audit`, and the API a role with INSERT but no UPDATE - a compromised API then cannot forge hashes over its own rows. Rejected together with `sync`. |

**Why async is the default.** The advisory lock that sync mode takes on
every audited operation was measured as the whole throughput ceiling of
the system (benchmark/README.md): ~420 rps instance-wide regardless of
data size, hardware or concurrency, with negative scaling at high client
counts. Async sealing removes that ceiling (4.3x at c=32 on the same
26.8M dataset, still climbing at c=64) while keeping every guarantee
except one: a row's chain hash exists ~2s after the fact instead of at
commit. What survives in the window: the row itself is written in the
same transaction as the operation (fail closed - an operation that cannot
be audited does not happen), and the append-only trigger blocks every
edit. What is given up in the window: DELETING an unsealed row breaks no
hash, so an attacker with DBA-level access (enough to defeat the trigger)
has seconds instead of one row of deniability. Deployments where that
window is unacceptable set `sync` and accept the measured ceiling - the
mode exists precisely so this is the operator's choice, and both modes
run the full test suite in CI.

Mode changes are restart-only, deliberately: two modes live in one process
would mean part of the traffic locking and part not, with no clean
boundary. `sync -> async` needs nothing. `async -> sync` is handled by the
server itself: startup drains every unsealed row **before** the listeners
open, so no record is ever left outside the chain by the switch (covered
by `TestModeSwitchRestartLosesNothing`). When switching a multi-replica
deployment to sync, stop ALL replicas first: a lingering async replica
whose transaction commits after the new instance's startup drain leaves
that row outside the chain until the next drain (`sunder verify-audit`
fails visibly on exactly this state under sync). `sunder sealer -once`
drains the backlog from a cron job or by hand; `sunder verify-audit` always prints
the active mode and the pending count; the `sunder_audit_unsealed_rows`
gauge is the alarm for a stalled sealer.

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

## Audit read events (P4.2)

Lookups and attribute reads are the highest-volume audited events; the
audit log is never pruned. How they are recorded is a runtime choice:

| Variable | Default | Range | Description |
|---|---|---|---|
| `SUNDER_AUDIT_READS` | `bucketed` | `bucketed` \| `chained` | `bucketed`: reads UPSERT into hourly buckets keyed `(client_id, user_id, cid, action, hour)`; a closer turns each finished hour into ONE chained audit row carrying a digest over the hour's buckets, and sealed buckets are immutable (trigger) and digest-checked by `verify-audit`. Cuts audit growth by the repeat-access factor and stores less about operator behaviour. `chained`: every read is its own chained row - per-event tamper evidence, pre-P4.2 behaviour. |

Trade-off in one line: under `bucketed`, tamper evidence for READS holds
at hour granularity (an open bucket of the current hour can be altered by
a DBA-level attacker without breaking a digest); mutations - register,
erase, consent, OTI - are always chained per event in both modes. The
hourly close runs in the server, or in `sunder sealer` when
`SUNDER_AUDIT_SEAL_EXTERNAL=true`; `sunder sealer -once` closes finished
hours too, and `verify-audit` recomputes every sealed hour's digest.

**Operator attribution (`user_id`).** A client system may attribute each
read to the operator inside it: the `user_id` body field on `POST
/v1/lookup`, or the `X-Sunder-User-Id` header on GET routes (body wins if
both are sent). It is an opaque ID - `[A-Za-z0-9._@:-]`, max 64, never a
name - validated with a 400 on anything else, stored as a queryable
`user_id` column on chained rows and as a bucket key, and returned in the
Article 15 access trail. It is CLIENT-ASSERTED: Sunder records it, it
does not verify it - the same trust model as Databunker's `who` field,
with two differences in Sunder's favour: the record is tamper-evident and
carries no raw values. The data subject is always the CID; `user_id` is
never the person being looked up.

## Derived search indexes (Phase 3, F1/F2)

Both OFF by default: each widens the search surface and adds token rows
per contact, and an upgrade must never do that silently. Enabling either
on an existing dataset is "flip the variable, run `sunder keys rekey`" -
the rekey sweep backfills the derived tokens from the encrypted blobs.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_SEARCH_FUZZY_NAME` | `false` | Phonetic name narrowing: each word of a name is reduced to a versioned phonetic code ("ph1", built for Croatian: diacritics, dj/đ/d spellings, ije/je/e, vowel typos) and the CODE is HMAC-tokenized. A lookup's `name` then narrows on exact OR phonetic match. Names remain narrowing-only - never a primary key. |
| `SUNDER_SEARCH_PHONE_SUFFIX` | `false` | Partial phone lookup: the last 8 digits of each number are HMAC-tokenized (domain-separated), and `POST /v1/lookup` accepts `phone_suffix` (>= 8 digits; national or international spelling both work). It answers ONLY when exactly one person matches after narrowing - a multi-hit is a miss, never a list and never a count, so bulk-deny holds for partial search too. Combine with `name` to disambiguate. |

Cost when enabled: one extra HMAC and one extra index row per name word
(max 4) and per phone at registration; the exact email/phone lookup path
is untouched. The database stores only keyed HMACs of the derived values,
never the values themselves.

## Select security (F3)

| Variable | Default | Description |
|---|---|---|
| `SUNDER_SEARCH_UNLOCK` | `false` | Strict posture: fuzzy and partial lookups additionally spend a 60-second single-use unlock token (`POST /v1/admin/unlock` with `{"purpose":"search"}`, sent as `X-Sunder-Unlock`). Default off: single-hit lookups are rate-limited and audited already, and a pre-flight round trip per caller-ID lookup kills that flow. Genuinely BULK surfaces (bulk tokenization) require an unlock token always, regardless of this switch. |

Per-client narrowing lives on the client record, not in env: `sunder client
create -attributes iban,tier` restricts which attribute names that
credential can read (GetAttribute refuses, Export/Access filter); `-role
readonly|service|admin` applies an action preset instead of `-actions`.

## Value tokenization (F4)

No configuration - the surface is gated by the `tokens.create` /
`tokens.read` actions on the client. `POST /v1/tokens` swaps a value (max
8 KB) for an opaque token, `type: "card"` returns a Luhn-valid,
length-preserving, BIN-free digit token; `unique: true` dedups by keyed
HMAC per scope; `expires_final` (RFC3339) and `sliding_seconds` bound the
mapping's life; expired rows are swept by `sunder retention run`. Bulk
endpoints (`/v1/tokens/bulk`, `/v1/tokens/bulk/read`, max 1000 items)
always require an unlock token with purpose `bulk-tokens`.

## File vault (F5)

Off unless a storage driver is configured - files are a new data class,
an upgrade must not silently start accepting them.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_FILES_STORAGE` | `` (disabled) | `local` or `s3` |
| `SUNDER_FILES_DIR` | `./filestore` | local driver directory |
| `SUNDER_FILES_MAX_MB` | `25` | per-file cap, 1-4096 |
| `SUNDER_FILES_S3_ENDPOINT` | | S3-compatible endpoint (AWS/MinIO/R2), https |
| `SUNDER_FILES_S3_BUCKET` | | bucket name |
| `SUNDER_FILES_S3_REGION` | `us-east-1` | SigV4 region |
| `SUNDER_FILES_S3_ACCESS_KEY` / `_SECRET_KEY` | | credentials |
| `SUNDER_FILES_S3_PATH_STYLE` | `false` | `true` for MinIO |

Crypto chain: PII KEK wraps a per-person RECORD KEY, which wraps a
per-file DEK, which encrypts content in 4 MiB AES-256-GCM chunks (chunk
index in the AAD - chunks cannot be reordered or transplanted). Erasure
deletes the record key row: every file of that person is unrecoverable at
commit time (crypto-shredding), and `sunder retention run`
garbage-collects the dead ciphertext. The storage driver only ever sees
ciphertext.

## Attribute blob versioning (F6)

OFF by default: keeping history extends the storage-limitation clock, a
real GDPR tension, so an upgrade must not silently start retaining
superseded values.

| Variable | Default | Description |
|---|---|---|
| `SUNDER_VERSIONS_KEEP` | `0` | keep the N most recent prior blob versions per cid (0 = off, max 1000) |
| `SUNDER_VERSIONS_TTL` | `0s` | also prune versions older than this via `sunder retention run` |

Every overwrite of a cid's attribute blob snapshots the PREVIOUS value
into `cid_blob_versions` in the SAME transaction as the write. History is
read through `GET /v1/contacts/{cid}/versions` (metadata) and
`GET /v1/contacts/{cid}/versions/{n}/attributes/{name}` (one field,
`attributes.history` action) - purpose-, consent- and allowlist-checked
and audited exactly like a live read. History is erased with the person
(same personal data, one generation older) and pruned by retention.

## PostgreSQL sizing (P4.5)

Stock Postgres defaults (128 MB `shared_buffers`) measure the defaults,
not the system - the shipped compose file and the values below come from
the 26.8M-contact scale test in `benchmark/README.md`. Sunder itself
holds no state; give the memory to Postgres.

| Setting | Small (4 GB host) | Large (48 GB host) | Why |
|---|---|---|---|
| `shared_buffers` | `512MB` | `12GB` | ~25% of the RAM given to Postgres; the token indexes live here |
| `effective_cache_size` | `1536MB` | `32GB` | ~75%; planner hint, allocates nothing |
| `max_wal_size` | `4GB` | `16GB` | bulk ingest (`sunder import`) checkpoints less often |
| `random_page_cost` | `1.1` | `1.1` | NVMe/SSD assumption; keep 4.0 only on spinning disks |
| `maintenance_work_mem` | default | `2GB` | index builds during migrations at scale |

Keyed-HMAC search tokens are uniformly random, so index access has no
locality: cache residency is the whole game, which is why
`shared_buffers` matters more here than for a typical CRUD schema.
