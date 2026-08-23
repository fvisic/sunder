# Sunder - Full Project Code Review

- **Date:** 2026-08-23
- **Reviewed state:** commit `37c704d` (P2.1 signer split) plus uncommitted work-in-progress (P2.2 credential expiry: `internal/auth/auth.go`, `internal/store/migrations/0009_credential_expiry.sql`)
- **Scope:** all Go code, documentation, tests, SDKs, ops/deploy tooling
- **Method:** every production Go file read line-by-line; `go build`, `go vet` clean; full test suite (including DB integration tests against local Postgres 16) passes; four parallel deep-dive reviews (docs accuracy, SDKs, ops/tooling, test-suite quality); the highest-impact findings were verified with standalone repros.

## Verdict

The core is in genuinely good shape: the crypto layer (PASETO v4.public, AAD-bound PII envelopes, strict keystore, the new Engine/signer split), authorization, scope isolation, audit chain, and GDPR flows are carefully designed and the documented security properties hold in code, with the exceptions listed below. Nothing found is an exploitable security hole. The two findings I would fix before the next release are **F1** (all per-handler metrics and both latency alerts are silently broken) and **F2** (lost-update races that can silently drop PII attributes under concurrency).

---

## A. Code - correctness & security

### F1. HIGH - Per-handler metrics label is always `/v1/` for every API route; both latency alerts can never fire

`internal/api/server.go:155-160` reads `r.Pattern` in the `instrument` wrapper, which sits *outside* the auth middleware. The outer mux stamps `Pattern = "/v1/"` on the request in place, but `auth.Middleware` (`internal/auth/auth.go`) calls `next.ServeHTTP(w, r.WithContext(...))` - a shallow copy - so the inner v1 mux stamps `"POST /v1/lookup"` etc. only on the copy. The instrument wrapper never sees it. Verified with a standalone repro (Go 1.25): observed pattern after the middleware hop is `"/v1/"`.

Consequences:

- `sunder_requests_total` / `sunder_request_seconds` collapse all 11 API routes into one `handler="/v1/"` series.
- `ops/prometheus-alerts.yaml:27` (`SunderLookupLatencyHigh`, `handler="POST /v1/lookup"`) and `:37` (`SunderOTIVerifyLatencyHigh`) match zero series - the alerts silently never fire.
- The Grafana "by handler" panels (`ops/grafana-dashboard.json` panels 1-3) show one merged series.

Fix in `server.go`, not in the alert files: record the pattern where it is actually known (e.g. instrument *inside* the middleware chain, or capture the pattern on the response-recorder from within the innermost handler layer).

### F2. MEDIUM - Lost-update races on PII blob read-modify-write paths can silently drop attributes

Three places read the encrypted blob, merge in memory, and write back without locking the row:

1. `internal/service/contacts.go:271-300` (`registerTx`): `SELECT pii_encrypted ...` then `UPDATE cids SET pii_encrypted=...` inside the tx, but without `FOR UPDATE`. Two concurrent registrations that dedup onto the same person/cid (same contact arriving from two systems at once - exactly the dedup path's purpose) both read the old blob, both merge, and the last commit wins: the first writer's new attributes are silently lost. Read-committed isolation raises no error.
2. `internal/service/oti.go:288-336` (`shareIntoScope`, inside `Verify`): same pattern against the verifier-scope blob; races with a concurrent register/verify on the same cid.
3. `internal/service/rekey.go:154-165` (`rekeyPerson`): worse - the decrypt happens via `c.Pool` reads and the re-encrypt `UPDATE` is a separate non-transactional statement with no guard. A register/share that commits between the read and the write is overwritten with stale attributes (real data loss, and the row is stamped with the new key so nothing looks wrong afterwards).

Fix: `SELECT ... FOR UPDATE` in (1) and (2); in (3) make the update conditional (`WHERE pii_key_id=$old AND pii_alg=$oldalg`) and skip the row when it no longer matches - it was re-keyed on touch anyway.

### F3. LOW - Enumeration warning can be skipped entirely by the equality check

`internal/api/lookup.go:44-48` logs the "possible enumeration attack" warning only when `misses == enumerationThreshold` (exactly 100). The weighted sliding-window count is not monotonic per call (the `frac*prev` term decays between calls; the Redis variant truncates a float), so the count can go 99 -> 101 and the warning never fires. The `sunder_lookup_misses_total` counter still increments per miss, so Prometheus-based alerting is unaffected - only the log line is unreliable. Fix: `>=` with a once-per-window latch.

### F4. LOW - Redis limiter: INCR and EXPIRE are not atomic

`internal/ratelimit/redis.go:196-201`: if the process dies or errors between `INCR` and `EXPIRE`, the bucket key lives forever (Redis memory leak; one stale key per client per window boundary hit). A Lua script or `SET ... EX NX` + `INCR` closes it. Also, `RedisLimiter.Failures()` is never exported to metrics, so fail-open degradation is invisible to ops.

### F5. LOW - Signer socket: brief permission window and unenforced directory perms

`internal/crypto/signer.go:94-99`: between `net.Listen` (socket created with umask-derived mode) and `os.Chmod(0o600)` there is a short window where another same-host user could connect if the parent directory allows traversal. `os.MkdirAll(dir, 0o700)` does not tighten a pre-existing directory. Low impact (deployments put the socket in a private dir), but cheap to fix: `syscall.Umask` around Listen, or verify/enforce directory ownership and mode at startup.

### F6. LOW - Unknown-kid path in OTI verify is the cache-busting vector its comment denies

`internal/service/oti.go:178-189`: every token with a forged unknown `kid` triggers `Ring.Invalidate()` plus a keys-table reload. The comment claims forged kids "cannot turn this into a cache-busting vector at scale", but each such (authenticated) request does exactly one cache invalidation + DB round trip, and also evicts the cache for concurrent legitimate requests. Impact is small (cheap query, authenticated callers only, rate-limitable), but the comment overstates the protection; a per-kind cooldown on the refresh would match the comment's intent.

### F7. INFO - FileKeystore stale-lock reclaim shares the temp path

`internal/crypto/keystore.go:96-99,130-145`: after a 30s stale-lock reclaim, two processes can both run `writeKey` against the same `p+".tmp"`; interleaved truncate/rename can transiently publish a short/empty key file, which `Key()` then rejects (`want 32 bytes`) until the next `Ensure`. Fail-closed and extremely unlikely; use a unique temp name (`os.CreateTemp`) if you ever care.

### Work-in-progress (P2.1 / P2.2) - state as reviewed

- **P2.1 signer split** (`crypto.Engine`, `ServeSigner`, `RemoteEngine`): clean design, behaviour-parity and malformed-frame tests present, full stack e2e over the socket passes. No correctness issues found beyond F5.
- **P2.2 credential expiry** (uncommitted): logic is sound - the expiry check runs *after* the constant-time compare, so `credential_expired` only leaks validity of a secret the caller already holds (deliberate, acceptable). Incomplete as of this review: `RotateSecret` has no caller; the `sunder client rotate-secret` CLI referenced in migration `0009` does not exist yet; `client create` cannot set an expiry; the new expiry branch has no test.

---

## B. Ops / deployment

### F8. HIGH (when mTLS enabled) - Helm probes can never pass with `tls.mtlsSecretName` set

`deploy/helm/sunder/templates/deployment.yaml:26-29` uses `httpGet` probes with `scheme: HTTPS` when TLS is on, but a configured client CA sets `tls.RequireAndVerifyClientCert` (`internal/api/server.go:218`). Kubelet HTTPS probes present no client certificate, so every probe handshake is refused: pods never become Ready and are liveness-killed in a loop. Use `tcpSocket`/`exec` probes (or a separate plaintext health listener) for the mTLS configuration.

### F9. MEDIUM - Anchor CronJob likely cannot write to its PVC

`deploy/helm/sunder/templates/cronjobs.yaml:24-40` runs `sunder anchor -out /anchors` as uid 65532 (non-root image) but sets no `securityContext`/`fsGroup`; freshly provisioned PVCs typically mount root-owned 0755, so the daily `.tsr` export fails with permission denied. Add `fsGroup: 65532` (the main Deployment already has a proper securityContext).

### F10. LOW - databunker migrator: `-dry-run` + `-map-out` clobbers a real mapping file

`migrate/databunker/main.go:268-270` returns `("", nil)` in dry-run; the worker (`:113-117`) treats that as success and appends `{token, ""}`; `:144` `os.Create` truncates. A dry-run re-check after a real migration overwrites the only token->CID mapping record with empty CIDs. Dry-run should skip the mapping append and the CSV write. (Adjacent dead code at `:239-244`: the `default:` arm's `if k == "email" || k == "phone"` can never match - those keys are consumed by earlier `case` arms.)

Verified clean: Dockerfile (non-root both stages, no secrets in layers, `.dockerignore` re-include works - checked with a real build), compose (loopback-only ports, env names match `config.go`), Helm env plumbing and v0.2.0 tags, Grafana metric names, demo scripts, benchmark/k6 endpoints, CI/release workflows (coverage gate, cosign, SBOM).

---

## C. Documentation & API contract

### F11. HIGH - `api/openapi.yaml` `OtiIssueRequest` schema is corrupted

Lines ~686-704: `audience:` is an empty node; its `type: string`, description and example are mis-indented under `share_attributes`, which now has duplicate `type`/`description` keys. A YAML parser yields `audience: null` and `share_attributes: {type: string, ...}` - the array typing and description are lost. The file is embedded and served live at `GET /openapi.yaml` and RELEASING.md names it "the source of truth", so any codegen/validator consumer gets a wrong contract for `/v1/oti`. Re-indent the block.

### F12. MEDIUM - `consent_denied` is missing from the error contract

The server returns 403 `{"error":"consent_denied"}` (`internal/api/contacts.go:28-29`) from attribute reads and OTI issuance, but the code is absent from the OpenAPI `Error.error` enum (`api/openapi.yaml:741-753`), from the `ForbiddenOrPurpose` 403 responses, and from the canonical code list at the top of `docs/API.md` - even though both documents mention it elsewhere in prose. All five SDKs consequently map it to generic Forbidden (see F16).

### F13. LOW - Stale/overbroad claims in design docs

- `docs/THREAT-MODEL.md` row 9 calls the shared rate-limit backend "planned"; the Redis-backed limiter/detector exists (`internal/ratelimit/redis.go`) and is wired via `SUNDER_REDIS_ADDR`.
- `docs/ARCHITECTURE.md` / `docs/DESIGN.md` §5: "the only runtime dependency is pgx" / "crypto hot path is stdlib only" - `golang.org/x/text` (NFKC on every registration/lookup) is a direct dependency and `x/crypto/chacha20poly1305` is on the crypto path. Side note: `go.mod` marks `golang.org/x/crypto` as `// indirect` despite the direct import - run `go mod tidy`.
- `docs/API.md` (Audit section), `docs/DESIGN.md` §4, README: "audit ... inside the same transaction as the operation" is true for register/scopes.issue/oti.issue/oti.verify but NOT for `attributes.read` and `lookup`, which use standalone `audit.Append` (own transaction; the guarantee is preserved differently - fail-closed *before* the value is released). Reword.
- `docs/API.md:39` and the `/v1/contacts` description in `openapi.yaml` hardcode "AES-256-GCM blob"; with algorithm agility, new blobs follow `SUNDER_PII_ALG` (the rest of the docs already say so).

---

## D. SDKs

All five SDKs (python, typescript, java, php, dotnet) have correct endpoint paths, methods, field names, status-code expectations and retry policies; TLS verification is never disabled; python/ts/php/java test suites all pass locally. Findings:

### F14. MEDIUM - TypeScript: unguarded `res.json()` on 2xx breaks the SDK's own error contract

`sdks/typescript/src/index.ts:395`: a non-JSON success body escapes as a raw `SyntaxError` instead of `SunderError`, unlike the other four SDKs which map this to `bad_response` (and test it). Related: TS is also the only SDK that does not shape-check success bodies - a 2xx missing `cid` yields `{cid: undefined}` silently.

### F15. LOW - TypeScript: error mapping is status-first, other SDKs are code-first

`index.ts:72-94` switches on HTTP status and consults the server `error` code only inside the 400/403 arms; python/php/java/dotnet map the code first (explicitly tested behaviour there). Not a live bug (the server never emits mismatched pairs) but a cross-SDK divergence.

### F16. LOW - `consent_denied` missing from every SDK's error map

Consequence of F12: all five SDKs degrade it to generic Forbidden; callers cannot type-match "consent withdrawn" vs "action not granted". The raw code survives in the exception's `code` field.

### F17. LOW - TypeScript: `combineSignals` leaks abort listeners on Node 18-20.2

`index.ts:32-42`: the fallback path adds a `{once:true}` listener per request to a caller-supplied long-lived signal and never removes it on normal completion - unbounded accumulation (`MaxListenersExceededWarning`).

---

## E. Test suite

Strong overall (isolation via per-test databases, fault-injection, real e2e over TLS/mTLS/signer socket). Substantive issues:

1. **`internal/api/fault_e2e_test.go:124`** - the "oti verify on dead pool" assertion never reaches the pool: purpose `"x"` fails the `CanUse` check before any DB access, so the test passes even if the dead-pool behaviour regressed. Use a granted purpose.
2. **`internal/crypto/crypto_test.go:208-210`** (`TestCSPRNGFailureSurfaces`) - the Encrypt case exercises key *generation* failure, not the nonce CSPRNG branch in `LocalEngine.Seal` that the name promises. Create the key first, then stub `randRead`.
3. **`internal/crypto/signer_test.go:101-107`** - the directory-permission assertion tests `os.MkdirTemp` (the helper), not `ServeSigner`; production could change to 0755 and it would still pass.
4. **`internal/api/rotation_e2e_test.go:77-99`** - "retired signing key stops verifying" is asserted only via ring state; no test presents an actually-v1-signed token after retirement (the crafted-token technique from `TestOTIUnknownKidRejected` would work).
5. **Flakiness risks:** fixed 400 ms sleep in `cmd/sunder/run_env_test.go:62` (migrate+bootstrap+listen on slow CI); 50 ms sleep after signer kill in `internal/api/signer_e2e_test.go:114-118` (pooled connection may still serve - poll until failure instead); minute-boundary race in `internal/api/lookup_e2e_test.go:94-103`; wall-clock vs Postgres-clock dependency in `internal/service/tunables_test.go:34-41`.
6. **`internal/api/tls_run_test.go:109-143`** - the mTLS-refusal test passes vacuously if the server never bound (every `Get` errors); assert `Run`'s error via `<-done`.
7. **Untested security branches (low risk, defense-in-depth):** the signed-claims audience check `internal/service/oti.go:193-195` (all existing tests fail earlier at the scope check) and the "signed but never persisted -> forged" branch at `oti.go:234-235` with a validly signed token. The new P2.2 credential-expiry branch in `internal/auth/auth.go` is currently untested.
8. **`internal/store/store_test.go:11-36`** - the one test that migrates the shared `SUNDER_TEST_DB_URL` database directly instead of an isolated per-test DB; permanent schema pollution of the shared server.

---

## Suggested priority

| Order | Findings | Why |
|---|---|---|
| 1 | F1, F11 | Silently broken today: no per-handler observability + published API contract wrong |
| 2 | F2 | Only finding that can lose data (PII attributes) |
| 3 | F8, F9 | Break the moment the corresponding deploy option is used |
| 4 | F12, F14, F10 | Contract/SDK correctness, migrator data clobber |
| 5 | Test items 1-4, 6 | Assertions that cannot catch their intended regression |
| 6 | Everything else | Low severity / documentation hygiene |
