# Sunder - Code Review

| Pass | Baseline | Findings |
|---|---|---|
| 1 | `37c704d` + uncommitted P2.2 | F1-F17 |
| 2 | `e1f321e` (Phase 2, P2.1-P2.6) | N1-N23 |
| 3 | `0f39e8c` + working tree | verified passes 1-2; raised P0-P11 |
| **4 (this one)** | `0f39e8c` + working tree | verified pass 3 |

**Method.** Every claimed fix is traced to its production call path, never read from a comment or a commit message. Load-bearing items are confirmed with executable repros: a live exploit test for the erasure bypass, a timing harness for the enumeration oracle, a concurrency test for the blob races, a forgery test against the project's own crypto primitives, and `helm template` for chart values.

## Verdict

**The tree is green again** - the mid-flight `0016` refactor that had 4 tests failing last pass is finished, and the full suite passes.

**N2 (enumeration oracle) is now closed.** A 40 ms constant-time floor was added to `Start`. Measured, 25 distinct registered addresses vs 25 unknown, each probed exactly once so the per-address throttle never short-circuits:

```
before the floor:  UNKNOWN 1.98 ms   KNOWN 4.44 ms   (2.2x, near-total separation)
after  the floor:  UNKNOWN 41.02 ms  KNOWN 40.81 ms  (gap -0.2 ms, i.e. noise)
                   24 of 25 known probes fall inside the unknown range
```

That is the right kind of fix: it does not pretend the work is equal, it makes the difference unobservable, and the comment says exactly that. The accompanying test was also rewritten from a vacuous `hit <= miss + 300ms` tolerance into a real assertion (no perfect separation between the fastest hit and the slowest miss).

**Two things now block CI**, and neither is in the feature code:

- **Coverage is 89.2% against a gate that was just raised to 90.0%.** The gate went 88 → 90 in `.github/workflows/ci.yml` while actual coverage sits below it, so the pipeline fails on the raise itself.
- **`TestAnchorEnvironmentErrors` is flaky under the exact CI command.** Reproduced once in five full-suite runs of `go test -race -coverprofile ... ./...`; never reproducible in isolation or with the `internal/audit` package alone (6 attempts). It only shows up when the whole suite loads the machine and contends on the shared Postgres, which is precisely the CI condition.

**Everything raised in pass 3 is still open.** P0-a and P0-b in particular were the two HIGH items, and both still have a comment or a test asserting they are handled.

---

# Part A - Fixed this round

- **N2** - constant-time floor, measured above. `portalStartFloor = 40 * time.Millisecond` (`internal/service/portal.go:45`), applied in a `defer` so it covers every return path including errors.
- **The `0016` refactor is complete** - `portal_test.go` no longer references the dropped `token` column, and the test that expected the old no-retry behaviour was updated to match the corrected worker.
- **New outbox test coverage** - `internal/api/portal_hardening_test.go` adds transient-failure retry, attempt-cap give-up, a nothing-usable-at-rest check on the sealed payload, the timing test above, and handler edge cases. This closes the pass-3 complaint that the retry and settle logic - where P3 and P4 live - was the least-covered new code.

Carried forward as fixed from earlier passes: F6, F13, N1 (primary exploit), N3-N8, N10-N18, N20-N23, and the low items listed in pass 3. Of the 40 findings in passes 1-2, 34 are fully fixed, 3 partial, 2 not fixed, 1 resolved as a documented design decision.

---

# Part B - Still open

Ordered by severity. Nothing here is new this round; all of it was raised in pass 3 and re-verified against the current tree.

### P0-a - the erasure guard is read outside the transaction that writes, and `GetAttribute` has no guard (HIGH)

Unchanged. `contacts.go:417` is still `FROM cids WHERE cid=$1 AND scope=$2` with no `persons` join, and `mergeIntoBlob` (`contacts.go:465`) still takes `FOR UPDATE` on `cids` alone.

Two consequences. The tombstone check in `ExternalClaims` runs on `c.Pool` (autocommit) while the merge runs in a separate transaction, so an `erasePerson` that commits in between lets a fresh live blob land on a tombstoned CID. And `GetAttribute` returns 404 after an erasure only because the blob is NULL - the accident, not a guard - while appending the `attributes.read` audit row (`contacts.go:433`) *before* the empty-blob check at `:439`, so a read of an erased person is recorded as a real disclosure.

One change covers both: put the predicate in the locking read - `FROM cids c JOIN persons p ON p.id = c.person_id WHERE c.cid = $1 AND p.erased_at IS NULL FOR UPDATE OF c` - and add the same join to `GetAttribute`.

### P0-b - the degenerate-key guard misses the point that actually forges (HIGH)

Unchanged: `external.go:109` still rejects only `isAllZero(pubKey)`. That catches `00…00` and misses the **identity point `01 00…00`**, the one small-order encoding that is universally forgeable under Go's cofactorless verify. Re-verified against this repo's own primitives:

```
FORGERY ACCEPTED for message "anything"
FORGERY ACCEPTED for message "{\"iss\":\"gov\",\"claims\":{\"age_gte_18\":\"true\"}}"
FORGERY ACCEPTED for message ""
isAllZero(identity point) = false   <- guard misses it
```

A 64-byte signature of `01` followed by zeros verifies for any payload under that key, and `sunder issuer add` (`main.go:646-670`) validates hex length only. It needs an operator to register that specific key, so it is onboarding integrity rather than a remote exploit - but the comment at `external.go:105-108` and the test at `external_test.go:263-277` both assert the class is handled, which is how a gap stops being looked at. Reject all eight small-order encodings, at `issuer add` as well as at verify.

### P1 - every unauthenticated portal login attempt takes the global audit lock (MEDIUM-HIGH)

`audit.Append` still runs before the `if !found` return (`portal.go:106-113`), and `AppendTx` takes `pg_advisory_xact_lock(appendLockKey)` - the single lock serialising every audit write in the product. An unauthenticated public endpoint can therefore serialise the whole service's write path. The 5/min per-IP limit is the only brake, and it is bypassable via N9 below.

### P9 - the claims rate limit fails open, restoring the N4 DoS (MEDIUM)

`redis.go:202` fails closed only for keys prefixed `portal:`; the `claims:` bucket (`api/contacts.go:118`) is not, and `SUNDER_REDIS_FAIL_CLOSED` defaults to false. A Redis outage removes the limit and any client holding `claims.external` can again serialise the instance behind the audit lock. The "degrade abuse control, not availability" rationale is inverted here - on this endpoint the abuse control *is* the availability control, which is the same reasoning that made the portal buckets fail closed.

### N9 - the client-IP header reads the attacker-controlled end (MEDIUM)

`api/portal.go:29-31` still takes the **left-most** `X-Forwarded-For` entry. nginx-ingress's default `$proxy_add_x_forwarded_for` appends, so the left-most value is caller-supplied: a random header per request yields a fresh bucket every time, defeating both the login-mail cap and the probe limit. `docs/CONFIG.md:73` still offers `X-Forwarded-For` as the example with no warning that the header must be one the proxy overwrites. Use right-most-minus-trusted-hops. The function's own comment already says "a blindly trusted header is a limiter bypass" - the intent is right, the index is wrong.

### P3 - concurrent replicas double-send every mail (MEDIUM)

Still no `FOR UPDATE SKIP LOCKED` or lease anywhere in `portal.go` or `gdpr.go`; the claim is a plain `SELECT ... WHERE status='PENDING'` and the POST precedes the status update. The worker runs in every replica and the chart defaults to `replicaCount: 2`, so every login link is mailed twice and the per-address cap of 3 becomes 3R. Worth fixing once for both workers.

### P10 - envelope rows survive erasure; acceptance and pruning use different clocks (MEDIUM)

`erasePerson` still touches no `external_envelopes` rows, so an issuer-chosen `jti` outlives an Article 17 erasure by up to `maxEnvelopeLifetime` plus a cron interval (~48h) - while `gdpr.go:525-527` states that is not acceptable. Acceptance uses the application clock (`external.go:130,135`), pruning the database clock (`gdpr.go:529`); a DB clock running ahead prunes rows for envelopes the app still accepts, reopening a replay window.

### P4 - PENDING outbox rows are never pruned, and erasure does not clear them (LOW-MEDIUM)

`PrunePortal` still deletes only `status <> 'PENDING'`, and `erasePerson` touches no portal tables (verified by grep). An unreachable mailer grows the table without bound, and a pending login or erase-confirm for a person erased in the meantime still gets delivered. Since `0016` the payload is sealed, so this is lifecycle and correctness, not plaintext-at-rest.

### P2 - the audit chain records the hit/miss answer (LOW-MEDIUM)

`Detail: {"queued": found}` (`portal.go:110`) sits three lines under a comment reading "Nothing about the address is logged - the audit chain must not become the enumeration oracle either". The address is not logged, so it is not an oracle by itself, but anyone who can read the chain and time their own probe gets confirmation. Logging the attempt without the outcome keeps the accountability value.

### N19 - the TSA CA path is documented as configurable and is inert (LOW-MEDIUM)

Unchanged, and still the F6 pattern: `deploy/helm/sunder/values.yaml:83` defines `anchor.caPath` with a comment naming the review finding, and `grep -rn caPath deploy/` returns exactly that one line. Re-proven by rendering:

```
$ helm template t deploy/helm/sunder --set anchor.caPath=/custom/my-ca.pem
args: ["anchor", "-out", "/anchors", "-ca", "/etc/sunder/tsa-ca.pem"]
```

There is also no volume or secret to supply a different bundle, so pointing `anchor.tsaUrl` at your own TSA still makes `Anchor` hard-fail and silently stop producing evidence - which the values comment itself warns about while offering no way to avoid it.

### Remaining low items (all unchanged)

- **P5** - `allowEmailSend` autocommits before the token/outbox transaction, so a rolled-back transaction still burns a send; three such events lock a citizen out for 15 minutes with an empty inbox.
- **P6** - the dedicated portal listener (`server.go:309-313`) sets only `ReadHeaderTimeout`; the main API server sets Read, Write and Idle. This is the unauthenticated public listener.
- **P7** - one goroutine drains both queues sequentially (`server.go:276,284`), so a hanging mailer starves erasure webhook delivery and vice versa.
- **P8** - no `SUNDER_PORTAL_*` variable appears anywhere under `deploy/`; the N12 configuration is correct but the documented deployment path cannot reach it.
- **P11** - `iat` is decoded and never read (`external.go:40`); claim names are length-checked but not charset-checked, so an issuer with `*` can store names unreachable through `GET /v1/contacts/{cid}/attributes/{name}`; the 24h envelope lifetime and the new 429 are absent from `docs/API.md` and the OpenAPI spec; `PruneEnvelopes` carries `RunRetention`'s doc comment; `maxEnvelopeLifetime` and migration 0015's `DEFAULT now() + interval '24 hours'` are independently hardcoded and will drift; `external.go:112` discards `PasetoVerify`'s returned payload and keeps the struct parsed from the unverified one (safe today, unenforced).
- **Webhook URL validation** is still prefix-only (`main.go:135-137`): `http://localhost.attacker.example/` passes the loopback branch.
- **Issuer key rotation** still has no `revoked_at` or history, so remove-then-add silently re-attributes stored `<claim>@<issuer>` attributes to the new key holder.

---

# Part C - CI and test suite

**Coverage: 89.2%, gate: 90.0% → CI fails.** Measured with the exact CI invocation (`go test -race -coverprofile=... -coverpkg=./internal/...,./cmd/... ./...`). The gate was raised from 88 to 90 in this working tree; coverage did not follow. Either the raise lands with the tests that justify it, or it lands after them.

**`TestAnchorEnvironmentErrors` is flaky under the CI command.** Reproduced once in five full-suite `-race` runs; six attempts in isolation and package-alone were all clean, so it is load- or contention-dependent rather than deterministic. `internal/audit` tests manipulate process-global `PATH` via `t.Setenv` and shell out to `openssl`, and every package shares one Postgres server - any of those is a plausible source. Worth pinning down before it starts failing pull requests at random; a flaky gate teaches people to re-run rather than read.

**Test quality moved in the right direction.** The portal timing test now asserts something real (no perfect separation between fastest hit and slowest miss) instead of a 300 ms tolerance ~120x the signal. It is still a weak-form assertion - it catches single-shot enumeration, not a gap that only becomes exploitable after statistical averaging - but it is honest about what it checks, and with the 40 ms floor in place there is no longer a gap for it to miss.

---

## Suggested order

| Priority | Items | Rationale |
|---|---|---|
| 1 | Coverage vs the 90% gate; the anchor flake | Both fail CI today, neither is in the feature code |
| 2 | **P0-a, P0-b** | The erasure guard is racy and `GetAttribute` relies on an accident; the key guard blocks the wrong point. Both have a comment or test asserting otherwise |
| 3 | P1, N9, P9 | An unauthenticated endpoint that can serialise all audit writes, a bypassable brake in front of it, and a claims limiter that vanishes when Redis blinks |
| 4 | P3, P4, P10 | Double-sent mail, unbounded PENDING rows, envelope rows outliving erasure; fix the claim pattern once for both workers |
| 5 | N19 | Wire `caPath` and add a volume for a custom CA, or drop the value and state the chart is FreeTSA-only |
| 6 | P2, P5-P8, P11, webhook URL validation, issuer revocation | Correctness and hardening |
