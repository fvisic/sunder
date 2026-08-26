# SDKs and API

Six languages, one wire protocol - pick an SDK for the retry policy and
typed errors, or call the OpenAPI spec directly; either way the same HTTP
contract and the same error codes apply everywhere.

## Mechanism

```mermaid
flowchart LR
    App["Your code"] -->|"crm.LookupByEmail(ctx, email)"| SDK["Sunder SDK\n(Go/TS/Python/Java/.NET/PHP)"]
    SDK -->|"POST /v1/lookup\nAuthorization: Bearer client_id.secret"| HTTP["HTTP call"]
    HTTP --> Sunder["Sunder server"]
    Sunder -->|"200 {cid}"| Success["typed CID value"]
    Sunder -->|"404 {error:not_found}"| ErrMap["error taxonomy mapping"]
    Sunder -->|"429 {error:rate_limited}"| ErrMap
    Sunder -->|"5xx / network failure"| Retry["retry once\n(lookup, IssueOTI only)"]
    Retry -->|"still failing"| ErrMap
    Retry -->|"succeeds"| Success
    ErrMap -->|"errors.Is(err, sunder.ErrNotFound)"| App
    Success --> App
```

`VerifyOTI` is never retried - the token is single-use, so a retry after
an ambiguous network failure could legitimately come back as
`token_used` and the SDK cannot tell whether the first attempt already
succeeded. A definite 4xx verdict and a cancelled context are never
retried on any call.

## Steps

1. **Pick the SDK for your stack and install it.** All six wrap the same
   `/v1/*` surface: transport, bearer auth, timeouts, retries and error
   mapping - zero cryptography client-side.

   ```bash
   go get github.com/fvisic/sunder/sdks/go@latest        # Go 1.25+
   npm install @sunder-id/sunder                          # Node 18+
   pip install sunder-client                               # Python 3.10+
   ```

   ```xml
   <!-- Java 17+ (Maven) -->
   <dependency>
     <groupId>io.sunderid</groupId>
     <artifactId>sunder-client</artifactId>
     <version>0.1.0</version>
   </dependency>
   ```

   ```bash
   dotnet add package SunderId.Client                      # .NET 8.0
   composer require sunder-id/sunder-client                 # PHP 8.1+
   ```

2. **Configure from the environment** - every SDK defaults to `SUNDER_URL`
   and `SUNDER_CREDENTIAL` (`<client_id>.<secret>`, printed once by
   `sunder client create`):

   ```go
   crm, err := sunder.New("", "") // reads SUNDER_URL / SUNDER_CREDENTIAL
   ```

3. **Or call the HTTP API directly** - useful for languages without an
   SDK, or for scripting against the demo stack:

   ```bash
   curl -sX POST https://sunder.internal/v1/contacts \
     -H "Authorization: Bearer $SUNDER_CREDENTIAL" \
     -H "Content-Type: application/json" \
     -d '{"email": "filip@example.com", "name": "Filip Visic",
          "attributes": {"loyalty_tier": "gold"}}'
   ```

4. **Match on the sentinel errors, not on HTTP status codes**, so a status
   code change in a future minor version does not silently break your
   branch logic:

   ```go
   _, err := erp.VerifyOTI(ctx, token, "create_order", "erp")
   switch {
   case errors.Is(err, sunder.ErrTokenUsed):
       // Already consumed - a replay, or your own retry.
   case errors.Is(err, sunder.ErrConsentDenied):
       // Withdrawn consent - distinct from ErrPurposeNotAllowed.
   case errors.Is(err, sunder.ErrCredentialExpired):
       // Correct secret, past its expiry: rotate it, do not retry.
   }
   ```

5. **Import the machine-readable contract** for codegen, contract tests
   or exploratory calls:

   - OpenAPI 3.1: [`api/openapi.yaml`](../../../api/openapi.yaml) - the
     source of truth for every request/response schema and error response.
   - Postman: [`api/sunder.postman_collection.json`](../../../api/sunder.postman_collection.json) -
     set `baseUrl`, `credCrm`, `credErp`, `credNotifier` as collection
     variables; the "Demo" folders are ordered flows runnable top-to-bottom
     with test scripts that pass `cid`/`token` between steps automatically.

## Error taxonomy

Identical across all six SDKs and identical to the raw JSON `{"error":
"<code>"}` shape:

| Sentinel | HTTP | Code |
|---|---|---|
| `ErrUnauthorized` | 401 | `unauthorized` |
| `ErrCredentialExpired` | 401 | `credential_expired` |
| `ErrForbidden` | 403 | `forbidden` |
| `ErrConsentDenied` | 403 | `consent_denied` |
| `ErrPurposeNotAllowed` | 403 | `purpose_not_allowed` |
| `ErrAudienceMismatch` | 403 | `audience_mismatch` |
| `ErrNotFound` | 404 | `not_found` |
| `ErrValidation` | 400 | `validation` / `bad_json` |
| `ErrTokenInvalid` | 400 | `token_invalid` |
| `ErrTokenUsed` | 409 | `token_used` |
| `ErrTokenExpired` | 410 | `token_expired` |
| `ErrRateLimited` | 429 | `rate_limited` |
| `ErrServiceUnavailable` | 503 (or network failure, `Status` 0) | `service_unavailable` |
| `ErrBadResponse` | - | malformed/unexpected server response |

`credential_expired` means the secret itself is correct but past its
expiry - rotate with `sunder client rotate-secret`, do not retry.
`consent_denied` means the data subject withdrew consent for that
purpose; it is distinct from `purpose_not_allowed`, which is a missing
grant on the calling client, not a subject decision.

## Security notes

- **No SDK ships cryptography.** Every one is a thin transport client
  (stdlib HTTP + JSON where the language allows it); signing, hashing and
  encryption happen exclusively on the server, so there is no client-side
  key material to leak from an SDK dependency.
- **Credentials print exactly once.** `sunder client create` shows the
  secret at creation time only; only its hash is stored server-side, so a
  lost credential means issuing a new one, not recovering the old one.
- **`VerifyOTI` retries never happen automatically**, on purpose - an SDK
  that blindly retried a verify call could turn a successful handoff into
  a spurious `token_used` failure for the caller, or worse, mask an actual
  double-spend attempt. Reconciling an ambiguous verify failure is left to
  the caller, who has ticket/order context the SDK does not.
- **A definite 4xx is never retried.** Retrying a validation error or a
  purpose/audience mismatch cannot succeed and would only inflate
  rate-limit counters and audit volume for no benefit.
- **The error taxonomy is deliberately coarse on non-validation 4xx
  bodies.** Only `validation` responses carry a `detail` field - the rest
  stay generic to avoid turning error messages into an oracle for probing
  scope or purpose configuration.
