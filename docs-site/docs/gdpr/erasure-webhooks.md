# Erasure Webhooks

A scope's own system (CRM, billing, support desk) needs to learn, reliably and verifiably, when a person it holds a pseudonym for must be forgotten - without keeping a live connection to Sunder or trusting a request it can't authenticate.

## Mechanism

Sunder is the only component that knows every scope holding a person, so an erasure fans out: one signed webhook event per scope, queued transactionally with the erasure itself and delivered by a worker that retries until a scope's endpoint acknowledges - or gives up and marks the event `FAILED`.

```mermaid
sequenceDiagram
    participant O as Privacy officer / portal
    participant S as Sunder GDPR service
    participant DB as Postgres
    participant CRM as crm webhook
    participant BIL as billing webhook

    O->>S: POST /v1/dsr/erase {cid}
    S->>DB: tx - wipe blobs, delete search tokens, tombstone person
    S->>DB: insert erasure_events (one row per scope holding this person)
    S-->>O: 200 {erasure_id, scopes}

    Note over S,DB: DeliverPending - runs once immediately, then every minute
    DB->>S: claim PENDING events (SKIP LOCKED), mark SENDING
    S->>CRM: POST {event:"erase", scope:"crm", cid, erasure_id, ts} + X-Sunder-Signature
    CRM-->>S: 200
    S->>DB: status=DELIVERED; audit "dsr.erase.delivered"

    S->>BIL: POST {event:"erase", scope:"billing", cid, erasure_id, ts} + X-Sunder-Signature
    BIL-->>S: connection refused
    S->>DB: attempts+=1, status=PENDING (retried next sweep)
    Note over S,DB: after MaxAttempts (default 10): status=FAILED, audit "dsr.erase.failed"
```

## Steps

### 1. Register the scope's endpoint

```bash
sunder webhook set -scope crm -url https://crm.internal/hooks/sunder-erase
```

Each scope registers its own URL and gets its own secret; there is no shared secret across scopes.

### 2. Trigger an erasure

```bash
curl -X POST https://sunder.internal/v1/dsr/erase \
  -H "Authorization: Bearer privacy_officer.<secret>" \
  -H "Content-Type: application/json" \
  -d '{"cid": "cid_9f2a..."}'
```

```json
{"erasure_id": 4821, "scopes": 3}
```

One event is queued per scope that held a CID for this person; delivery is attempted immediately (best-effort) and retried by the periodic worker for anything still `PENDING`.

### 3. Verify the signature on receipt

The receiving endpoint gets:

```
POST /hooks/sunder-erase
Content-Type: application/json
X-Sunder-Signature: 7a1c...  (hex HMAC-SHA256 of the raw body, keyed with your scope's secret)

{"event":"erase","scope":"crm","cid":"cid_9f2a...","erasure_id":4821,"ts":"2026-08-23T10:15:00Z"}
```

Verify before acting on it:

```bash
echo -n "$RAW_BODY" | openssl dgst -sha256 -hmac "$SCOPE_WEBHOOK_SECRET" -hex
# compare against the X-Sunder-Signature header - reject on mismatch
```

No SDK ships a receiver helper for this - verification is a single stdlib HMAC-SHA256 call in any language, deliberately not something worth a dependency.

### 4. Check delivery status

```bash
sunder dsr events
```

Shows the queue by status - `PENDING`, `SENDING`, `DELIVERED`, `NO_WEBHOOK` (scope has no registered endpoint), `FAILED` (attempts cap reached). Every terminal transition is also written to the audit chain.

## Security notes

- **Redirects are never followed on delivery.** The HTTP client used for webhook POSTs treats every redirect as a stop condition. A compromised or hostile receiver cannot steer the signed payload at an internal address it doesn't otherwise control.
- **Delivery is bounded, not infinite.** Each POST times out after `SUNDER_WEBHOOK_TIMEOUT` (default 5s) and the queue gives up after `SUNDER_WEBHOOK_MAX_ATTEMPTS` (default 10) failed attempts, marking the event `FAILED` with an audited terminal transition. One dead endpoint cannot starve the whole delivery queue - but it also means delivery is not guaranteed forever; a scope must alert on `FAILED` rows, not assume eventual success.
- **The payload carries only `scope`, `cid`, `erasure_id`, `ts` - no PII, no other scope's data.** A receiver at one scope learns nothing about any other scope's relationship with the person beyond the pseudonym it already held.
- **A tombstoned person cannot be erased twice.** `erasePerson` checks `erased_at IS NOT NULL` under a row lock before doing anything; a second call on an already-erased person is rejected rather than re-queuing a duplicate round of webhook deliveries.
- **A scope without a registered webhook does not silently lose the event.** It is marked `NO_WEBHOOK` and audited, not dropped - the gap is visible in `sunder dsr events` and the audit chain rather than hidden.
- **The `_portal` scope is reserved for the mailer, not a data scope's erasure webhook.** Registering an erasure endpoint under `_portal` or the mailer endpoint under a data scope is a configuration error the two surfaces don't detect for you - keep them registered under the correct scope names.
