# OTI Handoff

One system needs to hand another system "this specific person" for one
operation - place an order, send an escalation, start a session - without
handing over its own scoped pseudonym, without the token being usable
twice, and without the receiver being able to replay it later for
something else. The One-Time Identifier (OTI) is a PASETO v4.public token
(Ed25519 - the version pins the algorithm, eliminating JWT-style algorithm
confusion) bound to exactly one purpose and one audience, valid five
minutes, and single-use *by database transition*, not just by signature.

## Mechanism

```mermaid
sequenceDiagram
    participant CRM as CRM (issuer, scope=crm)
    participant Sunder
    participant DB as Postgres (oti table)
    participant ERP as ERP (verifier, scope=erp)

    CRM->>Sunder: POST /v1/oti {cid, purpose:"create_order", audience:"erp", share_attributes:["shipping_address"]}
    Sunder->>Sunder: sign PASETO v4.public (Ed25519), kid=key version, exp=+5min
    Sunder-->>CRM: 201 {token, expires_at}
    CRM->>ERP: hand token to ERP (out of band - queue, webhook, redirect)

    ERP->>Sunder: POST /v1/oti/verify {token, purpose:"create_order", audience:"erp"}
    Sunder->>Sunder: check signature, purpose, audience == caller's own scope
    Sunder->>DB: UPDATE oti SET status='USED' WHERE token_id=? AND status='VALID'
    DB-->>Sunder: 1 row updated (atomic CAS)
    Sunder->>DB: auto-issue/fetch ERP's own scoped CID for the person; copy share_attributes into erp's blob
    Sunder-->>ERP: 200 {cid: "<erp's own CID>", shared:["shipping_address"]}

    Note over ERP,Sunder: A network blip now makes ERP unsure the call landed.<br/>Blind-retrying is exactly the wrong move:
    ERP->>Sunder: POST /v1/oti/verify (same token again)
    Sunder->>DB: UPDATE ... WHERE status='VALID' -> 0 rows matched
    Sunder-->>ERP: 409 {"error": "token_used"}
```

The issuer's own pseudonym (`crm`'s CID) never appears in the verify
response - the ERP learns only *its own* scoped CID for the same person.
The `UPDATE ... WHERE status='VALID'` is the actual single-use enforcement;
the signature only proves the token is genuine and unexpired, not that it
hasn't already been consumed.

## Steps

1. **Issue the token from the issuer's scope**, optionally attaching
   attributes to copy into the verifier's blob at verification:

   ```bash
   curl -sX POST https://sunder.internal/v1/oti \
     -H "Authorization: Bearer $CRM_CLIENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "cid": "CID-01J8ZK3V4WXYZ",
       "purpose": "create_order",
       "audience": "erp",
       "share_attributes": ["shipping_address"]
     }'
   ```

   `201 {"token": "v4.public.eyJj...", "expires_at": "2026-08-26T12:05:00Z"}`

   SDK equivalent: `client.IssueOTI(ctx, cid, "create_order", "erp", &sunder.IssueOptions{ShareAttributes: []string{"shipping_address"}})`.

2. **Hand the token to the verifier** over whatever channel the
   integration already uses - it is a five-minute, single-audience,
   single-purpose bearer credential, so treat it as a secret in transit.

3. **Verify and consume it from the verifier's own scope** - `audience`
   must equal the caller's own scope, or the call fails closed:

   ```bash
   curl -sX POST https://sunder.internal/v1/oti/verify \
     -H "Authorization: Bearer $ERP_CLIENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"token": "v4.public.eyJj...", "purpose": "create_order", "audience": "erp"}'
   ```

   `200 {"cid": "CID-77QANT4XPLM2", "shared": ["shipping_address"]}`

   SDK equivalent: `client.VerifyOTIFull(ctx, token, "create_order", "erp")`.

4. **For delayed actions (escalation e-mails and similar), do not cache
   the shared value.** Consume the token immediately at step 3, then fetch
   the shared attribute just-in-time when the delayed action actually
   fires, storing nothing in between:

   ```bash
   curl -sX GET "https://sunder.internal/v1/contacts/CID-77QANT4XPLM2/attributes/shipping_address?purpose=create_order" \
     -H "Authorization: Bearer $ERP_CLIENT_TOKEN"
   ```

   `200 {"value": "Ilica 1, Zagreb"}`

## Security notes

- **Never blind-retry a verify call.** A retry after an ambiguous network
  failure (timeout, dropped connection) can legitimately return `409
  token_used` for a call that actually succeeded - the SDKs deliberately
  do not retry this endpoint, unlike `oti.issue` and `lookup`, which retry
  once on 5xx/network failure.
- **Single use is a database fact, not a signature check.** The
  `VALID -> USED` transition is an atomic compare-and-swap; a valid
  signature on an already-used token still gets `409 token_used`, never a
  second success.
- **A token only verifies for the audience it was issued for.** The
  caller's scope must equal the token's `audience`, or the response is
  `403 audience_mismatch` - a token addressed to `erp` cannot be redeemed
  by `analytics` even with a valid signature.
- **A token only verifies for the purpose it was issued for.** Presenting
  it with a different `purpose` string is a validation failure, not a
  silent purpose swap.
- **Nothing is shared unless the issuer explicitly listed it.**
  `share_attributes` defaults to empty - a handoff by default proves *who*
  without revealing *what*. The verifier never receives the issuer's own
  scoped CID, only its own.
- **Five-minute TTL bounds the exposure window** - an intercepted token is
  worthless well before most manual replay would be possible, and PASETO
  v4's fixed algorithm means there is no `alg` header to downgrade or
  confuse, unlike JWT.
