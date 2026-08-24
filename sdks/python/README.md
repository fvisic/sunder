# sunder-client (Python)

Python SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only - transport, auth, timeouts, retries and error mapping.
Zero cryptography, zero third-party dependencies (stdlib `urllib`), Python 3.10+.

## Install

```sh
pip install sunder-client
```

## Quickstart

The same ~20-line flow as every Sunder SDK: register → lookup → issue OTI → verify.

```python
import sunder_client

# Config defaults to env: SUNDER_URL, SUNDER_CREDENTIAL ("client_id.secret")
crm = sunder_client.SunderClient(url="http://localhost:8080",
                                 credential="crm_client.secret")
erp = sunder_client.SunderClient(url="http://localhost:8080",
                                 credential="erp_client.secret")

# 1. Register a contact - you get a pseudonym (CID), never store the PII yourself
cid = crm.register_contact({"email": "filip@example.com",
                            "name": "Filip Visic",
                            "attributes": {"loyalty_tier": "gold"}})

# 2. Look the person up later without exposing PII (LOOKUP != AUTHENTICATION)
cid = crm.lookup_by_email("filip@example.com")

# 3. Hand the person to another system with a one-time identifier
oti = crm.issue_oti(cid, purpose="create_order", audience="erp")

# 4. The other system verifies it and gets its OWN scoped CID -
#    the two pseudonyms are unlinkable without the Sunder instance
erp_cid = erp.verify_oti(oti["token"], purpose="create_order", audience="erp")
print(erp_cid)
```

## Errors

All failures raise a subclass of `sunder_client.SunderError` (with `.code`,
`.status`, `.detail`): `NotFoundError`, `UnauthorizedError`, `ForbiddenError`,
`PurposeNotAllowedError`, `AudienceMismatchError`, `TokenUsedError`,
`TokenExpiredError`, `TokenInvalidError`, `RateLimitedError`,
`ValidationError`, `ServiceUnavailableError`.

## Retry policy (baked in)

Lookups and `issue_oti` retry once on 5xx/network errors. `verify_oti` is
**never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedError`; the SDK
surfaces that distinctly so your code can decide.
