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

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped:

```python
# Consent gates attribute reads for that purpose, independently of the
# client's own grant. The audit trail of consent SURVIVES erasure.
crm.set_consent(cid, "marketing", True)

# Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
access = dpo.dsr_access(cid)                 # holdings + who accessed them
export = crm.dsr_export(cid)                 # this scope's holdings, portable
dpo.dsr_erase(cid)                           # children LISTED, not erased
dpo.dsr_erase(cid, cascade=["guardian"])     # named link types cascade

# Value vault. Binding the token to a cid is what makes erasure destroy it.
token = crm.tokenize(iban, cid=cid, unique=True)
value = crm.detokenize(token)

# Bulk routes ALWAYS need a single-use unlock token, whatever
# SUNDER_SEARCH_UNLOCK is set to.
unlock = crm.unlock("tokens")["unlock_token"]
tokens = crm.tokenize_bulk(unlock, [{"value": v, "cid": cid} for v in values])

# Files are sealed under a key wrapped by the person's record key, so
# erasing the person shreds them.
meta = crm.upload_file(cid, "scan.pdf", data, content_type="application/pdf")
blob = crm.download_file(meta["id"], "support")

# A share is a SNAPSHOT, and partner_label is what the Article 15 answer
# reports as the recipient.
share = crm.create_share(cid, ["email"], partner_label="partner-bank",
                         purpose="kyc", ttl_seconds=3600)
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```python
crm = SunderClient(user_id="agent-7")
```

## Retry policy (baked in)

Lookups and `issue_oti` retry once on 5xx/network errors. `verify_oti` is
**never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedError`; the SDK
surfaces that distinctly so your code can decide.

Everything that destroys data or spends a single-use credential is attempted
**exactly once**, for the same reason: `dsr_erase`/`dsrErase`/`DsrEraseAsync`,
the token and file deletes, share revocation, unlink, and both bulk vault
routes (they spend an unlock token).
