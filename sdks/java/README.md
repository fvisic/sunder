# sunder-client (Java)

Java SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only - transport, auth, timeouts, retries and error mapping.
Zero cryptography, zero runtime dependencies (`java.net.http` plus a
hand-rolled minimal JSON codec), Java 17+.

## Install

```xml
<dependency>
  <groupId>io.sunderid</groupId>
  <artifactId>sunder-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Quickstart

The same ~20-line flow as every Sunder SDK: register → lookup → issue OTI → verify.

```java
import io.sunderid.client.OtiResult;
import io.sunderid.client.SunderClient;
import java.util.Map;

// Config defaults to env: SUNDER_URL, SUNDER_CREDENTIAL ("client_id.secret")
var crm = new SunderClient("http://localhost:8080", "crm_client.secret");
var erp = new SunderClient("http://localhost:8080", "erp_client.secret");

// 1. Register a contact - you get a pseudonym (CID), never store the PII yourself
String cid = crm.registerContact(Map.of(
        "email", "filip@example.com",
        "name", "Filip Visic",
        "attributes", Map.of("loyalty_tier", "gold")));

// 2. Look the person up later without exposing PII (LOOKUP != AUTHENTICATION)
cid = crm.lookupByEmail("filip@example.com");

// 3. Hand the person to another system with a one-time identifier
OtiResult oti = crm.issueOti(cid, "create_order", "erp");

// 4. The other system verifies it and gets its OWN scoped CID -
//    the two pseudonyms are unlinkable without the Sunder instance
String erpCid = erp.verifyOti(oti.token(), "create_order", "erp");
System.out.println(erpCid);
```

## Configuration

| Constructor argument | Env fallback        | Meaning                             |
|----------------------|---------------------|-------------------------------------|
| `url`                | `SUNDER_URL`        | Base URL of your Sunder instance    |
| `credential`         | `SUNDER_CREDENTIAL` | `<client_id>.<secret>` bearer token |
| `timeout`            | -                   | Per-request `Duration` (default 10s)|

## Errors

All failures throw a subclass of `io.sunderid.client.SunderException` (with
`getCode()`, `getStatus()` - `null` for network-level failures - and
`getDetail()`): `NotFoundException`, `UnauthorizedException`,
`ForbiddenException`, `PurposeNotAllowedException`, `AudienceMismatchException`,
`TokenUsedException`, `TokenExpiredException`, `TokenInvalidException`,
`RateLimitedException`, `ValidationException`, `ServiceUnavailableException`.

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped:

```java
// Consent gates attribute reads for that purpose, independently of the
// client's own grant. The audit trail of consent SURVIVES erasure.
crm.setConsent(cid, "marketing", true);

// Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
Map<String, Object> access = dpo.dsrAccess(cid);   // holdings + who read them
Map<String, Object> export = crm.dsrExport(cid);   // this scope's holdings
dpo.dsrErase(cid);                                 // children LISTED, not erased
dpo.dsrErase(cid, List.of("guardian"));            // named link types cascade

// Value vault. Binding the token to a cid is what makes erasure destroy it.
String token = crm.tokenize(iban, Map.of("cid", cid, "unique", true));
String value = crm.detokenize(token);

// Bulk routes ALWAYS need a single-use unlock token, whatever
// SUNDER_SEARCH_UNLOCK is set to.
String unlock = (String) crm.unlock("tokens").get("unlock_token");
List<String> tokens = crm.tokenizeBulk(unlock, items);

// Files are sealed under a key wrapped by the person's record key, so
// erasing the person shreds them.
Map<String, Object> meta = crm.uploadFile(cid, "scan.pdf", bytes, "application/pdf", null);
byte[] blob = crm.downloadFile((String) meta.get("id"), "support");

// A share is a SNAPSHOT, and partner_label is what the Article 15 answer
// reports as the recipient.
Map<String, Object> share = crm.createShare(cid, List.of("email"),
        Map.of("partner_label", "partner-bank", "purpose", "kyc", "ttl_seconds", 3600));
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```java
SunderClient crm = new SunderClient(url, cred, Duration.ofSeconds(10), "agent-7");
```

## Retry policy (baked in)

Lookups and `issueOti` retry once on 5xx/network errors. `verifyOti` is
**never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedException`; the
SDK surfaces that distinctly so your code can decide.

Everything that destroys data or spends a single-use credential is attempted
**exactly once**, for the same reason: `dsr_erase`/`dsrErase`/`DsrEraseAsync`,
the token and file deletes, share revocation, unlink, and both bulk vault
routes (they spend an unlock token).

## Development

```sh
bash run-tests.sh   # plain javac/java, no Maven or dependencies needed
mvn test            # same suite via the exec plugin (CI/release)
```
