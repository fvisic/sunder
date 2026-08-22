# sunder-client (Java)

Java SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only — transport, auth, timeouts, retries and error mapping.
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

// 1. Register a contact — you get a pseudonym (CID), never store the PII yourself
String cid = crm.registerContact(Map.of(
        "email", "filip@example.com",
        "name", "Filip Visic",
        "attributes", Map.of("loyalty_tier", "gold")));

// 2. Look the person up later without exposing PII (LOOKUP != AUTHENTICATION)
cid = crm.lookupByEmail("filip@example.com");

// 3. Hand the person to another system with a one-time identifier
OtiResult oti = crm.issueOti(cid, "create_order", "erp");

// 4. The other system verifies it and gets its OWN scoped CID —
//    the two pseudonyms are unlinkable without the Sunder instance
String erpCid = erp.verifyOti(oti.token(), "create_order", "erp");
System.out.println(erpCid);
```

## Configuration

| Constructor argument | Env fallback        | Meaning                             |
|----------------------|---------------------|-------------------------------------|
| `url`                | `SUNDER_URL`        | Base URL of your Sunder instance    |
| `credential`         | `SUNDER_CREDENTIAL` | `<client_id>.<secret>` bearer token |
| `timeout`            | —                   | Per-request `Duration` (default 10s)|

## Errors

All failures throw a subclass of `io.sunderid.client.SunderException` (with
`getCode()`, `getStatus()` — `null` for network-level failures — and
`getDetail()`): `NotFoundException`, `UnauthorizedException`,
`ForbiddenException`, `PurposeNotAllowedException`, `AudienceMismatchException`,
`TokenUsedException`, `TokenExpiredException`, `TokenInvalidException`,
`RateLimitedException`, `ValidationException`, `ServiceUnavailableException`.

## Retry policy (baked in)

Lookups and `issueOti` retry once on 5xx/network errors. `verifyOti` is
**never** blind-retried — the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedException`; the
SDK surfaces that distinctly so your code can decide.

## Development

```sh
bash run-tests.sh   # plain javac/java, no Maven or dependencies needed
mvn test            # same suite via the exec plugin (CI/release)
```
