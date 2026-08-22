# SunderId.Client (.NET)

.NET SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only — transport, auth, timeouts, retries and error mapping.
Zero cryptography, zero dependencies beyond the BCL (`System.Net.Http` +
`System.Text.Json`). One NuGet package covers C#, F# and VB.NET.

Targets `net8.0` only: `netstandard2.0` would preclude the in-box
`System.Text.Json` defaults and force a package dependency, defeating the
zero-dependency rule.

## Install

```sh
dotnet add package SunderId.Client
```

## Quickstart

The same ~20-line flow as every Sunder SDK: register → lookup → issue OTI → verify.

```csharp
using SunderId.Client;

// Config defaults to env: SUNDER_URL, SUNDER_CREDENTIAL ("client_id.secret")
var crm = new SunderClient("http://localhost:8080", "crm_client.secret");
var erp = new SunderClient("http://localhost:8080", "erp_client.secret");

// 1. Register a contact — you get a pseudonym (CID), never store the PII yourself
var cid = await crm.RegisterContactAsync(new ContactAttributes
{
    Email = "filip@example.com",
    Name = "Filip Visic",
    Attributes = new Dictionary<string, string> { ["loyalty_tier"] = "gold" },
});

// 2. Look the person up later without exposing PII (LOOKUP != AUTHENTICATION)
cid = await crm.LookupByEmailAsync("filip@example.com");

// 3. Hand the person to another system with a one-time identifier
var oti = await crm.IssueOtiAsync(cid, purpose: "create_order", audience: "erp");

// 4. The other system verifies it and gets its OWN scoped CID —
//    the two pseudonyms are unlinkable without the Sunder instance
var erpCid = await erp.VerifyOtiAsync(oti.Token, purpose: "create_order", audience: "erp");
Console.WriteLine(erpCid);
```

## Errors

All failures throw a subclass of `SunderException` (with `Code`, `Status`,
`Detail`): `SunderNotFoundException`, `SunderUnauthorizedException`,
`SunderForbiddenException`, `SunderPurposeNotAllowedException`,
`SunderAudienceMismatchException`, `SunderTokenUsedException`,
`SunderTokenExpiredException`, `SunderTokenInvalidException`,
`SunderRateLimitedException`, `SunderValidationException`,
`SunderServiceUnavailableException` (5xx and network failures/timeouts).

## Retry policy (baked in)

Lookups and `IssueOtiAsync` retry once on 5xx/network errors. `VerifyOtiAsync`
is **never** blind-retried — the token is single-use, and a retry after an
ambiguous network failure would legitimately return
`SunderTokenUsedException`; the SDK surfaces that distinctly so your code can
decide.

## Development

Build and tests run in CI (GitHub Actions with `actions/setup-dotnet`) — that
is the validation path for this SDK; a local dotnet toolchain is not assumed.

```sh
dotnet test SunderId.sln
```

Tests use an injected fake `HttpMessageHandler` (the `handler` constructor
parameter) — no sockets, no live server needed.
