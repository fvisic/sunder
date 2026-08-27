# SunderId.Client (.NET)

.NET SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only - transport, auth, timeouts, retries and error mapping.
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

// 1. Register a contact - you get a pseudonym (CID), never store the PII yourself
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

// 4. The other system verifies it and gets its OWN scoped CID -
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

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped:

```csharp
// Consent gates attribute reads for that purpose, independently of the
// client's own grant. The audit trail of consent SURVIVES erasure.
await crm.SetConsentAsync(cid, "marketing", true);

// Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
var access = await dpo.DsrAccessAsync(cid);      // holdings + who read them
var export = await crm.DsrExportAsync(cid);      // this scope's holdings
await dpo.DsrEraseAsync(cid);                    // children LISTED, not erased
await dpo.DsrEraseAsync(cid, new[] { "guardian" }); // named types cascade

// Value vault. Binding the token to a cid is what makes erasure destroy it.
var token = await crm.TokenizeAsync(iban,
    new Dictionary<string, object> { ["cid"] = cid, ["unique"] = true });
var value = await crm.DetokenizeAsync(token);

// Bulk routes ALWAYS need a single-use unlock token, whatever
// SUNDER_SEARCH_UNLOCK is set to.
var unlock = (await crm.UnlockAsync("tokens")).GetProperty("unlock_token").GetString()!;
var tokens = await crm.TokenizeBulkAsync(unlock, items);

// Files are sealed under a key wrapped by the person's record key, so
// erasing the person shreds them.
var meta = await crm.UploadFileAsync(cid, "scan.pdf", bytes, "application/pdf");
var blob = await crm.DownloadFileAsync(meta.GetProperty("id").GetString()!, "support");

// A share is a SNAPSHOT, and partner_label is what the Article 15 answer
// reports as the recipient.
var share = await crm.CreateShareAsync(cid, new[] { "email" },
    new Dictionary<string, object> { ["partner_label"] = "partner-bank" });
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```csharp
var crm = new SunderClient(url, cred, userId: "agent-7");
```

## Retry policy (baked in)

Lookups and `IssueOtiAsync` retry once on 5xx/network errors. `VerifyOtiAsync`
is **never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return
`SunderTokenUsedException`; the SDK surfaces that distinctly so your code can
decide.

Everything that destroys data or spends a single-use credential is attempted
**exactly once**, for the same reason: `dsr_erase`/`dsrErase`/`DsrEraseAsync`,
the token and file deletes, share revocation, unlink, and both bulk vault
routes (they spend an unlock token).

## Development

Build and tests run in CI (GitHub Actions with `actions/setup-dotnet`) - that
is the validation path for this SDK; a local dotnet toolchain is not assumed.

```sh
dotnet test SunderId.sln
```

Tests use an injected fake `HttpMessageHandler` (the `handler` constructor
parameter) - no sockets, no live server needed.
