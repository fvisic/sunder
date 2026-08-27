# @sunder-id/sunder

TypeScript SDK for [Sunder](../../README.md), the pseudonymous identity
provider. A thin client (zero runtime dependencies, global `fetch`,
Node 18+): transport, auth, timeouts, retries and error mapping - all
cryptography stays server-side.

## Install

```sh
npm install @sunder-id/sunder
```

## Configuration

| Option (constructor) | Env fallback        | Meaning                             |
|----------------------|---------------------|-------------------------------------|
| `url`                | `SUNDER_URL`        | Base URL of your Sunder instance    |
| `credential`         | `SUNDER_CREDENTIAL` | `<client_id>.<secret>` bearer token |

## Quickstart

```ts
import { SunderClient, SunderError } from "@sunder-id/sunder";

const sunder = new SunderClient(); // reads SUNDER_URL / SUNDER_CREDENTIAL

// 1. Register a contact - returns the pseudonym in YOUR scope.
const { cid } = await sunder.registerContact({
  email: "filip@example.com",
  phone: "+385 91 123 4567",
  attributes: { loyalty_tier: "gold" },
});

// 2. Look the person up later. LOOKUP != AUTHENTICATION.
const found = await sunder.lookupByEmail("filip@example.com");

// 3. Hand the person to another system: issue a one-time identifier
//    (5 minutes, one use, one audience, one purpose).
const oti = await sunder.issueOti(found.cid, "create_order", "erp");

// 4. The "erp" system verifies with ITS OWN client and receives ITS OWN
//    scoped CID - the issuer's pseudonym never crosses the scope boundary.
const erp = new SunderClient({ url: process.env.SUNDER_URL, credential: erpCredential });
const order = await erp.verifyOti(oti.token, "create_order", "erp");
console.log(order.cid); // CID in the erp scope
```

## Errors

Every failure throws `SunderError` with a `code` from the unified taxonomy
shared by all Sunder SDKs: `Unauthorized`, `Forbidden`, `PurposeNotAllowed`,
`AudienceMismatch`, `NotFound`, `Validation`, `TokenInvalid`, `TokenUsed`,
`TokenExpired`, `RateLimited`, `ServiceUnavailable`, `NetworkError`.

```ts
try {
  await sunder.lookupByEmail("nobody@example.com");
} catch (err) {
  if (err instanceof SunderError && err.code === "NotFound") {
    // no match in YOUR scope (the person may exist elsewhere - by design)
  }
}
```

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped:

```ts
// Consent gates attribute reads for that purpose, independently of the
// client's own grant. The audit trail of consent SURVIVES erasure.
await crm.setConsent(cid, "marketing", true);

// Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
const access = await dpo.dsrAccess(cid);        // holdings + who accessed them
const exported = await crm.dsrExport(cid);      // this scope's holdings
await dpo.dsrErase(cid);                        // children LISTED, not erased
await dpo.dsrErase(cid, ["guardian"]);          // named link types cascade

// Value vault. Binding the token to a cid is what makes erasure destroy it.
const token = await crm.tokenize({ value: iban, cid, unique: true });
const value = await crm.detokenize(token);

// Bulk routes ALWAYS need a single-use unlock token, whatever
// SUNDER_SEARCH_UNLOCK is set to.
const { unlock_token } = await crm.unlock("tokens");
const tokens = await crm.tokenizeBulk(unlock_token, items);

// Files are sealed under a key wrapped by the person's record key, so
// erasing the person shreds them.
const meta = await crm.uploadFile(cid, blob, "scan.pdf");
const bytes = await crm.downloadFile(meta.id, "support");

// A share is a SNAPSHOT, and partner_label is what the Article 15 answer
// reports as the recipient.
const share = await crm.createShare({
  cid, fields: ["email"], partner_label: "partner-bank",
  purpose: "kyc", ttl_seconds: 3600,
});
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```ts
const crm = new SunderClient({ userId: "agent-7" });
```

## Retry policy (baked in)

- `lookupByEmail` / `lookupByPhone` / `lookupByName` and `issueOti` retry
  **once** on 5xx or network failure.
- `verifyOti` is **never** blind-retried: the token is single-use, so a retry
  after an ambiguous network failure would legitimately return `TokenUsed`.
  The SDK surfaces that distinctly so *you* decide how to reconcile.

Everything that destroys data or spends a single-use credential is attempted
**exactly once**, for the same reason: `dsr_erase`/`dsrErase`/`DsrEraseAsync`,
the token and file deletes, share revocation, unlink, and both bulk vault
routes (they spend an unlock token).

## Development

```sh
npm install
npm test   # tsc && node --test dist/index.test.js
```
