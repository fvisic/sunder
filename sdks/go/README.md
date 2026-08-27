# sunder (Go)

Go SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only - transport, auth, timeouts, retries and error mapping.
Zero cryptography, zero dependencies beyond the standard library, Go 1.25+.

The SDK is its own Go module, so importing it never pulls in the server's
dependency tree.

## Install

```sh
go get github.com/fvisic/sunder/sdks/go@latest
```

## Quickstart

The same ~20-line flow as every Sunder SDK: register, look up, issue an
OTI, verify it.

```go
package main

import (
	"context"
	"fmt"
	"log"

	sunder "github.com/fvisic/sunder/sdks/go"
)

func main() {
	ctx := context.Background()

	// Config defaults to the environment: SUNDER_URL and SUNDER_CREDENTIAL
	// ("client_id.secret", printed once by `sunder client create`).
	crm, err := sunder.New("", "")
	if err != nil {
		log.Fatal(err)
	}

	cid, err := crm.RegisterContact(ctx, sunder.RegisterInput{
		Email:      "ana@example.com",
		Phone:      "+385 91 123 4567",
		Name:       "Ana Anic",
		Attributes: map[string]string{"tier": "gold"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// A lookup returns a pseudonym. It does NOT prove you are talking to
	// that person: LOOKUP != AUTHENTICATION.
	same, err := crm.LookupByEmail(ctx, "ana@example.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cid == same) // true

	// Hand the identity to another system: one purpose, one audience,
	// single use, five minutes.
	oti, err := crm.IssueOTI(ctx, cid, "create_order", "erp", nil)
	if err != nil {
		log.Fatal(err)
	}

	// The ERP verifies with ITS OWN credential and gets ITS OWN pseudonym.
	erp, err := sunder.New("", "erp.secret")
	if err != nil {
		log.Fatal(err)
	}
	erpCID, err := erp.VerifyOTI(ctx, oti.Token, "create_order", "erp")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(erpCID != cid) // true - the pseudonyms are unlinkable
}
```

## Selective disclosure

Prove a fact without disclosing the value. The verifier receives booleans;
the birthdate never crosses the scope boundary.

```go
oti, err := crm.IssueOTI(ctx, cid, "age_check", "webshop", &sunder.IssueOptions{
	SharePredicates: []sunder.Predicate{sunder.AgeAtLeast("birthdate", 18)},
})
// ...
out, err := shop.VerifyOTIFull(ctx, oti.Token, "age_check", "webshop")
for _, p := range out.Predicates {
	if !p.Known {
		// The attribute was absent or unparseable. Deliberately NOT the
		// same as "the check failed" - for age_gte, treat it as unknown.
		continue
	}
	fmt.Println(p.Attr, p.Op, p.Result)
}
```

`Known` is op-specific: for `age_gte` it is false when the attribute is
absent or unparseable, so "we do not know the birthdate" never reads as
"under 18"; for `exists` it is always true, because absence is the answer
that predicate asks for.

## Attribute sharing (delayed flows)

`ShareAttributes` copies issuer-approved attributes into the verifier's
scope at verification, which is what makes a delayed action work - an
escalation e-mail sent hours later fetches the address just in time, and
the verifier stores no PII of its own:

```go
oti, err := crm.IssueOTI(ctx, cid, "escalation", "mailer", &sunder.IssueOptions{
	ShareAttributes: []string{"email"},
})
```

## Errors

Every failure is a `*sunder.Error` carrying `Code`, `Status` and `Detail`,
and matches a sentinel through `errors.Is`:

```go
_, err := erp.VerifyOTI(ctx, token, "create_order", "erp")
switch {
case errors.Is(err, sunder.ErrTokenUsed):
	// Already consumed - a replay, or your own retry.
case errors.Is(err, sunder.ErrTokenExpired):
	// Past its five-minute life: ask the issuer for a new one.
case errors.Is(err, sunder.ErrConsentDenied):
	// The person withdrew consent for this purpose. Not the same as
	// ErrPurposeNotAllowed, which is a missing grant on your client.
case errors.Is(err, sunder.ErrCredentialExpired):
	// Correct secret, past its expiry: rotate it, do not retry.
case errors.Is(err, sunder.ErrServiceUnavailable):
	// 5xx or a network failure (Status 0 for the latter).
}
```

The taxonomy is identical across all six Sunder SDKs: `ErrUnauthorized`,
`ErrCredentialExpired`, `ErrForbidden`, `ErrConsentDenied`,
`ErrPurposeNotAllowed`, `ErrAudienceMismatch`, `ErrNotFound`,
`ErrValidation`, `ErrTokenInvalid`, `ErrTokenUsed`, `ErrTokenExpired`,
`ErrRateLimited`, `ErrServiceUnavailable`, `ErrBadResponse`.

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped (`api.go`):

```go
// Consent gates attribute reads for that purpose, independently of the
// client's own grant. The audit trail of consent SURVIVES erasure.
_, err := crm.SetConsent(ctx, cid, "marketing", true)

// Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
access, err := dpo.DSRAccess(ctx, cid)   // holdings + who accessed them
export, err := crm.DSRExport(ctx, cid)   // this scope's holdings, portable
res, err := dpo.DSRErase(ctx, cid)       // children LISTED, not erased
res, err = dpo.DSRErase(ctx, cid, "guardian") // named link types cascade

// Value vault. Binding the token to a cid is what makes erasure destroy it.
tok, err := crm.Tokenize(ctx, sunder.TokenizeInput{Value: iban, CID: cid, Unique: true})
val, err := crm.Detokenize(ctx, tok)

// Bulk routes ALWAYS need a single-use unlock token, whatever
// SUNDER_SEARCH_UNLOCK is set to.
u, err := crm.Unlock(ctx, "tokens")
toks, err := crm.TokenizeBulk(ctx, u.Token, items)

// Files are sealed under a key wrapped by the person's record key, so
// erasing the person shreds them.
meta, err := crm.UploadFile(ctx, cid, "scan.pdf", "application/pdf", f, time.Time{})
body, err := crm.DownloadFile(ctx, meta.ID, "support")
defer body.Close()

// A share is a SNAPSHOT, and partner_label is what the Article 15 answer
// reports as the recipient.
sh, err := crm.CreateShare(ctx, sunder.ShareInput{
	CID: cid, Fields: []string{"email"}, PartnerLabel: "partner-bank",
	Purpose: "kyc", TTLSeconds: 3600})
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```go
c, err := sunder.New(url, cred, sunder.WithUserID("agent-7"))
```

## Retry policy

Baked in rather than configurable, because the safe answer differs per
operation:

- reads (lookups, `GetAttribute`, the DSR reads, `Detokenize`, `ListFiles`,
  `FetchShare`, `ListLinks`, `ListVersions`) and `IssueOTI` retry **once** on
  a 5xx or network failure;
- `VerifyOTI` is **never** retried. The token is single-use, so a retry
  after an ambiguous network failure would legitimately come back as
  `ErrTokenUsed` and you could not tell whether the first attempt
  succeeded. That reconciliation is yours to make.
- the same rule extends to everything that destroys data or spends a
  single-use credential: `DSRErase`, `DeleteToken`, `DeleteFile`,
  `RevokeShare`, `Unlink`, `TokenizeBulk` and `DetokenizeBulk`. All are
  attempted exactly once.

A definite 4xx verdict is never retried, and neither is a cancelled
context.

## Options

```go
c, err := sunder.New(url, cred, sunder.WithTimeout(3*time.Second))

// Or supply your own client - for mTLS client certificates, a proxy, or
// custom transport settings:
c, err = sunder.New(url, cred, sunder.WithHTTPClient(&http.Client{
	Timeout:   5 * time.Second,
	Transport: myTransport,
}))
```

A `Client` is safe for concurrent use.

## Tests

```sh
cd sdks/go && go test ./...
```

The suite runs against an in-process mock server: every route, body shape
and success shape, the full error taxonomy, path-escaping against
injection, the retry policy (including the assertion that `VerifyOTI`
makes exactly one attempt), network failures and concurrent use.
