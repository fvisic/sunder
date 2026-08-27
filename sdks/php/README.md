# sunder-client (PHP)

PHP SDK for [Sunder](../../README.md), a pseudonymous identity provider.
Thin client only - transport, auth, timeouts, retries and error mapping.
Zero cryptography, zero runtime dependencies (plain PHP streams), PHP 8.1+.

## Install

```sh
composer require sunder-id/sunder-client
```

## Quickstart

The same ~20-line flow as every Sunder SDK: register → lookup → issue OTI → verify.

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Sunder\SunderClient;

// Config defaults to env: SUNDER_URL, SUNDER_CREDENTIAL ("client_id.secret")
$crm = new SunderClient(url: 'http://localhost:8080', credential: 'crm_client.secret');
$erp = new SunderClient(url: 'http://localhost:8080', credential: 'erp_client.secret');

// 1. Register a contact - you get a pseudonym (CID), never store the PII yourself
$cid = $crm->registerContact(['email' => 'filip@example.com',
                              'name' => 'Filip Visic',
                              'attributes' => ['loyalty_tier' => 'gold']]);

// 2. Look the person up later without exposing PII (LOOKUP != AUTHENTICATION)
$cid = $crm->lookupByEmail('filip@example.com');

// 3. Hand the person to another system with a one-time identifier
$oti = $crm->issueOti($cid, purpose: 'create_order', audience: 'erp');

// 4. The other system verifies it and gets its OWN scoped CID -
//    the two pseudonyms are unlinkable without the Sunder instance
$erpCid = $erp->verifyOti($oti['token'], purpose: 'create_order', audience: 'erp');
echo $erpCid, PHP_EOL;
```

## Errors

All failures throw a subclass of `Sunder\SunderException` (with public
`$code`, `$status`, `$detail`; root class `Sunder\SunderError`):
`NotFoundException`, `UnauthorizedException`, `ForbiddenException`,
`PurposeNotAllowedException`, `AudienceMismatchException`,
`TokenUsedException`, `TokenExpiredException`, `TokenInvalidException`,
`RateLimitedException`, `ValidationException`, `ServiceUnavailableException`.

## Beyond the handoff

Consent, the data-subject rights endpoints, value tokenization, the file
vault, cross-org shares, person links, attribute version history, external
claims and the admin unlock are all wrapped:

```php
// Consent gates attribute reads for that purpose, independently of the
// client's own grant. The audit trail of consent SURVIVES erasure.
$crm->setConsent($cid, 'marketing', true);

// Article 15 (org-wide), 20 (caller scope), 17 (org-wide, destructive).
$access = $dpo->dsrAccess($cid);              // holdings + who accessed them
$export = $crm->dsrExport($cid);              // this scope's holdings
$dpo->dsrErase($cid);                         // children LISTED, not erased
$dpo->dsrErase($cid, ['guardian']);           // named link types cascade

// Value vault. Binding the token to a cid is what makes erasure destroy it.
$token = $crm->tokenize($iban, ['cid' => $cid, 'unique' => true]);
$value = $crm->detokenize($token);

// Bulk routes ALWAYS need a single-use unlock token, whatever
// SUNDER_SEARCH_UNLOCK is set to.
$unlock = $crm->unlock('tokens')['unlock_token'];
$tokens = $crm->tokenizeBulk($unlock, $items);

// Files are sealed under a key wrapped by the person's record key, so
// erasing the person shreds them.
$meta = $crm->uploadFile($cid, 'scan.pdf', $bytes, 'application/pdf');
$blob = $crm->downloadFile($meta['id'], 'support');

// A share is a SNAPSHOT, and partner_label is what the Article 15 answer
// reports as the recipient.
$share = $crm->createShare($cid, ['email'], [
    'partner_label' => 'partner-bank', 'purpose' => 'kyc', 'ttl_seconds' => 3600,
]);
```

Attribute the reads to an operator inside your system - it lands in the
audit chain and in the Article 15 answer:

```php
$crm = new SunderClient($url, $cred, 10.0, 'agent-7');
```

## Retry policy (baked in)

Lookups and `issueOti` retry once on 5xx/network errors. `verifyOti` is
**never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedException`;
the SDK surfaces that distinctly so your code can decide.

Everything that destroys data or spends a single-use credential is attempted
**exactly once**, for the same reason: `dsr_erase`/`dsrErase`/`DsrEraseAsync`,
the token and file deletes, share revocation, unlink, and both bulk vault
routes (they spend an unlock token).

## Development

```sh
composer install
vendor/bin/phpunit tests
```

## Requirements

PHP 8.1+, `allow_url_fopen=1` (the transport uses PHP's HTTP stream
wrapper; the client fails fast at construction when it is disabled).
