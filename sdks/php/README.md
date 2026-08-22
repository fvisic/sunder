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

## Retry policy (baked in)

Lookups and `issueOti` retry once on 5xx/network errors. `verifyOti` is
**never** blind-retried - the token is single-use, and a retry after an
ambiguous network failure would legitimately return `TokenUsedException`;
the SDK surfaces that distinctly so your code can decide.

## Development

```sh
composer install
vendor/bin/phpunit tests
```

## Requirements

PHP 8.1+, `allow_url_fopen=1` (the transport uses PHP's HTTP stream
wrapper; the client fails fast at construction when it is disabled).
