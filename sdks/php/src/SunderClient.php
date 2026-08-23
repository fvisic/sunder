<?php

declare(strict_types=1);

namespace Sunder;

/**
 * Sunder PHP SDK - a thin client for the Sunder pseudonymous identity API.
 *
 * Implements the canonical CidProviderClient interface (docs/DESIGN.md, SDK design rules):
 * transport, auth, timeouts, retries and error mapping only. Zero
 * cryptography, zero runtime dependencies (plain PHP streams).
 *
 * Retry policy (baked in, the SDK design rules (docs/DESIGN.md)):
 *  - lookups and issueOti retry once on 5xx / network errors (safe);
 *  - verifyOti is NEVER blind-retried (single-use token - a retry after an
 *    ambiguous network failure would legitimately return TokenUsed).
 *
 * Remember: LOOKUP != AUTHENTICATION - a lookup hit never proves the caller
 * is talking to that person.
 */
final class SunderClient
{
    /** Exact JSON "error" codes first; falls through to status-only rules. */
    private const CODE_MAP = [
        'unauthorized' => UnauthorizedException::class,
        'forbidden' => ForbiddenException::class,
        'credential_expired' => CredentialExpiredException::class,
        'consent_denied' => ConsentDeniedException::class,
        'purpose_not_allowed' => PurposeNotAllowedException::class,
        'audience_mismatch' => AudienceMismatchException::class,
        'not_found' => NotFoundException::class,
        'validation' => ValidationException::class,
        'bad_json' => ValidationException::class,
        'token_invalid' => TokenInvalidException::class,
        'token_used' => TokenUsedException::class,
        'token_expired' => TokenExpiredException::class,
        'rate_limited' => RateLimitedException::class,
    ];

    private const STATUS_MAP = [
        400 => ValidationException::class,
        401 => UnauthorizedException::class,
        403 => ForbiddenException::class,
        404 => NotFoundException::class,
        409 => TokenUsedException::class,
        410 => TokenExpiredException::class,
        429 => RateLimitedException::class,
    ];

    private string $base;
    private string $credential;
    private float $timeout;

    /**
     * @param string|null $url        base URL of the Sunder instance; defaults to $SUNDER_URL.
     * @param string|null $credential "client_id.secret" bearer credential; defaults to $SUNDER_CREDENTIAL.
     * @param float       $timeout    per-request timeout in seconds (default 10).
     */
    public function __construct(?string $url = null, ?string $credential = null, float $timeout = 10.0)
    {
        $url = $url ?? (string) getenv('SUNDER_URL');
        $credential = $credential ?? (string) getenv('SUNDER_CREDENTIAL');
        if ($url === '') {
            throw new \InvalidArgumentException('Sunder URL required (arg or SUNDER_URL)');
        }
        if ($credential === '') {
            throw new \InvalidArgumentException('Sunder credential required (arg or SUNDER_CREDENTIAL)');
        }
        if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOL)) {
            // Fail loudly at construction: with the http wrapper disabled
            // every call would surface as a transient-looking network error.
            throw new \RuntimeException('SunderClient requires allow_url_fopen=1 (php.ini)');
        }
        $this->base = rtrim($url, '/');
        $this->credential = $credential;
        $this->timeout = $timeout;
    }

    // -- contacts -------------------------------------------------------------

    /**
     * Registers (or dedup-merges) a contact; returns the caller-scope CID.
     *
     * $attributes is the full request body: email/phone/name (plus the plural
     * "emails"/"phones" lists for contacts with several searchable
     * identifiers) and an optional nested "attributes" map of custom fields.
     */
    public function registerContact(array $attributes): string
    {
        // PHP cannot distinguish an empty map from an empty list: a nested
        // empty "attributes" array would encode as [] and the server would
        // reject it (Go unmarshals it into a map). Force the object form.
        if (isset($attributes['attributes']) && $attributes['attributes'] === []) {
            $attributes['attributes'] = new \stdClass();
        }
        return $this->expectString(
            $this->request('POST', '/v1/contacts', $attributes),
            'cid'
        );
    }

    /**
     * Issues the same person's CID in another scope. Linkage-capable -
     * grant sparingly; prefer OTIs for cross-system handoff.
     */
    public function issueScopedCid(string $cid, string $scope): string
    {
        $path = '/v1/contacts/' . rawurlencode($cid) . '/scopes';
        return $this->expectString(
            $this->request('POST', $path, ['scope' => $scope]),
            'cid'
        );
    }

    // -- lookup (LOOKUP != AUTHENTICATION) --------------------------------------

    /** Finds a contact by email; returns the caller-scope CID. Retries once on 5xx. */
    public function lookupByEmail(string $email): string
    {
        return $this->expectString(
            $this->request('POST', '/v1/lookup', ['email' => $email], retry: true),
            'cid'
        );
    }

    /** Finds a contact by phone; returns the caller-scope CID. Retries once on 5xx. */
    public function lookupByPhone(string $phone): string
    {
        return $this->expectString(
            $this->request('POST', '/v1/lookup', ['phone' => $phone], retry: true),
            'cid'
        );
    }

    /**
     * Finds a contact by name plus a second factor (email or phone).
     *
     * A name alone is never an identifier; exactly the API's rule is
     * enforced client-side: at least one of email/phone is required.
     */
    public function lookupByName(string $name, ?string $email = null, ?string $phone = null): string
    {
        if ($email === null && $phone === null) {
            throw new ValidationException(
                'validation',
                null,
                'lookupByName requires email or phone as a second factor'
            );
        }
        $body = ['name' => $name];
        if ($email !== null) {
            $body['email'] = $email;
        }
        if ($phone !== null) {
            $body['phone'] = $phone;
        }
        return $this->expectString(
            $this->request('POST', '/v1/lookup', $body, retry: true),
            'cid'
        );
    }

    // -- attributes -------------------------------------------------------------

    /** Fetches exactly one attribute value (purpose-checked, audited server-side). */
    public function getAttribute(string $cid, string $name, string $purpose): string
    {
        $path = '/v1/contacts/' . rawurlencode($cid)
            . '/attributes/' . rawurlencode($name)
            . '?purpose=' . rawurlencode($purpose);
        return $this->expectString($this->request('GET', $path), 'value');
    }

    // -- OTI ----------------------------------------------------------------------

    /**
     * Issues a one-time identifier: 5 minutes, one use, one audience, one
     * purpose. Safe to retry (retries once on 5xx / network failure).
     *
     * @return array{token: string, expiresAt: string}
     */
    public function issueOti(string $cid, string $purpose, string $audience, ?array $shareAttributes = null, ?array $sharePredicates = null): array
    {
        $body = ['cid' => $cid, 'purpose' => $purpose, 'audience' => $audience];
        if ($shareAttributes !== null && $shareAttributes !== []) {
            // Issuer-authorized attributes copied into the verifier's scope.
            $body['share_attributes'] = array_values($shareAttributes);
        }
        if ($sharePredicates !== null && $sharePredicates !== []) {
            // Issuer-authorized predicate claims, e.g.
            // [['attr' => 'birthdate', 'op' => 'age_gte', 'value' => 18]];
            // the verifier receives booleans only, never the value.
            $body['share_predicates'] = array_values($sharePredicates);
        }
        $raw = $this->request(
            'POST',
            '/v1/oti',
            $body,
            retry: true
        );
        return [
            'token' => $this->expectString($raw, 'token'),
            'expiresAt' => $this->expectString($raw, 'expires_at'),
        ];
    }

    /**
     * Verifies and consumes an OTI; returns the VERIFIER's own scoped CID.
     *
     * NEVER blind-retried: the token is single-use, so a retry after an
     * ambiguous network failure could consume-then-fail as TokenUsed. On
     * TokenUsed after a failure, the caller decides how to reconcile.
     */
    public function verifyOti(string $token, string $purpose, string $audience): string
    {
        return $this->expectString($this->verifyOtiFull($token, $purpose, $audience), 'cid');
    }

    /**
     * Like verifyOti but returns the full result: ['cid' => ..., and when
     * present 'shared' (copied attribute names) and 'predicates' (each
     * ['attr','op','value','result','known']; known=false means the
     * attribute was absent - NOT a failed check).
     *
     * @return array<string, mixed>
     */
    public function verifyOtiFull(string $token, string $purpose, string $audience): array
    {
        return $this->request(
            'POST',
            '/v1/oti/verify',
            ['token' => $token, 'purpose' => $purpose, 'audience' => $audience]
        );
    }

    // -- ops ------------------------------------------------------------------

    /**
     * Liveness probe (no auth server-side); returns ["status" => ...].
     *
     * @return array{status: string}
     */
    public function health(): array
    {
        [$status, $raw] = $this->send('GET', '/healthz', null, withAuth: false);
        if ($status < 200 || $status >= 300) {
            throw $this->mapError($status, $raw);
        }
        $text = trim($raw);
        return ['status' => $text !== '' ? $text : 'ok'];
    }

    // -- transport ---------------------------------------------------------

    /**
     * One HTTP round trip plus a single extra attempt when $retry is set and
     * the failure is a 5xx or a network error.
     */
    private function request(string $method, string $path, ?array $body = null, bool $retry = false): array
    {
        $attempts = $retry ? 2 : 1;
        $last = null;
        for ($i = 0; $i < $attempts; $i++) {
            try {
                return $this->doRequest($method, $path, $body);
            } catch (ServiceUnavailableException $e) {
                $last = $e;
            }
        }
        throw $last;
    }

    private function doRequest(string $method, string $path, ?array $body): array
    {
        [$status, $raw] = $this->send($method, $path, $body, withAuth: true);
        if ($status < 200 || $status >= 300) {
            throw $this->mapError($status, $raw);
        }
        $parsed = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new SunderException('bad_response', null, 'non-JSON response body');
        }
        if (!is_array($parsed)) {
            throw new SunderException('bad_response', null, 'unexpected response shape');
        }
        return $parsed;
    }

    /**
     * Performs a single HTTP exchange over plain PHP streams; network-level
     * failures surface as ServiceUnavailableException, never as raw errors.
     *
     * @return array{0: int, 1: string} [status, raw body]
     */
    private function send(string $method, string $path, ?array $body, bool $withAuth): array
    {
        $headers = [];
        if ($withAuth) {
            $headers[] = 'Authorization: Bearer ' . $this->credential;
        }
        $headers[] = 'Accept: application/json';
        $options = [
            'method' => $method,
            'timeout' => $this->timeout,
            'ignore_errors' => true, // return error bodies instead of failing
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            // Empty bodies must encode as a JSON object, not a JSON list.
            $encoded = $body === [] ? '{}' : json_encode($body, JSON_UNESCAPED_SLASHES);
            if ($encoded === false) {
                // json_encode fails on invalid UTF-8; silently sending an
                // empty body would turn into a misleading server-side 400.
                throw new ValidationException(
                    'validation',
                    null,
                    'request body is not valid UTF-8/JSON: ' . json_last_error_msg()
                );
            }
            $options['content'] = $encoded;
        }
        $options['header'] = implode("\r\n", $headers);
        $context = stream_context_create(['http' => $options]);

        $raw = @file_get_contents($this->base . $path, false, $context);
        if ($raw === false) {
            $err = error_get_last();
            $msg = $err !== null ? $err['message'] : 'unknown error';
            throw new ServiceUnavailableException('service_unavailable', null, 'network failure: ' . $msg);
        }

        $status = 0;
        $contentLength = null;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1]; // keep the last status line (redirects)
                $contentLength = null; // headers restart after a redirect
            } elseif (preg_match('#^Content-Length:\s*(\d+)#i', $line, $m)) {
                $contentLength = (int) $m[1];
            }
        }
        // A read timeout mid-body makes PHP return the TRUNCATED body with
        // no error; that is a network-level failure (retryable), not a
        // malformed response.
        if ($contentLength !== null && strlen($raw) < $contentLength) {
            throw new ServiceUnavailableException(
                'service_unavailable',
                null,
                sprintf('network failure: response truncated (%d of %d bytes)', strlen($raw), $contentLength)
            );
        }
        if ($status === 0) {
            throw new ServiceUnavailableException(
                'service_unavailable',
                null,
                'network failure: no HTTP status line in response'
            );
        }
        return [$status, $raw];
    }

    /** Builds the taxonomy exception for a non-2xx response. */
    private function mapError(int $status, string $body): SunderError
    {
        $code = '';
        $detail = null;
        $parsed = json_decode($body, true);
        if (is_array($parsed)) {
            $rawCode = $parsed['error'] ?? '';
            $code = is_scalar($rawCode) ? (string) $rawCode : '';
            $rawDetail = $parsed['detail'] ?? null;
            if ($rawDetail !== null) {
                $detail = is_scalar($rawDetail) ? (string) $rawDetail : json_encode($rawDetail);
            }
        }

        if ($status >= 500) {
            return new ServiceUnavailableException($code !== '' ? $code : 'service_unavailable', $status, $detail);
        }
        $class = self::CODE_MAP[$code] ?? self::STATUS_MAP[$status] ?? SunderException::class;
        return new $class($code !== '' ? $code : 'http_' . $status, $status, $detail);
    }

    /** Pulls a required string field out of a parsed response body. */
    private function expectString(array $parsed, string $key): string
    {
        $value = $parsed[$key] ?? null;
        if (!is_string($value)) {
            throw new SunderException('bad_response', null, "missing \"{$key}\" in response");
        }
        return $value;
    }
}
