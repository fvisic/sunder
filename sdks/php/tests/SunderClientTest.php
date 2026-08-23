<?php

declare(strict_types=1);

namespace Sunder\Tests;

use PHPUnit\Framework\TestCase;
use Sunder\AudienceMismatchException;
use Sunder\ForbiddenException;
use Sunder\NotFoundException;
use Sunder\PurposeNotAllowedException;
use Sunder\RateLimitedException;
use Sunder\ServiceUnavailableException;
use Sunder\SunderClient;
use Sunder\SunderError;
use Sunder\SunderException;
use Sunder\TokenExpiredException;
use Sunder\TokenInvalidException;
use Sunder\TokenUsedException;
use Sunder\UnauthorizedException;
use Sunder\ValidationException;

/**
 * Tests the Sunder PHP SDK against a mock Sunder instance (PHP built-in
 * server started from the test, queue/log exchanged through files).
 */
final class SunderClientTest extends TestCase
{
    private static string $url;
    private static string $stateDir;
    /** @var resource */
    private static $proc;

    private SunderClient $client;

    public static function setUpBeforeClass(): void
    {
        self::$stateDir = sys_get_temp_dir() . '/sunder-php-mock-' . getmypid() . '-' . bin2hex(random_bytes(4));
        mkdir(self::$stateDir, 0700, true);
        touch(self::$stateDir . '/requests.log');
        touch(self::$stateDir . '/responses.queue');

        $port = self::freePort();
        self::$url = "http://127.0.0.1:{$port}";

        putenv('SUNDER_MOCK_DIR=' . self::$stateDir);
        $proc = proc_open(
            [PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/mock_server_router.php'],
            [
                1 => ['file', tempnam(sys_get_temp_dir(), 'sunder-mock-out'), 'w'],
                2 => ['file', tempnam(sys_get_temp_dir(), 'sunder-mock-err'), 'w'],
            ],
            $pipes
        );
        if ($proc === false) {
            self::fail('could not start mock server');
        }
        self::$proc = $proc;

        // Wait until the server accepts connections.
        $deadline = microtime(true) + 5.0;
        while (microtime(true) < $deadline) {
            $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if ($sock !== false) {
                fclose($sock);
                return;
            }
            usleep(50_000);
        }
        self::fail('mock server did not come up');
    }

    public static function tearDownAfterClass(): void
    {
        if (isset(self::$proc) && is_resource(self::$proc)) {
            proc_terminate(self::$proc);
            proc_close(self::$proc);
        }
        putenv('SUNDER_MOCK_DIR');
        array_map('unlink', glob(self::$stateDir . '/*') ?: []);
        @rmdir(self::$stateDir);
    }

    protected function setUp(): void
    {
        file_put_contents(self::$stateDir . '/requests.log', '');
        file_put_contents(self::$stateDir . '/responses.queue', '');
        $this->client = new SunderClient(self::$url, 'client_id.secret');
    }

    // -- helpers ---------------------------------------------------------------

    private static function freePort(): int
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($sock, "cannot bind: {$errstr}");
        $name = stream_socket_get_name($sock, false);
        fclose($sock);
        return (int) substr($name, strrpos($name, ':') + 1);
    }

    /** Queues responses: each is [status, payload] (array payload = JSON, string = text/plain). */
    private function queue(array ...$responses): void
    {
        $lines = '';
        foreach ($responses as [$status, $payload]) {
            $lines .= json_encode(['status' => $status, 'payload' => $payload]) . "\n";
        }
        file_put_contents(self::$stateDir . '/responses.queue', $lines, FILE_APPEND | LOCK_EX);
    }

    /** @return array<int, array{method: string, path: string, headers: array, body: ?array}> */
    private function requests(): array
    {
        $lines = array_filter(explode("\n", (string) file_get_contents(self::$stateDir . '/requests.log')), 'strlen');
        return array_map(static fn (string $l): array => json_decode($l, true), array_values($lines));
    }

    // -- success paths -----------------------------------------------------

    public function testRegisterContact(): void
    {
        $this->queue([201, ['cid' => 'CID-1']]);
        $attributes = [
            'email' => 'filip@example.com',
            'emails' => ['f2@example.com'],
            'phone' => '+385911234567',
            'name' => 'Filip Visic',
            'attributes' => ['loyalty_tier' => 'gold'],
        ];

        $cid = $this->client->registerContact($attributes);

        $this->assertSame('CID-1', $cid);
        $reqs = $this->requests();
        $this->assertCount(1, $reqs);
        $this->assertSame('POST', $reqs[0]['method']);
        $this->assertSame('/v1/contacts', $reqs[0]['path']);
        $this->assertSame($attributes, $reqs[0]['body']);
        $this->assertSame('Bearer client_id.secret', $reqs[0]['headers']['authorization']);
        $this->assertSame('application/json', $reqs[0]['headers']['accept']);
        $this->assertSame('application/json', $reqs[0]['headers']['content-type']);
    }

    public function testIssueScopedCid(): void
    {
        $this->queue([200, ['cid' => 'CID-billing']]);

        $cid = $this->client->issueScopedCid('CID-1', 'billing');

        $this->assertSame('CID-billing', $cid);
        $reqs = $this->requests();
        $this->assertSame('POST', $reqs[0]['method']);
        $this->assertSame('/v1/contacts/CID-1/scopes', $reqs[0]['path']);
        $this->assertSame(['scope' => 'billing'], $reqs[0]['body']);
    }

    public function testIssueScopedCidEncodesCidInPath(): void
    {
        $this->queue([200, ['cid' => 'CID-2']]);

        $this->client->issueScopedCid('CID a/b', 'crm');

        $this->assertSame('/v1/contacts/CID%20a%2Fb/scopes', $this->requests()[0]['path']);
    }

    public function testLookupByEmail(): void
    {
        $this->queue([200, ['cid' => 'CID-1']]);

        $cid = $this->client->lookupByEmail('filip@example.com');

        $this->assertSame('CID-1', $cid);
        $reqs = $this->requests();
        $this->assertSame('POST', $reqs[0]['method']);
        $this->assertSame('/v1/lookup', $reqs[0]['path']);
        $this->assertSame(['email' => 'filip@example.com'], $reqs[0]['body']);
    }

    public function testLookupByPhone(): void
    {
        $this->queue([200, ['cid' => 'CID-1']]);

        $cid = $this->client->lookupByPhone('+385911234567');

        $this->assertSame('CID-1', $cid);
        $this->assertSame(['phone' => '+385911234567'], $this->requests()[0]['body']);
    }

    public function testLookupByNameWithEmail(): void
    {
        $this->queue([200, ['cid' => 'CID-1']]);

        $cid = $this->client->lookupByName('Filip Visic', 'filip@example.com');

        $this->assertSame('CID-1', $cid);
        $this->assertSame(
            ['name' => 'Filip Visic', 'email' => 'filip@example.com'],
            $this->requests()[0]['body']
        );
    }

    public function testLookupByNameWithPhone(): void
    {
        $this->queue([200, ['cid' => 'CID-1']]);

        $cid = $this->client->lookupByName('Filip Visic', null, '+385911234567');

        $this->assertSame('CID-1', $cid);
        $this->assertSame(
            ['name' => 'Filip Visic', 'phone' => '+385911234567'],
            $this->requests()[0]['body']
        );
    }

    public function testLookupByNameWithoutSecondFactorFailsLocally(): void
    {
        try {
            $this->client->lookupByName('Filip Visic');
            $this->fail('expected ValidationException');
        } catch (ValidationException $e) {
            $this->assertSame('validation', $e->code);
            $this->assertNull($e->status);
            $this->assertStringContainsString('second factor', (string) $e->detail);
        }
        $this->assertCount(0, $this->requests(), 'must not reach the server');
    }

    public function testGetAttribute(): void
    {
        $this->queue([200, ['value' => 'filip@example.com']]);

        $value = $this->client->getAttribute('CID-1', 'email', 'support tickets');

        $this->assertSame('filip@example.com', $value);
        $reqs = $this->requests();
        $this->assertSame('GET', $reqs[0]['method']);
        $this->assertSame(
            '/v1/contacts/CID-1/attributes/email?purpose=support%20tickets',
            $reqs[0]['path']
        );
        $this->assertNull($reqs[0]['body']);
        $this->assertSame('Bearer client_id.secret', $reqs[0]['headers']['authorization']);
    }

    public function testIssueOti(): void
    {
        $this->queue([201, ['token' => 'v4.public.abc', 'expires_at' => '2026-08-22T12:00:00Z']]);

        $oti = $this->client->issueOti('CID-1', 'create_order', 'erp');

        $this->assertSame(
            ['token' => 'v4.public.abc', 'expiresAt' => '2026-08-22T12:00:00Z'],
            $oti
        );
        $reqs = $this->requests();
        $this->assertSame('POST', $reqs[0]['method']);
        $this->assertSame('/v1/oti', $reqs[0]['path']);
        $this->assertSame(
            ['cid' => 'CID-1', 'purpose' => 'create_order', 'audience' => 'erp'],
            $reqs[0]['body']
        );
    }

    public function testPredicateClaims(): void
    {
        $this->queue([201, ['token' => 'v4.public.p', 'expires_at' => '2026-01-01T00:00:00Z']]);
        $this->client->issueOti('CID-1', 'age_check', 'webshop', null,
            [['attr' => 'birthdate', 'op' => 'age_gte', 'value' => 18]]);
        $reqs = $this->requests();
        $this->assertSame(
            [['attr' => 'birthdate', 'op' => 'age_gte', 'value' => 18]],
            $reqs[0]['body']['share_predicates']
        );

        $this->queue([200, ['cid' => 'CID-web', 'predicates' => [
            ['attr' => 'birthdate', 'op' => 'age_gte', 'value' => 18,
             'result' => true, 'known' => true],
        ]]]);
        $out = $this->client->verifyOtiFull('v4.public.p', 'age_check', 'webshop');
        $this->assertSame('CID-web', $out['cid']);
        $this->assertTrue($out['predicates'][0]['result']);
        $this->assertTrue($out['predicates'][0]['known']);
    }

    public function testVerifyOti(): void
    {
        $this->queue([200, ['cid' => 'CID-erp-9']]);

        $cid = $this->client->verifyOti('v4.public.abc', 'create_order', 'erp');

        $this->assertSame('CID-erp-9', $cid);
        $reqs = $this->requests();
        $this->assertSame('POST', $reqs[0]['method']);
        $this->assertSame('/v1/oti/verify', $reqs[0]['path']);
        $this->assertSame(
            ['token' => 'v4.public.abc', 'purpose' => 'create_order', 'audience' => 'erp'],
            $reqs[0]['body']
        );
    }

    public function testHealth(): void
    {
        $this->queue([200, 'ok']);

        $health = $this->client->health();

        $this->assertSame(['status' => 'ok'], $health);
        $reqs = $this->requests();
        $this->assertSame('GET', $reqs[0]['method']);
        $this->assertSame('/healthz', $reqs[0]['path']);
        $this->assertArrayNotHasKey('authorization', $reqs[0]['headers'], 'healthz is unauthenticated');
    }

    public function testHealthEmptyBodyDefaultsToOk(): void
    {
        $this->queue([200, '']);

        $this->assertSame(['status' => 'ok'], $this->client->health());
    }

    public function testTrailingSlashInUrlIsTrimmed(): void
    {
        $this->queue([200, ['cid' => 'CID-1']]);
        $client = new SunderClient(self::$url . '/', 'client_id.secret');

        $client->lookupByEmail('a@b.c');

        $this->assertSame('/v1/lookup', $this->requests()[0]['path']);
    }

    // -- error mapping -------------------------------------------------------

    public function testErrorCodeMappingTable(): void
    {
        $cases = [
            // [status, server error code, expected class]
            [401, 'unauthorized', UnauthorizedException::class],
            [403, 'forbidden', ForbiddenException::class],
            [403, 'purpose_not_allowed', PurposeNotAllowedException::class],
            [403, 'audience_mismatch', AudienceMismatchException::class],
            [404, 'not_found', NotFoundException::class],
            [400, 'validation', ValidationException::class],
            [400, 'bad_json', ValidationException::class],
            [400, 'token_invalid', TokenInvalidException::class],
            [409, 'token_used', TokenUsedException::class],
            [410, 'token_expired', TokenExpiredException::class],
            [429, 'rate_limited', RateLimitedException::class],
        ];
        foreach ($cases as [$status, $code, $class]) {
            $this->queue([$status, ['error' => $code]]);
            try {
                // registerContact never retries, so every case is exactly one hit.
                $this->client->registerContact(['email' => 'a@b.c']);
                $this->fail("expected {$class} for {$status} {$code}");
            } catch (SunderError $e) {
                $this->assertInstanceOf($class, $e, "{$status} {$code}");
                $this->assertSame($code, $e->code, "{$status} {$code}");
                $this->assertSame($status, $e->status, "{$status} {$code}");
            }
        }
        $this->assertCount(count($cases), $this->requests());
    }

    public function testServerErrorCodeWinsOverStatus(): void
    {
        // The JSON "error" field maps first, then the HTTP status.
        $this->queue([404, ['error' => 'token_used']]);

        $this->expectException(TokenUsedException::class);
        $this->client->registerContact(['email' => 'a@b.c']);
    }

    public function testStatusFallbackWhenBodyIsNotJson(): void
    {
        $this->queue([404, 'gone fishing']);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
            $this->fail('expected NotFoundException');
        } catch (NotFoundException $e) {
            $this->assertSame('http_404', $e->code);
            $this->assertSame(404, $e->status);
            $this->assertNull($e->detail);
        }
    }

    public function testUnknownCodeAndStatusFallsBackToBaseException(): void
    {
        $this->queue([418, ['error' => 'weird_code']]);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
            $this->fail('expected SunderException');
        } catch (SunderException $e) {
            $this->assertSame(SunderException::class, get_class($e));
            $this->assertSame('weird_code', $e->code);
            $this->assertSame(418, $e->status);
        }
    }

    public function testDetailIsPassedThrough(): void
    {
        $this->queue([400, ['error' => 'validation', 'detail' => 'email or phone required']]);
        try {
            $this->client->registerContact([]);
            $this->fail('expected ValidationException');
        } catch (ValidationException $e) {
            $this->assertSame('validation', $e->code);
            $this->assertSame('email or phone required', $e->detail);
            $this->assertSame('validation: email or phone required', $e->getMessage());
        }
    }

    public function testFiveHundredKeepsServerCode(): void
    {
        $this->queue([500, ['error' => 'internal']]);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame('internal', $e->code);
            $this->assertSame(500, $e->status);
        }
        $this->assertCount(1, $this->requests(), 'registerContact never retries');
    }

    public function testFiveXxWithoutCodeIsServiceUnavailable(): void
    {
        $this->queue([503, 'try later']);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame('service_unavailable', $e->code);
            $this->assertSame(503, $e->status);
        }
    }

    public function testNonJsonSuccessBodyIsBadResponse(): void
    {
        $this->queue([201, 'not json at all']);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
            $this->fail('expected SunderException');
        } catch (SunderException $e) {
            $this->assertSame('bad_response', $e->code);
            $this->assertNull($e->status);
        }
    }

    // -- retry policy -----------------------------------------------------------

    public function testLookupRetriesOnceOnFiveXxThenSucceeds(): void
    {
        $this->queue([500, ['error' => 'internal']], [200, ['cid' => 'CID-1']]);

        $cid = $this->client->lookupByEmail('a@b.c');

        $this->assertSame('CID-1', $cid);
        $this->assertCount(2, $this->requests(), 'exactly one retry');
    }

    public function testLookupRetriesExactlyOnceThenThrows(): void
    {
        // Three 5xx responses queued; only two may ever be consumed.
        $this->queue([500, ['error' => 'internal']], [500, ['error' => 'internal']], [500, ['error' => 'internal']]);
        try {
            $this->client->lookupByPhone('+385911234567');
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame(500, $e->status);
        }
        $this->assertCount(2, $this->requests(), 'exactly two attempts, never more');
    }

    public function testLookupByNameRetriesOnce(): void
    {
        $this->queue([503, ['error' => 'internal']], [200, ['cid' => 'CID-1']]);

        $this->assertSame('CID-1', $this->client->lookupByName('F', 'a@b.c'));
        $this->assertCount(2, $this->requests());
    }

    public function testIssueOtiRetriesOnceOnFiveXxThenSucceeds(): void
    {
        $this->queue(
            [500, ['error' => 'internal']],
            [201, ['token' => 't', 'expires_at' => 'now+5m']]
        );

        $oti = $this->client->issueOti('CID-1', 'create_order', 'erp');

        $this->assertSame('t', $oti['token']);
        $this->assertCount(2, $this->requests());
    }

    public function testVerifyOtiNeverRetries(): void
    {
        $this->queue([500, ['error' => 'internal']], [200, ['cid' => 'CID-1']]);
        try {
            $this->client->verifyOti('t', 'create_order', 'erp');
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame(500, $e->status);
        }
        $this->assertCount(1, $this->requests(), 'verifyOti is single-use: never blind-retried');
    }

    public function testRegisterContactNeverRetries(): void
    {
        $this->queue([500, ['error' => 'internal']], [201, ['cid' => 'CID-1']]);
        $this->expectException(ServiceUnavailableException::class);
        try {
            $this->client->registerContact(['email' => 'a@b.c']);
        } finally {
            $this->assertCount(1, $this->requests());
        }
    }

    public function testGetAttributeNeverRetries(): void
    {
        $this->queue([500, ['error' => 'internal']], [200, ['value' => 'x']]);
        $this->expectException(ServiceUnavailableException::class);
        try {
            $this->client->getAttribute('CID-1', 'email', 'support');
        } finally {
            $this->assertCount(1, $this->requests());
        }
    }

    public function testNonFiveXxErrorsAreNotRetried(): void
    {
        $this->queue([404, ['error' => 'not_found']], [200, ['cid' => 'CID-1']]);
        $this->expectException(NotFoundException::class);
        try {
            $this->client->lookupByEmail('a@b.c');
        } finally {
            $this->assertCount(1, $this->requests(), 'only 5xx/network is retryable');
        }
    }

    // -- network failures ---------------------------------------------------

    public function testNetworkFailureIsServiceUnavailable(): void
    {
        $client = new SunderClient('http://127.0.0.1:1', 'client_id.secret'); // port 1: deterministic connection refusal, no freed-port race
        try {
            $client->verifyOti('t', 'create_order', 'erp');
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame('service_unavailable', $e->code);
            $this->assertNull($e->status);
            $this->assertStringContainsString('network failure', (string) $e->detail);
        }
    }

    public function testHealthNetworkFailureIsServiceUnavailable(): void
    {
        $client = new SunderClient('http://127.0.0.1:1', 'client_id.secret'); // port 1: deterministic connection refusal, no freed-port race
        try {
            $client->health();
            $this->fail('expected ServiceUnavailableException');
        } catch (ServiceUnavailableException $e) {
            $this->assertSame('service_unavailable', $e->code);
            $this->assertNull($e->status);
            $this->assertStringContainsString('network failure', (string) $e->detail);
        }
    }

    // -- configuration ---------------------------------------------------------

    public function testEnvConfig(): void
    {
        putenv('SUNDER_URL=' . self::$url);
        putenv('SUNDER_CREDENTIAL=env_client.env_secret');
        try {
            $this->queue([200, ['cid' => 'CID-1']]);
            $client = new SunderClient();

            $this->assertSame('CID-1', $client->lookupByEmail('a@b.c'));
            $this->assertSame(
                'Bearer env_client.env_secret',
                $this->requests()[0]['headers']['authorization']
            );
        } finally {
            putenv('SUNDER_URL');
            putenv('SUNDER_CREDENTIAL');
        }
    }

    public function testArgsWinOverEnv(): void
    {
        putenv('SUNDER_URL=http://example.invalid');
        putenv('SUNDER_CREDENTIAL=env_client.env_secret');
        try {
            $this->queue([200, ['cid' => 'CID-1']]);
            $client = new SunderClient(self::$url, 'arg_client.arg_secret');

            $this->assertSame('CID-1', $client->lookupByEmail('a@b.c'));
            $this->assertSame(
                'Bearer arg_client.arg_secret',
                $this->requests()[0]['headers']['authorization']
            );
        } finally {
            putenv('SUNDER_URL');
            putenv('SUNDER_CREDENTIAL');
        }
    }

    public function testMissingUrlThrows(): void
    {
        putenv('SUNDER_URL');
        putenv('SUNDER_CREDENTIAL');
        $this->expectException(\InvalidArgumentException::class);
        new SunderClient(null, 'client_id.secret');
    }

    public function testMissingCredentialThrows(): void
    {
        putenv('SUNDER_URL');
        putenv('SUNDER_CREDENTIAL');
        $this->expectException(\InvalidArgumentException::class);
        new SunderClient(self::$url, null);
    }
}
