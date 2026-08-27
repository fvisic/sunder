<?php

declare(strict_types=1);

namespace Sunder\Tests;

use PHPUnit\Framework\TestCase;
use Sunder\NotFoundException;
use Sunder\ServiceUnavailableException;
use Sunder\SunderClient;

/**
 * The routes beyond the core handoff surface: consent, data-subject rights,
 * value tokenization, the file vault, shares, links, version history,
 * external claims and the admin unlock.
 *
 * Each test asserts the wire contract and the properties a client can get
 * wrong: an empty cascade must not be sent as an opt-in, bulk routes must
 * carry the unlock token, and destructive calls are never blind-retried.
 */
final class SunderApiTest extends TestCase
{
    private static string $url;
    private static string $stateDir;
    /** @var resource */
    private static $proc;

    private SunderClient $client;

    public static function setUpBeforeClass(): void
    {
        self::$stateDir = sys_get_temp_dir() . '/sunder-php-api-' . getmypid() . '-' . bin2hex(random_bytes(4));
        mkdir(self::$stateDir, 0700, true);
        touch(self::$stateDir . '/requests.log');
        touch(self::$stateDir . '/responses.queue');

        $port = self::freePort();
        self::$url = "http://127.0.0.1:{$port}";

        putenv('SUNDER_MOCK_DIR=' . self::$stateDir);
        $proc = proc_open(
            [PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/mock_server_router.php'],
            [
                1 => ['file', tempnam(sys_get_temp_dir(), 'sunder-api-out'), 'w'],
                2 => ['file', tempnam(sys_get_temp_dir(), 'sunder-api-err'), 'w'],
            ],
            $pipes
        );
        if ($proc === false) {
            self::fail('could not start mock server');
        }
        self::$proc = $proc;

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

    private function queue(array ...$responses): void
    {
        $lines = '';
        foreach ($responses as [$status, $payload]) {
            $lines .= json_encode(['status' => $status, 'payload' => $payload]) . "\n";
        }
        file_put_contents(self::$stateDir . '/responses.queue', $lines, FILE_APPEND | LOCK_EX);
    }

    /** @return array<int, array{method: string, path: string, headers: array, body: ?array, raw: string}> */
    private function requests(): array
    {
        $lines = array_filter(explode("\n", (string) file_get_contents(self::$stateDir . '/requests.log')), 'strlen');
        return array_map(static fn (string $l): array => json_decode($l, true), array_values($lines));
    }

    private function only(): array
    {
        $reqs = $this->requests();
        $this->assertCount(1, $reqs, 'expected exactly one request');
        return $reqs[0];
    }

    // -- consent ----------------------------------------------------------------

    public function testSetConsentSendsARealBoolean(): void
    {
        $this->queue([200, ['cid' => 'CID1', 'purpose' => 'billing', 'granted' => false]]);
        $out = $this->client->setConsent('CID1', 'billing', false);
        $this->assertFalse($out['granted']);
        $this->assertFalse($this->only()['body']['granted']);
    }

    public function testGetConsentReturnsTheList(): void
    {
        $this->queue([200, ['consents' => [['purpose' => 'billing', 'granted' => true]]]]);
        $got = $this->client->getConsent('CID1');
        $this->assertCount(1, $got);
        $this->assertSame('/v1/consent/CID1', $this->only()['path']);
    }

    // -- data subject rights -----------------------------------------------------

    public function testDsrAccessCarriesHoldingsBeyondTheBlob(): void
    {
        $this->queue([200, [
            'scopes' => [[
                'scope' => 'crm',
                'cid' => 'CID1',
                'value_tokens' => [['token' => 'tok_1']],
                'files' => [['id' => 'f1']],
                'shares' => [['uuid' => 'u1', 'partner_label' => 'partner-bank']],
                'links' => [['cid' => 'CID2', 'link_type' => 'guardian']],
            ]],
            'audit_trail' => [['ts' => '2026-01-01T00:00:00Z', 'client_id' => 'crm', 'action' => 'lookup', 'count' => 3]],
        ]]);
        $got = $this->client->dsrAccess('CID1');
        $scope = $got['scopes'][0];
        foreach (['value_tokens', 'files', 'shares', 'links'] as $section) {
            $this->assertCount(1, $scope[$section], "{$section} was dropped");
        }
        // The share's recipient label IS the Article 15 answer.
        $this->assertSame('partner-bank', $scope['shares'][0]['partner_label']);
        $this->assertStringContainsString('cid=CID1', $this->only()['path']);
    }

    public function testDsrExportIsCallerScopeOnly(): void
    {
        $this->queue([200, ['scope' => 'crm', 'cid' => 'CID1', 'attributes' => ['email' => 'a@b.c']]]);
        $got = $this->client->dsrExport('CID1');
        $this->assertSame('crm', $got['scope']);
        $this->assertStringStartsWith('/v1/dsr/export?cid=', $this->only()['path']);
    }

    public function testEraseOmitsCascadeUnlessAsked(): void
    {
        $this->queue([200, ['erasure_id' => 7, 'scopes' => 2, 'linked' => [['cid' => 'CID2', 'link_type' => 'guardian', 'cascaded' => false]]]]);
        $got = $this->client->dsrErase('CID1');
        $this->assertSame(7, $got['erasure_id']);
        $this->assertArrayNotHasKey('cascade', $this->only()['body']);
    }

    public function testEraseForwardsNamedLinkTypes(): void
    {
        $this->queue([200, ['erasure_id' => 8, 'scopes' => 1]]);
        $this->client->dsrErase('CID1', ['guardian']);
        $this->assertSame(['guardian'], $this->only()['body']['cascade']);
    }

    public function testEraseIsNeverRetried(): void
    {
        $this->queue([503, ['error' => 'service_unavailable']]);
        $this->expectException(ServiceUnavailableException::class);
        try {
            $this->client->dsrErase('CID1');
        } finally {
            $this->assertCount(1, $this->requests(), 'a destructive call must be attempted once');
        }
    }

    // -- value tokenization -------------------------------------------------------

    public function testTokenizeOmitsAnUnsetCid(): void
    {
        $this->queue([201, ['token' => 'tok_abc']]);
        $token = $this->client->tokenize('4111111111111111', ['type' => 'card', 'unique' => true]);
        $this->assertSame('tok_abc', $token);
        $body = $this->only()['body'];
        $this->assertArrayNotHasKey('cid', $body);
        $this->assertTrue($body['unique']);
    }

    public function testDetokenizeAndDelete(): void
    {
        $this->queue([200, ['value' => 'secret']], [200, ['status' => 'deleted']]);
        $this->assertSame('secret', $this->client->detokenize('tok_1'));
        $this->client->deleteToken('tok_1');
        $reqs = $this->requests();
        $this->assertSame('DELETE', $reqs[1]['method']);
    }

    public function testBulkRoutesCarryTheUnlockToken(): void
    {
        $this->queue([201, ['tokens' => ['t1', 't2']]]);
        $got = $this->client->tokenizeBulk('unlock_xyz', [['value' => 'a'], ['value' => 'b']]);
        $this->assertSame(['t1', 't2'], $got);
        $this->assertSame('unlock_xyz', $this->only()['headers']['x-sunder-unlock']);
    }

    public function testBulkReadIsNotRetried(): void
    {
        // The unlock token is spent by the first attempt: a retry would come
        // back already-used and hide whether the batch landed.
        $this->queue([503, ['error' => 'service_unavailable']]);
        $this->expectException(ServiceUnavailableException::class);
        try {
            $this->client->detokenizeBulk('unlock_xyz', ['t1']);
        } finally {
            $this->assertCount(1, $this->requests());
        }
    }

    // -- file vault ----------------------------------------------------------------

    public function testUploadSendsMultipartWithFilenameAndExpiry(): void
    {
        $this->queue([201, ['id' => 'f1', 'name' => 'scan.pdf', 'sha256' => 'deadbeef']]);
        $meta = $this->client->uploadFile('CID1', 'scan.pdf', 'hello', 'application/pdf', '2030-01-02T03:04:05Z');
        $this->assertSame('deadbeef', $meta['sha256']);
        $req = $this->only();
        $this->assertStringStartsWith('multipart/form-data', $req['headers']['content-type']);
        // PHP parses the multipart body into $_FILES before php://input can
        // be read, so the mock reports the parsed part rather than raw bytes.
        $this->assertSame('scan.pdf', $req['files']['file']['name']);
        $this->assertSame('application/pdf', $req['files']['file']['type']);
        $this->assertSame('hello', $req['files']['file']['content']);
        $this->assertSame('2030-01-02T03:04:05Z', $req['headers']['x-sunder-file-expiry']);
    }

    public function testUploadOmitsTheExpiryHeaderWhenNone(): void
    {
        $this->queue([201, ['id' => 'f1']]);
        $this->client->uploadFile('CID1', 'a.txt', 'x');
        $this->assertArrayNotHasKey('x-sunder-file-expiry', $this->only()['headers']);
    }

    public function testListFilesSendsThePurposeAndDownloadMapsErrors(): void
    {
        $this->queue([200, ['files' => [['id' => 'f1']]]]);
        $files = $this->client->listFiles('CID1', 'support');
        $this->assertSame('f1', $files[0]['id']);
        $this->assertStringContainsString('purpose=support', $this->only()['path']);

        file_put_contents(self::$stateDir . '/requests.log', '');
        $this->queue([200, 'raw-bytes'], [404, ['error' => 'not_found']]);
        $this->assertSame('raw-bytes', $this->client->downloadFile('f1', 'support'));
        // A 404 must not reach the caller as the bytes of an error page.
        $this->expectException(NotFoundException::class);
        $this->client->downloadFile('missing', 'support');
    }

    // -- shares, links, versions -----------------------------------------------------

    public function testCreateShareSendsThePartnerLabel(): void
    {
        $this->queue([201, ['uuid' => 'u1', 'expires_at' => '2026-01-01T00:00:00Z']]);
        $got = $this->client->createShare('CID1', ['email'], [
            'partner_label' => 'partner-bank', 'purpose' => 'kyc', 'ttl_seconds' => 3600,
        ]);
        $this->assertSame('u1', $got['uuid']);
        $this->assertSame('partner-bank', $this->only()['body']['partner_label']);
    }

    public function testFetchAndRevokeShare(): void
    {
        $this->queue([200, ['fields' => ['email' => 'a@b.c']]], [200, ['status' => 'revoked']]);
        $this->assertSame(['email' => 'a@b.c'], $this->client->fetchShare('u1'));
        $this->client->revokeShare('u1');
        $this->assertSame('DELETE', $this->requests()[1]['method']);
    }

    public function testLinksRoundTrip(): void
    {
        $this->queue(
            [201, ['status' => 'linked']],
            [200, ['links' => [['cid' => 'CHILD', 'link_type' => 'guardian', 'role' => 'parent']]]],
            [200, ['status' => 'unlinked']],
        );
        $this->client->link('PARENT', 'CHILD', 'guardian');
        $links = $this->client->listLinks('PARENT');
        $this->assertSame('parent', $links[0]['role']);
        $this->client->unlink('PARENT', 'CHILD');
        $reqs = $this->requests();
        $this->assertSame('guardian', $reqs[0]['body']['link_type']);
        $this->assertSame('DELETE', $reqs[2]['method']);
    }

    public function testHistoricalReadStillSendsThePurpose(): void
    {
        $this->queue([200, ['versions' => [['version_no' => 2]]]], [200, ['value' => 'old@example.com']]);
        $this->assertSame(2, $this->client->listVersions('CID1')[0]['version_no']);
        $this->assertSame('old@example.com', $this->client->getVersionAttribute('CID1', 2, 'email', 'support'));
        // An old value is not a lesser secret.
        $this->assertSame(
            '/v1/contacts/CID1/versions/2/attributes/email?purpose=support',
            $this->requests()[1]['path']
        );
    }

    // -- claims, unlock, attribution ----------------------------------------------------

    public function testExternalClaimKeepsIssuerProvenance(): void
    {
        $this->queue([200, ['stored' => ['verified_age@gov-id']]]);
        $stored = $this->client->storeExternalClaim('CID1', 'eyJ...envelope');
        $this->assertStringContainsString('@', $stored[0]);
        $this->assertSame('eyJ...envelope', $this->only()['body']['envelope']);
    }

    public function testUnlockMintsASingleUseToken(): void
    {
        $this->queue([201, ['unlock_token' => 'unlock_xyz', 'expires_at' => '2026-01-01T00:01:00Z']]);
        $got = $this->client->unlock('tokens');
        $this->assertSame('unlock_xyz', $got['unlock_token']);
        $this->assertSame('tokens', $this->only()['body']['purpose']);
    }

    public function testUserIdIsSentOnEveryCall(): void
    {
        $client = new SunderClient(self::$url, 'client_id.secret', 10.0, 'agent-7');
        $this->queue([200, ['value' => 'a@b.c']]);
        $client->getAttribute('CID1', 'email', 'support');
        $this->assertSame('agent-7', $this->only()['headers']['x-sunder-user-id']);
    }

    public function testReadyProbe(): void
    {
        $this->queue([200, 'ok']);
        $this->assertSame('ok', $this->client->ready()['status']);
        $this->assertSame('/readyz', $this->only()['path']);
    }
}
