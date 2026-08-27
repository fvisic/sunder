<?php

declare(strict_types=1);

/**
 * Router script for the PHP built-in server used as a mock Sunder instance.
 *
 * State lives in the directory named by SUNDER_MOCK_DIR:
 *  - requests.log:    one JSON line per served request (method, path, headers, body);
 *  - responses.queue: one JSON line per queued response ({"status", "payload"});
 *                     a string payload is served as text/plain, anything else
 *                     as JSON. An empty queue serves 500 {"error":"internal"}.
 */

$dir = getenv('SUNDER_MOCK_DIR');
if ($dir === false || $dir === '') {
    http_response_code(500);
    exit('SUNDER_MOCK_DIR not set');
}

// Record the request.
$rawBody = file_get_contents('php://input');
$record = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => $_SERVER['REQUEST_URI'],
    'headers' => array_change_key_case(getallheaders(), CASE_LOWER),
    'body' => $rawBody === '' ? null : json_decode($rawBody, true),
    // The raw body as well: a multipart upload is not JSON, and the tests
    // assert on the boundary, the filename and the content. PHP consumes a
    // multipart body into $_FILES before php://input can be read, so that
    // case is reported separately rather than as an empty raw body.
    'raw' => $rawBody,
    'files' => array_map(
        static fn (array $f): array => [
            'name' => $f['name'],
            'type' => $f['type'],
            'content' => is_string($f['tmp_name']) && is_readable($f['tmp_name'])
                ? (string) file_get_contents($f['tmp_name'])
                : '',
        ],
        $_FILES
    ),
];
file_put_contents($dir . '/requests.log', json_encode($record) . "\n", FILE_APPEND | LOCK_EX);

// Pop the next queued response.
$status = 500;
$payload = ['error' => 'internal'];
$fh = fopen($dir . '/responses.queue', 'c+');
if ($fh !== false) {
    flock($fh, LOCK_EX);
    $lines = array_values(array_filter(explode("\n", (string) stream_get_contents($fh)), 'strlen'));
    if ($lines !== []) {
        $next = json_decode(array_shift($lines), true);
        $status = (int) $next['status'];
        $payload = $next['payload'];
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, $lines === [] ? '' : implode("\n", $lines) . "\n");
    }
    flock($fh, LOCK_UN);
    fclose($fh);
}

http_response_code($status);
if (is_string($payload)) {
    header('Content-Type: text/plain');
    echo $payload;
} else {
    header('Content-Type: application/json');
    echo json_encode($payload);
}
