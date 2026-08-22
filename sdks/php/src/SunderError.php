<?php

declare(strict_types=1);

namespace Sunder;

/**
 * Root error type for all Sunder API failures — same taxonomy and trigger
 * conditions as every other Sunder SDK (Python's SunderError, TS's
 * SunderError). Catch this to catch everything the client can throw.
 *
 * Properties:
 *  - $code:   machine-readable error code (the API's JSON "error" field,
 *             or a synthetic code such as "service_unavailable").
 *  - $status: HTTP status code, or null for pure network failures.
 *  - $detail: optional human-readable detail from the API.
 */
class SunderError extends \RuntimeException
{
    /**
     * Machine-readable error code (string). Redeclared without a native type
     * because \Exception already defines an untyped $code.
     *
     * @var string
     */
    public $code;
    public ?int $status;
    public ?string $detail;

    public function __construct(string $code, ?int $status = null, ?string $detail = null)
    {
        $this->code = $code;
        $this->status = $status;
        $this->detail = $detail;
        $message = ($detail === null || $detail === '') ? $code : "{$code}: {$detail}";
        parent::__construct($message);
    }
}
