<?php

declare(strict_types=1);

namespace Sunder;

/**
 * Base exception for the Sunder error taxonomy. Every per-code subclass
 * below extends it; it in turn extends SunderError, so both
 * `catch (SunderException $e)` and `catch (SunderError $e)` catch every
 * failure the client can throw.
 */
class SunderException extends SunderError
{
}

/** 401 `unauthorized` - missing/invalid credential. */
class UnauthorizedException extends SunderException
{
}

/** 403 `forbidden` - action not in the client's allowed actions. */
class ForbiddenException extends SunderException
{
}

/** 401 `credential_expired` - correct secret, past its expiry: rotate it. */
class CredentialExpiredException extends SunderException
{
}

/** 403 `consent_denied` - the data subject withdrew consent for this purpose. */
class ConsentDeniedException extends SunderException
{
}

/** 403 `purpose_not_allowed` - purpose not in the client's allowed purposes. */
class PurposeNotAllowedException extends SunderException
{
}

/** 403 `unlock_required` - the credential IS entitled, but the call needs a single-use unlock token it did not present (POST /v1/admin/unlock, then X-Sunder-Unlock). Distinct from forbidden: the two call for opposite responses. */
class UnlockRequiredException extends SunderException
{
}

/** 403 `audience_mismatch` - OTI addressed to a different audience. */
class AudienceMismatchException extends SunderException
{
}

/** 404 `not_found` - no match, including CIDs of foreign scopes. */
class NotFoundException extends SunderException
{
}

/** 400 `validation` / `bad_json` - invalid request (also raised locally). */
class ValidationException extends SunderException
{
}

/** 400 `token_invalid` - bad OTI signature, purpose or shape. */
class TokenInvalidException extends SunderException
{
}

/** 409 `token_used` - the single-use OTI was already consumed. */
class TokenUsedException extends SunderException
{
}

/** 410 `token_expired` - the OTI outlived its 5-minute window. */
class TokenExpiredException extends SunderException
{
}

/** 429 `rate_limited` - per-client lookup rate limit exceeded. */
class RateLimitedException extends SunderException
{
}

/** Any 5xx response, or a network-level failure (then $status is null). */
class ServiceUnavailableException extends SunderException
{
}
