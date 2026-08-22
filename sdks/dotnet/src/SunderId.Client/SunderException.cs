// Unified Sunder SDK error taxonomy — identical names and identical trigger
// conditions across all Sunder SDKs (PLAN section 10.1).

using System;

namespace SunderId.Client;

/// <summary>
/// Base exception for all Sunder API failures.
/// </summary>
public class SunderException : Exception
{
    /// <summary>
    /// Machine-readable error code: the API's JSON "error" field, or a
    /// synthetic code such as "service_unavailable" or "http_404".
    /// </summary>
    public string Code { get; }

    /// <summary>HTTP status code, or null for pure network failures.</summary>
    public int? Status { get; }

    /// <summary>Optional human-readable detail from the API.</summary>
    public string? Detail { get; }

    /// <summary>Creates a Sunder exception.</summary>
    /// <param name="code">Machine-readable error code.</param>
    /// <param name="status">HTTP status code, or null for network failures.</param>
    /// <param name="detail">Optional human-readable detail.</param>
    public SunderException(string code, int? status = null, string? detail = null)
        : base(detail is null ? code : code + ": " + detail)
    {
        Code = code;
        Status = status;
        Detail = detail;
    }
}

/// <summary>401 unauthorized — missing or invalid credential.</summary>
public sealed class SunderUnauthorizedException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderUnauthorizedException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>403 forbidden — the client may not perform this action.</summary>
public sealed class SunderForbiddenException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderForbiddenException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>403 purpose_not_allowed — purpose outside the client's allowed purposes.</summary>
public sealed class SunderPurposeNotAllowedException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderPurposeNotAllowedException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>403 audience_mismatch — the OTI is addressed to a different audience.</summary>
public sealed class SunderAudienceMismatchException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderAudienceMismatchException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>404 not_found — no match, including CIDs of other scopes.</summary>
public sealed class SunderNotFoundException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderNotFoundException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>400 validation / bad_json — invalid request (also raised locally).</summary>
public sealed class SunderValidationException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderValidationException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>400 token_invalid — bad OTI signature, purpose or shape.</summary>
public sealed class SunderTokenInvalidException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderTokenInvalidException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>409 token_used — the single-use OTI has already been consumed.</summary>
public sealed class SunderTokenUsedException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderTokenUsedException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>410 token_expired — the OTI's 5-minute lifetime is over.</summary>
public sealed class SunderTokenExpiredException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderTokenExpiredException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>429 rate_limited — the client exceeded its per-minute limit.</summary>
public sealed class SunderRateLimitedException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderRateLimitedException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}

/// <summary>
/// 5xx responses AND network-level failures (connection errors, timeouts) —
/// same taxonomy and trigger conditions as every other Sunder SDK.
/// </summary>
public sealed class SunderServiceUnavailableException : SunderException
{
    /// <summary>Creates the exception; see <see cref="SunderException" /> for the parameters.</summary>
    public SunderServiceUnavailableException(string code, int? status = null, string? detail = null)
        : base(code, status, detail) { }
}
