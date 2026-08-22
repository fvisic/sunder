// Sunder .NET SDK — a thin client for the Sunder pseudonymous identity
// provider (v1 API).
//
// Design rules (docs/DESIGN.md, SDK design rules):
// - Zero cryptography here: transport, auth, timeouts, retries, error mapping.
// - Zero dependencies beyond the BCL (System.Net.Http + System.Text.Json).
// - Per-endpoint retry policy: lookups and IssueOtiAsync retry once on 5xx or
//   network failure; VerifyOtiAsync is NEVER blind-retried (single-use token —
//   a retry after an ambiguous network failure would legitimately return
//   TokenUsed; that outcome is surfaced distinctly for the caller to decide).

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SunderId.Client;

/// <summary>
/// Input for <see cref="SunderClient.RegisterContactAsync" />. At least one
/// email or phone is required (enforced server-side). Null properties are
/// omitted from the request body.
/// </summary>
public sealed class ContactAttributes
{
    /// <summary>Primary email (searchable).</summary>
    [JsonPropertyName("email")]
    public string? Email { get; set; }

    /// <summary>Additional searchable emails.</summary>
    [JsonPropertyName("emails")]
    public IList<string>? Emails { get; set; }

    /// <summary>Primary phone (searchable, E.164 or common formatting).</summary>
    [JsonPropertyName("phone")]
    public string? Phone { get; set; }

    /// <summary>Additional searchable phones.</summary>
    [JsonPropertyName("phones")]
    public IList<string>? Phones { get; set; }

    /// <summary>Person's name (a narrowing key, never an identifier).</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>
    /// Additional attributes stored in the caller-scope encrypted blob.
    /// "email", "phone" and "name" are reserved names and rejected here.
    /// </summary>
    [JsonPropertyName("attributes")]
    public IDictionary<string, string>? Attributes { get; set; }
}

/// <summary>Result of <see cref="SunderClient.IssueOtiAsync" />.</summary>
/// <param name="Token">PASETO v4.public one-time identifier.</param>
/// <param name="ExpiresAt">RFC 3339 timestamp; tokens live 5 minutes, one use,
/// one audience, one purpose.</param>
public sealed record OtiResult(string Token, string ExpiresAt);

/// <summary>
/// Client for the Sunder v1 API. Implements the canonical CidProviderClient
/// interface (docs/DESIGN.md, SDK design rules). All methods throw a subclass of
/// <see cref="SunderException" /> on failure.
///
/// Remember: LOOKUP != AUTHENTICATION — a lookup hit never proves the caller
/// is talking to that person.
/// </summary>
public sealed class SunderClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _baseUrl;
    private readonly string _credential;
    private readonly HttpClient _http;

    /// <summary>Creates a client for a Sunder instance.</summary>
    /// <param name="url">Base URL of the Sunder instance; defaults to env SUNDER_URL.</param>
    /// <param name="credential">"client_id.secret" bearer credential; defaults to env SUNDER_CREDENTIAL.</param>
    /// <param name="timeout">Per-request timeout; defaults to 10 seconds.</param>
    /// <param name="handler">Optional HTTP message handler (injectable for tests).</param>
    public SunderClient(
        string? url = null,
        string? credential = null,
        TimeSpan? timeout = null,
        HttpMessageHandler? handler = null)
    {
        url ??= Environment.GetEnvironmentVariable("SUNDER_URL");
        credential ??= Environment.GetEnvironmentVariable("SUNDER_CREDENTIAL");
        if (string.IsNullOrEmpty(url))
            throw new ArgumentException("Sunder URL required (argument or SUNDER_URL)", nameof(url));
        if (string.IsNullOrEmpty(credential))
            throw new ArgumentException("Sunder credential required (argument or SUNDER_CREDENTIAL)", nameof(credential));
        _baseUrl = url.TrimEnd('/');
        _credential = credential;
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = timeout ?? TimeSpan.FromSeconds(10);
    }

    // -- contacts ------------------------------------------------------------

    /// <summary>
    /// Registers (or dedup-merges) a contact. Returns the caller-scope CID.
    /// </summary>
    public async Task<string> RegisterContactAsync(ContactAttributes attrs)
    {
        ArgumentNullException.ThrowIfNull(attrs);
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/contacts",
            JsonSerializer.Serialize(attrs, JsonOptions),
            retryOnce: false).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    /// <summary>
    /// Issues the same person's CID in another scope. Linkage-capable —
    /// grant sparingly; prefer OTIs for cross-system handoff.
    /// </summary>
    public async Task<string> IssueScopedCidAsync(string cid, string scope)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid) + "/scopes";
        var root = await RequestAsync(
            HttpMethod.Post, path,
            JsonSerializer.Serialize(new Dictionary<string, string> { ["scope"] = scope }),
            retryOnce: false).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    // -- lookup (LOOKUP != AUTHENTICATION) -------------------------------------

    /// <summary>
    /// Finds a contact by email; returns the caller-scope CID. Throws
    /// <see cref="SunderNotFoundException" /> on a miss. Retries once on 5xx.
    /// </summary>
    public async Task<string> LookupByEmailAsync(string email)
    {
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/lookup",
            JsonSerializer.Serialize(new Dictionary<string, string> { ["email"] = email }),
            retryOnce: true).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    /// <summary>
    /// Finds a contact by phone; returns the caller-scope CID. Throws
    /// <see cref="SunderNotFoundException" /> on a miss. Retries once on 5xx.
    /// </summary>
    public async Task<string> LookupByPhoneAsync(string phone)
    {
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/lookup",
            JsonSerializer.Serialize(new Dictionary<string, string> { ["phone"] = phone }),
            retryOnce: true).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    /// <summary>
    /// Finds a contact by name plus a second factor (email or phone) — a name
    /// alone is a narrowing key, never an identifier. Exactly the API's rule
    /// is enforced client-side: at least one of email/phone is required, or a
    /// <see cref="SunderValidationException" /> is thrown without any request.
    /// </summary>
    public async Task<string> LookupByNameAsync(string name, string? email = null, string? phone = null)
    {
        if (email is null && phone is null)
            throw new SunderValidationException(
                "validation", null,
                "LookupByNameAsync requires email or phone as a second factor");
        var body = new Dictionary<string, string> { ["name"] = name };
        if (email is not null) body["email"] = email;
        if (phone is not null) body["phone"] = phone;
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/lookup",
            JsonSerializer.Serialize(body),
            retryOnce: true).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    // -- attributes ------------------------------------------------------------

    /// <summary>
    /// Fetches exactly one attribute value; purpose is mandatory and must be
    /// in the caller's allowed purposes. Every fetch is audited server-side.
    /// </summary>
    public async Task<string> GetAttributeAsync(string cid, string name, string purpose)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid)
            + "/attributes/" + Uri.EscapeDataString(name)
            + "?purpose=" + Uri.EscapeDataString(purpose);
        var root = await RequestAsync(HttpMethod.Get, path, null, retryOnce: false)
            .ConfigureAwait(false);
        return GetStringField(root, "value");
    }

    // -- OTI ---------------------------------------------------------------

    /// <summary>
    /// Issues a one-time identifier: 5 minutes, one use, one audience, one
    /// purpose. Safe to retry (retries once on 5xx / network failure).
    /// </summary>
    public async Task<OtiResult> IssueOtiAsync(string cid, string purpose, string audience)
    {
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/oti",
            JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["cid"] = cid,
                ["purpose"] = purpose,
                ["audience"] = audience,
            }),
            retryOnce: true).ConfigureAwait(false);
        return new OtiResult(GetStringField(root, "token"), GetStringField(root, "expires_at"));
    }

    /// <summary>
    /// Verifies and consumes a one-time identifier; returns the VERIFIER's own
    /// scoped CID. NEVER blind-retried: the token is single-use, so a retry
    /// after an ambiguous network failure would legitimately return TokenUsed.
    /// On TokenUsed after a failure, the caller decides how to reconcile.
    /// </summary>
    public async Task<string> VerifyOtiAsync(string token, string purpose, string audience)
    {
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/oti/verify",
            JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["token"] = token,
                ["purpose"] = purpose,
                ["audience"] = audience,
            }),
            retryOnce: false).ConfigureAwait(false); // single-use token — see method doc
        return GetStringField(root, "cid");
    }

    // -- ops -------------------------------------------------------------------

    /// <summary>
    /// Liveness probe (GET /healthz, no auth server-side). Returns the body
    /// text, or "ok" when empty. Network failures surface as
    /// <see cref="SunderServiceUnavailableException" /> like everywhere else.
    /// </summary>
    public async Task<string> HealthAsync()
    {
        int status;
        string text;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _baseUrl + "/healthz");
            using var response = await _http.SendAsync(request).ConfigureAwait(false);
            status = (int)response.StatusCode;
            text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new SunderServiceUnavailableException(
                "service_unavailable", null, "network failure: " + ex.Message);
        }
        catch (OperationCanceledException ex)
        {
            // HttpClient timeouts surface as TaskCanceledException (an
            // OperationCanceledException); the SDK takes no CancellationToken,
            // so any cancellation here is a timeout.
            throw new SunderServiceUnavailableException(
                "service_unavailable", null, "request timed out: " + ex.Message);
        }
        if (status < 200 || status >= 300)
            throw CreateError(status, text);
        var trimmed = text.Trim();
        return trimmed.Length > 0 ? trimmed : "ok";
    }

    /// <summary>Disposes the underlying HttpClient.</summary>
    public void Dispose() => _http.Dispose();

    // -- transport -------------------------------------------------------------

    /// <summary>
    /// One HTTP round trip; a single extra attempt when retryOnce is set and
    /// the failure is a 5xx or a network error. Non-5xx errors throw at once.
    /// </summary>
    private async Task<JsonElement> RequestAsync(
        HttpMethod method, string path, string? jsonBody, bool retryOnce)
    {
        var attempts = retryOnce ? 2 : 1;
        SunderException? last = null;
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            int status;
            string text;
            try
            {
                using var request = BuildRequest(method, path, jsonBody);
                using var response = await _http.SendAsync(request).ConfigureAwait(false);
                status = (int)response.StatusCode;
                text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                last = new SunderServiceUnavailableException(
                    "service_unavailable", null, "network failure: " + ex.Message);
                continue; // retryable if attempts remain
            }
            catch (OperationCanceledException ex)
            {
                // HttpClient timeouts surface as TaskCanceledException (an
                // OperationCanceledException); the SDK takes no
                // CancellationToken, so any cancellation here is a timeout.
                last = new SunderServiceUnavailableException(
                    "service_unavailable", null, "request timed out: " + ex.Message);
                continue; // retryable if attempts remain
            }

            if (status >= 200 && status < 300)
            {
                try
                {
                    using var doc = JsonDocument.Parse(text);
                    return doc.RootElement.Clone();
                }
                catch (JsonException)
                {
                    throw new SunderException("bad_response", null, "non-JSON response body");
                }
            }

            last = CreateError(status, text);
            if (last is not SunderServiceUnavailableException)
                throw last; // only 5xx / network failures are retryable
        }
        throw last!;
    }

    private HttpRequestMessage BuildRequest(HttpMethod method, string path, string? jsonBody)
    {
        var request = new HttpRequestMessage(method, _baseUrl + path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _credential);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (jsonBody is not null)
            request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        return request;
    }

    /// <summary>
    /// Builds the taxonomy exception for a non-2xx response: the JSON "error"
    /// field decides first, then the HTTP status.
    /// </summary>
    private static SunderException CreateError(int status, string body)
    {
        var code = "";
        string? detail = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("error", out var e)
                    && e.ValueKind == JsonValueKind.String)
                    code = e.GetString() ?? "";
                if (doc.RootElement.TryGetProperty("detail", out var d)
                    && d.ValueKind == JsonValueKind.String)
                    detail = d.GetString();
            }
        }
        catch (JsonException)
        {
            // Non-JSON error body: fall through to status-only mapping.
        }

        if (status >= 500)
            return new SunderServiceUnavailableException(
                code.Length > 0 ? code : "service_unavailable", status, detail);

        var c = code.Length > 0 ? code : "http_" + status;
        return code switch
        {
            "unauthorized" => new SunderUnauthorizedException(c, status, detail),
            "forbidden" => new SunderForbiddenException(c, status, detail),
            "purpose_not_allowed" => new SunderPurposeNotAllowedException(c, status, detail),
            "audience_mismatch" => new SunderAudienceMismatchException(c, status, detail),
            "not_found" => new SunderNotFoundException(c, status, detail),
            "validation" or "bad_json" => new SunderValidationException(c, status, detail),
            "token_invalid" => new SunderTokenInvalidException(c, status, detail),
            "token_used" => new SunderTokenUsedException(c, status, detail),
            "token_expired" => new SunderTokenExpiredException(c, status, detail),
            "rate_limited" => new SunderRateLimitedException(c, status, detail),
            _ => status switch
            {
                400 => new SunderValidationException(c, status, detail),
                401 => new SunderUnauthorizedException(c, status, detail),
                403 => new SunderForbiddenException(c, status, detail),
                404 => new SunderNotFoundException(c, status, detail),
                409 => new SunderTokenUsedException(c, status, detail),
                410 => new SunderTokenExpiredException(c, status, detail),
                429 => new SunderRateLimitedException(c, status, detail),
                _ => new SunderException(c, status, detail),
            },
        };
    }

    private static string GetStringField(JsonElement root, string name)
    {
        if (root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty(name, out var el)
            && el.ValueKind == JsonValueKind.String)
            return el.GetString()!;
        throw new SunderException("bad_response", null, "missing \"" + name + "\" in response");
    }
}
