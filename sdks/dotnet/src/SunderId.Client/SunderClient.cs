// Sunder .NET SDK - a thin client for the Sunder pseudonymous identity
// provider (v1 API).
//
// Design rules (docs/DESIGN.md, SDK design rules):
// - Zero cryptography here: transport, auth, timeouts, retries, error mapping.
// - Zero dependencies beyond the BCL (System.Net.Http + System.Text.Json).
// - Per-endpoint retry policy: lookups and IssueOtiAsync retry once on 5xx or
//   network failure; VerifyOtiAsync is NEVER blind-retried (single-use token -
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
/// Remember: LOOKUP != AUTHENTICATION - a lookup hit never proves the caller
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
    private readonly string? _userId;

    /// <summary>Creates a client for a Sunder instance.</summary>
    /// <param name="url">Base URL of the Sunder instance; defaults to env SUNDER_URL.</param>
    /// <param name="credential">"client_id.secret" bearer credential; defaults to env SUNDER_CREDENTIAL.</param>
    /// <param name="timeout">Per-request timeout; defaults to 10 seconds.</param>
    /// <param name="handler">Optional HTTP message handler (injectable for tests).</param>
    /// <param name="userId">
    /// Attributes every read to an operator inside the calling system, sent as
    /// X-Sunder-User-Id and recorded in the audit chain. It upgrades an
    /// Article 15 answer from "which system accessed this" to "which operator
    /// that system says accessed it". CLIENT-ASSERTED and unverifiable by
    /// design: Sunder records the claim and proves it was not altered
    /// afterwards, not that it was true. Accepts [A-Za-z0-9._@:-], 1-64
    /// characters; anything else is a 400 rather than a silent drop.
    /// </param>
    public SunderClient(
        string? url = null,
        string? credential = null,
        TimeSpan? timeout = null,
        HttpMessageHandler? handler = null,
        string? userId = null)
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
        _userId = userId;
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
    /// Issues the same person's CID in another scope. Linkage-capable -
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
    /// Finds a contact by name plus a second factor (email or phone) - a name
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
    public async Task<OtiResult> IssueOtiAsync(string cid, string purpose, string audience,
        IEnumerable<string>? shareAttributes = null,
        IEnumerable<IReadOnlyDictionary<string, object>>? sharePredicates = null)
    {
        var body = new Dictionary<string, object>
        {
            ["cid"] = cid,
            ["purpose"] = purpose,
            ["audience"] = audience,
        };
        var share = shareAttributes is null ? null : new List<string>(shareAttributes);
        if (share is { Count: > 0 })
        {
            // Issuer-authorized attributes copied into the verifier's scope.
            body["share_attributes"] = share;
        }
        var preds = sharePredicates is null
            ? null
            : new List<IReadOnlyDictionary<string, object>>(sharePredicates);
        if (preds is { Count: > 0 })
        {
            // Issuer-authorized predicate claims, e.g.
            // {"attr": "birthdate", "op": "age_gte", "value": 18}; the
            // verifier receives booleans only, never the value.
            body["share_predicates"] = preds;
        }
        var root = await RequestAsync(
            HttpMethod.Post, "/v1/oti",
            JsonSerializer.Serialize(body),
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
        var root = await VerifyOtiFullAsync(token, purpose, audience).ConfigureAwait(false);
        return GetStringField(root, "cid");
    }

    /// <summary>
    /// Like <see cref="VerifyOtiAsync" /> but returns the full JSON result:
    /// "cid", and when present "shared" (copied attribute names) and
    /// "predicates" (attr/op/value/result/known). For age_gte, known=false
    /// means the attribute was absent or unparseable - NOT a failed check;
    /// for exists, known is always true because absence is the answer.
    /// </summary>
    public async Task<JsonElement> VerifyOtiFullAsync(string token, string purpose, string audience)
    {
        return await RequestAsync(
            HttpMethod.Post, "/v1/oti/verify",
            JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["token"] = token,
                ["purpose"] = purpose,
                ["audience"] = audience,
            }),
            retryOnce: false).ConfigureAwait(false); // single-use token - see method doc
    }


    // -- consent ---------------------------------------------------------------

    /// <summary>
    /// Records the person's decision for one purpose.
    /// </summary>
    /// <remarks>
    /// Consent gates attribute reads for that purpose: revoking it makes
    /// <see cref="GetAttributeAsync" /> throw
    /// <see cref="SunderConsentDeniedException" /> even though the client's own
    /// grant is unchanged. Every call is appended to the audit chain, and that
    /// trail SURVIVES erasure - it is the accountability record of what was
    /// consented to and when.
    /// </remarks>
    public async Task<JsonElement> SetConsentAsync(string cid, string purpose, bool granted)
    {
        var body = new Dictionary<string, object>
        {
            ["cid"] = cid,
            ["purpose"] = purpose,
            ["granted"] = granted,
        };
        return await RequestAsync(HttpMethod.Post, "/v1/consent",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    /// <summary>
    /// Lists every purpose the caller's scope has recorded for a person. A
    /// purpose that was never set is ABSENT, not false: "no decision" and
    /// "refused" are different facts.
    /// </summary>
    public async Task<JsonElement> GetConsentAsync(string cid)
    {
        var path = "/v1/consent/" + Uri.EscapeDataString(cid);
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    // -- data subject rights -----------------------------------------------------

    /// <summary>
    /// Article 15, ORG-WIDE: {"scopes": [...], "audit_trail": [...]}.
    /// </summary>
    /// <remarks>
    /// Each scope carries the holdings that do NOT live in the attribute blob -
    /// value tokens, files, the RECIPIENTS of shares, and links. This crosses
    /// scope boundaries on the data subject's behalf, so it needs its own grant
    /// and is itself audited; never route it through an ordinary integration
    /// credential.
    /// </remarks>
    public async Task<JsonElement> DsrAccessAsync(string cid)
    {
        var path = "/v1/dsr/access?cid=" + Uri.EscapeDataString(cid);
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Article 20 for the CALLER's scope only: the same holdings sections in
    /// machine-readable form, for portability.
    /// </summary>
    public async Task<JsonElement> DsrExportAsync(string cid)
    {
        var path = "/v1/dsr/export?cid=" + Uri.EscapeDataString(cid);
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Article 17: erases the person org-wide, queueing one Article 19
    /// notification per scope that held them.
    /// </summary>
    /// <param name="cid">The person to erase.</param>
    /// <param name="cascade">
    /// Link types ("guardian", "member", "owner") whose linked children are
    /// erased too. Null or empty, the children are LISTED in the result and
    /// left untouched - an accidental cascade would delete a third party's
    /// data, so it is opt-in per link type.
    /// </param>
    /// <remarks>
    /// A cascade is one transaction PER PERSON, and the plan is recorded before
    /// any child is touched: re-issuing the identical call after an
    /// interruption RESUMES the outstanding children. Once everything is done
    /// it throws <see cref="SunderNotFoundException" />, deliberately
    /// indistinguishable from a cid that never existed. Never retried: it is
    /// destructive, and resuming is the caller's decision.
    /// </remarks>
    public async Task<JsonElement> DsrEraseAsync(string cid, IEnumerable<string>? cascade = null)
    {
        var body = new Dictionary<string, object> { ["cid"] = cid };
        var types = cascade is null ? null : new List<string>(cascade);
        // An empty list must not be sent: absence is what "cascade nothing"
        // looks like on the wire.
        if (types is { Count: > 0 })
            body["cascade"] = types;
        return await RequestAsync(HttpMethod.Post, "/v1/dsr/erase",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    // -- value tokenization --------------------------------------------------------

    /// <summary>
    /// Vaults one value and returns its opaque token.
    /// </summary>
    /// <param name="value">The plaintext to vault (max 8192 bytes).</param>
    /// <param name="options">
    /// Optional "type" ("string" default, or "card" which also validates the
    /// Luhn checksum), "cid", "unique", "expires_final" and "sliding_seconds".
    /// The cid binds the token to a person in the caller's scope, so erasure and
    /// the retention sweep destroy it; omit it ONLY for a scope-wide value
    /// belonging to no single subject, because an unattributed token survives
    /// that person's erasure.
    /// </param>
    public async Task<string> TokenizeAsync(
        string value, IReadOnlyDictionary<string, object>? options = null)
    {
        var body = new Dictionary<string, object> { ["value"] = value };
        if (options is not null)
        {
            foreach (var kv in options)
                body[kv.Key] = kv.Value;
        }
        var root = await RequestAsync(HttpMethod.Post, "/v1/tokens",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
        return GetStringField(root, "token");
    }

    /// <summary>
    /// Resolves a token back to its value. Audited per read and, for a cid-bound
    /// token, attributed to that person's CID - so "who read my tokenized IBAN"
    /// is answerable from the access trail.
    /// </summary>
    public async Task<string> DetokenizeAsync(string token)
    {
        var path = "/v1/tokens/" + Uri.EscapeDataString(token);
        var root = await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
        return GetStringField(root, "value");
    }

    /// <summary>
    /// Destroys a token and its value. Not retried: it is destructive.
    /// </summary>
    public async Task DeleteTokenAsync(string token)
    {
        var path = "/v1/tokens/" + Uri.EscapeDataString(token);
        await RequestAsync(HttpMethod.Delete, path, null, retryOnce: false)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Vaults many values in one call; tokens come back in input order.
    /// </summary>
    /// <remarks>
    /// Bulk surfaces ALWAYS require a single-use unlock token, regardless of
    /// SUNDER_SEARCH_UNLOCK: one call touching many people is exactly the shape
    /// a rate limit does not constrain. Get one from <see cref="UnlockAsync" />.
    /// The whole batch is validated before the token is spent, so a rejected
    /// item does not burn the unlock.
    /// </remarks>
    public async Task<JsonElement> TokenizeBulkAsync(
        string unlockToken, IEnumerable<IReadOnlyDictionary<string, object>> items)
    {
        var body = new Dictionary<string, object>
        {
            ["items"] = new List<IReadOnlyDictionary<string, object>>(items),
        };
        return await RequestAsync(HttpMethod.Post, "/v1/tokens/bulk",
            JsonSerializer.Serialize(body), retryOnce: false,
            new Dictionary<string, string> { ["X-Sunder-Unlock"] = unlockToken }, null)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves many tokens in one call. Requires an unlock token, for the same
    /// reason <see cref="TokenizeBulkAsync" /> does.
    /// </summary>
    public async Task<JsonElement> DetokenizeBulkAsync(
        string unlockToken, IEnumerable<string> tokens)
    {
        var body = new Dictionary<string, object> { ["tokens"] = new List<string>(tokens) };
        return await RequestAsync(HttpMethod.Post, "/v1/tokens/bulk/read",
            JsonSerializer.Serialize(body), retryOnce: false,
            new Dictionary<string, string> { ["X-Sunder-Unlock"] = unlockToken }, null)
            .ConfigureAwait(false);
    }

    // -- file vault -------------------------------------------------------------------

    /// <summary>
    /// Stores a file for a person; returns its metadata.
    /// </summary>
    /// <remarks>
    /// Each file gets its own data key, wrapped by the person's record key - so
    /// erasing the person shreds the file even if the object store still holds
    /// the ciphertext. <paramref name="expiresAt" /> (RFC 3339) sets a hard
    /// deadline after which the file is unreadable and swept. Never retried: a
    /// retried upload after an ambiguous failure stores the file twice.
    /// </remarks>
    public async Task<JsonElement> UploadFileAsync(
        string cid, string filename, byte[] content,
        string contentType = "application/octet-stream", string? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        var form = new MultipartFormDataContent();
        var part = new ByteArrayContent(content);
        part.Headers.TryAddWithoutValidation("Content-Type", contentType);
        form.Add(part, "file", filename);
        var headers = expiresAt is null
            ? null
            : new Dictionary<string, string> { ["X-Sunder-File-Expiry"] = expiresAt };
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid) + "/files";
        return await RequestAsync(HttpMethod.Post, path, null, retryOnce: false,
            headers, form).ConfigureAwait(false);
    }

    /// <summary>
    /// Lists a person's files (metadata only). Purpose-gated and consent-gated
    /// like any other read; expired files are hidden.
    /// </summary>
    public async Task<JsonElement> ListFilesAsync(string cid, string purpose)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid)
            + "/files?purpose=" + Uri.EscapeDataString(purpose);
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Downloads one file's plaintext.
    /// </summary>
    /// <remarks>
    /// A download that fails mid-stream ABORTS the connection rather than
    /// completing a 200 with a short body, so a truncated read surfaces as a
    /// network error - verify the length, or the "sha256" from
    /// <see cref="ListFilesAsync" />, before treating the bytes as complete.
    /// </remarks>
    public async Task<byte[]> DownloadFileAsync(string id, string purpose)
    {
        var path = "/v1/files/" + Uri.EscapeDataString(id)
            + "?purpose=" + Uri.EscapeDataString(purpose);
        try
        {
            using var request = BuildRequest(HttpMethod.Get, path, null);
            using var response = await _http.SendAsync(request).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            if (status < 200 || status >= 300)
            {
                // A 404 must surface as the taxonomy error, never as the bytes
                // of an error page the caller would write to disk as the file.
                var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                throw CreateError(status, text);
            }
            return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new SunderServiceUnavailableException(
                "service_unavailable", null, "network failure: " + ex.Message);
        }
        catch (OperationCanceledException ex)
        {
            throw new SunderServiceUnavailableException(
                "service_unavailable", null, "request timed out: " + ex.Message);
        }
    }

    /// <summary>
    /// Removes a file. Its name and digest are redacted immediately; the
    /// ciphertext is collected by the retention sweep. Not retried.
    /// </summary>
    public async Task DeleteFileAsync(string id)
    {
        var path = "/v1/files/" + Uri.EscapeDataString(id);
        await RequestAsync(HttpMethod.Delete, path, null, retryOnce: false)
            .ConfigureAwait(false);
    }

    // -- cross-org shares ----------------------------------------------------------------

    /// <summary>
    /// Discloses a SNAPSHOT of named fields to a partner.
    /// </summary>
    /// <remarks>
    /// The returned uuid is unguessable and, when the server runs with
    /// SUNDER_SHARES_PUBLIC, is the ONLY credential needed to fetch it - treat
    /// it as a bearer secret. <paramref name="options" /> accepts
    /// "partner_label" (which identifies the recipient in the audit trail and in
    /// the Article 15 answer), "purpose" and "ttl_seconds".
    /// </remarks>
    public async Task<JsonElement> CreateShareAsync(
        string cid, IEnumerable<string> fields,
        IReadOnlyDictionary<string, object>? options = null)
    {
        var body = new Dictionary<string, object>
        {
            ["cid"] = cid,
            ["fields"] = new List<string>(fields),
        };
        if (options is not null)
        {
            foreach (var kv in options)
                body[kv.Key] = kv.Value;
        }
        return await RequestAsync(HttpMethod.Post, "/v1/shares",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads a share's fields. An expired, revoked or erased share throws
    /// <see cref="SunderNotFoundException" />.
    /// </summary>
    public async Task<JsonElement> FetchShareAsync(string uuid)
    {
        var path = "/v1/shares/" + Uri.EscapeDataString(uuid);
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Withdraws a share. Precise to (cid, purpose) on the consent path, so
    /// revoking one never silently withdraws another. Not retried.
    /// </summary>
    public async Task RevokeShareAsync(string uuid)
    {
        var path = "/v1/shares/" + Uri.EscapeDataString(uuid);
        await RequestAsync(HttpMethod.Delete, path, null, retryOnce: false)
            .ConfigureAwait(false);
    }

    // -- person links ---------------------------------------------------------------------

    /// <summary>
    /// Relates two people in the caller's scope. Erasing the parent LISTS the
    /// children; it never erases them unless
    /// <see cref="DsrEraseAsync" /> names the link type.
    /// </summary>
    public async Task LinkAsync(string parentCid, string childCid, string linkType)
    {
        var body = new Dictionary<string, string>
        {
            ["parent_cid"] = parentCid,
            ["child_cid"] = childCid,
            ["link_type"] = linkType,
        };
        await RequestAsync(HttpMethod.Post, "/v1/links",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    /// <summary>Removes the relation. Not retried.</summary>
    public async Task UnlinkAsync(string parentCid, string childCid)
    {
        var body = new Dictionary<string, string>
        {
            ["parent_cid"] = parentCid,
            ["child_cid"] = childCid,
        };
        await RequestAsync(HttpMethod.Delete, "/v1/links",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    /// <summary>
    /// Reports this person's links, each with the role ("parent" or "child")
    /// this cid plays in it.
    /// </summary>
    public async Task<JsonElement> ListLinksAsync(string cid)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid) + "/links";
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    // -- attribute version history -----------------------------------------------------------

    /// <summary>
    /// Reports the retained revisions of a person's attributes, newest first.
    /// How many are kept is the server's SUNDER_VERSIONS_KEEP / _TTL decision;
    /// history is personal data and is destroyed by erasure like everything else.
    /// </summary>
    public async Task<JsonElement> ListVersionsAsync(string cid)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid) + "/versions";
        return await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one attribute as it was at a past revision. Purpose-gated,
    /// consent-gated and audited exactly like a current read: an old value is
    /// not a lesser secret.
    /// </summary>
    public async Task<string> GetVersionAttributeAsync(
        string cid, long versionNo, string name, string purpose)
    {
        var path = "/v1/contacts/" + Uri.EscapeDataString(cid)
            + "/versions/" + versionNo.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + "/attributes/" + Uri.EscapeDataString(name)
            + "?purpose=" + Uri.EscapeDataString(purpose);
        var root = await RequestAsync(HttpMethod.Get, path, null, retryOnce: true)
            .ConfigureAwait(false);
        return GetStringField(root, "value");
    }

    // -- external claims ------------------------------------------------------------------------

    /// <summary>
    /// Ingests a signed envelope from a trusted issuer; returns the names
    /// actually stored.
    /// </summary>
    /// <remarks>
    /// Stored attribute names carry the issuer's provenance after an '@'
    /// separator - which is why '@' is refused in a caller-supplied attribute
    /// name: an attribute an external issuer vouched for must never be
    /// impersonable by an ordinary write.
    /// </remarks>
    public async Task<JsonElement> StoreExternalClaimAsync(string cid, string envelope)
    {
        var body = new Dictionary<string, string>
        {
            ["cid"] = cid,
            ["envelope"] = envelope,
        };
        return await RequestAsync(HttpMethod.Post, "/v1/claims/external",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
    }

    // -- admin ------------------------------------------------------------------------------------

    /// <summary>
    /// Mints a single-use token authorizing one privileged call.
    /// </summary>
    /// <remarks>
    /// "search" covers fuzzy and partial lookups when SUNDER_SEARCH_UNLOCK is
    /// on; "tokens" covers the bulk vault routes. It lives about a minute and is
    /// spent by ONE call. Requires the admin.unlock action, and the server
    /// refuses to grant that to a credential with no expiry: a standing key to
    /// every gated surface is not something an audit can reconstruct after the
    /// fact.
    /// </remarks>
    public async Task<JsonElement> UnlockAsync(string purpose)
    {
        var body = new Dictionary<string, string> { ["purpose"] = purpose };
        return await RequestAsync(HttpMethod.Post, "/v1/admin/unlock",
            JsonSerializer.Serialize(body), retryOnce: false).ConfigureAwait(false);
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
        => await RequestAsync(method, path, jsonBody, retryOnce, null, null)
            .ConfigureAwait(false);

    private async Task<JsonElement> RequestAsync(
        HttpMethod method, string path, string? jsonBody, bool retryOnce,
        IReadOnlyDictionary<string, string>? extraHeaders, HttpContent? rawContent)
    {
        // A pre-built HttpContent is disposed with the request that carried
        // it, so a second attempt would send a disposed body. None of the
        // callers that pass one ask for a retry; this makes that structural.
        var attempts = retryOnce && rawContent is null ? 2 : 1;
        SunderException? last = null;
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            int status;
            string text;
            try
            {
                using var request = BuildRequest(method, path, jsonBody, extraHeaders, rawContent);
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

    private HttpRequestMessage BuildRequest(
        HttpMethod method, string path, string? jsonBody,
        IReadOnlyDictionary<string, string>? extraHeaders = null,
        HttpContent? rawContent = null)
    {
        var request = new HttpRequestMessage(method, _baseUrl + path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _credential);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (_userId is not null)
            request.Headers.TryAddWithoutValidation("X-Sunder-User-Id", _userId);
        if (extraHeaders is not null)
        {
            foreach (var header in extraHeaders)
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        if (rawContent is not null)
            // Pre-built content (a multipart upload) sets its own
            // Content-Type with the boundary.
            request.Content = rawContent;
        else if (jsonBody is not null)
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
            "credential_expired" => new SunderCredentialExpiredException(c, status, detail),
            "consent_denied" => new SunderConsentDeniedException(c, status, detail),
            "purpose_not_allowed" => new SunderPurposeNotAllowedException(c, status, detail),
            "unlock_required" => new SunderUnlockRequiredException(c, status, detail),
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
