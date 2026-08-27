// The routes beyond the core handoff surface: consent, data-subject rights,
// value tokenization, the file vault, shares, links, version history,
// external claims and the admin unlock.
//
// Each test asserts the wire contract and the properties a client can get
// wrong: an empty cascade must not be sent as an opt-in, bulk routes must
// carry the unlock token, and destructive calls are never blind-retried.

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace SunderId.Client.Tests;

public class SunderApiTests
{
    private static (SunderClient Client, FakeHandler Handler) NewClient(string? userId = null)
    {
        var handler = new FakeHandler();
        var client = new SunderClient("http://sunder.test", "client_id.secret",
            handler: handler, userId: userId);
        return (client, handler);
    }

    // -- consent -------------------------------------------------------------

    [Fact]
    public async Task SetConsent_SendsARealBoolean()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID1\",\"purpose\":\"billing\",\"granted\":false}");
        var res = await client.SetConsentAsync("CID1", "billing", false);
        Assert.False(res.GetProperty("granted").GetBoolean());
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/v1/consent", req.PathAndQuery);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal(JsonValueKind.False, doc.RootElement.GetProperty("granted").ValueKind);
    }

    [Fact]
    public async Task GetConsent_ListsRecordedPurposes()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"consents\":[{\"purpose\":\"billing\",\"granted\":true}]}");
        var res = await client.GetConsentAsync("CID1");
        Assert.Equal(1, res.GetProperty("consents").GetArrayLength());
        Assert.Equal("/v1/consent/CID1", Assert.Single(handler.Requests).PathAndQuery);
    }

    // -- data subject rights --------------------------------------------------

    [Fact]
    public async Task DsrAccess_CarriesHoldingsBeyondTheBlob()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK,
            "{\"scopes\":[{\"scope\":\"crm\",\"cid\":\"CID1\"," +
            "\"value_tokens\":[{\"token\":\"tok_1\"}]," +
            "\"files\":[{\"id\":\"f1\"}]," +
            "\"shares\":[{\"uuid\":\"u1\",\"partner_label\":\"partner-bank\"}]," +
            "\"links\":[{\"cid\":\"CID2\",\"link_type\":\"guardian\"}]}]," +
            "\"audit_trail\":[{\"ts\":\"2026-01-01T00:00:00Z\",\"client_id\":\"crm\"," +
            "\"action\":\"lookup\",\"count\":3}]}");
        var res = await client.DsrAccessAsync("CID1");
        var scope = res.GetProperty("scopes")[0];
        foreach (var section in new[] { "value_tokens", "files", "shares", "links" })
            Assert.Equal(1, scope.GetProperty(section).GetArrayLength());
        // The share's recipient label IS the Article 15 answer.
        Assert.Equal("partner-bank",
            scope.GetProperty("shares")[0].GetProperty("partner_label").GetString());
        Assert.Equal("/v1/dsr/access?cid=CID1", Assert.Single(handler.Requests).PathAndQuery);
    }

    [Fact]
    public async Task DsrExport_IsCallerScopeOnly()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"scope\":\"crm\",\"cid\":\"CID1\"}");
        var res = await client.DsrExportAsync("CID1");
        Assert.Equal("crm", res.GetProperty("scope").GetString());
        Assert.Equal("/v1/dsr/export?cid=CID1", Assert.Single(handler.Requests).PathAndQuery);
    }

    [Fact]
    public async Task DsrErase_OmitsCascadeWhenNoneRequested()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK,
            "{\"erasure_id\":7,\"scopes\":2,\"linked\":[{\"cid\":\"CID2\",\"link_type\":\"guardian\",\"cascaded\":false}]}");
        var res = await client.DsrEraseAsync("CID1");
        Assert.Equal(7, res.GetProperty("erasure_id").GetInt64());
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.False(doc.RootElement.TryGetProperty("cascade", out _),
            "no cascade was requested, so the key must be absent from the body");
    }

    [Fact]
    public async Task DsrErase_ForwardsNamedLinkTypes()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"erasure_id\":8,\"scopes\":1}");
        await client.DsrEraseAsync("CID1", new[] { "guardian" });
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.Equal("guardian", doc.RootElement.GetProperty("cascade")[0].GetString());
    }

    [Fact]
    public async Task DsrErase_SendsNoCascadeForAnEmptyList()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"erasure_id\":9,\"scopes\":1}");
        await client.DsrEraseAsync("CID1", Array.Empty<string>());
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.False(doc.RootElement.TryGetProperty("cascade", out _));
    }

    [Fact]
    public async Task DsrErase_IsNeverRetried()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "{\"error\":\"service_unavailable\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.DsrEraseAsync("CID1"));
        Assert.Single(handler.Requests); // destructive: exactly one attempt
    }

    // -- value tokenization ----------------------------------------------------

    [Fact]
    public async Task Tokenize_OmitsAnUnsetCid()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"token\":\"tok_abc\"}");
        var token = await client.TokenizeAsync("4111111111111111",
            new Dictionary<string, object> { ["type"] = "card", ["unique"] = true });
        Assert.Equal("tok_abc", token);
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.False(doc.RootElement.TryGetProperty("cid", out _),
            "an unset cid must be omitted, not sent empty");
        Assert.True(doc.RootElement.GetProperty("unique").GetBoolean());
    }

    [Fact]
    public async Task DetokenizeAndDelete()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"value\":\"secret\"}");
        Assert.Equal("secret", await client.DetokenizeAsync("tok_1"));
        handler.Enqueue(HttpStatusCode.OK, "{\"status\":\"deleted\"}");
        await client.DeleteTokenAsync("tok_1");
        Assert.Equal("DELETE", handler.Requests[1].Method);
    }

    [Fact]
    public async Task DeleteToken_IsNotRetried()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "{\"error\":\"service_unavailable\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.DeleteTokenAsync("tok_1"));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task BulkRoutes_CarryTheUnlockToken()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"tokens\":[\"t1\",\"t2\"]}");
        var res = await client.TokenizeBulkAsync("unlock_xyz", new[]
        {
            new Dictionary<string, object> { ["value"] = "a" },
            new Dictionary<string, object> { ["value"] = "b" },
        });
        Assert.Equal(2, res.GetProperty("tokens").GetArrayLength());
        Assert.Equal("unlock_xyz", Assert.Single(handler.Requests).Headers["X-Sunder-Unlock"]);
    }

    [Fact]
    public async Task BulkRead_IsNotRetried()
    {
        // The unlock token is spent by the first attempt: a retry would come
        // back already-used and hide whether the batch landed.
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "{\"error\":\"service_unavailable\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.DetokenizeBulkAsync("unlock_xyz", new[] { "t1" }));
        Assert.Single(handler.Requests);
    }

    // -- file vault --------------------------------------------------------------

    [Fact]
    public async Task UploadFile_SendsMultipartWithFilenameAndExpiry()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"id\":\"f1\",\"sha256\":\"deadbeef\"}");
        var meta = await client.UploadFileAsync("CID1", "scan.pdf",
            Encoding.UTF8.GetBytes("hello"), "application/pdf", "2030-01-02T03:04:05Z");
        Assert.Equal("deadbeef", meta.GetProperty("sha256").GetString());
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/v1/contacts/CID1/files", req.PathAndQuery);
        Assert.StartsWith("multipart/form-data", req.ContentType);
        Assert.Contains("scan.pdf", req.Body);
        Assert.Contains("hello", req.Body);
        Assert.Equal("2030-01-02T03:04:05Z", req.Headers["X-Sunder-File-Expiry"]);
    }

    [Fact]
    public async Task UploadFile_OmitsTheExpiryHeaderWhenNull()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"id\":\"f1\"}");
        await client.UploadFileAsync("CID1", "a.txt", Encoding.UTF8.GetBytes("x"));
        Assert.False(Assert.Single(handler.Requests).Headers.ContainsKey("X-Sunder-File-Expiry"));
    }

    [Fact]
    public async Task ListFiles_SendsThePurpose()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"files\":[{\"id\":\"f1\"}]}");
        var res = await client.ListFilesAsync("CID1", "support");
        Assert.Equal(1, res.GetProperty("files").GetArrayLength());
        Assert.Equal("/v1/contacts/CID1/files?purpose=support",
            Assert.Single(handler.Requests).PathAndQuery);
    }

    [Fact]
    public async Task DownloadFile_ReturnsBytes()
    {
        var (client, handler) = NewClient();
        handler.EnqueueBytes(HttpStatusCode.OK, Encoding.UTF8.GetBytes("raw-bytes"));
        var bytes = await client.DownloadFileAsync("f1", "support");
        Assert.Equal("raw-bytes", Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public async Task DownloadFile_MapsErrorsInsteadOfReturningABody()
    {
        // A 404 must not reach the caller as the bytes of an error page.
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.NotFound, "{\"error\":\"not_found\"}");
        await Assert.ThrowsAsync<SunderNotFoundException>(
            () => client.DownloadFileAsync("missing", "support"));
    }

    // -- shares, links, versions ----------------------------------------------------

    [Fact]
    public async Task CreateShare_SendsThePartnerLabel()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"uuid\":\"u1\"}");
        var res = await client.CreateShareAsync("CID1", new[] { "email" },
            new Dictionary<string, object> { ["partner_label"] = "partner-bank" });
        Assert.Equal("u1", res.GetProperty("uuid").GetString());
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.Equal("partner-bank", doc.RootElement.GetProperty("partner_label").GetString());
    }

    [Fact]
    public async Task FetchAndRevokeShare()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"fields\":{\"email\":\"a@b.c\"}}");
        var res = await client.FetchShareAsync("u1");
        Assert.Equal("a@b.c", res.GetProperty("fields").GetProperty("email").GetString());
        handler.Enqueue(HttpStatusCode.OK, "{\"status\":\"revoked\"}");
        await client.RevokeShareAsync("u1");
        Assert.Equal("DELETE", handler.Requests[1].Method);
    }

    [Fact]
    public async Task Links_RoundTrip()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"status\":\"linked\"}");
        await client.LinkAsync("PARENT", "CHILD", "guardian");
        using (var doc = JsonDocument.Parse(handler.Requests[0].Body!))
            Assert.Equal("guardian", doc.RootElement.GetProperty("link_type").GetString());

        handler.Enqueue(HttpStatusCode.OK,
            "{\"links\":[{\"cid\":\"CHILD\",\"link_type\":\"guardian\",\"role\":\"parent\"}]}");
        var links = await client.ListLinksAsync("PARENT");
        Assert.Equal("parent", links.GetProperty("links")[0].GetProperty("role").GetString());

        handler.Enqueue(HttpStatusCode.OK, "{\"status\":\"unlinked\"}");
        await client.UnlinkAsync("PARENT", "CHILD");
        Assert.Equal("DELETE", handler.Requests[2].Method);
    }

    [Fact]
    public async Task HistoricalRead_StillSendsThePurpose()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"versions\":[{\"version_no\":2}]}");
        var versions = await client.ListVersionsAsync("CID1");
        Assert.Equal(2, versions.GetProperty("versions")[0].GetProperty("version_no").GetInt64());

        handler.Enqueue(HttpStatusCode.OK, "{\"value\":\"old@example.com\"}");
        var value = await client.GetVersionAttributeAsync("CID1", 2, "email", "support");
        Assert.Equal("old@example.com", value);
        // An old value is not a lesser secret.
        Assert.Equal("/v1/contacts/CID1/versions/2/attributes/email?purpose=support",
            handler.Requests[1].PathAndQuery);
    }

    // -- claims, unlock, attribution -------------------------------------------------

    [Fact]
    public async Task ExternalClaim_KeepsIssuerProvenance()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"stored\":[\"verified_age@gov-id\"]}");
        var res = await client.StoreExternalClaimAsync("CID1", "eyJ...envelope");
        Assert.Contains("@", res.GetProperty("stored")[0].GetString());
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.Equal("eyJ...envelope", doc.RootElement.GetProperty("envelope").GetString());
    }

    [Fact]
    public async Task Unlock_MintsASingleUseToken()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created,
            "{\"unlock_token\":\"unlock_xyz\",\"expires_at\":\"2026-01-01T00:01:00Z\"}");
        var res = await client.UnlockAsync("tokens");
        Assert.Equal("unlock_xyz", res.GetProperty("unlock_token").GetString());
        using var doc = JsonDocument.Parse(Assert.Single(handler.Requests).Body!);
        Assert.Equal("tokens", doc.RootElement.GetProperty("purpose").GetString());
    }

    [Fact]
    public async Task UserId_IsSentOnEveryCall()
    {
        var (client, handler) = NewClient(userId: "agent-7");
        handler.Enqueue(HttpStatusCode.OK, "{\"value\":\"a@b.c\"}");
        await client.GetAttributeAsync("CID1", "email", "support");
        Assert.Equal("agent-7", Assert.Single(handler.Requests).Headers["X-Sunder-User-Id"]);
    }
}
