// Tests for the Sunder .NET SDK against a fake HttpMessageHandler.
// Mirrors the Python/TypeScript SDK test suites: success paths with request
// assertions, full error mapping, retry policy with exact attempt counts.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace SunderId.Client.Tests;

public class SunderClientTests
{
    private static (SunderClient Client, FakeHandler Handler) NewClient()
    {
        var handler = new FakeHandler();
        var client = new SunderClient("http://sunder.test", "client_id.secret", handler: handler);
        return (client, handler);
    }

    // -- success paths -----------------------------------------------------

    [Fact]
    public async Task RegisterContact_SendsBodyAndParsesCid()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"cid\":\"CID-1\"}");
        var cid = await client.RegisterContactAsync(
            new ContactAttributes { Email = "a@b.c", Name = "A B" });
        Assert.Equal("CID-1", cid);
        var req = Assert.Single(handler.Requests);
        Assert.Equal("POST", req.Method);
        Assert.Equal("/v1/contacts", req.PathAndQuery);
        Assert.Equal("Bearer client_id.secret", req.Authorization);
        Assert.Equal("application/json", req.ContentType);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal("a@b.c", doc.RootElement.GetProperty("email").GetString());
        Assert.Equal("A B", doc.RootElement.GetProperty("name").GetString());
        // Null properties must be omitted entirely.
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task RegisterContact_SerializesAllFieldsWithApiNames()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created, "{\"cid\":\"CID-1\"}");
        await client.RegisterContactAsync(new ContactAttributes
        {
            Email = "a@b.c",
            Emails = new List<string> { "b@c.d" },
            Phone = "+385911234567",
            Phones = new List<string> { "+385911111111" },
            Name = "A B",
            Attributes = new Dictionary<string, string> { ["loyalty_tier"] = "gold" },
        });
        using var doc = JsonDocument.Parse(handler.Requests[0].Body!);
        var root = doc.RootElement;
        Assert.Equal("a@b.c", root.GetProperty("email").GetString());
        Assert.Equal("b@c.d", root.GetProperty("emails")[0].GetString());
        Assert.Equal("+385911234567", root.GetProperty("phone").GetString());
        Assert.Equal("+385911111111", root.GetProperty("phones")[0].GetString());
        Assert.Equal("A B", root.GetProperty("name").GetString());
        Assert.Equal("gold", root.GetProperty("attributes").GetProperty("loyalty_tier").GetString());
        Assert.Equal(6, root.EnumerateObject().Count());
    }

    [Fact]
    public async Task IssueScopedCid_PostsToScopesPath()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-billing\"}");
        var cid = await client.IssueScopedCidAsync("CID-1", "billing");
        Assert.Equal("CID-billing", cid);
        var req = Assert.Single(handler.Requests);
        Assert.Equal("POST", req.Method);
        Assert.Equal("/v1/contacts/CID-1/scopes", req.PathAndQuery);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal("billing", doc.RootElement.GetProperty("scope").GetString());
        Assert.Equal(1, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task LookupByEmail_SendsSingleKeyBody()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByEmailAsync("a@b.c"));
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/v1/lookup", req.PathAndQuery);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal("a@b.c", doc.RootElement.GetProperty("email").GetString());
        Assert.Equal(1, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task LookupByPhone_SendsSingleKeyBody()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByPhoneAsync("+385911234567"));
        using var doc = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal("+385911234567", doc.RootElement.GetProperty("phone").GetString());
        Assert.Equal(1, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task LookupByName_WithEmailSecondFactor()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByNameAsync("A B", email: "a@b.c"));
        using var doc = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal("A B", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("a@b.c", doc.RootElement.GetProperty("email").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task LookupByName_WithPhoneSecondFactor()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByNameAsync("A B", phone: "+385911234567"));
        using var doc = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal("A B", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("+385911234567", doc.RootElement.GetProperty("phone").GetString());
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task LookupByName_RequiresSecondFactorLocally()
    {
        var (client, handler) = NewClient();
        var ex = await Assert.ThrowsAsync<SunderValidationException>(
            () => client.LookupByNameAsync("A B"));
        Assert.Equal("validation", ex.Code);
        Assert.Null(ex.Status);
        Assert.Empty(handler.Requests); // rejected before any request
    }

    [Fact]
    public async Task GetAttribute_UsesGetWithPurposeQuery()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"value\":\"gold\"}");
        var value = await client.GetAttributeAsync("CID-1", "loyalty_tier", "support");
        Assert.Equal("gold", value);
        var req = Assert.Single(handler.Requests);
        Assert.Equal("GET", req.Method);
        Assert.Equal("/v1/contacts/CID-1/attributes/loyalty_tier?purpose=support", req.PathAndQuery);
        Assert.Null(req.Body);
    }

    [Fact]
    public async Task IssueOti_ParsesTokenAndExpiry()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.Created,
            "{\"token\":\"v4.public.x\",\"expires_at\":\"2026-01-01T00:00:00Z\"}");
        var oti = await client.IssueOtiAsync("CID-1", "create_order", "erp");
        Assert.Equal("v4.public.x", oti.Token);
        Assert.Equal("2026-01-01T00:00:00Z", oti.ExpiresAt);
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/v1/oti", req.PathAndQuery);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal("CID-1", doc.RootElement.GetProperty("cid").GetString());
        Assert.Equal("create_order", doc.RootElement.GetProperty("purpose").GetString());
        Assert.Equal("erp", doc.RootElement.GetProperty("audience").GetString());
    }

    [Fact]
    public async Task VerifyOti_ReturnsVerifierScopedCid()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-erp\"}");
        var cid = await client.VerifyOtiAsync("v4.public.x", "create_order", "erp");
        Assert.Equal("CID-erp", cid);
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/v1/oti/verify", req.PathAndQuery);
        using var doc = JsonDocument.Parse(req.Body!);
        Assert.Equal("v4.public.x", doc.RootElement.GetProperty("token").GetString());
    }

    [Fact]
    public async Task Health_ReturnsBodyText()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.OK, "ok", "text/plain");
        Assert.Equal("ok", await client.HealthAsync());
        var req = Assert.Single(handler.Requests);
        Assert.Equal("/healthz", req.PathAndQuery);
        Assert.Null(req.Authorization); // healthz needs no auth
    }

    [Fact]
    public async Task Health_MapsErrorsAndNetworkFailures()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "db unavailable", "text/plain");
        var ex = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.HealthAsync());
        Assert.Equal(503, ex.Status);

        handler.EnqueueNetworkFailure();
        var netEx = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.HealthAsync());
        Assert.Equal("service_unavailable", netEx.Code);
        Assert.Null(netEx.Status);
    }

    // -- error mapping -------------------------------------------------------

    [Theory]
    [InlineData(401, "unauthorized", typeof(SunderUnauthorizedException))]
    [InlineData(403, "forbidden", typeof(SunderForbiddenException))]
    [InlineData(403, "purpose_not_allowed", typeof(SunderPurposeNotAllowedException))]
    [InlineData(403, "audience_mismatch", typeof(SunderAudienceMismatchException))]
    [InlineData(404, "not_found", typeof(SunderNotFoundException))]
    [InlineData(400, "validation", typeof(SunderValidationException))]
    [InlineData(400, "bad_json", typeof(SunderValidationException))]
    [InlineData(400, "token_invalid", typeof(SunderTokenInvalidException))]
    [InlineData(409, "token_used", typeof(SunderTokenUsedException))]
    [InlineData(410, "token_expired", typeof(SunderTokenExpiredException))]
    [InlineData(429, "rate_limited", typeof(SunderRateLimitedException))]
    [InlineData(500, "internal", typeof(SunderServiceUnavailableException))]
    public async Task ErrorMapping_CodeFieldDecidesFirst(int status, string code, Type exceptionType)
    {
        var (client, handler) = NewClient();
        handler.Enqueue((HttpStatusCode)status, "{\"error\":\"" + code + "\"}");
        var ex = await Assert.ThrowsAnyAsync<SunderException>(
            () => client.VerifyOtiAsync("t", "p", "a"));
        Assert.IsType(exceptionType, ex);
        Assert.Equal(code, ex.Code);
        Assert.Equal(status, ex.Status);
    }

    [Fact]
    public async Task ErrorMapping_FallsBackToStatusWhenBodyNotJson()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.NotFound, "", "text/plain");
        var ex = await Assert.ThrowsAsync<SunderNotFoundException>(
            () => client.VerifyOtiAsync("t", "p", "a"));
        Assert.Equal("http_404", ex.Code);
        Assert.Equal(404, ex.Status);
    }

    [Fact]
    public async Task ErrorMapping_NonJson5xxIsServiceUnavailable()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "Service Unavailable", "text/plain");
        var ex = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.VerifyOtiAsync("t", "p", "a"));
        Assert.Equal("service_unavailable", ex.Code);
        Assert.Equal(503, ex.Status);
    }

    [Fact]
    public async Task ErrorMapping_UnknownStatusIsBaseException()
    {
        var (client, handler) = NewClient();
        handler.Enqueue((HttpStatusCode)418, "{}");
        var ex = await Assert.ThrowsAnyAsync<SunderException>(
            () => client.VerifyOtiAsync("t", "p", "a"));
        Assert.Equal(typeof(SunderException), ex.GetType());
        Assert.Equal("http_418", ex.Code);
    }

    [Fact]
    public async Task ErrorMapping_PreservesDetail()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.BadRequest,
            "{\"error\":\"validation\",\"detail\":\"name alone is rejected\"}");
        var ex = await Assert.ThrowsAsync<SunderValidationException>(
            () => client.LookupByNameAsync("A B", email: "x@y.z"));
        Assert.Equal("name alone is rejected", ex.Detail);
    }

    [Fact]
    public async Task Errors_AreAllSunderExceptions()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.NotFound, "{\"error\":\"not_found\"}");
        await Assert.ThrowsAnyAsync<SunderException>(() => client.LookupByEmailAsync("a@b.c"));
    }

    // -- retry policy -------------------------------------------------------

    [Fact]
    public async Task Lookup_RetriesOnceOn5xxThenSucceeds()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.InternalServerError, "{\"error\":\"internal\"}");
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByEmailAsync("a@b.c"));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task IssueOti_RetriesOnceThenGivesUp()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "{\"error\":\"internal\"}");
        handler.Enqueue(HttpStatusCode.ServiceUnavailable, "{\"error\":\"internal\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.IssueOtiAsync("CID-1", "p", "erp"));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task VerifyOti_NeverRetriesOn5xx()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.InternalServerError, "{\"error\":\"internal\"}");
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-erp\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.VerifyOtiAsync("t", "p", "erp"));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task VerifyOti_NeverRetriesOnNetworkFailure()
    {
        var (client, handler) = NewClient();
        handler.EnqueueNetworkFailure();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-erp\"}");
        var ex = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.VerifyOtiAsync("t", "p", "erp"));
        Assert.Equal("service_unavailable", ex.Code);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task RegisterContact_DoesNotRetryOn5xx()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.InternalServerError, "{\"error\":\"internal\"}");
        handler.Enqueue(HttpStatusCode.Created, "{\"cid\":\"CID-1\"}");
        await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.RegisterContactAsync(new ContactAttributes { Email = "a@b.c" }));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Lookup_DoesNotRetryOn4xx()
    {
        var (client, handler) = NewClient();
        handler.Enqueue(HttpStatusCode.NotFound, "{\"error\":\"not_found\"}");
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        await Assert.ThrowsAsync<SunderNotFoundException>(
            () => client.LookupByEmailAsync("a@b.c"));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Lookup_RetriesOnceOnNetworkFailureThenSucceeds()
    {
        var (client, handler) = NewClient();
        handler.EnqueueNetworkFailure();
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        Assert.Equal("CID-1", await client.LookupByEmailAsync("a@b.c"));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Lookup_GivesUpAfterTwoNetworkFailures()
    {
        var (client, handler) = NewClient();
        handler.EnqueueNetworkFailure();
        handler.EnqueueNetworkFailure();
        var ex = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.LookupByEmailAsync("a@b.c"));
        Assert.Equal("service_unavailable", ex.Code);
        Assert.Null(ex.Status);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Timeout_MapsToServiceUnavailable()
    {
        var (client, handler) = NewClient();
        handler.EnqueueTimeout();
        var ex = await Assert.ThrowsAsync<SunderServiceUnavailableException>(
            () => client.VerifyOtiAsync("t", "p", "a"));
        Assert.Equal("service_unavailable", ex.Code);
        Assert.Null(ex.Status);
        Assert.Single(handler.Requests);
    }
}
