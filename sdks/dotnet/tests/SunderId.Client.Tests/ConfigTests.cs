// Configuration tests. All tests that touch SUNDER_* environment variables
// live in this one class so xunit's per-class serialization keeps them from
// racing each other; every other test passes url/credential explicitly and
// never reads the environment.

using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace SunderId.Client.Tests;

public class ConfigTests
{
    [Fact]
    public async Task EnvVariables_AreUsedAsFallback()
    {
        Environment.SetEnvironmentVariable("SUNDER_URL", "http://env.sunder.test");
        Environment.SetEnvironmentVariable("SUNDER_CREDENTIAL", "env_client.env_secret");
        try
        {
            var handler = new FakeHandler();
            var client = new SunderClient(handler: handler);
            handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
            await client.LookupByEmailAsync("a@b.c");
            var req = Assert.Single(handler.Requests);
            Assert.Equal("Bearer env_client.env_secret", req.Authorization);
            Assert.Equal("/v1/lookup", req.PathAndQuery);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SUNDER_URL", null);
            Environment.SetEnvironmentVariable("SUNDER_CREDENTIAL", null);
        }
    }

    [Fact]
    public void MissingConfig_Throws()
    {
        Environment.SetEnvironmentVariable("SUNDER_URL", null);
        Environment.SetEnvironmentVariable("SUNDER_CREDENTIAL", null);
        Assert.Throws<ArgumentException>(() => new SunderClient());
        Assert.Throws<ArgumentException>(() => new SunderClient("http://sunder.test"));
    }

    [Fact]
    public async Task TrailingSlashes_AreTrimmedFromBaseUrl()
    {
        var handler = new FakeHandler();
        var client = new SunderClient("http://sunder.test///", "c.s", handler: handler);
        handler.Enqueue(HttpStatusCode.OK, "{\"cid\":\"CID-1\"}");
        await client.LookupByEmailAsync("a@b.c");
        Assert.Equal("/v1/lookup", handler.Requests[0].PathAndQuery);
    }
}
