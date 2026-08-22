// Fake HttpMessageHandler: replays queued responses and records every request
// it serves. No sockets involved — HttpClient never connects anywhere.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SunderId.Client.Tests;

internal sealed record RecordedRequest(
    string Method,
    string PathAndQuery,
    string? Authorization,
    string? ContentType,
    string? Body);

internal sealed class FakeHandler : HttpMessageHandler
{
    public List<RecordedRequest> Requests { get; } = new();

    private readonly Queue<Func<HttpResponseMessage>> _responses = new();

    public void Enqueue(HttpStatusCode status, string body, string contentType = "application/json")
    {
        _responses.Enqueue(() => new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType),
        });
    }

    public void EnqueueNetworkFailure()
        => _responses.Enqueue(() => throw new HttpRequestException("simulated network failure"));

    public void EnqueueTimeout()
        => _responses.Enqueue(() => throw new TaskCanceledException("simulated timeout"));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string? body = null;
        if (request.Content is not null)
            body = await request.Content.ReadAsStringAsync(cancellationToken);
        string? auth = request.Headers.TryGetValues("Authorization", out var values)
            ? string.Join(" ", values)
            : null;
        Requests.Add(new RecordedRequest(
            request.Method.Method,
            request.RequestUri!.PathAndQuery,
            auth,
            request.Content?.Headers.ContentType?.MediaType,
            body));
        if (_responses.Count == 0)
        {
            return new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("{\"error\":\"internal\"}", Encoding.UTF8, "application/json"),
            };
        }
        return _responses.Dequeue()();
    }
}
