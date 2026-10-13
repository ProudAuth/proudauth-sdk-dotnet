using System.Net;
using System.Text;

namespace ProudAuth.Sdk.Internal;

internal sealed record HttpResult(int Status, byte[] Body, IReadOnlyDictionary<string, string> Headers)
{
    internal string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;
}

internal sealed class HttpTransport : IDisposable
{
    private readonly HttpClient client;
    private readonly bool ownsClient;
    internal HttpTransport(HttpClient? client)
    {
        ownsClient = client is null;
        this.client = client ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None })
        { Timeout = Timeout.InfiniteTimeSpan };
    }
    internal static Uri Url(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") ||
            uri.UserInfo != "" || uri.Fragment != "") throw new ArgumentException("A credential-free HTTP(S) URL without a fragment is required.");
        return uri;
    }
    internal static string Required(string value, string name) => string.IsNullOrWhiteSpace(value) ? throw new ArgumentException($"{name} is required.") : value;
    internal static TimeSpan Positive(TimeSpan value) => value <= TimeSpan.Zero || value.TotalMilliseconds > int.MaxValue ? throw new ArgumentOutOfRangeException(nameof(value)) : value;
    internal static string Segment(string value)
    {
        Required(value, "identifier");
        if (value is "." or "..") throw new ArgumentException("Dot path segments are not identifiers.");
        return Uri.EscapeDataString(value);
    }
    internal static string Form(string value) => Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal);
    internal static string Basic(string id, string secret) => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(Form(id) + ":" + Form(secret)));
    internal static string Query(IEnumerable<KeyValuePair<string, string>> fields) => string.Join("&", fields.Select(x => Form(x.Key) + "=" + Form(x.Value)));

    internal async Task<HttpResult> SendAsync(HttpRequestMessage request, TimeSpan timeout, int limit, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(Positive(timeout));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri is Uri effectiveUri && effectiveUri != request.RequestUri) throw new HttpRequestException("Redirects are refused.");
        if (response.Content.Headers.ContentLength > limit) throw new HttpRequestException("Response exceeds size limit.");
        using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(chunk, deadline.Token).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + n > limit) throw new HttpRequestException("Response exceeds size limit.");
            buffer.Write(chunk, 0, n);
        }
        var headers = response.Headers.Concat(response.Content.Headers).ToDictionary(x => x.Key, x => string.Join(", ", x.Value), StringComparer.OrdinalIgnoreCase);
        return new((int)response.StatusCode, buffer.ToArray(), headers);
    }
    public void Dispose() { if (ownsClient) client.Dispose(); }
}
