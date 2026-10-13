using System.Text.Json;

namespace ProudAuth.Sdk.Internal;

internal sealed class JwksCache(HttpTransport http, string url, TimeSpan timeout, TimeSpan minRefresh, TimeProvider clock)
{
    private readonly object gate = new();
    private Dictionary<string, JsonElement> keys = new(StringComparer.Ordinal);
    private DateTimeOffset? lastFetch;
    private Task? inflight;
    private bool everLoaded;
    private int fetchCount;
    internal int FetchCount => Volatile.Read(ref fetchCount);

    internal async Task<JsonElement> KeyAsync(string kid, CancellationToken cancellationToken)
    {
        await RefreshAsync(false, cancellationToken).ConfigureAwait(false);
        lock (gate) if (keys.TryGetValue(kid, out var key)) return key;
        await RefreshAsync(true, cancellationToken).ConfigureAwait(false);
        lock (gate)
        {
            if (keys.TryGetValue(kid, out var key)) return key;
            throw new VerifierException(everLoaded ? "unknown_key" : "unavailable");
        }
    }
    private Task RefreshAsync(bool force, CancellationToken cancellationToken)
    {
        Task task;
        lock (gate)
        {
            if (inflight is not null) task = inflight;
            else
            {
                if ((!force && keys.Count > 0) || (lastFetch is not null && clock.GetUtcNow() - lastFetch < minRefresh)) return Task.CompletedTask;
                lastFetch = clock.GetUtcNow(); Interlocked.Increment(ref fetchCount);
                task = inflight = LoadAsync();
            }
        }
        return task.WaitAsync(cancellationToken);
    }
    private async Task LoadAsync()
    {
        await Task.Yield(); // Publish the shared task before it can complete, including synchronous test transports.
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/jwk-set+json");
            var response = await http.SendAsync(request, timeout, 1 << 20, CancellationToken.None).ConfigureAwait(false);
            if (response.Status != 200) throw new VerifierException("unavailable");
            var p = Json.Object(response.Body);
            if (p.Get("keys").ValueKind != JsonValueKind.Array) throw new VerifierException("unavailable");
            var next = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            var duplicate = new HashSet<string>(StringComparer.Ordinal);
            foreach (var k in p.Get("keys").EnumerateArray())
            {
                if (!Jose.Usable(k)) continue;
                var kid = k.Str("kid");
                if (!next.TryAdd(kid, k)) duplicate.Add(kid);
            }
            foreach (var kid in duplicate) next.Remove(kid); // Ambiguous identifiers never select a key.
            lock (gate) { keys = next; everLoaded = true; }
        }
        catch { /* Keep known keys on fetch failure. Initial failures still deny access. */ }
        finally { lock (gate) inflight = null; }
    }
}
