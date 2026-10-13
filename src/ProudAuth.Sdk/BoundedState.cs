using System.Globalization;
using System.Text.Json;
using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

public sealed record BoundedStateOptions
{
    public required string BaseUrl { get; init; }
    public required string Realm { get; init; }
    public required Func<CancellationToken, Task<string>> Token { get; init; }
    public required TimeSpan MaxStaleness { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    public HttpClient? HttpClient { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>Replays session events, preserving revocations across restarts and cursor expiry (SES-019).</summary>
public sealed class BoundedState : IDisposable
{
    private readonly BoundedStateOptions options;
    private readonly HttpTransport http;
    private readonly string endpoint;
    private readonly SemaphoreSlim syncGate = new(1);
    private readonly object gate = new();
    private string cursor = "";
    private DateTimeOffset? synced;
    private readonly Dictionary<string, DateTimeOffset> sessions = new(), subjects = new(), orgs = new();
    private readonly Dictionary<(string, string), DateTimeOffset> members = new();
    private static readonly HashSet<string> SubjectEvents = ["user.suspended", "user.locked", "user.deleted", "user.password_reset", "security.refresh_reuse_detected", "security.credential_compromised"];
    private static readonly HashSet<string> OrgEvents = ["organization.suspended", "organization.deleted", "organization.archived"];
    private static readonly HashSet<string> MemberEvents = ["organization.membership.removed", "organization.membership.suspended", "authorization.role.unassigned"];
    public BoundedState(BoundedStateOptions options)
    {
        HttpTransport.Url(options.BaseUrl); HttpTransport.Positive(options.MaxStaleness); HttpTransport.Positive(options.Timeout);
        ArgumentNullException.ThrowIfNull(options.Token);
        endpoint = options.BaseUrl.TrimEnd('/') + "/api/v1/realms/" + HttpTransport.Segment(options.Realm) + "/session-events";
        this.options = options; http = new(options.HttpClient);
    }
    private async Task<JsonElement> GetAsync(Dictionary<string, string> query, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.Timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint + "?" + HttpTransport.Query(query));
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + await options.Token(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false));
            var response = await http.SendAsync(request, options.Timeout, 4 << 20, deadline.Token).ConfigureAwait(false);
            if (response.Status == 410) throw new CursorExpiredException();
            if (response.Status != 200) throw new VerifierException("unavailable");
            var p = Json.Object(response.Body);
            if (p.Get("next_cursor").ValueKind != JsonValueKind.String ||
                (p.Has("events") && p.Get("events").ValueKind is not (JsonValueKind.Array or JsonValueKind.Null))) throw new VerifierException("unavailable");
            return p;
        }
        catch (CursorExpiredException) { throw; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new VerifierException("unavailable"); }
    }
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await syncGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var p = await GetAsync(new() { ["from"] = "now" }, cancellationToken).ConfigureAwait(false);
            lock (gate) { cursor = p.Str("next_cursor"); synced = options.TimeProvider.GetUtcNow(); }
        }
        finally { syncGate.Release(); }
    }
    public async Task SyncAsync(int waitSeconds = 0, CancellationToken cancellationToken = default)
    {
        if (waitSeconds < 0 || waitSeconds > 25) throw new ArgumentOutOfRangeException(nameof(waitSeconds));
        await syncGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            for (var i = 0; i < 100; i++)
            {
                string position; lock (gate) position = cursor;
                var query = new Dictionary<string, string> { ["cursor"] = position, ["limit"] = "500" };
                if (i == 0 && waitSeconds > 0) query["wait"] = waitSeconds.ToString(CultureInfo.InvariantCulture);
                JsonElement p;
                try { p = await GetAsync(query, cancellationToken).ConfigureAwait(false); }
                catch (CursorExpiredException) { lock (gate) cursor = ""; throw; }
                var events = p.Get("events").ValueKind == JsonValueKind.Array ? p.Get("events").EnumerateArray().ToArray() : [];
                lock (gate)
                {
                    foreach (var ev in events) Apply(ev);
                    cursor = p.Str("next_cursor");
                    if (events.Length < 500) { synced = options.TimeProvider.GetUtcNow(); return; }
                }
            }
        }
        catch (VerifierException) { throw new VerifierException("unavailable"); }
        finally { syncGate.Release(); }
    }
    private static void Revoke<TKey>(Dictionary<TKey, DateTimeOffset> map, TKey key, DateTimeOffset at) where TKey : notnull
    { if (!map.TryGetValue(key, out var previous) || at > previous) map[key] = at; }
    private void Apply(JsonElement ev)
    {
        if (!DateTimeOffset.TryParse(ev.Str("occurred_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at))
            throw new VerifierException("unavailable");
        var data = ev.Get("data"); var type = ev.Str("event_type"); var user = data.Str("user_id");
        if (type is "authorization.role.unassigned" or "security.refresh_reuse_detected")
        { var subject = data.Str("subject_id"); user = subject.StartsWith("usr_", StringComparison.Ordinal) ? subject : ""; }
        var org = ev.Str("organization_id");
        if (type == "session.revoked" && data.Str("session_id") != "") Revoke(sessions, data.Str("session_id"), at);
        else if (SubjectEvents.Contains(type) && user != "") Revoke(subjects, user, at);
        else if (OrgEvents.Contains(type))
        { var id = data.Str("organization_id"); if (id == "") id = org; if (id != "") Revoke(orgs, id, at); }
        else if (MemberEvents.Contains(type) && user != "" && org != "") Revoke(members, (user, org), at);
    }
    public void Check(Claims claims)
    {
        lock (gate)
        {
            if (synced is null || options.TimeProvider.GetUtcNow() - synced > options.MaxStaleness) throw new VerifierException("stale_state");
            var issued = claims.IssuedAt ?? DateTimeOffset.MinValue;
            if (sessions.ContainsKey(claims.SessionId) || (subjects.TryGetValue(claims.Subject, out var sub) && issued <= sub) ||
                (orgs.TryGetValue(claims.OrgId, out var org) && issued <= org) ||
                (members.TryGetValue((claims.Subject, claims.OrgId), out var member) && issued <= member)) throw new VerifierException("revoked");
        }
    }
    public async Task RunAsync(CancellationToken cancellationToken, Action<Exception>? onError = null)
    {
        var backoff = 1000; var resyncing = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            try { await SyncAsync(20, cancellationToken).ConfigureAwait(false); backoff = 1000; resyncing = false; }
            catch (Exception e)
            {
                if (cancellationToken.IsCancellationRequested) return;
                try { onError?.Invoke(e); } catch { }
                if (e is CursorExpiredException && !resyncing) { resyncing = true; continue; }
                try { await Task.Delay(backoff, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                backoff = Math.Min(backoff * 2, 30000);
            }
        }
    }
    public void Dispose() => http.Dispose();
}

public sealed class BoundedVerifier(IAuthenticator verifier, BoundedState state) : IAuthenticator
{
    public async Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default)
    {
        var claims = await verifier.AuthenticateAsync(token, cancellationToken).ConfigureAwait(false);
        state.Check(claims); return claims;
    }
}
