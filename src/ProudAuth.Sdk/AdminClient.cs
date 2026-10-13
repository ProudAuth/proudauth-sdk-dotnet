using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

[JsonConverter(typeof(SecretConverter))]
[DebuggerDisplay("[REDACTED]")]
public sealed class Secret(string value)
{
    private readonly string value = value;
    public string Reveal() => value;
    public override string ToString() => "[REDACTED]";
}
public sealed class SecretConverter : JsonConverter<Secret>
{
    public override Secret Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => new(reader.GetString() ?? "");
    public override void Write(Utf8JsonWriter writer, Secret value, JsonSerializerOptions options) => writer.WriteStringValue("[REDACTED]");
}

/// <summary>JSON object whose secret-bearing values are Secret instances at every depth.</summary>
public sealed class AdminObject : ReadOnlyDictionary<string, object?>
{
    internal AdminObject(IDictionary<string, object?> values) : base(values) { }
    public string String(string name) => TryGetValue(name, out var v) && v is string s ? s : "";
    public long Integer(string name) => TryGetValue(name, out var v) && v is long n ? n : 0;
    public IReadOnlyList<object?> Array(string name) => TryGetValue(name, out var v) && v is IReadOnlyList<object?> a ? a : System.Array.Empty<object?>();
}

public sealed class ProblemException : Exception
{
    public int Status { get; }
    public string Code { get; }
    public string Title { get; }
    public string Detail { get; }
    public string Type { get; }
    public string Instance { get; }
    public string RequestId { get; }
    public AdminObject Extra { get; }
    public AdminObject? Errors { get; }
    public IReadOnlyDictionary<string, string> Headers { get; }
    internal ProblemException(int status, AdminObject body, IReadOnlyDictionary<string, string> headers) : base($"admin: HTTP {status}")
    {
        Status = status; Code = body.String("code"); Title = body.String("title"); Detail = body.String("detail");
        Type = body.String("type"); Instance = body.String("instance"); Extra = body;
        Errors = body.TryGetValue("errors", out var e) ? e as AdminObject : null;
        RequestId = body.String("request_id"); if (RequestId == "" && headers.TryGetValue("X-Request-ID", out var id)) RequestId = id;
        Headers = headers;
    }
}

public sealed record AdminResponse<T>(int Status, IReadOnlyDictionary<string, string> Headers, string? ETag,
    string? Deprecation, string? Sunset, T Data);
public sealed record Page<T>(IReadOnlyList<T> Items, string NextCursor);
public sealed record DeprecationNotice(string Method, string Path, string Deprecation, string? Sunset);
public sealed record RequestOptions
{
    public string? IdempotencyKey { get; init; }
    public string? IfMatch { get; init; }
    public TimeSpan? Timeout { get; init; }
}
public sealed record AdminClientOptions
{
    public required string BaseUrl { get; init; }
    public required string Realm { get; init; }
    public Func<CancellationToken, Task<string>>? Token { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    public int MaxResponseBytes { get; init; } = 32 << 20;
    public string? UserAgent { get; init; }
    public Action<DeprecationNotice>? OnDeprecated { get; init; }
    public HttpClient? HttpClient { get; init; }
}
public sealed record User(string Id, string State, string DisplayName, long Version, AdminObject Data)
{
    internal static User From(AdminObject o) => new(o.String("id"), o.String("state"), o.String("display_name"), o.Integer("version"), o);
}
public sealed record Organization(string Id, string Slug, string DisplayName, string State, long Version, AdminObject Data)
{
    internal static Organization From(AdminObject o) => new(o.String("id"), o.String("slug"), o.String("display_name"), o.String("state"), o.Integer("version"), o);
}

/// <summary>Realm-scoped administration APIs, cursor pages, problems, deadlines and redacted one-time secrets (SDK-003/007).</summary>
public sealed class AdminClient : IDisposable
{
    public const string SdkVersion = "0.2.0";
    private readonly AdminClientOptions options;
    private readonly string endpoint;
    private readonly HttpTransport http;
    private static readonly HashSet<string> SecretMembers = ["client_secret", "client_secrets", "api_key", "signing_secret", "setup_token", "recovery_codes", "invitation_secret", "access_token", "refresh_token", "id_token", "handoff_code", "download_token", "token", "secret", "webhook_secrets"];
    public AdminClient(AdminClientOptions options)
    {
        var url = HttpTransport.Url(options.BaseUrl);
        if (url.Query != "") throw new ArgumentException("Base URL must not have a query.");
        HttpTransport.Positive(options.Timeout);
        if (options.MaxResponseBytes < 1) throw new ArgumentOutOfRangeException(nameof(options));
        endpoint = options.BaseUrl.TrimEnd('/') + "/api/v1/realms/" + HttpTransport.Segment(options.Realm);
        this.options = options; http = new(options.HttpClient);
    }
    public static string NewIdempotencyKey() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    private static void ValidatePath(string path)
    {
        if (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal) || path.Contains('#') || path.Contains('\\')) throw new ArgumentException("A realm-relative API path is required.");
        var decoded = Uri.UnescapeDataString(path.Split('?')[0]);
        if (decoded.Contains('\\') || decoded.Split('/').Any(x => x is "." or "..")) throw new ArgumentException("Path traversal is refused.");
    }
    public async Task<AdminResponse<object?>> RequestAsync(string method, string path, object? body = null,
        RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        var timeout = HttpTransport.Positive(requestOptions?.Timeout ?? options.Timeout);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        using var request = new HttpRequestMessage(new HttpMethod(method), endpoint + path);
        request.Headers.Accept.ParseAdd("application/json"); request.Headers.Accept.ParseAdd("application/problem+json");
        request.Headers.Add("ProudAuth-SDK", $"dotnet/{SdkVersion}");
        request.Headers.TryAddWithoutValidation("User-Agent", (options.UserAgent is null ? "" : options.UserAgent + " ") + $"proudauth-sdk-dotnet/{SdkVersion}");
        if (options.Token is not null)
        {
            try { request.Headers.Add("Authorization", "Bearer " + await options.Token(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false)); }
            catch (OperationCanceledException) { throw new AdminRequestException(cancellationToken.IsCancellationRequested ? "aborted" : "timeout", method, path); }
            catch { throw new AdminRequestException("token_source", method, path); }
        }
        if (requestOptions?.IdempotencyKey is string key) request.Headers.Add("Idempotency-Key", key);
        if (requestOptions?.IfMatch is string match) request.Headers.Add("If-Match", match);
        if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        HttpResult result;
        try { result = await http.SendAsync(request, timeout, options.MaxResponseBytes, deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw new AdminRequestException(cancellationToken.IsCancellationRequested ? "aborted" : "timeout", method, path); }
        catch { throw new AdminRequestException("network", method, path); }
        var deprecation = result.Header("Deprecation"); var sunset = result.Header("Sunset");
        if (deprecation is not null) options.OnDeprecated?.Invoke(new(method, path.Split('?')[0], deprecation, sunset));
        object? data = null;
        try { if (result.Body.Length > 0) data = Wrap(Json.Parse(result.Body)); }
        catch (VerifierException) { if (result.Status < 400) throw new AdminRequestException("invalid_response", method, path); }
        var headers = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(result.Headers, StringComparer.OrdinalIgnoreCase));
        if (result.Status >= 300) throw new ProblemException(result.Status, data as AdminObject ?? new(new Dictionary<string, object?>()), headers);
        return new(result.Status, headers, result.Header("ETag"), deprecation, sunset, data);
    }
    private static object? Wrap(JsonElement p, bool seal = false) => p.ValueKind switch
    {
        JsonValueKind.String => seal ? new Secret(p.GetString()!) : p.GetString(),
        JsonValueKind.Object => new AdminObject(p.EnumerateObject().ToDictionary(x => x.Name, x => Wrap(x.Value, seal || SecretMembers.Contains(x.Name)), StringComparer.Ordinal)),
        JsonValueKind.Array => System.Array.AsReadOnly(p.EnumerateArray().Select(x => Wrap(x, seal)).ToArray()),
        JsonValueKind.Number => p.TryGetInt64(out var n) ? (object)n : p.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null
    };
    private static AdminObject Object(object? value) => value as AdminObject ?? throw new AdminRequestException("invalid_response", "GET", "/");
    private async Task<AdminObject> DataAsync(string method, string path, object? body, RequestOptions? requestOptions, CancellationToken cancellationToken) =>
        Object((await RequestAsync(method, path, body, requestOptions, cancellationToken).ConfigureAwait(false)).Data);
    private static RequestOptions Idempotent(RequestOptions? options) => (options ?? new()) with { IdempotencyKey = options?.IdempotencyKey ?? NewIdempotencyKey() };
    public async IAsyncEnumerable<Page<AdminObject>> PagesAsync(string path, RequestOptions? requestOptions = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var cursor = ""; var seen = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            var p = cursor == "" ? path : path + (path.Contains('?') ? "&" : "?") + "cursor=" + Uri.EscapeDataString(cursor);
            var data = await DataAsync("GET", p, null, requestOptions, cancellationToken).ConfigureAwait(false);
            if (!data.TryGetValue("items", out var raw) || raw is not IReadOnlyList<object?> items || items.Any(x => x is not AdminObject))
                throw new AdminRequestException("invalid_response", "GET", path);
            if (data.TryGetValue("next_cursor", out var next) && next is not null and not string) throw new AdminRequestException("invalid_response", "GET", path);
            cursor = data.String("next_cursor");
            if (cursor != "" && !seen.Add(cursor)) throw new AdminRequestException("invalid_response", "GET", path);
            yield return new(System.Array.AsReadOnly(items.Cast<AdminObject>().ToArray()), cursor);
            if (cursor == "") yield break;
        }
    }
    public async IAsyncEnumerable<AdminObject> ListAsync(string path, RequestOptions? requestOptions = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    { await foreach (var page in PagesAsync(path, requestOptions, cancellationToken).ConfigureAwait(false)) foreach (var item in page.Items) yield return item; }
    public async IAsyncEnumerable<User> UsersAsync(string query = "", RequestOptions? requestOptions = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    { await foreach (var item in ListAsync("/users?q=" + Uri.EscapeDataString(query), requestOptions, cancellationToken).ConfigureAwait(false)) yield return User.From(item); }
    public async Task<AdminResponse<User>> GetUserAsync(string userId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        var r = await RequestAsync("GET", "/users/" + HttpTransport.Segment(userId), requestOptions: requestOptions, cancellationToken: cancellationToken).ConfigureAwait(false);
        return new(r.Status, r.Headers, r.ETag, r.Deprecation, r.Sunset, User.From(Object(r.Data)));
    }
    public Task<AdminObject> CreateUserAsync(object input, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", "/users", input, Idempotent(requestOptions), cancellationToken);
    public Task<AdminResponse<object?>> UpdateUserAsync(string userId, object patch, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => RequestAsync("PATCH", "/users/" + HttpTransport.Segment(userId), patch, requestOptions, cancellationToken);
    public Task<AdminResponse<object?>> SetUserStateAsync(string userId, string action, string reason, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default)
    {
        if (action is not ("suspend" or "reactivate" or "lock")) throw new ArgumentException("Unknown user state action.");
        return RequestAsync("POST", $"/users/{HttpTransport.Segment(userId)}/{action}", new { reason }, requestOptions, cancellationToken);
    }
    public async Task<long> RevokeSessionsAsync(string userId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) =>
        (await DataAsync("POST", $"/users/{HttpTransport.Segment(userId)}/revoke-sessions", new { }, requestOptions, cancellationToken).ConfigureAwait(false)).Integer("revoked_sessions");
    public async IAsyncEnumerable<Organization> OrganizationsAsync(RequestOptions? requestOptions = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    { await foreach (var item in ListAsync("/organizations", requestOptions, cancellationToken).ConfigureAwait(false)) yield return Organization.From(item); }
    public async Task<Organization> CreateOrganizationAsync(string slug, string displayName, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) =>
        Organization.From(await DataAsync("POST", "/organizations", new { slug, display_name = displayName }, Idempotent(requestOptions), cancellationToken).ConfigureAwait(false));
    public IAsyncEnumerable<AdminObject> MembersAsync(string orgId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => ListAsync($"/organizations/{HttpTransport.Segment(orgId)}/members", requestOptions, cancellationToken);
    public Task<AdminObject> AddMemberAsync(string orgId, string userId, string[] roleIds, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", $"/organizations/{HttpTransport.Segment(orgId)}/members", new { user_id = userId, role_ids = roleIds }, requestOptions, cancellationToken);
    public Task<AdminObject> InviteAsync(string orgId, string email, string[] roleIds, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", $"/organizations/{HttpTransport.Segment(orgId)}/invitations", new { email, role_ids = roleIds }, Idempotent(requestOptions), cancellationToken);
    public IAsyncEnumerable<AdminObject> InvitationsAsync(string orgId, string state = "", RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => ListAsync($"/organizations/{HttpTransport.Segment(orgId)}/invitations?state={Uri.EscapeDataString(state)}", requestOptions, cancellationToken);
    public Task<AdminResponse<object?>> RevokeInvitationAsync(string orgId, string invitationId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => RequestAsync("POST", $"/organizations/{HttpTransport.Segment(orgId)}/invitations/{HttpTransport.Segment(invitationId)}/revoke", requestOptions: requestOptions, cancellationToken: cancellationToken);
    public Task<AdminObject> InviteBatchAsync(string orgId, object[] items, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", $"/organizations/{HttpTransport.Segment(orgId)}/invitations/batch", new { items }, Idempotent(requestOptions), cancellationToken);
    public Task<AdminObject> RolesAsync(string boundary, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("GET", "/roles?boundary_type=" + Uri.EscapeDataString(boundary), null, requestOptions, cancellationToken);
    public Task<AdminObject> AssignAsync(string roleId, object subject, object scope, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", "/role-assignments", new { role_id = roleId, subject, scope }, requestOptions, cancellationToken);
    public IAsyncEnumerable<AdminObject> ClientsAsync(RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => ListAsync("/clients", requestOptions, cancellationToken);
    public Task<AdminObject> CreateClientAsync(object input, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", "/clients", input, requestOptions, cancellationToken);
    public Task<AdminObject> RotateClientSecretAsync(string clientRef, int retireOthersAfterSeconds, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", $"/clients/{HttpTransport.Segment(clientRef)}/credentials", new { retire_others_after_seconds = retireOthersAfterSeconds }, requestOptions, cancellationToken);
    public Task<AdminResponse<object?>> SetResourceGrantAsync(string clientRef, string resourceId, string[] scopes, string[] subjectTypes, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => RequestAsync("PUT", $"/clients/{HttpTransport.Segment(clientRef)}/resource-grants/{HttpTransport.Segment(resourceId)}", new { allowed_scopes = scopes, subject_types = subjectTypes }, requestOptions, cancellationToken);
    public Task<AdminObject> UserSessionsAsync(string userId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("GET", $"/users/{HttpTransport.Segment(userId)}/sessions", null, requestOptions, cancellationToken);
    public Task<AdminResponse<object?>> RevokeSessionAsync(string userId, string sessionId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => RequestAsync("DELETE", $"/users/{HttpTransport.Segment(userId)}/sessions/{HttpTransport.Segment(sessionId)}", requestOptions: requestOptions, cancellationToken: cancellationToken);
    public Task<AdminObject> RequestImpersonationAsync(object input, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", "/impersonation-requests", input, requestOptions, cancellationToken);
    public Task<AdminObject> IssueImpersonationAsync(string requestId, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("POST", $"/impersonation-requests/{HttpTransport.Segment(requestId)}/issue", null, requestOptions, cancellationToken);
    public Task<AdminResponse<object?>> RevokeImpersonationAsync(string grantId, string reason, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => RequestAsync("POST", $"/impersonation-grants/{HttpTransport.Segment(grantId)}/revoke", new { reason }, requestOptions, cancellationToken);
    public Task<AdminObject> ImpersonationGrantsAsync(IReadOnlyDictionary<string, string>? filter = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("GET", "/impersonation-grants?" + HttpTransport.Query(filter ?? new Dictionary<string, string>()), null, requestOptions, cancellationToken);
    public Task<AdminObject> SubjectPermissionsAsync(string subjectId, string orgId = "", RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => DataAsync("GET", $"/subjects/{HttpTransport.Segment(subjectId)}/permissions" + (orgId == "" ? "" : "?organization_id=" + Uri.EscapeDataString(orgId)), null, requestOptions, cancellationToken);
    public IAsyncEnumerable<AdminObject> AuditEventsAsync(IReadOnlyDictionary<string, string>? filter = null, RequestOptions? requestOptions = null, CancellationToken cancellationToken = default) => ListAsync("/audit-events?" + HttpTransport.Query(filter ?? new Dictionary<string, string>()), requestOptions, cancellationToken);
    public void Dispose() => http.Dispose();
}
