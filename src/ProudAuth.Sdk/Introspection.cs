using System.Text;
using System.Text.Json;
using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

public sealed record IntrospectorOptions
{
    public required string Endpoint { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public IReadOnlyList<string>? AcceptedKinds { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
    public int MaxTokenBytes { get; init; } = 8192;
    public HttpClient? HttpClient { get; init; }
}

/// <summary>Strict-online RFC 7662 validation. No positive cache or offline fallback (SDK-002).</summary>
public sealed class Introspector : IAuthenticator, IDisposable
{
    private readonly IntrospectorOptions options;
    private readonly HttpTransport http;
    private readonly HashSet<string> kinds;
    public Introspector(IntrospectorOptions options)
    {
        HttpTransport.Url(options.Endpoint); HttpTransport.Url(options.Issuer);
        HttpTransport.Required(options.ClientId, "client ID"); HttpTransport.Required(options.ClientSecret, "client secret");
        HttpTransport.Required(options.Audience, "audience"); HttpTransport.Positive(options.Timeout);
        if (options.MaxTokenBytes < 1) throw new ArgumentOutOfRangeException(nameof(options));
        kinds = new(options.AcceptedKinds ?? ["user_access", "service_access", "exchange_access", "api_key", "personal_access"], StringComparer.Ordinal);
        if (kinds.Count == 0 || kinds.Contains("impersonation_access")) throw new ArgumentException("Support tokens require SupportGuard.");
        this.options = options; http = new(options.HttpClient);
    }
    internal bool Accepts(string kind) => kinds.Contains(kind);
    internal async Task<Claims> IntrospectAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token)) throw new VerifierException("missing_token");
        if (Encoding.UTF8.GetByteCount(token) > options.MaxTokenBytes) throw new VerifierException("too_large");
        JsonElement p;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, options.Endpoint);
            request.Headers.TryAddWithoutValidation("Authorization", HttpTransport.Basic(options.ClientId, options.ClientSecret));
            request.Headers.Accept.ParseAdd("application/json");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token });
            var response = await http.SendAsync(request, options.Timeout, 64 << 10, cancellationToken).ConfigureAwait(false);
            if (response.Status != 200) throw new VerifierException("unavailable");
            p = Json.Object(response.Body);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new VerifierException("unavailable"); }
        if (p.Get("active").ValueKind != JsonValueKind.True) throw new VerifierException("inactive");
        if (p.Str("iss") != options.Issuer) throw new VerifierException("issuer");
        var audience = Json.Audience(p);
        if (audience.Length != 1 || audience[0] != options.Audience) throw new VerifierException("audience");
        if (p.Has("cnf")) throw new VerifierException("sender_constraint");
        return new(p, options.Audience, true);
    }
    public async Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default)
    {
        var c = await IntrospectAsync(token, cancellationToken).ConfigureAwait(false);
        if (!Accepts(c.TokenKind)) throw new VerifierException("token_kind");
        return c;
    }
    public void Dispose() => http.Dispose();
}

public static class SupportOperations
{
    public static IReadOnlyList<string> ProtectedOperations { get; } = Array.AsReadOnly(new[] {
        "password.change", "password.reset", "mfa.change", "identifier.change", "account.link", "credential.export",
        "api_key.create", "personal_token.create", "consent.modify", "idp.admin", "payment", "refund", "ownership.transfer",
        "secret.read", "secret", "delete", "purge" });
    public static IReadOnlyList<string> WriteSegments { get; } = Array.AsReadOnly(new[] {
        "create", "add", "insert", "update", "edit", "modify", "change", "set", "put", "patch", "write", "upsert", "replace",
        "delete", "remove", "destroy", "erase", "purge", "archive", "unarchive", "restore", "reset", "rotate", "revoke", "grant",
        "assign", "unassign", "link", "unlink", "transfer", "issue", "approve", "reject", "cancel", "enable", "disable", "suspend",
        "reactivate", "activate", "deactivate", "lock", "unlock", "invite", "send", "submit", "publish", "unpublish", "import", "merge",
        "move", "rename", "refund", "pay", "execute" });
    private static string[] Segments(string operation) => operation.Trim().ToLowerInvariant().Replace('-', '_').Split(['.', ':', '/'], StringSplitOptions.RemoveEmptyEntries);
    public static bool IsWriteOperation(string operation) => Segments(operation).Any(WriteSegments.Contains);
    public static bool IsProtectedOperation(string operation, IEnumerable<string>? protectedOperations = null)
    {
        var segs = Segments(operation);
        if (segs.Length == 0) return true;
        foreach (var entry in protectedOperations ?? ProtectedOperations)
        {
            var run = Segments(entry);
            if (run.Length == 0) continue;
            for (var i = 0; i + run.Length <= segs.Length; i++)
                if (run.Select((s, j) => segs[i + j] == s || segs[i + j] == s + "s" || segs[i + j] + "s" == s).All(x => x)) return true;
        }
        return false;
    }
}

public sealed record SupportEvent(string GrantId, string Actor, string? ActorIssuer, string Subject, string OrgId,
    string ClientId, string TokenId, string Operation, bool Read, bool Allowed, string? DenyReason, DateTimeOffset At);
public sealed record SupportGuardOptions
{
    public required Introspector Introspector { get; init; }
    public required Func<SupportEvent, CancellationToken, Task> Auditor { get; init; }
    public IReadOnlyList<string> WriteOperations { get; init; } = [];
    public IReadOnlyList<string> ProtectedOperations { get; init; } = [];
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>Online support contract: actor attribution, explicit writes, protected operations, audit before access.</summary>
public sealed class SupportGuard
{
    private readonly Introspector introspector;
    private readonly Func<SupportEvent, CancellationToken, Task> auditor;
    private readonly HashSet<string> writes;
    private readonly string[] protectedOps;
    private readonly TimeProvider clock;
    public SupportGuard(SupportGuardOptions options)
    {
        introspector = options.Introspector ?? throw new VerifierException("contract");
        auditor = options.Auditor ?? throw new VerifierException("contract");
        writes = new(options.WriteOperations.Select(x => x.Trim()), StringComparer.OrdinalIgnoreCase);
        protectedOps = SupportOperations.ProtectedOperations.Concat(options.ProtectedOperations).ToArray(); clock = options.TimeProvider;
    }
    public async Task<Claims> AuthorizeAsync(string token, string operation, bool read = false, CancellationToken cancellationToken = default) =>
        await DecideAsync(await introspector.IntrospectAsync(token, cancellationToken).ConfigureAwait(false), operation, read, cancellationToken).ConfigureAwait(false);
    public async Task<Claims> AuthorizeAnyAsync(string token, string operation, bool read = false, CancellationToken cancellationToken = default)
    {
        var c = await introspector.IntrospectAsync(token, cancellationToken).ConfigureAwait(false);
        if (c.IsSupport) return await DecideAsync(c, operation, read, cancellationToken).ConfigureAwait(false);
        if (!introspector.Accepts(c.TokenKind)) throw new VerifierException("token_kind");
        return c;
    }
    private async Task<Claims> DecideAsync(Claims c, string operation, bool read, CancellationToken cancellationToken)
    {
        if (!c.IsSupport || string.IsNullOrEmpty(c.Actor?.Subject) || c.ImpersonationGrantId == "") throw new VerifierException("token_kind");
        var effectiveRead = read && !SupportOperations.IsWriteOperation(operation);
        var reason = SupportOperations.IsProtectedOperation(operation, protectedOps) ? "protected_operation" :
            !effectiveRead && (c.SupportMode != "allowlisted_write" || !writes.Contains(operation.Trim())) ? "write_not_allowlisted" : null;
        var ev = new SupportEvent(c.ImpersonationGrantId, c.Actor.Subject, c.Actor.Issuer, c.Subject, c.OrgId, c.ClientId,
            c.Jti, operation, effectiveRead, reason is null, reason, clock.GetUtcNow());
        try { await auditor(ev, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new VerifierException("unavailable"); }
        if (reason is not null) throw new VerifierException("support_policy");
        return c;
    }
    public IAuthenticator Route(string operation, bool read = false) => new RouteAuthenticator(this, operation, read);
    private sealed class RouteAuthenticator(SupportGuard guard, string operation, bool read) : IAuthenticator
    {
        public Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default) => guard.AuthorizeAnyAsync(token, operation, read, cancellationToken);
    }
}
