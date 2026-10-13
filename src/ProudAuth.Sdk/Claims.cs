using System.Collections.ObjectModel;
using System.Text.Json;
using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

public interface IAuthenticator
{
    Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default);
}

public sealed record Actor(string Subject, string? Issuer = null, Actor? Act = null);

/// <summary>Verified request context. Compare organization with trusted resource data.</summary>
public sealed class Claims
{
    public string Issuer { get; }
    public string Subject { get; }
    public string Audience { get; }
    public string ClientId { get; }
    public IReadOnlyList<string> Scopes { get; }
    public string OrgId { get; }
    public string SessionId { get; }
    public string TokenKind { get; }
    public string Jti { get; }
    public DateTimeOffset? IssuedAt { get; }
    public DateTimeOffset? Expiry { get; }
    public DateTimeOffset? AuthTime { get; }
    public string Acr { get; }
    public double AuthzVersion { get; }
    public Actor? Actor { get; }
    public string SupportMode { get; }
    public string ImpersonationGrantId { get; }
    public bool Online { get; }
    public bool IsSupport => TokenKind == "impersonation_access";

    internal Claims(JsonElement p, string audience, bool online)
    {
        Issuer = p.Str("iss"); Subject = p.Str("sub"); Audience = audience; ClientId = p.Str("client_id");
        Scopes = new ReadOnlyCollection<string>(p.Str("scope").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        OrgId = p.Str("org_id"); SessionId = p.Str("sid"); TokenKind = p.Str("token_kind"); Jti = p.Str("jti");
        IssuedAt = Json.Date(p.Num("iat")); Expiry = Json.Date(p.Num("exp")); AuthTime = Json.Date(p.Num("auth_time"));
        Acr = p.Str("acr"); AuthzVersion = p.Num("authz_version") ?? 0;
        Actor = ParseActor(p.Get("act"), 0); SupportMode = p.Str("support_mode");
        ImpersonationGrantId = p.Str("impersonation_grant_id"); Online = online;
    }

    private static Actor? ParseActor(JsonElement p, int depth)
    {
        if (p.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (depth > 16 || p.ValueKind != JsonValueKind.Object || p.Get("sub").ValueKind != JsonValueKind.String)
            throw new VerifierException("malformed");
        return new Actor(p.Str("sub"), p.Str("iss"), ParseActor(p.Get("act"), depth + 1));
    }

    public bool HasScope(string scope) => Scopes.Contains(scope, StringComparer.Ordinal);
    public void RequireScope(params string[] scopes)
    {
        if (scopes.Any(s => !HasScope(s))) throw new VerifierException("scope");
    }
    public void RequireOrganization(string resourceOrgId)
    {
        if (string.IsNullOrEmpty(OrgId) || string.IsNullOrEmpty(resourceOrgId) || OrgId != resourceOrgId)
            throw new VerifierException("organization");
    }
}
