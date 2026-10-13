using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

public sealed record VerifierOptions
{
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public string? JwksUrl { get; init; }
    public IReadOnlyList<string>? Algorithms { get; init; }
    public IReadOnlyList<string>? AcceptedKinds { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan MinRefreshInterval { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);
    public int MaxTokenBytes { get; init; } = 8192;
    public HttpClient? HttpClient { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>Offline access JWT verification (SDK-001). Revocation is observed only at expiry.</summary>
public sealed class Verifier : IAuthenticator, IDisposable
{
    private readonly VerifierOptions options;
    private readonly HashSet<string> algorithms;
    private readonly HashSet<string> kinds;
    private readonly HttpTransport http;
    private readonly JwksCache jwks;
    public string Issuer => options.Issuer;
    public string Audience => options.Audience;
    public int FetchCount => jwks.FetchCount;
    public Verifier(VerifierOptions options)
    {
        HttpTransport.Url(options.Issuer); HttpTransport.Required(options.Audience, "audience");
        var url = HttpTransport.Url(options.JwksUrl ?? options.Issuer.TrimEnd('/') + "/jwks").AbsoluteUri;
        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > TimeSpan.FromSeconds(60) ||
            options.MinRefreshInterval < TimeSpan.FromSeconds(1) || options.MaxTokenBytes < 1) throw new ArgumentOutOfRangeException(nameof(options));
        HttpTransport.Positive(options.Timeout);
        algorithms = Jose.Algorithms(options.Algorithms);
        kinds = new(options.AcceptedKinds ?? ["user_access", "service_access", "exchange_access"], StringComparer.Ordinal);
        if (kinds.Count == 0 || kinds.Contains("impersonation_access")) throw new ArgumentException("Support tokens require SupportGuard.");
        this.options = options; http = new(options.HttpClient);
        jwks = new(http, url, options.Timeout, options.MinRefreshInterval, options.TimeProvider);
    }
    public async Task<Claims> VerifyAsync(string token, CancellationToken cancellationToken = default)
    {
        var jws = Jose.Parse(token, options.MaxTokenBytes);
        var h = jws.Header; var p = jws.Payload;
        if (p.Str("iss") != Issuer) throw new VerifierException("issuer"); // Before any network request.
        if (h.Has("crit")) throw new VerifierException("malformed");
        var alg = h.Str("alg");
        if (!algorithms.Contains(alg)) throw new VerifierException("algorithm");
        if (h.Str("typ").ToLowerInvariant() is not ("at+jwt" or "application/at+jwt")) throw new VerifierException("token_type");
        var kid = h.Str("kid"); if (kid == "") throw new VerifierException("unknown_key");
        var key = await jwks.KeyAsync(kid, cancellationToken).ConfigureAwait(false);
        if (key.Has("alg") && key.Str("alg") != alg) throw new VerifierException("algorithm");
        if (!Jose.Verify(alg, key, jws)) throw new VerifierException("signature");
        var aud = Json.Audience(p);
        if (aud.Length != 1 || aud[0] != Audience) throw new VerifierException("audience");
        var now = (options.TimeProvider.GetUtcNow() - DateTimeOffset.UnixEpoch).TotalSeconds;
        var skew = options.ClockSkew.TotalSeconds;
        if (p.Num("exp") is not double exp || now > exp + skew) throw new VerifierException("expired");
        if (p.Num("nbf") is double nbf && now + skew < nbf) throw new VerifierException("not_yet_valid");
        if (p.Num("iat") is double iat && iat > now + skew) throw new VerifierException("future_issued");
        if (p.Str("sub") == "" || p.Str("client_id") == "" || p.Str("jti") == "" || !kinds.Contains(p.Str("token_kind")))
            throw new VerifierException("token_kind");
        if (p.Has("cnf")) throw new VerifierException("sender_constraint");
        return new Claims(p, Audience, false);
    }
    public Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default) => VerifyAsync(token, cancellationToken);
    public void Dispose() => http.Dispose();
}

public sealed record IssuerRegistration(Verifier Verifier, string Tenant);
public sealed record TenantClaims(Claims Claims, string Tenant);
public sealed class MultiIssuerVerifier : IAuthenticator
{
    private readonly Dictionary<string, IssuerRegistration> issuers;
    public MultiIssuerVerifier(IReadOnlyDictionary<string, IssuerRegistration> registrations)
    {
        issuers = new(registrations, StringComparer.Ordinal);
        if (issuers.Count == 0 || issuers.Any(x => x.Key != x.Value.Verifier.Issuer || string.IsNullOrWhiteSpace(x.Value.Tenant)))
            throw new ArgumentException("Register each exact issuer with its verifier and tenant.");
    }
    public async Task<TenantClaims> VerifyTenantAsync(string token, CancellationToken cancellationToken = default)
    {
        var iss = Jose.Parse(token, 16384).Payload.Str("iss");
        if (!issuers.TryGetValue(iss, out var reg)) throw new VerifierException("issuer");
        return new(await reg.Verifier.VerifyAsync(token, cancellationToken).ConfigureAwait(false), reg.Tenant);
    }
    public async Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default) =>
        (await VerifyTenantAsync(token, cancellationToken).ConfigureAwait(false)).Claims;
}
