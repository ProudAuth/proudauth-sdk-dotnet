using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProudAuth.Sdk.Internal;

namespace ProudAuth.Sdk;

public sealed record OidcClientOptions
{
    public required string Issuer { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public string? ClientSecret { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = ["openid"];
    public string? Resource { get; init; }
    public IReadOnlyList<string>? Algorithms { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
    public TimeSpan MinRefreshInterval { get; init; } = TimeSpan.FromSeconds(30);
    public HttpClient? HttpClient { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>Store server-side and consume once on callback.</summary>
public sealed record AuthRequest(string State, string Nonce, string CodeVerifier, string Url, string RedirectUri,
    IReadOnlyList<string> Scopes, DateTimeOffset CreatedAt)
{
    public override string ToString() => "AuthRequest([REDACTED])";
}
public sealed record TokenSet(
    [property: JsonIgnore] string AccessToken, string TokenType, double ExpiresIn, DateTimeOffset ExpiresAt,
    [property: JsonIgnore] string? RefreshToken = null, [property: JsonIgnore] string? IdToken = null, string? Scope = null)
{
    public override string ToString() => "TokenSet([REDACTED])";
}
public sealed record IdTokenClaims(string Issuer, string Subject, IReadOnlyList<string> Audience, DateTimeOffset Expiry,
    DateTimeOffset? IssuedAt, DateTimeOffset? AuthTime, string Nonce, string Acr, IReadOnlyList<string> Amr,
    string Azp, string SessionId, string AtHash, string Email, string Name, JsonElement Claims);
public sealed record CodeExchangeResult(TokenSet Tokens, IdTokenClaims? IdClaims);

/// <summary>Discovery, code + PKCE S256, ID validation, rotated refresh, revocation and logout (SDK-004).</summary>
public sealed class OidcClient : IDisposable
{
    private readonly OidcClientOptions options;
    private readonly Uri issuerUri;
    private readonly HttpTransport http;
    private readonly HashSet<string> algorithms;
    private readonly string[] scopes;
    private readonly object gate = new();
    private Task<JsonElement>? discovery;
    private JwksCache? jwks;
    private static readonly HashSet<string> Reserved = ["client_id", "redirect_uri", "response_type", "state", "nonce", "code_challenge", "code_challenge_method", "scope", "resource", "request", "request_uri"];
    public string Issuer => options.Issuer;
    public string ClientId => options.ClientId;
    public int JwksFetchCount { get { lock (gate) return jwks?.FetchCount ?? 0; } }
    internal DateTimeOffset Now => options.TimeProvider.GetUtcNow();
    public OidcClient(OidcClientOptions options)
    {
        issuerUri = HttpTransport.Url(options.Issuer); HttpTransport.Url(options.RedirectUri);
        HttpTransport.Required(options.ClientId, "client ID"); HttpTransport.Positive(options.Timeout);
        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > TimeSpan.FromSeconds(60) || options.MinRefreshInterval < TimeSpan.FromSeconds(1))
            throw new ArgumentOutOfRangeException(nameof(options));
        algorithms = Jose.Algorithms(options.Algorithms); scopes = options.Scopes.ToArray();
        this.options = options; http = new(options.HttpClient);
    }
    public static string RandomValue() => Jose.Encode(RandomNumberGenerator.GetBytes(32));
    public static string PkceChallenge(string verifier) => Jose.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
    public static string HalfHash(string algorithm, string value)
    {
        var digest = algorithm == "EdDSA" ? SHA512.HashData(Encoding.UTF8.GetBytes(value)) : SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Jose.Encode(digest[..(digest.Length / 2)]);
    }
    public Task<JsonElement> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        lock (gate) return (discovery ??= LoadDiscoveryAsync()).WaitAsync(cancellationToken);
    }
    private async Task<JsonElement> LoadDiscoveryAsync()
    {
        await Task.Yield();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, Issuer.TrimEnd('/') + "/.well-known/openid-configuration");
            var response = await http.SendAsync(request, options.Timeout, 1 << 20, CancellationToken.None).ConfigureAwait(false);
            if (response.Status != 200) throw new OidcException("provider", "discovery_status");
            var p = Json.Object(response.Body);
            if (p.Str("issuer") != Issuer) throw new OidcException("provider", "discovery_issuer");
            return p;
        }
        catch (OidcException) { lock (gate) discovery = null; throw; }
        catch { lock (gate) discovery = null; throw new OidcException("provider", "discovery_unavailable"); }
    }
    private async Task<string> EndpointAsync(string name, CancellationToken cancellationToken)
    {
        var p = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var uri = HttpTransport.Url(p.Str(name));
            if (uri.Scheme != issuerUri.Scheme || uri.IdnHost != issuerUri.IdnHost || uri.Port != issuerUri.Port) throw new ArgumentException();
            return uri.AbsoluteUri;
        }
        catch { throw new OidcException("provider", "endpoint_origin"); }
    }
    private static string WithQuery(string endpoint, Dictionary<string, string> fields)
    {
        var uri = new UriBuilder(endpoint);
        var existing = ParseQuery(uri.Query);
        foreach (var field in fields) existing[field.Key] = [field.Value];
        uri.Query = HttpTransport.Query(existing.SelectMany(x => x.Value.Select(v => new KeyValuePair<string, string>(x.Key, v))));
        return uri.Uri.AbsoluteUri;
    }
    public async Task<AuthRequest> AuthorizationUrlAsync(IReadOnlyDictionary<string, string>? extraParams = null,
        IReadOnlyList<string>? scopes = null, string? resource = null, CancellationToken cancellationToken = default)
    {
        if (extraParams?.Keys.Any(Reserved.Contains) == true) throw new ArgumentException("Authorization security parameters cannot be overridden.");
        var ep = await EndpointAsync("authorization_endpoint", cancellationToken).ConfigureAwait(false);
        var requestedScopes = (scopes ?? this.scopes).ToArray();
        var state = RandomValue(); var nonce = RandomValue(); var verifier = RandomValue();
        var fields = new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = options.RedirectUri,
            ["response_type"] = "code",
            ["scope"] = string.Join(' ', requestedScopes),
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = PkceChallenge(verifier),
            ["code_challenge_method"] = "S256"
        };
        if ((resource ?? options.Resource) is string r) fields["resource"] = r;
        if (extraParams is not null) foreach (var p in extraParams) fields[p.Key] = p.Value;
        return new(state, nonce, verifier, WithQuery(ep, fields), options.RedirectUri, Array.AsReadOnly(requestedScopes), Now);
    }
    internal static Dictionary<string, List<string>> ParseQuery(string callback)
    {
        var query = callback.Contains('?') ? callback[(callback.IndexOf('?') + 1)..] : callback.TrimStart('?');
        query = query.Split('#')[0];
        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0].Replace('+', ' '));
            var value = parts.Length == 2 ? Uri.UnescapeDataString(parts[1].Replace('+', ' ')) : "";
            if (!result.TryGetValue(key, out var values)) result[key] = values = [];
            values.Add(value);
        }
        return result;
    }
    public async Task<CodeExchangeResult> ExchangeCodeAsync(AuthRequest authRequest, string callback, CancellationToken cancellationToken = default)
    {
        var p = ParseQuery(callback);
        string? One(string key)
        {
            if (!p.TryGetValue(key, out var values)) return null;
            if (values.Count != 1) throw new OidcException("provider", "duplicate_callback_parameter");
            return values[0];
        }
        var state = One("state");
        if (string.IsNullOrEmpty(state) || !Jose.Equal(state, authRequest.State)) throw new OidcException("state");
        var metadata = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
        var iss = One("iss");
        if ((iss is not null && iss != Issuer) || (iss is null && metadata.Get("authorization_response_iss_parameter_supported").ValueKind == JsonValueKind.True))
            throw new OidcException("provider", "callback_issuer");
        if (One("error") is not null) throw new OidcException("provider", "authorization_error");
        var code = One("code"); if (string.IsNullOrEmpty(code)) throw new OidcException("provider", "missing_code");
        var tokens = await TokenRequestAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["code_verifier"] = authRequest.CodeVerifier,
            ["redirect_uri"] = authRequest.RedirectUri
        }, cancellationToken).ConfigureAwait(false);
        IdTokenClaims? idClaims = null;
        if (tokens.IdToken is not null) idClaims = await ValidateIdTokenAsync(tokens.IdToken, authRequest.Nonce, tokens.AccessToken, cancellationToken: cancellationToken).ConfigureAwait(false);
        else if (authRequest.Scopes.Contains("openid")) throw new OidcException("id_token", "missing_id_token");
        return new(tokens, idClaims);
    }
    private async Task<HttpResult> PostAsync(string endpointName, Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        var ep = await EndpointAsync(endpointName, cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Post, ep);
        if (!string.IsNullOrEmpty(options.ClientSecret)) request.Headers.TryAddWithoutValidation("Authorization", HttpTransport.Basic(ClientId, options.ClientSecret));
        else fields["client_id"] = ClientId;
        request.Content = new FormUrlEncodedContent(fields);
        try { return await http.SendAsync(request, options.Timeout, 1 << 20, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new OidcException("provider", "endpoint_unavailable"); }
    }
    internal async Task<TokenSet> TokenRequestAsync(Dictionary<string, string> fields, CancellationToken cancellationToken = default)
    {
        var response = await PostAsync("token_endpoint", fields, cancellationToken).ConfigureAwait(false);
        try
        {
            var p = Json.Object(response.Body);
            if (response.Status != 200) throw new OidcException(p.Str("error") == "invalid_grant" ? "reauthenticate" : "provider", "token_status");
            var at = p.Str("access_token"); var tt = p.Str("token_type"); var expires = p.Num("expires_in") ?? 0;
            if (at == "" || !tt.Equals("Bearer", StringComparison.OrdinalIgnoreCase) || expires < 0) throw new OidcException("provider", "token_response");
            string? Optional(string key) => p.Str(key) is string v && v != "" ? v : null;
            return new(at, tt, expires, Now.AddSeconds(expires), Optional("refresh_token"), Optional("id_token"), Optional("scope"));
        }
        catch (OidcException) { throw; }
        catch { throw new OidcException("provider", "token_response"); }
    }
    public async Task<IdTokenClaims> ValidateIdTokenAsync(string token, string? nonce = null, string? accessToken = null,
        double? maxAgeSeconds = null, CancellationToken cancellationToken = default)
    {
        try
        {
            if (maxAgeSeconds is double age && (!double.IsFinite(age) || age < 0)) throw new ArgumentOutOfRangeException(nameof(maxAgeSeconds));
            var jws = Jose.Parse(token, 16384); var h = jws.Header; var p = jws.Payload;
            if (p.Str("iss") != Issuer) throw new OidcException("id_token", "issuer");
            if (h.Has("crit")) throw new OidcException("id_token", "critical_header");
            var alg = h.Str("alg");
            if (!algorithms.Contains(alg)) throw new OidcException("id_token", "algorithm");
            if (h.Has("typ") && !h.Str("typ").Equals("JWT", StringComparison.OrdinalIgnoreCase)) throw new OidcException("id_token", "type");
            var kid = h.Str("kid"); if (kid == "") throw new OidcException("id_token", "missing_kid");
            var url = await EndpointAsync("jwks_uri", cancellationToken).ConfigureAwait(false);
            JwksCache cache; lock (gate) cache = jwks ??= new(http, url, options.Timeout, options.MinRefreshInterval, options.TimeProvider);
            var key = await cache.KeyAsync(kid, cancellationToken).ConfigureAwait(false);
            if (key.Has("alg") && key.Str("alg") != alg) throw new OidcException("id_token", "algorithm");
            if (!Jose.Verify(alg, key, jws)) throw new OidcException("id_token", "signature");
            var aud = Json.Audience(p); var sub = p.Str("sub"); var azp = p.Str("azp");
            if (sub == "") throw new OidcException("id_token", "subject");
            if (!aud.Contains(ClientId)) throw new OidcException("id_token", "audience");
            if ((aud.Length > 1 || p.Has("azp")) && azp != ClientId) throw new OidcException("id_token", "authorized_party");
            var now = (Now - DateTimeOffset.UnixEpoch).TotalSeconds; var skew = options.ClockSkew.TotalSeconds;
            if (p.Num("exp") is not double exp || now > exp + skew) throw new OidcException("id_token", "expired");
            if (p.Num("iat") is double iat && iat > now + skew) throw new OidcException("id_token", "future_issued");
            if (!string.IsNullOrEmpty(nonce) && !Jose.Equal(p.Str("nonce"), nonce)) throw new OidcException("nonce");
            if (!string.IsNullOrEmpty(accessToken) && p.Has("at_hash") && !Jose.Equal(p.Str("at_hash"), HalfHash(alg, accessToken))) throw new OidcException("id_token", "at_hash");
            var authTime = p.Num("auth_time");
            if (maxAgeSeconds is double max && (authTime is null || now - authTime > max + skew)) throw new OidcException("id_token", "max_age");
            var amr = p.Get("amr").ValueKind == JsonValueKind.Array ? p.Get("amr").EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray() : [];
            return new(Issuer, sub, Array.AsReadOnly(aud), Json.Date(exp)!.Value, Json.Date(p.Num("iat")), Json.Date(authTime),
                p.Str("nonce"), p.Str("acr"), Array.AsReadOnly(amr), azp, p.Str("sid"), p.Str("at_hash"), p.Str("email"), p.Str("name"), p);
        }
        catch (VerifierException e) { throw new OidcException(e.Code == "unavailable" ? "provider" : "id_token", e.Code); }
    }
    public Session CreateSession(TokenSet tokens, IdTokenClaims? idClaims = null, Func<TokenSet, Task>? onRefresh = null, TimeSpan? refreshWindow = null) =>
        new(this, tokens, idClaims, onRefresh, refreshWindow ?? TimeSpan.FromSeconds(15));
    public async Task RevokeAsync(string token, string tokenTypeHint = "refresh_token", CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token)) return;
        var response = await PostAsync("revocation_endpoint", new() { ["token"] = token, ["token_type_hint"] = tokenTypeHint }, cancellationToken).ConfigureAwait(false);
        if (response.Status != 200) throw new OidcException("provider", "revocation_status");
    }
    public async Task<string> LogoutUrlAsync(string? idTokenHint = null, string? postLogoutRedirectUri = null, string? state = null, CancellationToken cancellationToken = default)
    {
        var ep = await EndpointAsync("end_session_endpoint", cancellationToken).ConfigureAwait(false);
        var fields = new Dictionary<string, string> { ["client_id"] = ClientId };
        if (idTokenHint is not null) fields["id_token_hint"] = idTokenHint;
        if (postLogoutRedirectUri is not null) fields["post_logout_redirect_uri"] = postLogoutRedirectUri;
        if (state is not null) fields["state"] = state;
        return WithQuery(ep, fields);
    }
    public async Task<string> LogoutAsync(Session session, string? postLogoutRedirectUri = null, string? state = null, CancellationToken cancellationToken = default)
    {
        var tokens = session.Tokens; session.Clear();
        if (tokens?.RefreshToken is string rt) await RevokeAsync(rt, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await LogoutUrlAsync(tokens?.IdToken, postLogoutRedirectUri, state, cancellationToken).ConfigureAwait(false);
    }
    public void Dispose() => http.Dispose();
}

/// <summary>One per browser session per process. Multiple instances need sticky routing or a distributed refresh lock.</summary>
public sealed class Session
{
    private readonly OidcClient client;
    private readonly Func<TokenSet, Task>? onRefresh;
    private readonly TimeSpan window;
    private readonly object gate = new();
    private TokenSet? tokens;
    private IdTokenClaims? idClaims;
    private Task<string>? inflight;
    private long generation;
    private int refreshCount;
    public TokenSet? Tokens { get { lock (gate) return tokens; } }
    public IdTokenClaims? IdClaims { get { lock (gate) return idClaims; } }
    public int RefreshCount => Volatile.Read(ref refreshCount);
    internal Session(OidcClient client, TokenSet tokens, IdTokenClaims? idClaims, Func<TokenSet, Task>? onRefresh, TimeSpan window)
    {
        if (window < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));
        this.client = client; this.tokens = tokens; this.idClaims = idClaims; this.onRefresh = onRefresh; this.window = window;
    }
    public void Clear() { lock (gate) { tokens = null; idClaims = null; generation++; } }
    public Task<string> AccessTokenAsync(string? rejectedToken = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (tokens is null) throw new OidcException("reauthenticate");
            if (inflight is not null) return inflight.WaitAsync(cancellationToken);
            if (rejectedToken != tokens.AccessToken && client.Now + window < tokens.ExpiresAt) return Task.FromResult(tokens.AccessToken);
            if (tokens.RefreshToken is null) { tokens = null; throw new OidcException("reauthenticate"); }
            return (inflight = RefreshAsync(tokens, generation)).WaitAsync(cancellationToken);
        }
    }
    private async Task<string> RefreshAsync(TokenSet current, long version)
    {
        await Task.Yield();
        try
        {
            Interlocked.Increment(ref refreshCount);
            // Shared rotation continues if one waiter cancels. Never retry a lost refresh response.
            var next = await client.TokenRequestAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = current.RefreshToken! }).ConfigureAwait(false);
            IdTokenClaims? previous; lock (gate) previous = idClaims;
            var nextClaims = previous;
            if (next.IdToken is string id)
            {
                nextClaims = await client.ValidateIdTokenAsync(id, accessToken: next.AccessToken).ConfigureAwait(false);
                if (previous is not null && previous.Subject != nextClaims.Subject) throw new OidcException("id_token", "subject_changed");
            }
            next = next with { RefreshToken = next.RefreshToken ?? current.RefreshToken, IdToken = next.IdToken ?? current.IdToken };
            lock (gate) if (generation != version || tokens is null) throw new OidcException("reauthenticate");
            if (onRefresh is not null) await onRefresh(next).ConfigureAwait(false);
            lock (gate)
            {
                if (generation != version || tokens is null) throw new OidcException("reauthenticate");
                tokens = next; idClaims = nextClaims;
            }
            return next.AccessToken;
        }
        catch { Clear(); throw new OidcException("reauthenticate"); }
        finally { lock (gate) inflight = null; }
    }
}
