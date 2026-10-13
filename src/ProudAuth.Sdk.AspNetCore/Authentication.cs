using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ProudAuth.Sdk.AspNetCore;

public sealed record AuthChallenge(int Status, string? WwwAuthenticate);
public static class BearerAuthentication
{
    private static readonly object ClaimsKey = new(), ErrorKey = new();
    private static readonly Regex Token = new("^[A-Za-z0-9\\-._~+/]+=*$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    public static string BearerToken(HttpRequest request)
    {
        if (request.Query.ContainsKey("access_token")) throw new VerifierException("invalid_request");
        var headers = request.Headers.Authorization;
        if (headers.Count > 1) throw new VerifierException("invalid_request");
        var value = headers.Count == 1 ? headers[0] : null;
        if (value is null || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) throw new VerifierException("missing_token");
        var raw = value[7..].Trim();
        if (raw.Length == 0) throw new VerifierException("missing_token");
        if (!Token.IsMatch(raw)) throw new VerifierException("malformed");
        return raw;
    }
    public static ProudAuth.Sdk.Claims? GetProudAuthClaims(this HttpContext context) => context.Items.TryGetValue(ClaimsKey, out var c) ? c as ProudAuth.Sdk.Claims : null;
    internal static void SetClaims(HttpContext context, ProudAuth.Sdk.Claims claims)
    {
        context.Items[ClaimsKey] = claims;
        var values = new List<Claim> {
            new(ClaimTypes.NameIdentifier, claims.Subject), new("sub", claims.Subject), new("iss", claims.Issuer),
            new("aud", claims.Audience), new("client_id", claims.ClientId), new("org_id", claims.OrgId),
            new("sid", claims.SessionId), new("token_kind", claims.TokenKind) };
        values.AddRange(claims.Scopes.Select(s => new Claim("scope", s)));
        if (claims.Actor is not null) values.Add(new("act.sub", claims.Actor.Subject));
        context.User = new ClaimsPrincipal(new ClaimsIdentity(values, ProudAuthDefaults.AuthenticationScheme));
    }
    internal static void SetError(HttpContext context, VerifierException error) => context.Items[ErrorKey] = error;
    internal static VerifierException? GetError(HttpContext context) => context.Items.TryGetValue(ErrorKey, out var e) ? e as VerifierException : null;
    private static string Quote(string value) => "\"" + new string(value.Where(c => !char.IsControl(c)).ToArray()).Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
    public static AuthChallenge Challenge(VerifierException error, string? realm = null, IReadOnlyList<string>? scopes = null)
    {
        string Bearer(string? code = null, bool includeScopes = false)
        {
            var parameters = new List<string>();
            if (!string.IsNullOrEmpty(realm)) parameters.Add("realm=" + Quote(realm));
            if (code is not null) parameters.Add("error=" + Quote(code));
            if (includeScopes && scopes?.Count > 0) parameters.Add("scope=" + Quote(string.Join(' ', scopes)));
            return "Bearer" + (parameters.Count > 0 ? " " + string.Join(", ", parameters) : "");
        }
        return error.Code switch
        {
            "missing_token" => new(401, Bearer()),
            "invalid_request" => new(400, Bearer("invalid_request")),
            "scope" => new(403, Bearer("insufficient_scope", true)),
            "organization" => new(403, Bearer("insufficient_scope")),
            "support_policy" => new(403, null),
            "unavailable" or "stale_state" => new(503, null),
            "contract" => new(500, null),
            _ => new(401, Bearer("invalid_token"))
        };
    }
    internal static Task SendAsync(HttpContext context, AuthChallenge challenge)
    {
        if (context.Response.HasStarted) return Task.CompletedTask;
        context.Response.StatusCode = challenge.Status;
        context.Response.Headers.CacheControl = "no-store";
        if (challenge.WwwAuthenticate is not null) context.Response.Headers.WWWAuthenticate = challenge.WwwAuthenticate;
        return Task.CompletedTask;
    }
}

public static class ProudAuthDefaults
{
    public const string AuthenticationScheme = "ProudAuth";
}
public sealed class ProudAuthAuthenticationOptions : AuthenticationSchemeOptions
{
    public IAuthenticator? Authenticator { get; set; }
    public string? Realm { get; set; }
}
public sealed class ProudAuthAuthenticationHandler(IOptionsMonitor<ProudAuthAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<ProudAuthAuthenticationOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var authenticator = Options.Authenticator ?? Context.RequestServices.GetService<IAuthenticator>() ?? throw new VerifierException("contract");
            var claims = await authenticator.AuthenticateAsync(BearerAuthentication.BearerToken(Request), Context.RequestAborted).ConfigureAwait(false);
            BearerAuthentication.SetClaims(Context, claims);
            return AuthenticateResult.Success(new AuthenticationTicket(Context.User, Scheme.Name));
        }
        catch (VerifierException error)
        {
            BearerAuthentication.SetError(Context, error);
            return error.Code == "missing_token" ? AuthenticateResult.NoResult() : AuthenticateResult.Fail(error);
        }
    }
    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        BearerAuthentication.SendAsync(Context, BearerAuthentication.Challenge(BearerAuthentication.GetError(Context) ?? new("missing_token"), Options.Realm));
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        BearerAuthentication.SendAsync(Context, BearerAuthentication.Challenge(new("scope"), Options.Realm));
}
public static class ProudAuthExtensions
{
    public static AuthenticationBuilder AddProudAuth(this AuthenticationBuilder builder, Action<ProudAuthAuthenticationOptions>? configure = null) =>
        builder.AddScheme<ProudAuthAuthenticationOptions, ProudAuthAuthenticationHandler>(ProudAuthDefaults.AuthenticationScheme, configure ?? (_ => { }));

    /// <summary>Protects all downstream routes; catches claim-helper denials in handlers as well.</summary>
    public static IApplicationBuilder UseProudAuth(this IApplicationBuilder app, IAuthenticator authenticator,
        string? realm = null, params string[] requiredScopes) => app.Use(next => async context =>
    {
        try
        {
            var claims = await authenticator.AuthenticateAsync(BearerAuthentication.BearerToken(context.Request), context.RequestAborted).ConfigureAwait(false);
            claims.RequireScope(requiredScopes);
            BearerAuthentication.SetClaims(context, claims);
            await next(context).ConfigureAwait(false);
        }
        catch (VerifierException error)
        {
            if (context.Response.HasStarted) throw;
            await BearerAuthentication.SendAsync(context, BearerAuthentication.Challenge(error, realm, requiredScopes)).ConfigureAwait(false);
        }
    });
}
