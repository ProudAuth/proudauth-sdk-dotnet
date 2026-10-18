<p align="center">
  <a href="https://proudauth.com"><img src="https://raw.githubusercontent.com/ProudAuth/.github/main/assets/banner-proudauth-sdk-dotnet.png" alt="ProudAuth SDK for .NET" width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/ProudAuth/proudauth-sdk-dotnet"><img alt=".NET" src="https://img.shields.io/badge/.NET-SDK-3ee6b0?logo=dotnet&logoColor=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth-sdk-dotnet/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ProudAuth/proudauth-sdk-dotnet/ci.yml?branch=main&label=ci&style=for-the-badge&labelColor=06120e"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
  <a href="https://proudauth.com/docs/sdks/dotnet/"><img alt="Documentation" src="https://img.shields.io/badge/docs-proudauth.com-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
</p>

# ProudAuth SDK for .NET

> **Repository status:** public standalone source; package version 0.2.0 remains unpublished.
> No package-registry release or stable-support window is promised yet.
> [Documentation](https://proudauth.com/docs/) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

First-party backend SDK for **.NET 8 or later**, version **0.2.0**, unpublished.
Apache-2.0. The solution contains two NuGet packages:

| Package | Features |
| --- | --- |
| `ProudAuth.Sdk` | Offline JWT verification, strict-online introspection, support-access guard, bounded revocation state, multi-issuer verification, OIDC/BFF and administration client |
| `ProudAuth.Sdk.AspNetCore` | ASP.NET Core authentication scheme and bearer middleware; depends on `ProudAuth.Sdk` |

RS256, PS256, ES256 and EdDSA (Ed25519) are supported. The SDK uses .NET
cryptography for ES256 and public-key import, and
[BouncyCastle.Cryptography 2.7.0](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.7.0)
for Ed25519 and RSA verification (including non-byte-aligned RSA-PSS keys).
RS256 requires the canonical SHA-256 DigestInfo encoding on every platform.
Invalid EC keys are skipped without disrupting valid keys in the same JWKS.
`none`, HMAC, private keys and RSA keys below 2048 bits are refused.

## Build and install

The packages have not been published to NuGet. Reference the projects directly:

```sh
dotnet add /path/to/your-app reference /path/to/proudauth-sdk-dotnet/src/ProudAuth.Sdk/ProudAuth.Sdk.csproj
dotnet add /path/to/your-api reference /path/to/proudauth-sdk-dotnet/src/ProudAuth.Sdk.AspNetCore/ProudAuth.Sdk.AspNetCore.csproj
```

Or build local NuGet packages, then install from the output directory:

```sh
dotnet restore ProudAuth.Sdk.sln --locked-mode
dotnet pack ProudAuth.Sdk.sln -c Release -o artifacts --no-restore
dotnet add /path/to/your-api package ProudAuth.Sdk.AspNetCore --version 0.2.0 --no-restore
dotnet restore /path/to/your-api --source /path/to/proudauth-sdk-dotnet/artifacts --source https://api.nuget.org/v3/index.json
```

The second source supplies Bouncy Castle.
Build/test locally with `dotnet run --project tests/ProudAuth.Sdk.Tests -c Release`, or:

```sh
dotnet restore ProudAuth.Sdk.sln --locked-mode
dotnet build ProudAuth.Sdk.sln -c Release --no-restore
dotnet run --project tests/ProudAuth.Sdk.Tests -c Release --no-build --no-restore
```

The test executable exits nonzero on failure. It runs all shared access-token
and support-operation fixtures, Go signature vectors, negative/concurrent
client tests, ASP.NET adapters and a real loopback HTTP redirect test.
CI is configured to run these checks on .NET 8 on Linux, macOS and Windows.
Local validation: **342 passed, zero failures/skips**, using .NET runtime
8.0.27 on macOS with SDK 8.0.421. Build, format verification, packaging and
installation into an ASP.NET Core consumer also pass. A separate local check
passed 15 assertions against the running ProudAuth image, including OIDC,
refresh rotation and revocation; see the historical monorepo validation record.
The live check is manual and is not part of the CI test executable.

## Pick a validation profile

| Profile | Use | Revocation exposure |
| --- | --- | --- |
| `Verifier` | Short-lived JWTs on ordinary API routes | Until token expiry plus clock skew (default 30 seconds, maximum 60) |
| `Introspector` | High-risk routes requiring authoritative state | One online check for every request; an outage denies access |
| `SupportGuard` | Opaque support/impersonation tokens | Online, actor-aware, audited before access; protected operations always denied |
| `BoundedState` + `BoundedVerifier` | Local JWT checks with bounded revocation lag | At most `MaxStaleness`; stale state denies with 503 |

Configure the exact issuer and one API audience. Check organization against
the resource's organization from your own database. `AuthzVersion` is only
a hint until compared with trusted current state. All token-only paths reject
`cnf` (including null): request-level DPoP/mTLS proof checking is not implemented.

## ASP.NET Core API

The authentication scheme works with standard authorization policies:

```csharp
using ProudAuth.Sdk;
using ProudAuth.Sdk.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IAuthenticator>(_ => new Verifier(new()
{
    Issuer = "https://id.example.com/realms/main",
    Audience = "https://api.example.com/orders"
}));
builder.Services.AddAuthentication(ProudAuthDefaults.AuthenticationScheme)
    .AddProudAuth(options => options.Realm = "orders");
builder.Services.AddAuthorization(options =>
    options.AddPolicy("orders.read", policy => policy
        .RequireAuthenticatedUser().RequireClaim("scope", "orders:read")));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/me", (HttpContext context) =>
{
    var claims = context.GetProudAuthClaims()!;
    return Results.Ok(new { claims.Subject, claims.OrgId });
}).RequireAuthorization("orders.read");
app.Run();
```

For a protected branch or an API where every downstream route requires a token,
use the middleware instead. It also maps `RequireScope` / `RequireOrganization`
exceptions raised inside a handler, before a response starts:

```csharp
app.UseProudAuth(verifier, realm: "orders", requiredScopes: ["orders:read"]);
app.MapGet("/orders/{id}", async (string id, HttpContext context) =>
{
    var order = await db.LoadOrder(id);
    context.GetProudAuthClaims()!.RequireOrganization(order.OrgId);
    return Results.Ok(order);
});
```

When using the authentication scheme, map claim-helper exceptions in your own
exception handler with `BearerAuthentication.Challenge(error)`. No tokens in
query parameters are accepted, including when a valid header is also present.
Multiple Authorization headers are refused.

| Failure | HTTP response |
| --- | --- |
| Missing token | 401, `WWW-Authenticate: Bearer` |
| Query-string token or duplicate Authorization headers | 400, `invalid_request` |
| Invalid, expired, inactive or revoked token | 401, `invalid_token` |
| Missing scope or wrong organization | 403, `insufficient_scope` |
| Support-policy denial | 403 |
| Unavailable dependency or stale revocation state | 503 |
| Missing support contract configuration | 500 |

Failure responses use `Cache-Control: no-store`. Verification exception `Code`
values match the other SDKs and are safe telemetry categories. Cancellation
requested by the caller remains an `OperationCanceledException`.

## Online validation and support access

```csharp
using var intro = new Introspector(new()
{
    Endpoint = "https://id.example.com/realms/main/oauth/introspect",
    Issuer = "https://id.example.com/realms/main",
    Audience = "https://api.example.com/orders",
    ClientId = resourceServerClientId,
    ClientSecret = resourceServerClientSecret
});
var claims = await intro.AuthenticateAsync(rawToken, cancellationToken);

var guard = new SupportGuard(new()
{
    Introspector = intro,
    Auditor = (e, ct) => auditStore.RecordSupportAccess(e, ct),
    WriteOperations = ["orders.annotate"]
});
var supportOrOrdinary = await guard.AuthorizeAnyAsync(rawToken,
    "orders.list", read: true, cancellationToken: cancellationToken);
// app.UseProudAuth(guard.Route("orders.list", read: true));
```

Every call performs exactly one introspection, with no positive cache or fallback.
`AuthorizeAsync` accepts support tokens only; `AuthorizeAnyAsync` routes by the
authoritative `token_kind`, irrespective of a token prefix.
Support writes require both `allowlisted_write` mode and an exact, case-insensitive
operation allowlist match. A write verb anywhere in an operation name overrides
`read: true`. Protected operations (credentials, payments, refunds, ownership,
secrets, deletes and purges) cannot be allowlisted. The default protected list
can be extended, never removed. Allowed and denied decisions are audited before
returning; audit failure denies access. `SupportOperations` exposes classification.

## Bounded revocation state

```csharp
using var state = new BoundedState(new()
{
    BaseUrl = "https://id.example.com",
    Realm = "main",
    Token = ct => GetServiceToken(ct), // admin audience, realm.session_events.read
    MaxStaleness = TimeSpan.FromSeconds(30)
});
await state.StartAsync(cancellationToken);
var authenticator = new BoundedVerifier(verifier, state);
// Keep state.RunAsync(applicationStopping, error => Report(error)) running
// in a BackgroundService for the application's lifetime.
```

`SyncAsync` follows all available pages, marking state fresh only on reaching
the end. A `CursorExpiredException` rewinds the cursor to retained history;
the next sync replays it and `RunAsync` does so immediately. Known revocations
survive `StartAsync` and replays never weaken them. `user.recovery_restricted`
does not revoke sessions. Stop `RunAsync` before disposing the state.

## Multiple issuers

```csharp
var multi = new MultiIssuerVerifier(new Dictionary<string, IssuerRegistration>
{
    [acmeVerifier.Issuer] = new(acmeVerifier, "acme"),
    [globexVerifier.Issuer] = new(globexVerifier, "globex")
});
var tenantClaims = await multi.VerifyTenantAsync(rawToken, cancellationToken);
```

Only explicitly registered issuers are accepted. Key application records by
`(Tenant, Claims.Subject)`, never email. The multi-issuer wrapper does not own
the registered verifiers; dispose them with your application.

## OIDC backend for frontend

```csharp
using var oidc = new OidcClient(new()
{
    Issuer = "https://id.example.com/realms/main",
    ClientId = "orders-bff",
    ClientSecret = bffClientSecret,
    RedirectUri = "https://app.example.com/callback",
    Scopes = ["openid", "orders:read"],
    Resource = "https://api.example.com/orders"
});
var login = await oidc.AuthorizationUrlAsync(cancellationToken: cancellationToken);
// Store login server-side behind an HttpOnly, Secure, SameSite cookie and redirect to login.Url.
// On callback: retrieve and REMOVE that stored AuthRequest, then:
var result = await oidc.ExchangeCodeAsync(login, callbackUrl, cancellationToken);
var session = oidc.CreateSession(result.Tokens, result.IdClaims,
    onRefresh: tokens => PersistRotatedTokens(tokens));
var accessToken = await session.AccessTokenAsync(cancellationToken: cancellationToken);
// If the API rejects that token, force one refresh:
accessToken = await session.AccessTokenAsync(rejectedToken: accessToken,
    cancellationToken: cancellationToken);
var logoutUrl = await oidc.LogoutAsync(session,
    postLogoutRedirectUri: "https://app.example.com/", cancellationToken: cancellationToken);
```

Discovery and its endpoints are pinned to the exact issuer and origin.
Callback state, duplicate parameters and RFC 9207 issuer checks precede code
exchange. ID validation checks signature, issuer, audience, `azp`, expiry,
issued-at, nonce, `at_hash` and optional maximum authentication age.
Store and consume login state once; the SDK does not supply a browser session store.

Refresh is single-flight per `Session`: canceled waiters do not abandon shared
rotation. Refresh or persistence failure clears the session with
`OidcException.Code == "reauthenticate"`; a lost response is never retried.
An in-flight refresh cannot resurrect a cleared session. Keep one Session per
browser session in one process; use sticky routing or a distributed refresh lock
across processes. Logout clears locally even if revocation fails.
`TokenSet.ToString()` is redacted and token fields are excluded from JSON;
persist the fields explicitly in your trusted server-side store.

### Using the ASP.NET Core OpenID Connect handler instead

`Microsoft.AspNetCore.Authentication.OpenIdConnect` (and Microsoft.Identity.Web
on top of it) works with ProudAuth once three options match the server's
profile. ProudAuth accepts only the `query`, `query.jwt` and `jwt` response
modes and only the authorization code flow with PKCE; the handler's default
`form_post` response mode is refused with `invalid_request`
([protocol profile, "Not supported"](https://github.com/proudauth/proudauth/blob/main/docs/protocols/oauth-oidc-profile.md)).

```csharp
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = "https://id.example.com/realms/main";
        options.ClientId = "orders-bff";
        options.ClientSecret = bffClientSecret;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.UsePkce = true;
        options.Scope.Add("orders:read");
    });
```

This guidance follows the published profile; no automated test in this
repository or in the service exercises the ASP.NET Core handler against
ProudAuth yet.

## Administration

```csharp
using var admin = new AdminClient(new()
{
    BaseUrl = "https://id.example.com",
    Realm = "main",
    Token = ct => GetAdminAccessToken(ct),
    OnDeprecated = notice => ReportDeprecation(notice)
});
await foreach (var user in admin.UsersAsync("ann", cancellationToken: cancellationToken))
    Console.WriteLine(user.Id);
var existing = await admin.GetUserAsync(userId, cancellationToken: cancellationToken);
await admin.UpdateUserAsync(userId, new { display_name = "Anna" },
    new RequestOptions { IfMatch = existing.ETag }, cancellationToken);
var created = await admin.CreateClientAsync(new { name = "orders", client_type = "confidential" },
    cancellationToken: cancellationToken);
var secret = (Secret)created["client_secret"]!;
await SaveSecret(secret.Reveal());
```

Helpers cover users, organizations, memberships, invitations, roles, clients,
sessions, resource grants, support grants, effective permissions and audit events.
`RequestAsync` covers other realm-relative APIs; `PagesAsync` and `ListAsync`
follow opaque cursors and reject loops. `User` and `Organization` are typed
records; extension fields and other resource results use `AdminObject`, with
`String`, `Integer`, `Array` and dictionary accessors.
`ProblemException` preserves RFC 9457 fields, validation errors, request ID and
response headers. `AdminRequestException` carries safe transport categories.
No request is automatically retried. Save and reuse `IdempotencyKey` for retries;
create-user, create-organization and invitation helpers generate one if omitted.
All requests send `ProudAuth-SDK: dotnet/0.2.0`. Deprecation callbacks omit query
strings. Deadlines cover both token acquisition and response body reads.

One-time secret members are recursively wrapped in `Secret`, including arrays
and objects under those members. `Reveal()` explicitly returns the value;
string conversion, debugger display and JSON serialization emit `[REDACTED]`.
See the shared [compatibility policy](https://proudauth.com/docs/integrations/sdk-compatibility/).

## HTTP transport and ownership

Clients are reusable and thread-safe. Reuse verifiers to share their bounded,
coalesced JWKS cache. The SDK-owned HttpClient disables redirects and applies
per-operation deadlines and body limits. Injected HttpClients remain owned by
the caller and **must use a handler with `AllowAutoRedirect = false`**; the SDK
cannot stop a custom handler from forwarding credentials before it returns.
Dispose SDK clients after their in-flight calls finish. Use HTTPS in production;
HTTP is accepted for local development. The core package does not require the
ASP.NET Core shared framework.
