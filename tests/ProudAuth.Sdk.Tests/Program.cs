using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ProudAuth.Sdk;
using ProudAuth.Sdk.AspNetCore;
using ProudAuth.Sdk.Internal;

// SDK-001, SDK-002, SDK-003, SDK-004, SDK-007, SDK-008, SDK-009, SDK-011, INT-009:
// No test-framework dependency. Exit nonzero on any failed case; fixtures are shared with the other SDKs.
var suite = new Suite();
await suite.RunAsync();
return suite.Failures == 0 ? 0 : 1;

internal sealed class Suite
{
    private const string Issuer = "https://id.example.test/realms/main", Audience = "https://api.example.test/orders";
    private readonly Clock clock = new(DateTimeOffset.FromUnixTimeSeconds(2000000000));
    private readonly RSA rsa = RSA.Create(2048);
    private int passed;
    internal int Failures { get; private set; }
    private JsonElement Jwk
    {
        get
        {
            var p = rsa.ExportParameters(false);
            return JsonSerializer.SerializeToElement(new { kid = "test", kty = "RSA", alg = "RS256", use = "sig", n = Jose.Encode(p.Modulus!), e = Jose.Encode(p.Exponent!) });
        }
    }
    private Dictionary<string, object?> Payload() => new()
    {
        ["iss"] = Issuer,
        ["sub"] = "usr_one",
        ["aud"] = Audience,
        ["client_id"] = "orders",
        ["jti"] = "jti_one",
        ["token_kind"] = "user_access",
        ["scope"] = "orders:read orders:write",
        ["org_id"] = "org_one",
        ["sid"] = "ses_one",
        ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds(),
        ["exp"] = clock.GetUtcNow().ToUnixTimeSeconds() + 300
    };
    private string Sign(Dictionary<string, object?>? payload = null, object? header = null, string algorithm = "RS256")
    {
        var h = Jose.Encode(JsonSerializer.SerializeToUtf8Bytes(header ?? new { alg = algorithm, typ = "at+jwt", kid = "test" }));
        var p = Jose.Encode(JsonSerializer.SerializeToUtf8Bytes(payload ?? Payload()));
        var input = Encoding.ASCII.GetBytes(h + "." + p);
        return h + "." + p + "." + Jose.Encode(rsa.SignData(input, HashAlgorithmName.SHA256, algorithm == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1));
    }
    private static HttpResponseMessage Response(object? body, int status = 200) => new((HttpStatusCode)status)
    {
        Content = new StringContent(body is string s ? s : JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
    };
    private HttpClient KeyClient() => new(new Handler((_, _) => Task.FromResult(Response(new { keys = new[] { Jwk } }))));
    private Verifier NewVerifier(HttpClient client, TimeProvider? time = null) => new(new() { Issuer = Issuer, Audience = Audience, HttpClient = client, TimeProvider = time ?? clock });
    private Introspector NewIntrospector(HttpClient client) => new(new()
    {
        Endpoint = Issuer + "/oauth/introspect",
        Issuer = Issuer,
        Audience = Audience,
        ClientId = "orders+:",
        ClientSecret = "fake secret&:",
        HttpClient = client
    });
    private Dictionary<string, object?> SupportPayload(string mode = "read_only")
    {
        var p = Payload(); p["active"] = true; p["token_kind"] = "impersonation_access"; p["act"] = new { sub = "usr_admin", iss = Issuer };
        p["impersonation_grant_id"] = "grant_one"; p["support_mode"] = mode; return p;
    }
    private async Task Test(string name, Func<Task> run)
    {
        try { await run(); passed++; Console.WriteLine($"PASS {name}"); }
        catch (Exception e) { Failures++; Console.WriteLine($"FAIL {name}: {e.GetType().Name} {e.Message}"); }
    }
    private static void Equal<T>(T expected, T actual)
    { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"expected {expected}, received {actual}"); }
    private static void True(bool value) { if (!value) throw new Exception("assertion failed"); }
    private static async Task Error(string code, Func<Task> run)
    {
        try { await run(); }
        catch (VerifierException e) { Equal(code, e.Code); return; }
        throw new Exception("expected verifier denial: " + code);
    }
    private static async Task OidcError(string code, Func<Task> run)
    {
        try { await run(); }
        catch (OidcException e) { Equal(code, e.Code); return; }
        throw new Exception("expected OIDC denial: " + code);
    }
    private static async Task AdminError(string code, Func<Task> run)
    {
        try { await run(); }
        catch (AdminRequestException e) { Equal(code, e.Code); return; }
        throw new Exception("expected admin error: " + code);
    }
    private static async Task Throws<T>(Func<Task> run) where T : Exception
    { try { await run(); } catch (T) { return; } throw new Exception("expected " + typeof(T).Name); }
    private static JsonElement Load(string path) => Json.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, path)));
    internal async Task RunAsync()
    {
        await Fixtures(); await VerifierTests(); await IntrospectionTests(); await BoundedTests(); await OidcTests(); await AdminTests(); await AspNetTests(); await TransportTests();
        rsa.Dispose();
        Console.WriteLine($"{passed} passed, {Failures} failed, 0 skipped");
    }
    private async Task Fixtures()
    {
        var fixtures = Load("fixtures/access-tokens/cases.json");
        using var client = new HttpClient(new Handler((_, _) => Task.FromResult(Response(fixtures.Get("jwks")))));
        using var verifier = new Verifier(new()
        {
            Issuer = fixtures.Str("issuer"),
            Audience = fixtures.Str("audience"),
            HttpClient = client,
            TimeProvider = new Clock(DateTimeOffset.FromUnixTimeSeconds((long)fixtures.Num("now")!))
        });
        foreach (var item in fixtures.Get("cases").EnumerateArray())
            await Test("shared access token: " + item.Str("name"), async () =>
            {
                if (item.Str("expect") == "accept") { var c = await verifier.VerifyAsync(item.Str("token")); True(!c.Online); }
                else await Error(item.Str("expect"), () => verifier.VerifyAsync(item.Str("token")));
            });
        var jwt = Load("vectors/jwt.json");
        using var jwtClient = new HttpClient(new Handler((_, _) => Task.FromResult(Response(jwt.Get("jwks")))));
        using var jwtVerifier = new Verifier(new()
        {
            Issuer = jwt.Str("issuer"),
            Audience = jwt.Str("audience"),
            HttpClient = jwtClient,
            TimeProvider = new Clock(DateTimeOffset.FromUnixTimeSeconds((long)jwt.Num("now")!))
        });
        foreach (var item in jwt.Get("cases").EnumerateArray())
            await Test("Go-signed JWT: " + item.Str("name"), async () =>
            {
                if (item.Str("expect") == "accept") await jwtVerifier.VerifyAsync(item.Str("token"));
                else await Error(item.Str("expect"), () => jwtVerifier.VerifyAsync(item.Str("token")));
            });
        foreach (var file in new[] { "rs256", "ps256", "es256", "ed25519" })
        {
            var vectors = Load("vectors/" + file + ".json"); var alg = vectors.Str("algorithm"); var keys = vectors.Get("keys");
            foreach (var k in keys.EnumerateObject()) await Test(file + " import: " + k.Name, () => { True(Jose.Usable(k.Value)); return Task.CompletedTask; });
            foreach (var v in vectors.Get("cases").EnumerateArray())
                await Test(file + " signature: " + v.Str("name"), () =>
                {
                    var key = keys.Get(v.Str("kid"));
                    Equal(v.Get("valid").GetBoolean(), Jose.Verify(alg, key, new(default, default, Convert.FromHexString(v.Str("msg")), Convert.FromHexString(v.Str("sig")))));
                    return Task.CompletedTask;
                });
            if (vectors.Get("invalid_keys").ValueKind == JsonValueKind.Array)
                foreach (var k in vectors.Get("invalid_keys").EnumerateArray()) await Test(file + " rejects key: " + k.Str("name"), () => { True(!Jose.Usable(k.Get("jwk"))); return Task.CompletedTask; });
        }
        var support = Load("fixtures/support-operations/cases.json");
        foreach (var item in support.Get("classification_only").EnumerateArray().Concat(support.Get("cases").EnumerateArray()))
            await Test("support classification: " + item.Str("operation"), () =>
            {
                Equal(item.Get("protected").GetBoolean(), SupportOperations.IsProtectedOperation(item.Str("operation")));
                Equal(item.Get("write").GetBoolean(), SupportOperations.IsWriteOperation(item.Str("operation"))); return Task.CompletedTask;
            });
        foreach (var item in support.Get("cases").EnumerateArray())
            await Test("shared support decision: " + item.Str("operation"), async () =>
            {
                using var c = new HttpClient(new Handler((_, _) => Task.FromResult(Response(SupportPayload(item.Str("support_mode"))))));
                using var intro = NewIntrospector(c); SupportEvent? recorded = null;
                var guard = new SupportGuard(new()
                {
                    Introspector = intro,
                    Auditor = (ev, _) => { recorded = ev; return Task.CompletedTask; },
                    WriteOperations = support.Get("write_operations").EnumerateArray().Select(x => x.GetString()!).ToArray()
                });
                var expect = item.Str("expect");
                if (expect == "allow") await guard.AuthorizeAsync("opaque", item.Str("operation"), item.Get("read").GetBoolean());
                else await Error("support_policy", () => guard.AuthorizeAsync("opaque", item.Str("operation"), item.Get("read").GetBoolean()));
                True(recorded is not null); Equal(expect == "allow", recorded!.Allowed); Equal(expect == "allow" ? null : expect, recorded.DenyReason);
                Equal("usr_admin", recorded.Actor);
            });
    }
    private async Task VerifierTests()
    {
        await Test("claims helpers enforce trusted organization and scopes", async () =>
        {
            using var http = KeyClient(); using var v = NewVerifier(http); var c = await v.VerifyAsync(Sign());
            c.RequireScope("orders:read"); c.RequireOrganization("org_one");
            await Error("scope", () => { c.RequireScope("admin"); return Task.CompletedTask; });
            await Error("organization", () => { c.RequireOrganization("org_other"); return Task.CompletedTask; });
        });
        await Test("issuer rejected before network and jku ignored", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler((r, _) => { calls++; Equal(Issuer + "/jwks", r.RequestUri!.AbsoluteUri); return Task.FromResult(Response(new { keys = new[] { Jwk } })); }));
            using var v = NewVerifier(http); var p = Payload(); p["iss"] = "https://evil.test";
            await Error("issuer", () => v.VerifyAsync(Sign(p))); Equal(0, calls);
            await v.VerifyAsync(Sign(header: new { alg = "RS256", typ = "at+jwt", kid = "test", jku = "https://evil.test/jwks" })); Equal(1, calls);
        });
        await Test("JWKS refresh coalesced and random kids rate limited", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler(async (_, ct) => { Interlocked.Increment(ref calls); await Task.Delay(15, ct); return Response(new { keys = new[] { Jwk } }); }));
            using var v = NewVerifier(http); var token = Sign(); await Task.WhenAll(Enumerable.Range(0, 30).Select(_ => v.VerifyAsync(token))); Equal(1, calls);
            var unknown = Sign(header: new { alg = "RS256", typ = "at+jwt", kid = "unknown" });
            for (var i = 0; i < 10; i++) await Error("unknown_key", () => v.VerifyAsync(unknown)); Equal(1, calls);
        });
        await Test("JWKS rotation removes retired keys and failure preserves known keys", async () =>
        {
            var time = new Clock(clock.GetUtcNow()); var body = Response(new { keys = new[] { Jwk } }); var mode = 0;
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(mode switch { 0 => Response(new { keys = new[] { Jwk } }), 1 => Response("bad", 503), _ => Response(new { keys = Array.Empty<object>() }) })));
            using var v = NewVerifier(http, time); var token = Sign(); await v.VerifyAsync(token); mode = 1; time.Advance(31);
            await Error("unknown_key", () => v.VerifyAsync(Sign(header: new { alg = "RS256", typ = "at+jwt", kid = "new" })));
            await v.VerifyAsync(token); mode = 2; time.Advance(31);
            await Error("unknown_key", () => v.VerifyAsync(Sign(header: new { alg = "RS256", typ = "at+jwt", kid = "new" })));
            await Error("unknown_key", () => v.VerifyAsync(token)); body.Dispose();
        });
        await Test("canceling a JWKS waiter leaves shared fetch intact", async () =>
        {
            using var http = new HttpClient(new Handler(async (_, ct) => { await Task.Delay(40, ct); return Response(new { keys = new[] { Jwk } }); }));
            using var v = NewVerifier(http); using var cancellation = new CancellationTokenSource();
            var first = v.VerifyAsync(Sign(), cancellation.Token); var second = v.VerifyAsync(Sign()); cancellation.Cancel();
            await Throws<OperationCanceledException>(() => first); await second; Equal(1, v.FetchCount);
        });
        await Test("duplicate nested and escaped members are rejected", async () =>
        {
            using var http = KeyClient(); using var v = NewVerifier(http);
            var header = Jose.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"test\"}"));
            foreach (var p in new[] { "{\"iss\":\"a\",\"\\u0069ss\":\"b\"}", "{\"act\":{\"sub\":\"a\",\"sub\":\"b\"}}" })
                await Error("duplicate_claim", () => v.VerifyAsync(header + "." + Jose.Encode(Encoding.UTF8.GetBytes(p)) + ".AA"));
        });
        foreach (var (claim, value, expected) in new (string, object?, string)[] {
            ("aud", new[] { Audience, "other" }, "audience"), ("exp", 1L, "expired"), ("nbf", 2000001000L, "not_yet_valid"),
            ("iat", 2000001000L, "future_issued"), ("token_kind", "impersonation_access", "token_kind"), ("cnf", null, "sender_constraint") })
            await Test("verifier denies " + expected, async () => { using var http = KeyClient(); using var v = NewVerifier(http); var p = Payload(); p[claim] = value; await Error(expected, () => v.VerifyAsync(Sign(p))); });
        await Test("multi-issuer registrations reject foreign issuers", async () =>
        {
            using var http = KeyClient(); using var v = NewVerifier(http); var multi = new MultiIssuerVerifier(new Dictionary<string, IssuerRegistration> { [Issuer] = new(v, "tenant_one") });
            Equal("tenant_one", (await multi.VerifyTenantAsync(Sign())).Tenant);
            var p = Payload(); p["iss"] = "https://other.test"; await Error("issuer", () => multi.VerifyTenantAsync(Sign(p)));
            await Throws<ArgumentException>(() => { _ = new MultiIssuerVerifier(new Dictionary<string, IssuerRegistration> { ["other"] = new(v, "tenant_one") }); return Task.CompletedTask; });
        });
        await Test("configuration refuses support and symmetric algorithms", async () =>
        {
            await Throws<ArgumentException>(() => { using var v = new Verifier(new() { Issuer = Issuer, Audience = Audience, AcceptedKinds = ["impersonation_access"] }); return Task.CompletedTask; });
            await Throws<ArgumentException>(() => { using var v = new Verifier(new() { Issuer = Issuer, Audience = Audience, Algorithms = ["HS256"] }); return Task.CompletedTask; });
        });
        await Test("key set outages fail closed", async () => { using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response("bad", 503)))); using var v = NewVerifier(http); await Error("unavailable", () => v.VerifyAsync(Sign())); });
        await Test("private and ambiguous signing keys never accepted", async () =>
        {
            var privateKey = JsonSerializer.Deserialize<Dictionary<string, object?>>(Jwk.GetRawText())!; privateKey["d"] = "AA";
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new { keys = new object[] { privateKey, Jwk, Jwk } }))));
            using var v = NewVerifier(http); await Error("unknown_key", () => v.VerifyAsync(Sign()));
        });
    }
    private async Task IntrospectionTests()
    {
        await Test("introspection basic credentials form encoded; no positive cache", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler(async (r, _) =>
            {
                calls++; Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("orders%2B%3A:fake+secret%26%3A")), r.Headers.GetValues("Authorization").Single());
                Equal("token=opaque", await r.Content!.ReadAsStringAsync()); var p = Payload(); p["active"] = calls == 1; return Response(p);
            }));
            using var intro = NewIntrospector(http); True((await intro.AuthenticateAsync("opaque")).Online);
            await Error("inactive", () => intro.AuthenticateAsync("opaque")); Equal(2, calls);
        });
        foreach (var body in new[] { "{\"active\":true,\"active\":false}", "garbage", "[]" })
            await Test("malformed introspection fails closed " + body.Length, async () => { using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(body)))); using var intro = NewIntrospector(http); await Error("unavailable", () => intro.AuthenticateAsync("opaque")); });
        await Test("ordinary routes reject support regardless of prefix", async () => { using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(SupportPayload())))); using var intro = NewIntrospector(http); await Error("token_kind", () => intro.AuthenticateAsync("ordinary-prefix")); });
        await Test("support audit failure denies access", async () =>
        {
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(SupportPayload())))); using var intro = NewIntrospector(http);
            var guard = new SupportGuard(new() { Introspector = intro, Auditor = (_, _) => throw new IOException("audit down") });
            await Error("unavailable", () => guard.AuthorizeAnyAsync("opaque", "orders.list", true));
        });
        await Test("missing support actor denied and ordinary guard uses one call", async () =>
        {
            var p = SupportPayload(); p.Remove("act"); var calls = 0;
            using var http = new HttpClient(new Handler((_, _) => { calls++; return Task.FromResult(Response(p)); })); using var intro = NewIntrospector(http);
            var guard = new SupportGuard(new() { Introspector = intro, Auditor = (_, _) => throw new Exception("ordinary must not audit") });
            await Error("token_kind", () => guard.AuthorizeAsync("opaque", "orders.list", true));
            p = Payload(); p["active"] = true; await guard.AuthorizeAnyAsync("pa_it_fake", "orders.list", true); Equal(2, calls);
        });
        await Test("online bound token rejected even null cnf", async () =>
        {
            var p = Payload(); p["active"] = true; p["cnf"] = null;
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(p)))); using var intro = NewIntrospector(http);
            await Error("sender_constraint", () => intro.AuthenticateAsync("opaque"));
        });
    }
    private async Task BoundedTests()
    {
        await Test("partially replayed backlog cannot mark bounded state fresh", async () =>
        {
            var time = new Clock(clock.GetUtcNow()); var backlog = false; var pages = 0;
            using var keys = KeyClient(); using var verifier = NewVerifier(keys, time); var claims = await verifier.VerifyAsync(Sign());
            var events = Enumerable.Range(0, 500).Select(_ => new { event_type = "user.recovery_restricted", occurred_at = time.GetUtcNow().ToString("O"), data = new { user_id = "usr_one" } }).ToArray();
            using var http = new HttpClient(new Handler((_, _) => { pages++; return Task.FromResult(Response(new { next_cursor = "cursor_" + pages, events = backlog ? events : [] })); }));
            using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), TimeProvider = time, HttpClient = http });
            await state.StartAsync(); time.Advance(61); backlog = true; await state.SyncAsync(); Equal(101, pages);
            await Error("stale_state", () => { state.Check(claims); return Task.CompletedTask; });
            backlog = false; await state.SyncAsync(); state.Check(claims);
        });
        await Test("older replay cannot weaken a subject revocation", async () =>
        {
            var at = clock.GetUtcNow().AddSeconds(10); var p = Payload(); p["iat"] = clock.GetUtcNow().ToUnixTimeSeconds() + 5;
            using var keys = KeyClient(); using var verifier = NewVerifier(keys); var claims = await verifier.VerifyAsync(Sign(p));
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new { next_cursor = "next", events = new[] { new { event_type = "user.suspended", occurred_at = at.ToString("O"), data = new { user_id = "usr_one" } } } }))));
            using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), TimeProvider = clock, HttpClient = http });
            await state.SyncAsync(); at = at.AddSeconds(-20); await state.SyncAsync();
            await Error("revoked", () => { state.Check(claims); return Task.CompletedTask; });
        });
        await Test("bounded state stale, revoked, restart and cursor-expiry replay", async () =>
        {
            var time = new Clock(clock.GetUtcNow()); var mode = 0; var rewound = false;
            using var http = new HttpClient(new Handler((r, _) =>
            {
                if (r.RequestUri!.AbsolutePath.EndsWith("jwks", StringComparison.Ordinal)) return Task.FromResult(Response(new { keys = new[] { Jwk } }));
                if (mode == 2) { mode = 3; return Task.FromResult(Response(new { }, 410)); }
                if (mode == 3) { True(r.RequestUri.Query.Contains("cursor=&", StringComparison.Ordinal)); rewound = true; }
                return Task.FromResult(Response(new { next_cursor = "next", events = mode == 1 ? new[] { new { event_type = "session.revoked", occurred_at = time.GetUtcNow().ToString("O"), data = new { session_id = "ses_one" } } } : [] }));
            }));
            using var v = NewVerifier(http, time); using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), TimeProvider = time, HttpClient = http });
            var c = await v.VerifyAsync(Sign()); await Error("stale_state", () => { state.Check(c); return Task.CompletedTask; });
            await state.StartAsync(); state.Check(c); mode = 1; await state.SyncAsync(); await Error("revoked", () => { state.Check(c); return Task.CompletedTask; });
            mode = 0; await state.StartAsync(); await Error("revoked", () => new BoundedVerifier(v, state).AuthenticateAsync(Sign()));
            mode = 2; await Throws<CursorExpiredException>(() => state.SyncAsync()); await state.SyncAsync(); True(rewound);
            time.Advance(61); await Error("stale_state", () => { state.Check(c); return Task.CompletedTask; });
        });
        await Test("bounded subject member org events and recovery restriction", async () =>
        {
            using var key = KeyClient(); using var v = NewVerifier(key); var claims = await v.VerifyAsync(Sign());
            foreach (var kind in new[] { "user.recovery_restricted", "user.suspended", "security.refresh_reuse_detected", "organization.suspended", "authorization.role.unassigned" })
            {
                using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new
                {
                    next_cursor = "next",
                    events = new[] {
                    new { event_type = kind, occurred_at = clock.GetUtcNow().ToString("O"), organization_id = "org_one", data = new { user_id = "usr_one", subject_id = "usr_one" } } }
                }))));
                using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), TimeProvider = clock, HttpClient = http });
                await state.SyncAsync();
                if (kind == "user.recovery_restricted") state.Check(claims);
                else await Error("revoked", () => { state.Check(claims); return Task.CompletedTask; });
            }
        });
        await Test("bounded malformed event cannot mark state fresh", async () =>
        {
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new { next_cursor = "next", events = new[] { new { event_type = "session.revoked", occurred_at = "invalid" } } }))));
            using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), HttpClient = http });
            await Error("unavailable", () => state.SyncAsync());
        });
        await Test("bounded runner cancellation stops poll immediately", async () =>
        {
            using var http = new HttpClient(new Handler(async (_, ct) => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); throw new Exception(); }));
            using var state = new BoundedState(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), MaxStaleness = TimeSpan.FromSeconds(60), HttpClient = http });
            using var ct = new CancellationTokenSource(30); await state.RunAsync(ct.Token).WaitAsync(TimeSpan.FromSeconds(2));
        });
    }
    private object Metadata(string? tokenEndpoint = null) => new
    {
        issuer = Issuer,
        authorization_endpoint = Issuer + "/oauth/authorize",
        token_endpoint = tokenEndpoint ?? Issuer + "/oauth/token",
        jwks_uri = Issuer + "/jwks",
        revocation_endpoint = Issuer + "/oauth/revoke",
        end_session_endpoint = Issuer + "/oauth/logout",
        authorization_response_iss_parameter_supported = true
    };
    private OidcClient NewOidc(HttpClient http) => new(new() { Issuer = Issuer, ClientId = "bff", ClientSecret = "fake", RedirectUri = "https://app.example.test/callback", Resource = Audience, TimeProvider = clock, HttpClient = http });
    private string IdToken(string nonce, string accessToken, string subject = "usr_one", object? audience = null, string? azp = null, string? hash = null)
    {
        var p = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = subject,
            ["aud"] = audience ?? "bff",
            ["exp"] = clock.GetUtcNow().ToUnixTimeSeconds() + 300,
            ["iat"] = clock.GetUtcNow().ToUnixTimeSeconds(),
            ["nonce"] = nonce,
            ["at_hash"] = hash ?? OidcClient.HalfHash("RS256", accessToken)
        };
        if (azp is not null) p["azp"] = azp;
        return Sign(p, new { alg = "RS256", typ = "JWT", kid = "test" });
    }
    private async Task OidcTests()
    {
        await Test("OIDC PKCE state nonce exchange and ID validation", async () =>
        {
            AuthRequest? ar = null; var tokenCalls = 0;
            using var http = new HttpClient(new Handler(async (r, _) =>
            {
                if (r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal)) return Response(Metadata());
                if (r.RequestUri.AbsolutePath.EndsWith("jwks", StringComparison.Ordinal)) return Response(new { keys = new[] { Jwk } });
                tokenCalls++; var fields = OidcClient.ParseQuery(await r.Content!.ReadAsStringAsync());
                Equal(ar!.CodeVerifier, fields["code_verifier"].Single()); Equal("authorization_code", fields["grant_type"].Single());
                return Response(new { access_token = "access", refresh_token = "refresh", token_type = "Bearer", expires_in = 300, id_token = IdToken(ar.Nonce, "access") });
            }));
            using var oidc = NewOidc(http); ar = await oidc.AuthorizationUrlAsync(); var q = OidcClient.ParseQuery(ar.Url);
            Equal("S256", q["code_challenge_method"].Single()); Equal(OidcClient.PkceChallenge(ar.CodeVerifier), q["code_challenge"].Single()); Equal(Audience, q["resource"].Single());
            var result = await oidc.ExchangeCodeAsync(ar, "?state=" + ar.State + "&code=fake&iss=" + Uri.EscapeDataString(Issuer));
            Equal("usr_one", result.IdClaims!.Subject); Equal("access", result.Tokens.AccessToken); Equal(1, tokenCalls);
            True(!JsonSerializer.Serialize(result.Tokens).Contains("refresh", StringComparison.OrdinalIgnoreCase));
            await OidcError("state", () => oidc.ExchangeCodeAsync(ar, "?state=wrong&code=fake")); Equal(1, tokenCalls);
            await OidcError("provider", () => oidc.ExchangeCodeAsync(ar, "?state=" + ar.State + "&code=fake")); Equal(1, tokenCalls);
            await OidcError("provider", () => oidc.ExchangeCodeAsync(ar, "?state=" + ar.State + "&iss=" + Uri.EscapeDataString(Issuer) + "&code=a&code=b"));
            await Throws<ArgumentException>(() => oidc.AuthorizationUrlAsync(new Dictionary<string, string> { ["state"] = "override" }));
        });
        await Test("OIDC nonce at_hash audience azp and access-token type denied", async () =>
        {
            using var http = new HttpClient(new Handler((r, _) => Task.FromResult(r.RequestUri!.AbsolutePath.EndsWith("jwks", StringComparison.Ordinal) ? Response(new { keys = new[] { Jwk } }) : Response(Metadata()))));
            using var oidc = NewOidc(http);
            await OidcError("nonce", () => oidc.ValidateIdTokenAsync(IdToken("wrong", "access"), "expected", "access"));
            await OidcError("id_token", () => oidc.ValidateIdTokenAsync(IdToken("n", "access", hash: "wrong"), "n", "access"));
            await OidcError("id_token", () => oidc.ValidateIdTokenAsync(IdToken("n", "access", audience: new[] { "bff", "other" }), "n"));
            await oidc.ValidateIdTokenAsync(IdToken("n", "access", audience: new[] { "bff", "other" }, azp: "bff"), "n");
            await OidcError("id_token", () => oidc.ValidateIdTokenAsync(Sign()));
            await OidcError("id_token", () => oidc.ValidateIdTokenAsync(IdToken("n", "access"), maxAgeSeconds: 60));
        });
        await Test("OIDC discovery exact issuer and same-origin endpoints", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler((_, _) => { calls++; return Task.FromResult(Response(Metadata("https://evil.test/token"))); }));
            using var oidc = NewOidc(http); var ar = await oidc.AuthorizationUrlAsync();
            await OidcError("provider", () => oidc.ExchangeCodeAsync(ar, "?state=" + ar.State + "&iss=" + Uri.EscapeDataString(Issuer) + "&code=fake")); Equal(1, calls);
        });
        await Test("OIDC refresh coalesced with canceled waiter and rejected-token retry", async () =>
        {
            var refreshes = 0; var persisted = 0;
            using var http = new HttpClient(new Handler(async (r, ct) =>
            {
                if (r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal)) return Response(Metadata());
                refreshes++; await Task.Delay(30, ct); return Response(new { access_token = "next", refresh_token = "rotated", expires_in = 300, token_type = "Bearer" });
            }));
            using var oidc = NewOidc(http); var session = oidc.CreateSession(new("old", "Bearer", 1, clock.GetUtcNow(), "refresh"), onRefresh: _ => { persisted++; return Task.CompletedTask; });
            using var ct = new CancellationTokenSource(); var canceled = session.AccessTokenAsync(cancellationToken: ct.Token);
            var others = Enumerable.Range(0, 20).Select(_ => session.AccessTokenAsync()).ToArray(); ct.Cancel();
            await Throws<OperationCanceledException>(() => canceled); foreach (var t in await Task.WhenAll(others)) Equal("next", t);
            Equal(1, refreshes); Equal(1, persisted); Equal("rotated", session.Tokens!.RefreshToken);
            await session.AccessTokenAsync(rejectedToken: "old"); Equal(1, refreshes);
            await session.AccessTokenAsync(rejectedToken: "next"); Equal(2, refreshes);
        });
        await Test("failed refresh clears session and cannot retry old token", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler((r, _) =>
            {
                if (r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal)) return Task.FromResult(Response(Metadata()));
                calls++; return Task.FromResult(Response(new { error = "invalid_grant" }, 400));
            }));
            using var oidc = NewOidc(http); var session = oidc.CreateSession(new("old", "Bearer", 0, clock.GetUtcNow(), "refresh"));
            await OidcError("reauthenticate", () => session.AccessTokenAsync()); await OidcError("reauthenticate", () => session.AccessTokenAsync()); Equal(1, calls); True(session.Tokens is null);
        });
        await Test("logout during refresh cannot resurrect session", async () =>
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var http = new HttpClient(new Handler(async (r, _) =>
            {
                if (r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal)) return Response(Metadata());
                entered.SetResult(); await release.Task; return Response(new { access_token = "next", refresh_token = "rotated", expires_in = 300, token_type = "Bearer" });
            }));
            using var oidc = NewOidc(http); var session = oidc.CreateSession(new("old", "Bearer", 0, clock.GetUtcNow(), "refresh"));
            var task = session.AccessTokenAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); session.Clear(); release.SetResult();
            await OidcError("reauthenticate", () => task); True(session.Tokens is null);
        });
        await Test("persistence failure clears rotated session", async () =>
        {
            using var http = new HttpClient(new Handler((r, _) => Task.FromResult(r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal) ? Response(Metadata()) : Response(new { access_token = "next", expires_in = 300, token_type = "Bearer" }))));
            using var oidc = NewOidc(http); var session = oidc.CreateSession(new("old", "Bearer", 0, clock.GetUtcNow(), "refresh"), onRefresh: _ => throw new IOException());
            await OidcError("reauthenticate", () => session.AccessTokenAsync()); True(session.Tokens is null);
        });
        await Test("logout clears locally even if revocation fails", async () =>
        {
            using var http = new HttpClient(new Handler((r, _) => Task.FromResult(r.RequestUri!.AbsolutePath.EndsWith("openid-configuration", StringComparison.Ordinal) ? Response(Metadata()) : Response("bad", 503))));
            using var oidc = NewOidc(http); var session = oidc.CreateSession(new("old", "Bearer", 300, clock.GetUtcNow().AddMinutes(5), "refresh"));
            await OidcError("provider", () => oidc.LogoutAsync(session)); True(session.Tokens is null);
        });
    }
    private async Task AdminTests()
    {
        await Test("admin typed user idempotency ETag and secret redaction", async () =>
        {
            using var http = new HttpClient(new Handler((r, _) =>
            {
                Equal("dotnet/0.2.0", r.Headers.GetValues("ProudAuth-SDK").Single());
                Equal("Bearer fake", r.Headers.GetValues("Authorization").Single()); Equal("proudauth-sdk-dotnet/0.2.0", r.Headers.UserAgent.ToString());
                if (r.Method == HttpMethod.Post) True(r.Headers.Contains("Idempotency-Key"));
                if (r.Method == HttpMethod.Patch) Equal("\"v1\"", r.Headers.GetValues("If-Match").Single());
                var response = Response(new { id = "usr_one", version = 1, client_secret = "do-not-log", nested = new { recovery_codes = new[] { "recovery" } } }); response.Headers.ETag = new("\"v1\""); return Task.FromResult(response);
            }));
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", Token = _ => Task.FromResult("fake"), HttpClient = http });
            var data = await admin.CreateUserAsync(new { email = "fake@example.test" }); var secret = (Secret)data["client_secret"]!;
            Equal("do-not-log", secret.Reveal()); Equal("[REDACTED]", secret.ToString()); True(!JsonSerializer.Serialize(data).Contains("do-not-log", StringComparison.Ordinal));
            var user = await admin.GetUserAsync("usr_one"); Equal("usr_one", user.Data.Id); Equal("\"v1\"", user.ETag);
            await admin.UpdateUserAsync("usr_one", new { display_name = "New" }, new() { IfMatch = user.ETag });
        });
        await Test("admin cursor pagination and loop detection", async () =>
        {
            var calls = 0; using var http = new HttpClient(new Handler((r, _) => { calls++; if (calls > 1) True(r.RequestUri!.Query.Contains("cursor=opaque", StringComparison.Ordinal)); return Task.FromResult(Response(new { items = new[] { new { id = "usr_" + calls } }, next_cursor = calls == 1 ? "opaque" : "" })); }));
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = http });
            var count = 0; await foreach (var user in admin.UsersAsync()) { count++; Equal("usr_" + count, user.Id); }
            Equal(2, count);
            using var loopHttp = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new { items = Array.Empty<object>(), next_cursor = "loop" }))));
            using var loop = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = loopHttp });
            await AdminError("invalid_response", async () => { await foreach (var _ in loop.ListAsync("/users")) { } });
        });
        await Test("admin RFC 9457 headers and deprecation omit search data", async () =>
        {
            DeprecationNotice? notice = null; using var http = new HttpClient(new Handler((_, _) => { var r = Response(new { code = "conflict", title = "Conflict", detail = "changed", errors = new { email = "taken" }, request_id = "req_one" }, 409); r.Headers.Add("Deprecation", "@1"); r.Headers.Add("Retry-After", "30"); return Task.FromResult(r); }));
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = http, OnDeprecated = n => notice = n });
            try { await admin.RequestAsync("GET", "/users?q=private"); throw new Exception("expected conflict"); }
            catch (ProblemException e) { Equal(409, e.Status); Equal("conflict", e.Code); Equal("req_one", e.RequestId); Equal("taken", e.Errors!.String("email")); Equal("30", e.Headers["Retry-After"]); }
            Equal("/users", notice!.Path);
        });
        await Test("admin deadlines include token source", async () =>
        {
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", Timeout = TimeSpan.FromMilliseconds(30), Token = async ct => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return "fake"; } });
            await AdminError("timeout", () => admin.RequestAsync("GET", "/users?q=private"));
            using var ct = new CancellationTokenSource(); ct.Cancel(); await AdminError("aborted", () => admin.RequestAsync("GET", "/users", cancellationToken: ct.Token));
        });
        await Test("admin rejects malformed JSON and traversal", async () =>
        {
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response("{\"id\":1,\"id\":2}"))));
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = http });
            await AdminError("invalid_response", () => admin.RequestAsync("GET", "/users"));
            foreach (var path in new[] { "/../other", "/%2e%2e/other", "//evil.test", "/users\\../other" }) await Throws<ArgumentException>(() => admin.RequestAsync("GET", path));
        });
    }
    private async Task AspNetTests()
    {
        await Test("ASP.NET real authorization policy gives 401 403 and 503", async () =>
        {
            using var keys = KeyClient(); using var verifier = NewVerifier(keys);
            var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Services.AddAuthentication(ProudAuthDefaults.AuthenticationScheme).AddProudAuth(o => o.Authenticator = new FailureAuthenticator(verifier));
            builder.Services.AddAuthorization(o => o.AddPolicy("read", p => p.RequireAuthenticatedUser().RequireClaim("scope", "orders:read")));
            await using var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization();
            app.MapGet("/orders", (HttpContext c) => Results.Json(new { subject = c.GetProudAuthClaims()!.Subject })).RequireAuthorization("read");
            await app.StartAsync(); using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
            async Task<int> Status(string? token)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/orders");
                if (token is not null) request.Headers.Authorization = new("Bearer", token);
                using var response = await client.SendAsync(request); return (int)response.StatusCode;
            }
            Equal(401, await Status(null)); Equal(200, await Status(Sign())); Equal(503, await Status("unavailable"));
            var p = Payload(); p["scope"] = "other"; Equal(403, await Status(Sign(p)));
            await app.StopAsync();
        });
        await Test("ASP.NET middleware attaches principal and fails closed", async () =>
        {
            using var http = KeyClient(); using var verifier = NewVerifier(http);
            var services = new ServiceCollection().AddLogging().BuildServiceProvider();
            var app = new ApplicationBuilder(services); app.UseProudAuth(verifier, "orders", "orders:read"); var called = 0;
            app.Run(context => { called++; Equal("usr_one", context.User.FindFirst("sub")!.Value); True(context.GetProudAuthClaims() is not null); return Task.CompletedTask; });
            var pipeline = app.Build(); var context = new DefaultHttpContext(); context.Request.Headers.Authorization = "Bearer " + Sign(); await pipeline(context); Equal(1, called);
            context = new DefaultHttpContext(); await pipeline(context); Equal(401, context.Response.StatusCode); Equal("no-store", context.Response.Headers.CacheControl.ToString()); Equal(1, called);
            context = new DefaultHttpContext(); context.Request.Headers.Authorization = "Bearer " + Sign(); context.Request.QueryString = new("?access_token=bad"); await pipeline(context); Equal(400, context.Response.StatusCode); Equal(1, called);
        });
        await Test("ASP.NET handler supports authentication policies and challenges", async () =>
        {
            using var http = KeyClient(); using var verifier = NewVerifier(http);
            using var services = new ServiceCollection().AddLogging().AddAuthentication(ProudAuthDefaults.AuthenticationScheme).AddProudAuth(o => o.Authenticator = verifier).Services.BuildServiceProvider();
            var context = new DefaultHttpContext { RequestServices = services }; context.Request.Headers.Authorization = "Bearer " + Sign();
            var result = await context.AuthenticateAsync(); True(result.Succeeded); Equal("usr_one", context.GetProudAuthClaims()!.Subject);
            using var scope = services.CreateScope(); context = new DefaultHttpContext { RequestServices = scope.ServiceProvider }; await context.ChallengeAsync(); Equal(401, context.Response.StatusCode);
        });
        await Test("RFC 6750 mappings protect upstream outages and support denial", () =>
        {
            foreach (var (code, status) in new[] { ("missing_token", 401), ("invalid_request", 400), ("signature", 401), ("scope", 403), ("organization", 403), ("support_policy", 403), ("unavailable", 503), ("stale_state", 503), ("contract", 500) })
                Equal(status, BearerAuthentication.Challenge(new(code)).Status);
            True(BearerAuthentication.Challenge(new("scope"), "realm\r\n", ["read"]).WwwAuthenticate!.Contains("scope=\"read\"", StringComparison.Ordinal)); return Task.CompletedTask;
        });
        await Test("duplicate Authorization and encoded query token denied", async () =>
        {
            var context = new DefaultHttpContext(); context.Request.Headers.Authorization = new Microsoft.Extensions.Primitives.StringValues(["Bearer a", "Bearer b"]);
            await Error("invalid_request", () => { _ = BearerAuthentication.BearerToken(context.Request); return Task.CompletedTask; });
            context.Request.Headers.Authorization = "Bearer a"; context.Request.QueryString = new("?%61ccess_token=x");
            await Error("invalid_request", () => { _ = BearerAuthentication.BearerToken(context.Request); return Task.CompletedTask; });
        });
    }
    private async Task TransportTests()
    {
        await Test("HTTP response body deadline and size limit enforced", async () =>
        {
            using var http = new HttpClient(new Handler((_, _) => Task.FromResult(Response(new string('x', 100)))));
            using var admin = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = http, MaxResponseBytes = 10 });
            await AdminError("network", () => admin.RequestAsync("GET", "/users"));
            using var delayed = new HttpClient(new Handler(async (_, ct) => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); throw new Exception(); }));
            using var timed = new AdminClient(new() { BaseUrl = "https://id.example.test", Realm = "main", HttpClient = delayed, Timeout = TimeSpan.FromMilliseconds(30) });
            await AdminError("timeout", () => timed.RequestAsync("GET", "/users"));
        });
        await Test("real loopback HTTP refuses redirects with credentials", async () =>
        {
            // Kestrel uses an ephemeral port; this tests the SDK-owned handler, not a mock HttpClient.
            var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders(); builder.WebHost.UseUrls("http://127.0.0.1:0");
            await using var app = builder.Build(); var targetCalls = 0;
            app.MapPost("/realms/main/oauth/introspect", () => Results.Redirect("/target")); app.MapGet("/target", () => { targetCalls++; return Results.Json(new { active = true }); });
            await app.StartAsync();
            var url = app.Urls.Single(); using var intro = new Introspector(new() { Endpoint = url + "/realms/main/oauth/introspect", Issuer = Issuer, Audience = Audience, ClientId = "fake", ClientSecret = "fake" });
            await Error("unavailable", () => intro.AuthenticateAsync("opaque")); Equal(0, targetCalls); await app.StopAsync();
        });
    }
}
internal sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handle) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => handle(request, cancellationToken);
}
internal sealed class Clock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset now = now;
    public override DateTimeOffset GetUtcNow() => now;
    internal void Advance(int seconds) => now = now.AddSeconds(seconds);
}
internal sealed class FailureAuthenticator(IAuthenticator inner) : IAuthenticator
{
    public Task<Claims> AuthenticateAsync(string token, CancellationToken cancellationToken = default) => token == "unavailable" ? throw new VerifierException("unavailable") : inner.AuthenticateAsync(token, cancellationToken);
}
