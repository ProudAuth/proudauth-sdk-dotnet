namespace ProudAuth.Sdk;

/// <summary>Stable categories; exception messages never include token or claim values (SDK-008).</summary>
public sealed class VerifierException(string code) : Exception($"proudauth: {code}")
{
    public string Code { get; } = code;
}

public sealed class OidcException(string code, string? reason = null) : Exception($"oidc: {code}" + (reason is null ? "" : $" ({reason})"))
{
    public string Code { get; } = code;
    public string? Reason { get; } = reason;
}

public sealed class CursorExpiredException() : Exception("session-event cursor expired; replay retained history");

public sealed class AdminRequestException(string code, string method, string path) : Exception($"admin: {method} {path.Split('?')[0]} ({code})")
{
    public string Code { get; } = code;
    public string Method { get; } = method;
    public string Path { get; } = path.Split('?')[0];
}
