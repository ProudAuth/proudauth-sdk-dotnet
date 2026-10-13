using System.Text;
using System.Text.Json;

namespace ProudAuth.Sdk.Internal;

internal static class Json
{
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    // JsonDocument accepts duplicate members. Check every object before making any security decision.
    internal static JsonElement Parse(byte[] bytes)
    {
        try
        {
            _ = Utf8.GetString(bytes);
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 64 });
            var objects = new Stack<HashSet<string>>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
                else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
                else if (reader.TokenType == JsonTokenType.PropertyName && !objects.Peek().Add(reader.GetString()!))
                    throw new VerifierException("duplicate_claim");
            }
            using var doc = JsonDocument.Parse(bytes);
            return doc.RootElement.Clone();
        }
        catch (Exception e) when (e is JsonException or DecoderFallbackException or InvalidOperationException)
        { throw new VerifierException("malformed"); }
    }

    internal static JsonElement Object(byte[] bytes)
    {
        var p = Parse(bytes);
        if (p.ValueKind != JsonValueKind.Object) throw new VerifierException("malformed");
        return p;
    }
    internal static JsonElement Get(this JsonElement p, string key) => p.ValueKind == JsonValueKind.Object && p.TryGetProperty(key, out var v) ? v : default;
    internal static bool Has(this JsonElement p, string key) => p.ValueKind == JsonValueKind.Object && p.TryGetProperty(key, out _);
    internal static string Str(this JsonElement p, string key)
    {
        var v = p.Get(key);
        if (v.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return "";
        if (v.ValueKind != JsonValueKind.String) throw new VerifierException("malformed");
        return v.GetString()!;
    }
    internal static double? Num(this JsonElement p, string key)
    {
        var v = p.Get(key);
        if (v.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.Number || !v.TryGetDouble(out var n) || !double.IsFinite(n))
            throw new VerifierException("malformed");
        return n;
    }
    internal static string[] Audience(JsonElement p)
    {
        var v = p.Get("aud");
        if (v.ValueKind == JsonValueKind.String) return [v.GetString()!];
        if (v.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return [];
        if (v.ValueKind != JsonValueKind.Array || v.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String))
            throw new VerifierException("malformed");
        return v.EnumerateArray().Select(x => x.GetString()!).ToArray();
    }
    internal static DateTimeOffset? Date(double? seconds)
    {
        if (seconds is null) return null;
        try { return DateTimeOffset.UnixEpoch.AddSeconds(seconds.Value); }
        catch (ArgumentOutOfRangeException) { throw new VerifierException("malformed"); }
    }
}
