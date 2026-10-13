using System.Security.Cryptography;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

namespace ProudAuth.Sdk.Internal;

internal sealed record Jws(JsonElement Header, JsonElement Payload, byte[] Input, byte[] Signature);
internal static class Jose
{
    internal static readonly string[] Supported = ["RS256", "PS256", "ES256", "EdDSA"];
    internal static HashSet<string> Algorithms(IEnumerable<string>? algorithms)
    {
        var a = new HashSet<string>(algorithms ?? Supported, StringComparer.Ordinal);
        if (a.Count == 0 || a.Any(x => !Supported.Contains(x))) throw new ArgumentException("Only RS256, PS256, ES256 and EdDSA are supported.");
        return a;
    }
    internal static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static byte[] Decode(string text)
    {
        if (text.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')) throw new VerifierException("malformed");
        try
        {
            var b = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
            if (Encode(b) != text) throw new VerifierException("malformed");
            return b;
        }
        catch (FormatException) { throw new VerifierException("malformed"); }
    }
    internal static Jws Parse(string raw, int maxBytes)
    {
        if (string.IsNullOrEmpty(raw)) throw new VerifierException("missing_token");
        if (Encoding.UTF8.GetByteCount(raw) > maxBytes) throw new VerifierException("too_large");
        var parts = raw.Split('.');
        if (parts.Length != 3) throw new VerifierException("malformed");
        return new(Json.Object(Decode(parts[0])), Json.Object(Decode(parts[1])), Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]));
    }
    internal static bool Usable(JsonElement k)
    {
        try
        {
            if (k.Str("kid") == "" || (k.Has("use") && k.Str("use") != "sig") ||
                new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" }.Any(x => k.Has(x))) return false;
            if (k.Has("alg") && k.Get("alg").ValueKind != JsonValueKind.String) return false;
            if (k.Has("key_ops") && (k.Get("key_ops").ValueKind != JsonValueKind.Array ||
                !k.Get("key_ops").EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == "verify"))) return false;
            switch (k.Str("kty"))
            {
                case "RSA":
                    using (var rsa = Rsa(k)) return rsa.KeySize >= 2048;
                case "EC":
                    if (k.Str("crv") != "P-256") return false;
                    using (var ec = Ec(k)) return ec.KeySize == 256;
                case "OKP": return k.Str("crv") == "Ed25519" && Decode(k.Str("x")).Length == 32;
                default: return false;
            }
        }
        catch (Exception e) when (e is VerifierException or CryptographicException or ArgumentException) { return false; }
    }
    private static RSA Rsa(JsonElement k)
    {
        var rsa = RSA.Create();
        try
        {
            var modulus = Decode(k.Str("n")); var exponent = Decode(k.Str("e"));
            var n = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
            var e = new BigInteger(exponent, isUnsigned: true, isBigEndian: true);
            if (n.IsEven || e.IsEven || e < 3 || e >= n || n.GetBitLength() < 2048) throw new CryptographicException();
            rsa.ImportParameters(new RSAParameters { Modulus = modulus, Exponent = exponent }); return rsa;
        }
        catch { rsa.Dispose(); throw; }
    }
    private static ECDsa Ec(JsonElement k)
    {
        var ec = ECDsa.Create();
        try
        {
            var x = Decode(k.Str("x")); var y = Decode(k.Str("y"));
            if (x.Length != 32 || y.Length != 32) throw new CryptographicException();
            ec.ImportParameters(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
            return ec;
        }
        catch { ec.Dispose(); throw; }
    }
    internal static bool Verify(string algorithm, JsonElement key, Jws jws)
    {
        try
        {
            switch (algorithm)
            {
                case "RS256" when key.Str("kty") == "RSA":
                    using (var rsa = Rsa(key)) return rsa.VerifyData(jws.Input, jws.Signature, HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                case "PS256" when key.Str("kty") == "RSA":
                    // Native PSS providers differ on non-byte-aligned RSA moduli. Bouncy Castle matches the Go oracle.
                    var modulus = new Org.BouncyCastle.Math.BigInteger(1, Decode(key.Str("n")));
                    var exponent = new Org.BouncyCastle.Math.BigInteger(1, Decode(key.Str("e")));
                    if (jws.Signature.Length != (modulus.BitLength + 7) / 8) return false;
                    var pss = new PssSigner(new RsaEngine(), new Sha256Digest(), 32);
                    pss.Init(false, new RsaKeyParameters(false, modulus, exponent));
                    pss.BlockUpdate(jws.Input, 0, jws.Input.Length);
                    return pss.VerifySignature(jws.Signature);
                case "ES256" when key.Str("kty") == "EC" && key.Str("crv") == "P-256":
                    using (var ec = Ec(key)) return jws.Signature.Length == 64 && ec.VerifyData(jws.Input, jws.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                case "EdDSA" when key.Str("kty") == "OKP" && key.Str("crv") == "Ed25519":
                    var signer = new Ed25519Signer();
                    signer.Init(false, new Ed25519PublicKeyParameters(Decode(key.Str("x")), 0));
                    signer.BlockUpdate(jws.Input, 0, jws.Input.Length);
                    return jws.Signature.Length == 64 && signer.VerifySignature(jws.Signature);
                default: return false;
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or VerifierException or Org.BouncyCastle.Crypto.CryptoException) { return false; }
    }
    internal static bool Equal(string a, string b) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
