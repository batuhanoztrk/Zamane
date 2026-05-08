using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zamane;

/// <summary>
/// Builds Zamane identity strings used to authenticate requests against
/// KamuSM's timestamp service.
/// </summary>
/// <remarks>
/// An identity is a DER-encoded ASN.1 SEQUENCE containing the customer
/// number, the AES-256-CBC ciphertext of a payload (typically the
/// timestamp request's message hash), and the PBKDF2 parameters used to
/// derive the encryption key:
/// <code>
/// SEQUENCE {
///   INTEGER       customerNo,
///   OCTET STRING  salt        (8 bytes),
///   INTEGER       iterations,
///   OCTET STRING  iv          (16 bytes),
///   OCTET STRING  ciphertext
/// }
/// </code>
/// </remarks>
public static class IdentityGenerator
{
    private const int SaltSize = 8;
    private const int IvSize = 16;
    private const int KeySize = 32;
    private const int DefaultIterations = 100;

    /// <summary>
    /// Builds an encrypted identity and returns it as a lower-case
    /// hex-encoded DER ASN.1 SEQUENCE.
    /// </summary>
    /// <param name="customerNo">The KamuSM customer number.</param>
    /// <param name="password">
    /// The KamuSM customer password used as the PBKDF2 input.
    /// </param>
    /// <param name="hashValue">
    /// The payload to encrypt; typically the message hash that will be
    /// sent to the timestamp server.
    /// </param>
    /// <param name="iterations">
    /// PBKDF2 iteration count. Defaults to <c>100</c>.
    /// </param>
    /// <param name="salt">
    /// An optional 8-byte salt. A cryptographically random salt is
    /// generated when not provided.
    /// </param>
    /// <param name="iv">
    /// An optional 16-byte initialization vector. A cryptographically
    /// random IV is generated when not provided.
    /// </param>
    /// <returns>The DER-encoded identity as a lower-case hex string.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="password"/> or
    /// <paramref name="hashValue"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="iterations"/> is zero or negative.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="salt"/> is not 8 bytes long, or
    /// <paramref name="iv"/> is not 16 bytes long.
    /// </exception>
    public static string CreateIdentity(
        BigInteger customerNo,
        string password,
        byte[] hashValue,
        int iterations = DefaultIterations,
        byte[]? salt = null,
        byte[]? iv = null)
    {
        salt ??= GenerateRandomBytes(SaltSize);
        iv ??= GenerateRandomBytes(IvSize);

        if (salt.Length != SaltSize)
            throw new ArgumentException($"Salt must be {SaltSize} bytes long.", nameof(salt));

        if (iv.Length != IvSize)
            throw new ArgumentException($"IV must be {IvSize} bytes long.", nameof(iv));

        using var pbkdf2 = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256);
        var key = pbkdf2.GetBytes(KeySize);

        var ciphertext = EncryptAesCbc(hashValue, key, iv);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(customerNo);
            writer.WriteOctetString(salt);
            writer.WriteInteger(iterations);
            writer.WriteOctetString(iv);
            writer.WriteOctetString(ciphertext);
        }

        return ConvertPolyfill.ToHexStringLower(writer.Encode());
    }

    private static byte[] EncryptAesCbc(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    private static byte[] GenerateRandomBytes(int size)
    {
        var bytes = new byte[size];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        return bytes;
    }
}