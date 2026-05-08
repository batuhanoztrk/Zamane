using System;
using System.Formats.Asn1;

namespace Zamane;

/// <summary>
/// Helpers for extracting fields from RFC 3161 <c>TimeStampReq</c>
/// structures.
/// </summary>
/// <remarks>
/// Expected ASN.1 schema:
/// <code>
/// TimeStampReq ::= SEQUENCE {
///   version        INTEGER  { v1(1) },
///   messageImprint MessageImprint,
///   reqPolicy      TSAPolicyId  OPTIONAL,
///   nonce          INTEGER      OPTIONAL,
///   certReq        BOOLEAN      DEFAULT FALSE,
///   extensions [0] IMPLICIT Extensions OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE {
///   hashAlgorithm  AlgorithmIdentifier,
///   hashedMessage  OCTET STRING
/// }
/// </code>
/// </remarks>
public static class TimeStampRequestParser
{
    /// <summary>
    /// Extracts the <c>messageImprint.hashedMessage</c> octet string
    /// from a DER-encoded <c>TimeStampReq</c>.
    /// </summary>
    /// <param name="timeStampReq">
    /// The DER-encoded <c>TimeStampReq</c> bytes.
    /// </param>
    /// <returns>The <c>hashedMessage</c> bytes.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="timeStampReq"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="AsnContentException">
    /// Thrown when the input is not a valid DER-encoded
    /// <c>TimeStampReq</c>.
    /// </exception>
    public static byte[] GetHashedMessage(byte[] timeStampReq)
    {
        var reader = new AsnReader(timeStampReq, AsnEncodingRules.DER);
        var tsReq = reader.ReadSequence();

        // version
        _ = tsReq.ReadInteger();

        // messageImprint SEQUENCE
        var messageImprint = tsReq.ReadSequence();

        // hashAlgorithm AlgorithmIdentifier (skipped)
        _ = messageImprint.ReadSequence();

        // hashedMessage OCTET STRING
        return messageImprint.ReadOctetString();
    }

    /// <summary>
    /// Extracts the <c>messageImprint.hashedMessage</c> octet string
    /// from a hex-encoded <c>TimeStampReq</c>.
    /// </summary>
    /// <param name="timeStampReqHex">
    /// The hex-encoded <c>TimeStampReq</c>.
    /// </param>
    /// <returns>The <c>hashedMessage</c> bytes.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="timeStampReqHex"/> is <c>null</c> or
    /// empty.
    /// </exception>
    public static byte[] GetHashedMessage(string timeStampReqHex)
    {
        return GetHashedMessage(ConvertPolyfill.FromHexString(timeStampReqHex));
    }
}