# Zamane

A small, dependency-free client library for KamuSM's Zamane
timestamp service. ASN.1 work is done with the built-in
`System.Formats.Asn1` API, so there are no external NuGet dependencies.

## Install

```bash
dotnet add package Zamane
```

## API

| Type | Responsibility |
| --- | --- |
| `IdentityGenerator` | `customerNo + password + hash` → DER-encoded hex identity |
| `TimeStampRequestParser` | `TimeStampReq` → `messageImprint.hashedMessage` |
| `TimeStampClient` | HTTP POST + `identity` header → Zamane `TimeStampResp` |

## Quick start

```csharp
using Zamane;

using var http = new HttpClient();
var client = new TimeStampClient(
    TimeStampClient.TestBaseUrl, // or .ProductionBaseUrl
    http);

byte[] tsr = await client.RequestTimestampAsync(
    customerNo:   "12345",
    password:     "secret",
    timeStampReq: tsReqBytes);

await File.WriteAllBytesAsync("token.tsr", tsr);
```

`tsReqBytes` must be a DER-encoded RFC 3161 `TimeStampReq`. Build one
with BouncyCastle (or any other ASN.1 toolkit) before calling the
client.

## Building an identity directly

```csharp
using System.Numerics;
using Zamane;

string identity = IdentityGenerator.CreateIdentity(
    customerNo: BigInteger.Parse("12345"),
    password:   "secret",
    hashValue:  hashBytes);

// Override iteration count, salt, IV:
string identity2 = IdentityGenerator.CreateIdentity(
    customerNo: 42,
    password:   "secret",
    hashValue:  hashBytes,
    iterations: 10_000,
    salt:       saltBytes, // 8 bytes
    iv:         ivBytes);  // 16 bytes
```

The hex string decodes to:

```
SEQUENCE {
  INTEGER       customerNo,
  OCTET STRING  salt        (8 bytes),
  INTEGER       iterations,
  OCTET STRING  iv          (16 bytes),
  OCTET STRING  ciphertext
}
```

## Reading `hashedMessage` from a `TimeStampReq`

```csharp
using Zamane;

byte[] hashedMessage = TimeStampRequestParser.GetHashedMessage(tsReqBytes);

// or from a hex string:
byte[] hashedMessage2 = TimeStampRequestParser.GetHashedMessage(tsReqHex);
```

## Using `IHttpClientFactory`

```csharp
services.AddHttpClient<TimeStampClient>(c =>
{
    c.BaseAddress = new Uri(TimeStampClient.ProductionBaseUrl);
    c.Timeout     = TimeSpan.FromSeconds(30);
});
```

`TimeStampClient` accepts a base URL and an optional `HttpClient`. In
DI scenarios, prefer passing a shared `HttpClient` instance.