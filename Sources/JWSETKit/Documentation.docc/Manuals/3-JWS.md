# JSON Web Signature (JWS)

Using JWS to create, sign and verify a custom payload.

## Overview

JSON Web Signature (JWS) represents content secured with digital
signatures or Message Authentication Codes (MACs) using JSON-based
data structures.  

Cryptographic algorithms and identifiers for use
with this specification are described in the separate JSON Web
Algorithms (JWA) specification and an IANA registry defined by that
specification. 

See [Keys documetation](4-keys) to find supported keys for verification and singing.

Supports `HS256`, `HS384` and `HS512` algorithms for signature.

## Initializing And Encoding

`JSONWebSignature` is generic struct that can contains and payload that conforms to
``ProtectedWebContainer`` which stores data that would be signed.

There are two implementations of ``ProtectedWebContainer`` in the library:
- ``ProtectedJSONWebContainer`` which the payload is a JSON and would be
    accessible using [value](protectedjsonwebcontainer/value).
- ``ProtectedDataWebContainer`` which the data can be any binary format,
    e.g. a nested/encrypted JWT.

To convert back a JWT instance to string representation,

```swift
let jwsString = try String(jws: jwt)
```
or
```swift
let jwsString = jws.description
```

To convert back to complete/flattened json serialization,

```swift
var encoder = JSONEncoder()
encoder.userInfo = [.jwsEncodedRepresentation: JSONWebSignatureRepresentation.json]
let json = try encoder.encode(jws)
```

## Verify Signature

To verify the signature(s), first [create public key(s)](4-keys) then use
`verifySignature(using:)` to verify signature(s).

If an array of keys is passed to `verifySignature(using:)` the most appropriate
key will be selected according `alg` value and then `kid` value if multiple keys
are candidates regarding [JOSE header](joseheader) counterpart of signature.

- Note: ``JSONWebSignature`` currently don't honor `b64` key in JOSE header if set to `false`.

Using symmetric key for `HS256`, etc.,
```swift
let hmacKey = SymmetricKey(data: hmacKeyData)
do {
    try jwt.verifySignature(using: hmacKey)
} catch {
    print("signature is invalid.")
}
```

Using RSA key for `RS256`, `PS256`, etc. according to `alg` header.
Also usable for Eliptic-Curve, but `CryptoKit.P256.Signing` is recommended.

```swift
let attributes: CFDictionary =
[
    kSecAttrKeyClass: kSecAttrKeyClassPublic,
    kSecAttrKeyType: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits: 2048,
] as CFDictionary
let rsaSecKey = SecKeyCreateWithData(rsaKeyData as CFData, attributes, nil)
do {
    try jwt.verifySignature(using: rsaSecKey)

    // Alternatively if `CommonCrypto` is not available, e.g. Linux.
    let rsaKey = try JSONWebRSAPublicKey(derRepresentation: rsaKeyData)
    try jwt.verifySignature(using: rsaKey)
} catch {
    print("signature is invalid.")
}
```

Using P-256 key for `ES256`, etc.,
```swift
do {
    let ecKey = try P256.Signing.PublicKey(derRepresentation: ecKeyData)
    try jwt.verifySignature(using: ecKey)
} catch {
    print("signature is invalid.")
}
```

Using a given X.509 certificate,

```swift
import X509

do {
    let certificate = try Certificate(derEncoded: certificateData)
    try jwt.verifySignature(using: certificate)

    // Alternatively CommonCrypto.SecCertificate can be used.
    let secCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData as CFData)!
    try jwt.verifySignature(using: secCertificate)
} catch {
    print("signature is invalid.")
}
```

## Updating/Adding Signature

If no header is set for signature, first add the header to JWS instance,

```swift
var header = JOSEHeader(algorithm: .hmacSHA256, type: "JWT")
jws.signatures = try [JSONWebSignatureHeader(header: header, signature: Data())]
```

Then [create private key(s)](4-keys) for signing operation.

If an array of keys is passed to `updateSignature(using:)` the most appropriate
key will be selected according `alg` value and then `kid` value if multiple keys
are candidates regarding [JOSE header](joseheader) counterpart of signature.

```swift
let hmacKey = SymmetricKey(size: .bits128)
try jws.updateSignature(using: hmacKey)
```

## Topics

### JOSE Headers

- ``JOSEHeader``
- ``JoseHeaderJWSRegisteredParameters``

### Signature

- ``JSONWebSignature``
